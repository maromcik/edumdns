use crate::error::ServerError;
use crate::transmitter::{PacketTransmitter, PacketTransmitterTask};
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::deadpool::Pool;
use edumdns_core::app_packet::{AppPacket, LocalAppPacket, LocalCommandPacket, NetworkAppPacket, NetworkCommandPacket, PacketTransmitRequestPacket, ProbePacket, NetworkStatusPacket, LocalStatusPacket};
use edumdns_core::bincode_types::{IpNetwork, MacAddr, Uuid};
use edumdns_core::connection::{TcpConnectionHandle, TcpConnectionMessage};
use edumdns_db::repositories::common::{DbCreate, DbReadMany, DbReadOne};
use edumdns_db::repositories::device::models::{CreateDevice, SelectSingleDevice};
use edumdns_db::repositories::device::repository::PgDeviceRepository;
use edumdns_db::repositories::packet::models::{CreatePacket, SelectManyPackets};
use edumdns_db::repositories::packet::repository::PgPacketRepository;
use log::{debug, error, info, warn};
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{Mutex, RwLock};
use edumdns_core::error::CoreError;

pub struct PacketStorage {
    pub packets: HashMap<Uuid, HashMap<(MacAddr, IpNetwork), HashSet<ProbePacket>>>,
    pub packet_receiver: Receiver<AppPacket>,
    pub transmitter_tasks: Arc<Mutex<HashMap<PacketTransmitRequestPacket, PacketTransmitterTask>>>,
    pub probe_handles: Arc<RwLock<HashMap<Uuid, TcpConnectionHandle>>>,
    pub probe_ws_handles: Arc<Mutex<HashMap<uuid::Uuid, HashMap<uuid::Uuid, Sender<AppPacket>>>>>,
    pub pg_device_repository: PgDeviceRepository,
    pub pg_packet_repository: PgPacketRepository,
    pub global_timeout: Duration,
}

impl PacketStorage {
    pub fn new(
        receiver: Receiver<AppPacket>,
        db_pool: Pool<AsyncPgConnection>,
        handles: Arc<RwLock<HashMap<Uuid, TcpConnectionHandle>>>,
        global_timeout: Duration,
    ) -> Self {
        Self {
            packets: HashMap::new(),
            packet_receiver: receiver,
            transmitter_tasks: Arc::new(Mutex::new(HashMap::new())),
            probe_handles: handles,
            probe_ws_handles: Arc::new(Mutex::new(HashMap::new())),
            pg_device_repository: PgDeviceRepository::new(db_pool.clone()),
            pg_packet_repository: PgPacketRepository::new(db_pool.clone()),
            global_timeout,
        }
    }

    pub async fn handle_packets(&mut self) {
        while let Some(packet) = self.packet_receiver.recv().await {
            match packet {
                AppPacket::Network(network_packet) => self.handle_network_packet(network_packet).await,
                AppPacket::Local(local_packet) => self.handle_local_packet(local_packet).await,
            }
        }
    }

    pub async fn handle_local_packet(&mut self, packet: LocalAppPacket) {
        match packet {
            LocalAppPacket::Command(command) => match command {
                LocalCommandPacket::RegisterForEvents { probe_id, session_id, respond_to } => {
                    self.probe_ws_handles.lock().await.entry(probe_id).or_insert(HashMap::new()).entry(session_id).or_insert(respond_to);
                }
                LocalCommandPacket::UnregisterFromEvents { probe_id, session_id } => {
                    if let Some(session) = self.probe_ws_handles.lock().await.get_mut(&probe_id) {
                        session.remove(&session_id);
                    }
                }
                LocalCommandPacket::TransmitDevicePackets(target) => {
                    if self.transmitter_tasks.lock().await.contains_key(&target) {
                        warn!("Transmitter task already exists for target: {}", target);
                    } else {
                        self.transmit_device_packets(target)
                    }
                }
                LocalCommandPacket::StopTransmitDevicePackets(target) => {
                    if let Some(t) = self.transmitter_tasks.lock().await.get(&target) {
                        t.transmitter_task.abort();
                    }
                    self.transmitter_tasks.lock().await.remove(&target);
                }
                LocalCommandPacket::ReconnectProbe(id) => self.send_reconnect(id).await,
            },
            LocalAppPacket::Status(_) => {},
        }
    }

    pub async fn handle_network_packet(&mut self, packet: NetworkAppPacket) {
        match packet {
            NetworkAppPacket::Command(_) => {}
            NetworkAppPacket::Status(status) => {
                match status {
                    NetworkStatusPacket::ProbeInvalidConfig(uuid, e) => {
                        if let Some(handles) = self.probe_ws_handles.lock().await.get(&uuid.0) {
                            for handle in handles.values() {
                                if let Err(err) = handle.send(AppPacket::Local(LocalAppPacket::Status(LocalStatusPacket::WsResponse(e.clone())))).await {
                                    warn!("Could not send response to a websocket {err}");
                                };
                            }
                            return;
                        }
                        warn!("Probe {uuid} not registered for websocket events: {e}");
                    }
                    NetworkStatusPacket::ProbeReconnectResponse(uuid, response) => {},
                    _ => {}
                }
            }
            NetworkAppPacket::Data(probe_packet) => {
                let src_mac = probe_packet
                    .packet_metadata
                    .datalink_metadata
                    .mac_metadata
                    .src_mac;

                let src_ip = probe_packet.packet_metadata.ip_metadata.src_ip;

                // self
                //     .packets
                //     .entry(probe_packet.probe_metadata.id)
                //     .or_default()
                //     .entry((src_mac, src_ip))
                //     .or_default()
                //     .insert(probe_packet.clone());
                match self.packets.entry(probe_packet.probe_metadata.id) {
                    Entry::Occupied(mut probe_entry) => {
                        match probe_entry.get_mut().entry((src_mac, src_ip)) {
                            Entry::Occupied(mut device_entry) => {
                                if !device_entry.get().contains(&probe_packet) {
                                    device_entry.get_mut().insert(probe_packet.clone());
                                    debug!("Probe and device found; stored packet in database");
                                    self.store_packet_in_database(probe_packet.clone()).await;
                                } else {
                                    debug!("Probe, device and packet found; no action");
                                }
                            }
                            Entry::Vacant(device_entry) => {
                                let device_entry = device_entry.insert(HashSet::new());
                                device_entry.insert(probe_packet.clone());
                                debug!("Probe found; stored device and packet in database");
                                self.store_device_in_database(probe_packet.clone()).await;
                                self.store_packet_in_database(probe_packet.clone()).await;
                            }
                        }
                    }
                    Entry::Vacant(probe_entry) => {
                        let probe_entry = probe_entry.insert(HashMap::new());
                        probe_entry
                            .entry((src_mac, src_ip))
                            .or_default()
                            .insert(probe_packet.clone());
                        self.store_device_in_database(probe_packet.clone()).await;
                        self.store_packet_in_database(probe_packet.clone()).await;
                        debug!("Probe not found in hashmap; stored device and packet in database");
                    }
                }
                debug!("Packet <MAC: {src_mac}, IP: {src_ip}> stored in memory");
            }
        }
    }

    pub async fn send_reconnect(&self, id: Uuid) {
        if let Some(handle) = self.probe_handles.read().await.get(&id) {
            let res = handle
                .send_message_with_response(|tx| {
                    TcpConnectionMessage::send_packet(
                        tx,
                        NetworkAppPacket::Command(NetworkCommandPacket::ReconnectThisProbe),
                    )
                })
                .await
                .map_err(ServerError::from);
            match res {
                Ok(o) => {
                    if let Err(e) = o {
                        error!(
                            "Error while reconnecting probe {id}: {}",
                            ServerError::from(e)
                        );
                    }
                }
                Err(e) => {
                    error!("Error while reconnecting probe {id}: {e}");
                }
            }
        }
    }

    pub async fn store_device_in_database(&self, packet: ProbePacket) {
        let src_mac = packet
            .packet_metadata
            .datalink_metadata
            .mac_metadata
            .src_mac;
        let src_ip = packet.packet_metadata.ip_metadata.src_ip;
        let device_repo = self.pg_device_repository.clone();
        tokio::task::spawn(async move {
            let device = device_repo
                .create(&CreateDevice::new(
                    packet.probe_metadata.id.0,
                    src_mac.to_octets(),
                    src_ip.0,
                    packet.packet_metadata.transport_metadata.dst_port,
                ))
                .await;
            match device {
                Ok(d) => {
                    debug!(
                        "Device <ID: {}, MAC: {}, IP: {}> stored in database",
                        d.id, src_mac, d.ip
                    );
                    d
                }
                Err(e) => {
                    error!(
                        "Could not store device <MAC: {}, IP: {}> in database: {e}",
                        src_mac, src_ip
                    );
                    return;
                }
            };
        });
    }

    pub async fn store_packet_in_database(&self, packet: ProbePacket) {
        let src_mac = packet
            .packet_metadata
            .datalink_metadata
            .mac_metadata
            .src_mac;
        let src_ip = packet.packet_metadata.ip_metadata.src_ip;
        let packet_repo = self.pg_packet_repository.clone();
        tokio::task::spawn(async move {
            let packet = packet_repo
                .create(&CreatePacket::new(
                    packet.probe_metadata.id.0,
                    src_mac.to_octets(),
                    packet
                        .packet_metadata
                        .datalink_metadata
                        .mac_metadata
                        .dst_mac
                        .0
                        .octets(),
                    src_ip.0,
                    packet.packet_metadata.ip_metadata.dst_ip.0,
                    packet.packet_metadata.transport_metadata.src_port,
                    packet.packet_metadata.transport_metadata.dst_port,
                    packet.payload,
                    packet.payload_hash,
                ))
                .await;
            match packet {
                Ok(p) => debug!(
                    "Packet <ProbeID: {}, MAC: {}, IP: {}> stored in database",
                    p.probe_id, src_mac, p.src_addr
                ),
                Err(e) => error!(
                    "Could not store packet <MAC: {}, IP: {}> in database: {e}",
                    src_mac, src_ip
                ),
            }
        });
    }

    pub fn transmit_device_packets(&mut self, transmit_request: PacketTransmitRequestPacket) {
        let packet_repo = self.pg_packet_repository.clone();
        let device_repo = self.pg_device_repository.clone();

        let probe_id = transmit_request.probe_uuid.0;
        let device_lookup = SelectSingleDevice::new(
            probe_id,
            transmit_request.device_mac.to_octets(),
            transmit_request.device_ip.0,
        );

        let transmitter_tasks = self.transmitter_tasks.clone();
        let global_timeout = self.global_timeout;
        tokio::task::spawn(async move {
            let device = match device_repo.read_one(&device_lookup).await {
                Ok(d) => d,
                Err(e) => {
                    warn!("No target device: {transmit_request}: {e}");
                    return;
                }
            };

            info!("Target device found: {}", transmit_request);

            let packets = match packet_repo
                .read_many(&SelectManyPackets::new(
                    Some(probe_id),
                    Some(device.mac),
                    None,
                    Some(device.ip),
                    None,
                    None,
                    None,
                    None,
                ))
                .await
            {
                Ok(p) => p,
                Err(e) => {
                    warn!("No packets found for target: {transmit_request}: {e}");
                    return;
                }
            };

            info!("Packets found for target: {}", transmit_request);

            let payloads = packets
                .into_iter()
                .map(|p| p.payload)
                .collect::<HashSet<Vec<u8>>>();
            let transmitter = PacketTransmitter::new(
                payloads,
                transmit_request.clone(),
                Duration::from_millis(device.interval as u64),
                global_timeout,
            )
            .await;

            let Ok(transmitter) = transmitter else {
                error!("Could not create transmitter for target: {transmit_request}");
                return;
            };
            let task = PacketTransmitterTask::new(transmitter);
            transmitter_tasks
                .lock()
                .await
                .entry(transmit_request)
                .or_insert(task);
        });
    }
}
