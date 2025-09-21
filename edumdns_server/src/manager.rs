use crate::ebpf::EbpfUpdater;
use crate::error::{ServerError, ServerErrorKind};
use crate::ordered_map::OrderedMap;
use crate::transmitter::{PacketTransmitter, PacketTransmitterTask};
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::deadpool::Pool;
use edumdns_core::app_packet::{
    AppPacket, LocalAppPacket, LocalCommandPacket, LocalStatusPacket, NetworkAppPacket,
    NetworkCommandPacket, NetworkStatusPacket, PacketTransmitRequestPacket, ProbePacket,
    ProbeResponse,
};
use edumdns_core::bincode_types::{IpNetwork, MacAddr, Uuid};
use edumdns_core::connection::{TcpConnectionHandle, TcpConnectionMessage};
use edumdns_db::repositories::common::{DbCreate, DbReadMany, DbReadOne};
use edumdns_db::repositories::device::models::{CreateDevice, SelectSingleDevice};
use edumdns_db::repositories::device::repository::PgDeviceRepository;
use edumdns_db::repositories::packet::models::{CreatePacket, SelectManyPackets};
use edumdns_db::repositories::packet::repository::PgPacketRepository;
use hickory_proto::op::Message;
use hickory_proto::rr::RData;
use hickory_proto::serialize::binary::BinDecodable;
use log::{debug, error, info, warn};
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::env;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{Mutex, RwLock};

#[derive(Clone)]
pub struct Proxy {
    pub proxy_ipv4: Ipv4Addr,
    pub proxy_ipv6: Ipv6Addr,
    pub ebpf_updater: Arc<Mutex<EbpfUpdater>>,
}

pub struct PacketManager {
    pub packets: HashMap<Uuid, HashMap<(MacAddr, IpNetwork), HashSet<ProbePacket>>>,
    pub packet_receiver: Receiver<AppPacket>,
    pub transmitter_tasks: Arc<Mutex<HashMap<PacketTransmitRequestPacket, PacketTransmitterTask>>>,
    pub probe_handles: Arc<RwLock<HashMap<Uuid, TcpConnectionHandle>>>,
    pub probe_ws_handles: HashMap<uuid::Uuid, HashMap<uuid::Uuid, Sender<ProbeResponse>>>,
    pub pg_device_repository: PgDeviceRepository,
    pub pg_packet_repository: PgPacketRepository,
    pub proxy: Option<Proxy>,
    pub global_timeout: Duration,
}

impl PacketManager {
    pub fn new(
        receiver: Receiver<AppPacket>,
        db_pool: Pool<AsyncPgConnection>,
        handles: Arc<RwLock<HashMap<Uuid, TcpConnectionHandle>>>,
        global_timeout: Duration,
    ) -> Result<Self, ServerError> {
        let use_proxy = env::var("EDUMDNS_SERVER_USE_PROXY")
            .unwrap_or("false".to_string())
            .parse::<bool>()
            .unwrap_or(false);

        let proxy_ipv4 = env::var("EDUMDNS_SERVER_PROXY_IPV4")
            .unwrap_or("127.0.0.1".to_string())
            .parse::<Ipv4Addr>()?;
        let proxy_ipv6 = env::var("EDUMDNS_SERVER_PROXY_IPV6")
            .unwrap_or("::1".to_string())
            .parse::<Ipv6Addr>()?;
        let proxy = if use_proxy {
            match EbpfUpdater::new() {
                Ok(updater) => Some(Proxy {
                    proxy_ipv4,
                    proxy_ipv6,
                    ebpf_updater: Arc::new(Mutex::new(updater)),
                }),
                Err(e) => {
                    error!("Could not create ebpf updater: {}", e);
                    None
                }
            }
        } else {
            None
        };

        Ok(Self {
            packets: HashMap::new(),
            packet_receiver: receiver,
            transmitter_tasks: Arc::new(Mutex::new(HashMap::new())),
            probe_handles: handles,
            probe_ws_handles: HashMap::new(),
            pg_device_repository: PgDeviceRepository::new(db_pool.clone()),
            pg_packet_repository: PgPacketRepository::new(db_pool.clone()),
            proxy,
            global_timeout,
        })
    }

    pub async fn handle_packets(&mut self) {
        while let Some(packet) = self.packet_receiver.recv().await {
            match packet {
                AppPacket::Network(network_packet) => {
                    self.handle_network_packet(network_packet).await
                }
                AppPacket::Local(local_packet) => self.handle_local_packet(local_packet).await,
            }
        }
    }

    pub async fn handle_local_packet(&mut self, packet: LocalAppPacket) {
        match packet {
            LocalAppPacket::Command(command) => match command {
                LocalCommandPacket::RegisterForEvents {
                    probe_id,
                    session_id,
                    respond_to,
                } => {
                    self.probe_ws_handles
                        .entry(probe_id)
                        .or_default()
                        .entry(session_id)
                        .or_insert(respond_to);
                }
                LocalCommandPacket::UnregisterFromEvents {
                    probe_id,
                    session_id,
                } => {
                    if let Some(session) = self.probe_ws_handles.get_mut(&probe_id) {
                        session.remove(&session_id);
                        if session.is_empty() {
                            self.probe_ws_handles.remove(&probe_id);
                        }
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
                    let Some(proxy) = &self.proxy else {
                        return;
                    };
                    if let Err(e) = proxy
                        .ebpf_updater
                        .lock()
                        .await
                        .remove_ip(target.device_ip, target.target_ip)
                    {
                        error!("Could not remove IP from an ebpf map: {}", e);
                    }
                }
                LocalCommandPacket::ReconnectProbe(id, session_id) => {
                    if let Err(e) = self.send_reconnect(id, session_id).await {
                        error!("Could not reconnect probe: {}", e);
                        self.probe_handles.write().await.remove(&id);
                        self.send_response_to_ws(
                            id,
                            session_id,
                            ProbeResponse::new_error(e.to_string()),
                        )
                        .await;
                    }
                }
            },
            LocalAppPacket::Status(status) => match status {
                LocalStatusPacket::GetLiveProbes => {}
                LocalStatusPacket::IsProbeLive {
                    probe_id,
                    respond_to,
                } => {
                    if self
                        .probe_handles
                        .read()
                        .await
                        .contains_key(&Uuid(probe_id))
                        && let Err(e) = respond_to.send(true)
                    {
                        error!("Could not send a response to probe {}: {}", probe_id, e);
                    }
                }
            },
        }
    }

    pub async fn handle_network_packet(&mut self, packet: NetworkAppPacket) {
        match packet {
            NetworkAppPacket::Command(_) => {}
            NetworkAppPacket::Status(status) => match status {
                NetworkStatusPacket::ProbeResponse(uuid, session_id, response) => {
                    self.send_response_to_ws(uuid, session_id, response).await;
                }
                _ => {}
            },
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

    pub async fn send_reconnect(
        &self,
        id: Uuid,
        session_id: Option<Uuid>,
    ) -> Result<(), ServerError> {
        if let Some(handle) = self.probe_handles.read().await.get(&id) {
            handle
                .send_message_with_response(|tx| {
                    TcpConnectionMessage::send_packet(
                        tx,
                        NetworkAppPacket::Command(NetworkCommandPacket::ReconnectThisProbe(
                            session_id,
                        )),
                    )
                })
                .await
                .map_err(ServerError::from)??;
        } else {
            warn!("Probe not found: {}", id);
            return Err(ServerError::new(
                ServerErrorKind::ProbeNotFound,
                "not connected",
            ));
        }
        Ok(())
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

    pub async fn send_response_to_ws(
        &self,
        id: Uuid,
        session_id: Option<Uuid>,
        response: ProbeResponse,
    ) {
        if let Some(handles) = self.probe_ws_handles.get(&id.0) {
            match session_id {
                None => {
                    for (id, handle) in handles {
                        match handle.send(response.clone()).await {
                            Ok(_) => {
                                debug!("Response sent to websocket: {}", id);
                            }
                            Err(err) => warn!("Could not send response to a websocket {err}"),
                        }
                    }
                }
                Some(ses_id) => {
                    if let Some(handle) = handles.get(&ses_id.0) {
                        match handle.send(response.clone()).await {
                            Ok(_) => {
                                debug!("Response sent to websocket: {}", id);
                            }
                            Err(err) => warn!("Could not send response to a websocket {err}"),
                        }
                    }
                }
            }
        }
    }

    pub fn transmit_device_packets(&mut self, transmit_request: PacketTransmitRequestPacket) {
        let packet_repo = self.pg_packet_repository.clone();
        let device_repo = self.pg_device_repository.clone();

        let probe_id = transmit_request.probe_uuid.0;
        let device_lookup = SelectSingleDevice::new(
            probe_id,
            transmit_request.device_mac.to_octets(),
            transmit_request.device_ip,
        );

        let proxy = self.proxy.clone();
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
            let payloads = if let Some(p) = &proxy {
                let mut payloads = HashSet::new();
                for packet in packets {
                    let Ok(mut message) = Message::from_bytes(packet.payload.as_slice()) else {
                        continue;
                    };
                    for ans in message.answers_mut() {
                        if ans.data().is_a() {
                            ans.set_data(RData::A(hickory_proto::rr::rdata::a::A::from(
                                p.proxy_ipv4,
                            )));
                        }
                        if ans.data().is_aaaa() {
                            ans.set_data(RData::AAAA(hickory_proto::rr::rdata::aaaa::AAAA::from(
                                p.proxy_ipv6,
                            )));
                        }
                    }
                    if let Ok(bytes) = message.to_vec() {
                        payloads.insert(bytes);
                    }
                }
                payloads
            } else {
                packets.into_iter().map(|p| p.payload).collect()
            };

            if payloads.is_empty() {
                warn!("No packets left after processing for target: {transmit_request}");
                return;
            }

            if let Some(p) = proxy {
                match p
                    .ebpf_updater
                    .lock()
                    .await
                    .add_ip(device.ip, transmit_request.target_ip)
                {
                    Ok(_) => {
                        info!("IP added to an ebpf map");
                    }
                    Err(e) => {
                        error!("Could not add IP to an ebpf map: {e}");
                    }
                }
            }

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
            info!("Transmitter task created for target: {}", transmit_request);
            transmitter_tasks
                .lock()
                .await
                .entry(transmit_request)
                .or_insert(task);
            info!("Transmitter task inserted for target");
        });
    }
}
