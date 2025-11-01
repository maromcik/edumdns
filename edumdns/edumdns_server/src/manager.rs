use crate::BUFFER_SIZE;
use crate::app_packet::{
    AppPacket, LocalAppPacket, LocalCommandPacket, LocalStatusPacket, PacketTransmitRequestPacket,
};
use crate::database::DbCommand;
use crate::ebpf::EbpfUpdater;
use crate::error::ServerError;
use crate::listen::ProbeHandles;
use crate::transmitter::{PacketTransmitter, PacketTransmitterTask};
use crate::utilities::rewrite_payloads;
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::deadpool::Pool;
use edumdns_core::app_packet::Id;
use edumdns_core::app_packet::{
    EntityType, NetworkAppPacket, NetworkCommandPacket, NetworkStatusPacket, ProbePacket,
    ProbeResponse,
};
use edumdns_core::bincode_types::{IpNetwork, MacAddr, Uuid};
use edumdns_core::connection::{TcpConnectionHandle, TcpConnectionMessage};
use edumdns_db::repositories::device::repository::PgDeviceRepository;
use edumdns_db::repositories::packet::models::SelectManyPackets;
use edumdns_db::repositories::packet::repository::PgPacketRepository;
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

pub struct PacketTransmitJob {
    pub packet: PacketTransmitRequestPacket,
    pub task: PacketTransmitterTask,
}

pub struct PacketManager {
    pub packets: HashMap<Uuid, HashMap<(MacAddr, IpNetwork), HashSet<ProbePacket>>>,
    pub command_transmitter: Sender<AppPacket>,
    pub command_receiver: Receiver<AppPacket>,
    pub data_receiver: Receiver<AppPacket>,
    pub db_transmitter: Sender<DbCommand>,
    pub transmitter_tasks: Arc<Mutex<HashMap<Id, PacketTransmitJob>>>,
    pub probe_handles: ProbeHandles,
    pub probe_ws_handles: HashMap<uuid::Uuid, HashMap<uuid::Uuid, Sender<ProbeResponse>>>,
    pub pg_device_repository: PgDeviceRepository,
    pub pg_packet_repository: PgPacketRepository,
    pub proxy: Option<Proxy>,
    pub global_timeout: Duration,
}

impl PacketManager {
    pub fn new(
        command_transmitter: Sender<AppPacket>,
        command_receiver: Receiver<AppPacket>,
        data_receiver: Receiver<AppPacket>,
        db_transmitter: Sender<DbCommand>,
        db_pool: Pool<AsyncPgConnection>,
        handles: Arc<RwLock<HashMap<Uuid, TcpConnectionHandle>>>,
        global_timeout: Duration,
    ) -> Result<Self, ServerError> {
        let proxy_ipv4 = env::var("EDUMDNS_SERVER_PROXY_IPV4")
            .map(|ip| ip.parse::<Ipv4Addr>().ok())
            .ok();
        let proxy_ipv6 = env::var("EDUMDNS_SERVER_PROXY_IPV6")
            .map(|ip| ip.parse::<Ipv6Addr>().ok())
            .ok();

        let proxy = match (proxy_ipv4, proxy_ipv6) {
            (Some(Some(ipv4)), Some(Some(ipv6))) => match EbpfUpdater::new() {
                Ok(updater) => Some(Proxy {
                    proxy_ipv4: ipv4,
                    proxy_ipv6: ipv6,
                    ebpf_updater: Arc::new(Mutex::new(updater)),
                }),
                Err(e) => {
                    error!("Could not create ebpf updater: {}", e);
                    None
                }
            },
            (_, _) => None,
        };

        Ok(Self {
            packets: HashMap::default(),
            command_transmitter,
            command_receiver,
            data_receiver,
            db_transmitter,
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
        loop {
            let packet = self.command_receiver.try_recv();
            if let Ok(packet) = packet {
                self.route_packets(packet).await;
                continue;
            }
            let packet = self.data_receiver.try_recv();
            if let Ok(packet) = packet {
                self.route_packets(packet).await;
                continue;
            }
            tokio::select! {
                packet = self.command_receiver.recv() => {
                    if let Some(packet) = packet {
                     self.route_packets(packet).await;
                    }
                }
                packet = self.data_receiver.recv() => {
                    if let Some(packet) = packet {
                     self.route_packets(packet).await;
                    }
                }
            }
        }
    }

    pub async fn route_packets(&mut self, packet: AppPacket) {
        match packet {
            AppPacket::Network(network_packet) => self.handle_network_packet(network_packet).await,
            AppPacket::Local(local_packet) => self.handle_local_packet(local_packet).await,
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
                LocalCommandPacket::TransmitDevicePackets {
                    request,
                    respond_to,
                } => self.transmit_device_packets(request, respond_to).await,
                LocalCommandPacket::StopTransmitDevicePackets(request_id) => {
                    self.stop_device_packets(request_id).await
                }
                LocalCommandPacket::ReconnectProbe(id, session_id) => {
                    if let Err(e) = self.send_reconnect(id, session_id).await {
                        if let Some(handle) = self.probe_handles.read().await.get(&id) {
                            let _ = handle.close().await;
                        }
                        self.send_response_to_ws(
                            id,
                            session_id,
                            ProbeResponse::new_error(e.to_string()),
                        )
                        .await;
                    }
                }
                LocalCommandPacket::InvalidateCache(entity) => {
                    match entity {
                        EntityType::Probe { probe_id } => {
                            self.packets.remove(&probe_id);
                        }
                        EntityType::Device {
                            probe_id,
                            device_mac,
                            device_ip,
                        } => {
                            if let Some(probe_entry) = self.packets.get_mut(&probe_id) {
                                probe_entry.remove(&(device_mac, device_ip));
                            }
                        }
                        EntityType::Packet(_) => {}
                    }
                    info!("Cache invalidated for entity: {:?}", entity);
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
                LocalStatusPacket::OperationUpdateToWs {
                    probe_id,
                    session_id,
                    message,
                } => {
                    self.send_response_to_ws(
                        probe_id,
                        session_id,
                        ProbeResponse::new_ok_with_value(&message),
                    )
                    .await
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
                match self.packets.entry(probe_packet.probe_metadata.id) {
                    Entry::Occupied(mut probe_entry) => {
                        match probe_entry.get_mut().entry((src_mac, src_ip)) {
                            Entry::Occupied(mut device_entry) => {
                                if device_entry.get().len() > BUFFER_SIZE {
                                    device_entry.get_mut().clear();
                                    info!(
                                        "Device buffer for <{src_mac}; {src_ip}> exceeded {BUFFER_SIZE} elements; cleared"
                                    );
                                }
                                if !device_entry.get().contains(&probe_packet) {
                                    device_entry.get_mut().insert(probe_packet.clone());
                                    self.send_db_packet(DbCommand::StorePacket(probe_packet))
                                        .await;
                                    debug!("Probe and device found; stored packet in database");
                                } else {
                                    debug!("Probe, device and packet found; no action");
                                }
                            }
                            Entry::Vacant(device_entry) => {
                                let device_entry = device_entry.insert(HashSet::default());
                                device_entry.insert(probe_packet.clone());
                                self.send_db_packet(DbCommand::StoreDevice(probe_packet.clone()))
                                    .await;
                                self.send_db_packet(DbCommand::StorePacket(probe_packet))
                                    .await;
                                debug!("Probe found; stored device and packet in database");
                            }
                        }
                    }
                    Entry::Vacant(probe_entry) => {
                        let probe_entry = probe_entry.insert(HashMap::default());
                        probe_entry
                            .entry((src_mac, src_ip))
                            .or_default()
                            .insert(probe_packet.clone());
                        self.send_db_packet(DbCommand::StoreDevice(probe_packet.clone()))
                            .await;
                        self.send_db_packet(DbCommand::StorePacket(probe_packet))
                            .await;
                        debug!("Probe not found in hashmap; stored device and packet in database");
                    }
                }
                debug!("Packet <MAC: {src_mac}, IP: {src_ip}> stored in memory");
            }
        }
    }

    pub async fn send_db_packet(&self, db_command: DbCommand) {
        if let Err(e) = self.db_transmitter.send(db_command).await {
            error!("Could not send commands to the DB handler: {e}");
        }
    }

    pub async fn send_reconnect(
        &self,
        id: Uuid,
        session_id: Option<Uuid>,
    ) -> Result<(), ServerError> {
        if let Some(handle) = self.probe_handles.write().await.remove(&id) {
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
            handle.close().await?;
        } else {
            warn!("Probe not found: {}", id);
            return Err(ServerError::ProbeNotFound);
        }
        Ok(())
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

    pub async fn transmit_device_packets(
        &mut self,
        request_packet: PacketTransmitRequestPacket,
        respond_to: tokio::sync::oneshot::Sender<Result<(), ServerError>>,
    ) {
        let packet_repo = self.pg_packet_repository.clone();
        let proxy = self.proxy.clone();
        let transmitter_tasks = self.transmitter_tasks.clone();
        let global_timeout = self.global_timeout;
        let command_transmitter_local = self.command_transmitter.clone();
        tokio::task::spawn(async move {
            if proxy.is_none() && request_packet.device.proxy {
                let err = "eBPF is not configured properly; contact your administrator";
                error!("{err} for target: {request_packet}");
                let _ = respond_to.send(Err(ServerError::EbpfMapError(err.to_string())));
                return;
            }

            let packets = match packet_repo
                .read_many(&SelectManyPackets::new(
                    None,
                    Some(request_packet.device.probe_id),
                    Some(request_packet.device.mac),
                    None,
                    Some(request_packet.device.ip),
                    None,
                    None,
                    None,
                    None,
                    None,
                ))
                .await
            {
                Ok(p) => p,
                Err(e) => {
                    warn!("No packets found for target: {request_packet}: {e}");
                    let _ = respond_to.send(Err(ServerError::PacketProcessingError(e.to_string())));
                    return;
                }
            };

            info!("Packets found for target: {}", request_packet);
            let payloads = if let Some(p) = &proxy
                && request_packet.device.proxy
            {
                rewrite_payloads(packets, p.proxy_ipv4, p.proxy_ipv6)
            } else {
                packets.into_iter().map(|p| p.payload).collect()
            };

            if payloads.is_empty() {
                let warning = "no packets left after processing";
                warn!("{warning} for target: {request_packet}");
                let _ =
                    respond_to.send(Err(ServerError::PacketProcessingError(warning.to_string())));
                return;
            }

            if let Some(p) = proxy
                && request_packet.device.proxy
            {
                match p
                    .ebpf_updater
                    .lock()
                    .await
                    .add_ip(request_packet.device.ip, request_packet.request.target_ip)
                {
                    Ok(_) => {}
                    Err(e) => {
                        let _ = respond_to.send(Err(e));
                        return;
                    }
                }
            }

            let transmitter = match PacketTransmitter::new(
                payloads,
                request_packet.clone(),
                global_timeout,
            )
            .await
            {
                Ok(t) => t,
                Err(e) => {
                    error!("{e}");
                    let _ = respond_to.send(Err(e));
                    return;
                }
            };

            let task = PacketTransmitterTask::new(
                transmitter,
                command_transmitter_local,
                request_packet.request.id,
            );
            info!("Transmitter task created for target: {}", request_packet);
            let job = PacketTransmitJob {
                packet: request_packet,
                task,
            };
            transmitter_tasks
                .lock()
                .await
                .entry(job.packet.request.id)
                .or_insert(job);
            let _ = respond_to.send(Ok(()));
        });
    }

    pub async fn stop_device_packets(&mut self, request_id: Id) {
        let device_repo = self.pg_device_repository.clone();
        let proxy = self.proxy.clone();
        let transmitter_tasks = self.transmitter_tasks.clone();
        tokio::task::spawn(async move {
            if let Err(e) = device_repo
                .delete_packet_transmit_request(&request_id)
                .await
            {
                error!("Could not delete packet transmit request ID: {request_id}: {e}");
            }
            let Some(job) = transmitter_tasks.lock().await.remove(&request_id) else {
                warn!("Transmitter task not found for request ID: {}", request_id);
                return;
            };
            job.task.transmitter_task.abort();

            if let Some(proxy) = &proxy
                && job.packet.device.proxy
                && let Err(e) = proxy
                    .ebpf_updater
                    .lock()
                    .await
                    .remove_ip(job.packet.device.ip, job.packet.request.target_ip)
            {
                error!("{e}");
            };
            info!("Transmitter task stopped for request ID: {}", request_id);
        });
    }
}
