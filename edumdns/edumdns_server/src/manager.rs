//! Central orchestrator that routes commands/data between probes, DB, and transmitters.
//!
//! `ServerManager` owns channel receivers, tracks device state, manages per-device
//! transmitters, handles WebSocket responses, and coordinates proxy/eBPF updates.

use crate::ProbeHandles;
use crate::app_packet::{
    AppPacket, LocalAppPacket, LocalCommandPacket, LocalDataPacket, LocalStatusPacket,
    PacketTransmitRequestPacket,
};
use crate::config::ServerConfig;
use crate::database::DbCommand;
use crate::ebpf::EbpfUpdater;
use crate::error::ServerError;
use crate::transmitter::{PacketTransmitter, PacketTransmitterTask};
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
use edumdns_db::repositories::packet::repository::PgPacketRepository;
use log::{debug, error, info, warn};
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{Mutex, RwLock};

#[derive(Clone)]
/// Holds proxy configuration and a handle to the eBPF updater.
///
/// When proxying is enabled for the server, the server rewrites A/AAAA answers to point to
/// a proxy IP pair and maintains kernel eBPF maps with client<->device IP
/// mappings. This struct groups the configured proxy IPs and a shared, mutex-
/// protected `EbpfUpdater` used to update those maps.
pub(crate) struct Proxy {
    /// IPv4/IPv6 pair to which DNS answers will be rewritten.
    pub(crate) proxy_ip: ProxyIp,
    /// Shared eBPF maps updater used to add/remove rewrite rules.
    pub(crate) ebpf_updater: Arc<Mutex<EbpfUpdater>>,
}

#[derive(Clone)]
/// Pair of proxy IPs used for DNS A/AAAA rewriting.
///
/// These addresses are substituted into outgoing DNS responses when proxying is
/// enabled. Both IPv4 and IPv6 must be provided.
pub(crate) struct ProxyIp {
    /// IPv4 address that replaces A records in DNS payloads.
    pub(crate) ipv4: Ipv4Addr,
    /// IPv6 address that replaces AAAA records in DNS payloads.
    pub(crate) ipv6: Ipv6Addr,
}

/// An in-flight transmit job along with its control channel.
///
/// Each job corresponds to a `PacketTransmitRequestPacket` and holds:
/// - the original request (for bookkeeping and eBPF cleanup)
/// - a join handle wrapper for the running transmitter task
/// - a channel used to push live updates (e.g., additional payloads or extend-duration commands)
struct PacketTransmitJob {
    /// The original request describing device and target parameters.
    packet: PacketTransmitRequestPacket,
    /// Handle to the spawned transmitter task.
    task: PacketTransmitterTask,
    /// Channel used to send live updates/commands to the transmitter.
    channel: Sender<LocalAppPacket>,
}

#[derive(Default)]
/// Cached data for a single device (MAC, IP) observed by a probe.
///
/// - `packets` keeps a deduplicated in-memory set of recently seen `ProbePacket`s
///  acting as a simple cache to alleviate the load on the database.
/// - `live_updates_transmitter` is an optional channel tied to an active
///   transmitter job; when present, newly arriving packets are forwarded to the
///   transmitter as live updates.
struct DeviceItem {
    /// Recent, deduplicated packets captured for this device.
    packets: HashSet<ProbePacket>,
    /// If set, sender used to push live updates to the transmitter.
    live_updates_transmitter: Option<Sender<LocalAppPacket>>,
}

/// Central orchestrator for routing, caching, and transmit task management.
///
/// `ServerManager` owns inbound channels for control (`command_receiver`) and
/// data (`data_receiver`), keeps an in-memory cache of recently seen packets per
/// probe/device, spawns UDP transmitters on demand, forwards WebSocket
/// responses, and optionally coordinates proxy/eBPF IP map updates.
pub(crate) struct ServerManager {
    packets: HashMap<Uuid, HashMap<(MacAddr, IpNetwork), DeviceItem>>,
    command_transmitter: Sender<AppPacket>,
    command_receiver: Receiver<AppPacket>,
    data_receiver: Receiver<AppPacket>,
    db_transmitter: Sender<DbCommand>,
    transmitter_tasks: Arc<Mutex<HashMap<Id, PacketTransmitJob>>>,
    probe_handles: ProbeHandles,
    probe_ws_handles: HashMap<uuid::Uuid, HashMap<uuid::Uuid, Sender<ProbeResponse>>>,
    pg_device_repository: PgDeviceRepository,
    pg_packet_repository: PgPacketRepository,
    proxy: Option<Proxy>,
    server_config: ServerConfig,
}

impl ServerManager {
    /// Create a new `ServerManager`.
    ///
    ///
    /// Parameters:
    /// - `command_transmitter`: channel used to post local commands back into the
    ///   manager (e.g., to stop transmit jobs after completion).
    /// - `command_receiver`: receives control packets from other subsystems (web,
    ///   timers, etc.).
    /// - `data_receiver`: receives network packets coming from probes.
    /// - `db_transmitter`: channel to the async DB manager for persisting devices/packets.
    /// - `db_pool`: database pool used to construct repositories for device/packet writes.
    /// - `handles`: map of live probe TCP handles for direct messaging.
    /// - `server_config`: global server configuration.
    ///
    /// Returns:
    /// - `ServerManager`
    pub fn new(
        command_transmitter: Sender<AppPacket>,
        command_receiver: Receiver<AppPacket>,
        data_receiver: Receiver<AppPacket>,
        db_transmitter: Sender<DbCommand>,
        db_pool: Pool<AsyncPgConnection>,
        handles: Arc<RwLock<HashMap<Uuid, TcpConnectionHandle>>>,
        server_config: ServerConfig,
    ) -> Self {
        let proxy = match &server_config.ebpf {
            Some(config) => match EbpfUpdater::new(&config.pin_location) {
                Ok(updater) => Some(Proxy {
                    proxy_ip: ProxyIp {
                        ipv4: config.proxy_ipv4,
                        ipv6: config.proxy_ipv6,
                    },
                    ebpf_updater: Arc::new(Mutex::new(updater)),
                }),
                Err(e) => {
                    error!("Could not create ebpf updater: {}", e);
                    None
                }
            },
            _ => None,
        };

        Self {
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
            server_config,
        }
    }

    /// Main event loop that receives `AppPacket`s and routes them.
    ///
    /// This continuously polls both the command and data channels, preferring any
    /// immediately available packets via `try_recv` before awaiting on either using
    /// `tokio::select!`. Packets are forwarded to `route_packets` for handling.
    ///
    /// Inputs:
    /// - `&mut self`: mutable access to update caches and internal state.
    ///
    /// Outputs:
    /// - Never returns under normal operation; the loop runs indefinitely.
    pub(crate) async fn handle_packets(&mut self) {
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

    /// Dispatch a single `AppPacket` to the appropriate handler.
    ///
    /// Parameters:
    /// - `packet`: either a `Network` packet coming from a probe or a `Local`
    ///   packet generated by server subsystems (web UI, timers, transmitter).
    ///
    /// Side effects:
    /// - Updates in-memory caches and may spawn/stop tasks depending on the
    ///   contained command.
    async fn route_packets(&mut self, packet: AppPacket) {
        match packet {
            AppPacket::Network(network_packet) => self.handle_network_packet(network_packet).await,
            AppPacket::Local(local_packet) => self.handle_local_packet(local_packet).await,
        }
    }

    /// Handle a locally-generated packet from internal subsystems.
    ///
    /// This covers control and status messages originating from the web layer,
    /// timers, or transmitter tasks. It updates internal state (e.g., WS
    /// registration map), spawns/stops transmitters, invalidates caches, and
    /// forwards updates to web sockets.
    ///
    /// Parameters:
    /// - `packet`: a `LocalAppPacket` variant describing the operation.
    ///
    /// Side effects:
    /// - Mutates `probe_ws_handles`, `packets`, and `transmitter_tasks`.
    /// - Sends messages over channels to running tasks.
    async fn handle_local_packet(&mut self, packet: LocalAppPacket) {
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
                LocalCommandPacket::ExtendPacketTransmitRequest(request_id) => {
                    if let Some(job) = self.transmitter_tasks.lock().await.get(&request_id) {
                        let _ = job
                            .channel
                            .send(LocalAppPacket::Command(
                                LocalCommandPacket::ExtendPacketTransmitRequest(request_id),
                            ))
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
            LocalAppPacket::Data(_) => {}
        }
    }

    /// Handle packets coming from probes over the network.
    ///
    /// Variants:
    /// - `NetworkAppPacket::Status::ProbeResponse` — forwards a response to
    ///   registered websocket sessions.
    /// - `NetworkAppPacket::Data` — updates the in-memory cache, forwards live
    ///   updates to an active transmitter (if any), and persists device/packet
    ///   records via the DB manager.
    ///
    /// Parameters:
    /// - `packet`: network packet received from a probe connection.
    ///
    /// Side effects:
    /// - Mutates `packets` cache; may send to `db_transmitter`; may send live
    ///   update data to transmitter channels.
    async fn handle_network_packet(&mut self, packet: NetworkAppPacket) {
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
                                if device_entry.get().packets.len()
                                    > self.server_config.connection.buffer_capacity
                                {
                                    device_entry.get_mut().packets.clear();
                                    info!(
                                        "Device buffer for <{src_mac}; {src_ip}> exceeded {} elements; cleared",
                                        self.server_config.connection.buffer_capacity
                                    );
                                }
                                if !device_entry.get().packets.contains(&probe_packet) {
                                    device_entry.get_mut().packets.insert(probe_packet.clone());
                                    if let Some(chan) = &device_entry.get().live_updates_transmitter
                                    {
                                        let _ = chan.try_send(LocalAppPacket::Data(
                                            LocalDataPacket::TransmitterLiveUpdateData(
                                                probe_packet.payload.clone(),
                                            ),
                                        ));
                                    }
                                    self.send_db_packet(DbCommand::StorePacket(probe_packet))
                                        .await;

                                    debug!("Probe and device found; stored packet in database");
                                } else {
                                    debug!("Probe, device and packet found; no action");
                                }
                            }
                            Entry::Vacant(device_entry) => {
                                let device_entry = device_entry.insert(DeviceItem::default());
                                device_entry.packets.insert(probe_packet.clone());
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
                            .packets
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

    /// Forward a database command to the async DB manager.
    ///
    /// Parameters:
    /// - `db_command`: a `DbCommand` describing what to persist.
    ///
    /// Errors:
    /// - Logs an error if the mpsc channel is closed; does not propagate.
    async fn send_db_packet(&self, db_command: DbCommand) {
        if let Err(e) = self.db_transmitter.send(db_command).await {
            error!("Could not send commands to the DB handler: {e}");
        }
    }

    /// Ask a probe to reconnect and close its current TCP session.
    ///
    /// Sends a `NetworkCommandPacket::ReconnectThisProbe(session_id)` to the
    /// probe's TCP connection (if present) and then closes the connection. This
    /// is used to prompt the probe to reconnect, typically after configuration
    /// changes.
    ///
    /// Parameters:
    /// - `id`: probe identifier.
    /// - `session_id`: optional web session that initiated the request (used for passing the
    /// response to a websocket).
    ///
    /// Returns:
    /// - `Ok(())` if the command was delivered and the connection closed.
    /// - `Err(ServerError::ProbeNotFound)` if the probe is not connected.
    /// - Other `ServerError` variants if sending/closing fails.
    async fn send_reconnect(&self, id: Uuid, session_id: Option<Uuid>) -> Result<(), ServerError> {
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

    /// Send a `ProbeResponse` to registered websocket clients for a probe.
    ///
    /// If `session_id` is `None`, the response is broadcast to all sessions
    /// subscribed for the given `probe_id`. Otherwise, only the targeted session
    /// receives the response.
    ///
    /// Parameters:
    /// - `id`: identifier of the probe whose sessions should receive the message.
    /// - `session_id`: optional specific session to target; `None` means broadcast.
    /// - `response`: payload sent to the websocket(s).
    ///
    /// Side effects:
    /// - Uses mpsc channels stored in `probe_ws_handles` to deliver messages; logs
    ///   warnings on delivery failures.
    async fn send_response_to_ws(
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

    /// Start (or enqueue) a UDP transmitter for a device based on a request.
    ///
    /// Steps:
    /// - Validates proxy/eBPF availability and subnet size constraints.
    /// - Loads matching packets from the DB; processes them (rewrite/filter) based
    ///   on proxy configuration; fails if none remain.
    /// - Optionally updates eBPF maps to add IP mappings for client-device proxying.
    /// - Spawns a `PacketTransmitter` task and registers it in `transmitter_tasks`.
    /// - Wires a live-updates channel so subsequent captured packets can be pushed
    ///   into the running transmitter.
    ///
    /// Parameters:
    /// - `request_packet`: device + transmit request metadata.
    /// - `respond_to`: oneshot where the result of the spawn operation is sent.
    ///
    /// Side effects:
    /// - May mutate eBPF maps; spawns a tokio task; updates `transmitter_tasks` and
    ///   sets a live update sender in the device cache.
    async fn transmit_device_packets(
        &mut self,
        request_packet: PacketTransmitRequestPacket,
        respond_to: tokio::sync::oneshot::Sender<Result<(), ServerError>>,
    ) {
        let packet_repo = self.pg_packet_repository.clone();
        let transmitter_tasks = self.transmitter_tasks.clone();
        let command_transmitter_local = self.command_transmitter.clone();
        let live_updater_channel =
            tokio::sync::mpsc::channel(self.server_config.connection.buffer_capacity);
        let device_entry = self
            .packets
            .entry(Uuid(request_packet.device.probe_id))
            .or_default();
        let packet_data = device_entry
            .entry((
                MacAddr::from_octets(request_packet.device.mac),
                IpNetwork(request_packet.device.ip),
            ))
            .or_default();
        packet_data.live_updates_transmitter = Some(live_updater_channel.0.clone());

        let mut transmitter = match PacketTransmitter::new(
            self.proxy.clone(),
            request_packet.clone(),
            live_updater_channel.1,
            self.server_config.clone(),
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

        tokio::spawn(async move {
            if let Err(e) = transmitter.validate().await {
                let _ = respond_to.send(Err(e));
                return;
            }
            if let Err(e) = transmitter.fetch_packets(packet_repo).await {
                let _ = respond_to.send(Err(e));
                return;
            };

            if let Err(e) = transmitter.configure_ebpf().await {
                let _ = respond_to.send(Err(e));
                return;
            };

            let task = PacketTransmitterTask::start(transmitter, command_transmitter_local);
            info!("Transmitter task created for target: {}", request_packet);
            
            let job = PacketTransmitJob {
                packet: request_packet,
                task,
                channel: live_updater_channel.0,
            };
            transmitter_tasks
                .lock()
                .await
                .entry(job.packet.request.id)
                .or_insert(job);
            let _ = respond_to.send(Ok(()));
        });
    }

    /// Stop a running transmitter task and clean up associated resources.
    ///
    /// Performs the following:
    /// - Deletes the persisted transmit request from the DB.
    /// - Aborts the corresponding transmitter task, if found.
    /// - When proxying was used, removes the IP pair from the eBPF maps.
    ///
    /// Parameters:
    /// - `request_id`: unique identifier of the transmit request to stop.
    ///
    /// Side effects:
    /// - Mutates the `transmitter_tasks` registry and eBPF maps; logs outcomes.
    async fn stop_device_packets(&mut self, request_id: Id) {
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
