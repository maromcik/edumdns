//! Central orchestrator that routes commands/data between probes, DB, and transmitters.
//!
//! `ServerManager` owns channel receivers, tracks device state, manages per-device
//! transmitters, handles WebSocket responses, and coordinates proxy/eBPF updates.

use crate::ProbeHandles;
use crate::app_packet::{AppPacket, LocalAppPacket, LocalCommandPacket, LocalStatusPacket};
use crate::config::ServerConfig;
use crate::database::actor::DbCommand;
use crate::error::ServerError;
use crate::server::cache::{Cache, CacheMiss};
use crate::transmit::manager::TransmitManager;
use edumdns_core::app_packet::{
    NetworkAppPacket, NetworkCommandPacket, NetworkStatusPacket, ProbeResponse,
};
use edumdns_core::bincode_types::Uuid;
use edumdns_core::connection::{TcpConnectionHandle, TcpConnectionMessage};
use log::{debug, error, warn};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::sync::mpsc::{Receiver, Sender};

/// An in-flight transmit job along with its control channel.
///
/// Each job corresponds to a `PacketTransmitRequestPacket` and holds:
/// - the original request (for bookkeeping and eBPF cleanup)
/// - a join handle wrapper for the running transmitter task
/// - a channel used to push live updates (e.g., additional payloads or extend-duration commands)

/// Central orchestrator for routing, caching, and transmit task management.
///
/// `ServerManager` owns inbound channels for control (`command_receiver`) and
/// data (`data_receiver`), keeps an in-memory cache of recently seen packets per
/// probe/device, spawns UDP transmitters on demand, forwards WebSocket
/// responses, and optionally coordinates proxy/eBPF IP map updates.
pub(crate) struct ServerManager {
    cache: Cache,
    transmit_manager: TransmitManager,
    command_receiver: Receiver<AppPacket>,
    data_receiver: Receiver<AppPacket>,
    db_transmitter: Sender<DbCommand>,
    probe_handles: ProbeHandles,
    probe_ws_handles: HashMap<uuid::Uuid, HashMap<uuid::Uuid, Sender<ProbeResponse>>>,
    server_config: Arc<ServerConfig>,
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
        command_receiver: Receiver<AppPacket>,
        data_receiver: Receiver<AppPacket>,
        db_transmitter: Sender<DbCommand>,
        handles: Arc<RwLock<HashMap<Uuid, TcpConnectionHandle>>>,
        transmit_manager: TransmitManager,
        server_config: Arc<ServerConfig>,
    ) -> Self {
        Self {
            cache: Cache::new(server_config.channel_buffer_capacity),
            transmit_manager,
            command_receiver,
            data_receiver,
            db_transmitter,
            probe_handles: handles,
            probe_ws_handles: HashMap::new(),
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
                } => {
                    let live_updater_channel =
                        tokio::sync::mpsc::channel(self.server_config.connection.buffer_capacity);
                    let sender = live_updater_channel.0.clone();
                    self.transmit_manager
                        .initiate_request(request.clone(), respond_to, live_updater_channel)
                        .await;
                    self.cache.set_transmitter(request, sender).await;
                }
                LocalCommandPacket::StopTransmitDevicePackets(request_id) => {
                    self.transmit_manager.stop_request(request_id);
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
                    self.cache.invalidate_cache(entity);
                }
                LocalCommandPacket::ExtendPacketTransmitRequest(request_id) => {
                    self.transmit_manager.extend_request(request_id).await;
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
                let cache_miss = self.cache.add(probe_packet.clone()).await;
                match cache_miss {
                    CacheMiss::Packet => {
                        self.send_db_packet(DbCommand::StorePacket(probe_packet))
                            .await
                    }
                    CacheMiss::PacketAndDevice => {
                        self.send_db_packet(DbCommand::StoreDevice(probe_packet.clone()))
                            .await;
                        self.send_db_packet(DbCommand::StorePacket(probe_packet))
                            .await;
                    }
                    CacheMiss::None => {}
                }
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
}
