use crate::app_packet::{
    AppPacket, LocalAppPacket, LocalCommandPacket, PacketTransmitRequestPacket,
};
use crate::config::ServerConfig;
use crate::error::ServerError;
use crate::server::ebpf::Proxy;
use crate::transmit::transmitter::Transmitter;
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::deadpool::Pool;
use edumdns_core::app_packet::Id;
use edumdns_db::repositories::device::repository::PgDeviceRepository;
use edumdns_db::repositories::packet::repository::PgPacketRepository;
use log::{error, info, warn};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::task::JoinHandle;

pub(crate) struct TransmitManager {
    tasks: Arc<Mutex<HashMap<Id, PacketTransmitJob>>>,
    pg_device_repository: PgDeviceRepository,
    pg_packet_repository: PgPacketRepository,
    command_transmitter: Sender<AppPacket>,
    proxy: Option<Proxy>,
    server_config: Arc<ServerConfig>,
}

impl TransmitManager {
    pub(crate) fn new(
        db_pool: Pool<AsyncPgConnection>,
        command_transmitter: Sender<AppPacket>,
        proxy: Option<Proxy>,
        server_config: Arc<ServerConfig>,
    ) -> Self {
        Self {
            tasks: Arc::new(Mutex::new(HashMap::new())),
            pg_device_repository: PgDeviceRepository::new(db_pool.clone()),
            pg_packet_repository: PgPacketRepository::new(db_pool.clone()),
            command_transmitter,
            proxy,
            server_config,
        }
    }

    pub(crate) async fn extend_request(&self, request_id: Id) {
        if let Some(job) = self.tasks.lock().await.get(&request_id) {
            let _ = job
                .channel
                .send(LocalAppPacket::Command(
                    LocalCommandPacket::ExtendPacketTransmitRequest(request_id),
                ))
                .await;
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
    pub(crate) async fn initiate_request(
        &mut self,
        request_packet: Arc<PacketTransmitRequestPacket>,
        respond_to: tokio::sync::oneshot::Sender<Result<(), ServerError>>,
        live_updater_channel: (Sender<LocalAppPacket>, Receiver<LocalAppPacket>),
    ) {
        let packet_repo = self.pg_packet_repository.clone();
        let transmitter_tasks = self.tasks.clone();
        let command_transmitter_local = self.command_transmitter.clone();

        let mut transmitter = match Transmitter::new(
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

            let task = TransmitTask::start(transmitter, command_transmitter_local);
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

    pub(crate) fn stop_request(&self, request_id: Id) {
        let device_repo = self.pg_device_repository.clone();
        let proxy = self.proxy.clone();
        let transmitter_tasks = self.tasks.clone();
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

struct PacketTransmitJob {
    /// The original request describing device and target parameters.
    packet: Arc<PacketTransmitRequestPacket>,
    /// Handle to the spawned transmitter task.
    task: TransmitTask,
    /// Channel used to send live updates/commands to the transmitter.
    channel: Sender<LocalAppPacket>,
}

/// Join-handle wrapper for a spawned UDP packet transmitter task.
///
/// This type encapsulates the background task responsible for replaying
/// captured UDP payloads to target hosts. When the task finishes (either
/// because the duration elapsed or a stop command was received), it sends a
/// `LocalCommandPacket::StopTransmitDevicePackets` back to the `ServerManager`
/// to finalize cleanup and book-keeping.
struct TransmitTask {
    /// Join handle of the running transmitter task.
    transmitter_task: JoinHandle<()>,
}

impl TransmitTask {
    /// Spawn a new transmitter task.
    ///
    /// Parameters:
    /// - `transmitter`: a fully constructed `PacketTransmitter` state machine
    ///   that holds payloads, target info, and live-update channel.
    /// - `command_transmitter`: channel used to notify the manager upon natural
    ///   completion that the transmit request should be stopped/cleaned up.
    /// - `request_id`: identifier of the corresponding `PacketTransmitRequest`.
    ///
    /// Returns:
    /// - `PacketTransmitterTask` containing a join handle to the spawned task.
    ///
    /// Side effects:
    /// - Spawns a Tokio task; upon completion, posts a local stop command.
    fn start(
        mut transmitter: Transmitter,
        command_transmitter: Sender<AppPacket>,
    ) -> Self {
        let transmitter_task = tokio::task::spawn(async move {
            transmitter.transmit().await;
            info!("Transmitter task finished");
            if let Err(e) = command_transmitter
                .send(AppPacket::Local(LocalAppPacket::Command(
                    LocalCommandPacket::StopTransmitDevicePackets(
                        transmitter.transmit_request.request.id,
                    ),
                )))
                .await
                .map_err(ServerError::from)
            {
                error!(
                    "Error sending stop transmit command for request {}: {}",
                    transmitter.transmit_request.request.id, e
                );
            }
        });
        Self { transmitter_task }
    }
}
