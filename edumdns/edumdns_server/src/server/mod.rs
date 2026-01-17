use crate::app_packet::AppPacket;
use crate::config::ServerConfig;
use crate::database::actor::DbCommand;
use crate::server::ebpf::{Proxy};
use crate::server::manager::ServerManager;
use crate::{ProbeHandles};
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::deadpool::Pool;
use log::{info};
use std::sync::Arc;
use tokio::sync::mpsc::{Receiver, Sender};
use crate::transmit::manager::TransmitManager;

pub(crate) mod cache;
pub(crate) mod ebpf;
pub(crate) mod manager;

pub async fn spawn_server_task(
    pool: Pool<AsyncPgConnection>,
    probe_handles: ProbeHandles,
    command_channel: (Sender<AppPacket>, Receiver<AppPacket>),
    data_receiver: Receiver<AppPacket>,
    db_sender: Sender<DbCommand>,
    server_config: Arc<ServerConfig>,
) {
    let _server_manager_task = tokio::task::spawn(async move {
        let proxy = Proxy::new(server_config.clone());
        let transmit_manager = TransmitManager::new(
            pool,
            command_channel.0,
            proxy,
            server_config.clone(),
        );

        let mut manager = ServerManager::new(
            command_channel.1,
            data_receiver,
            db_sender,
            probe_handles,
            transmit_manager,
            server_config,
        );
        manager.handle_packets().await;
        info!("Packet manager initialized");
    });
}
