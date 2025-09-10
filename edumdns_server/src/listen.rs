use crate::connection::ConnectionManager;
use crate::error::{ServerError, ServerErrorKind};
use crate::manager::PacketManager;
use crate::parse_host;
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::deadpool::Pool;
use edumdns_core::app_packet::AppPacket;
use edumdns_core::bincode_types::Uuid;
use edumdns_core::connection::TcpConnectionHandle;
use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio::sync::mpsc::{Receiver, Sender};

async fn handle_connection(mut connection_manager: ConnectionManager) -> Result<Uuid, ServerError> {
    let uuid = connection_manager.connection_init_server().await?;
    connection_manager.transfer_packets().await?;
    info!("Probe {uuid} disconnected");
    Ok(uuid)
}

pub async fn listen(
    pool: Pool<AsyncPgConnection>,
    (tx, rx): (Sender<AppPacket>, Receiver<AppPacket>),
    global_timeout: Duration,
) -> Result<(), ServerError> {
    let host = parse_host();
    info!("Starting on {host}");
    let listener = TcpListener::bind(host).await?;
    info!("Listening on {}", listener.local_addr()?);

    let pool_local = pool.clone();
    let probe_handles: Arc<RwLock<HashMap<Uuid, TcpConnectionHandle>>> =
        Arc::new(RwLock::new(HashMap::new()));
    let probe_handles_local = probe_handles.clone();
    let _packet_storage_task = tokio::task::spawn(async move {
        match PacketManager::new(rx, pool_local, probe_handles_local, global_timeout) {
            Ok(mut manager) => manager.handle_packets().await,
            Err(e) => {
                error!("Could not initialize packet manager: {e}");
            }
        }

    });
    info!("Packet storage initialized");

    loop {
        let (socket, addr) = listener.accept().await?;
        info!("Connection from {addr}");
        let connection_manager = ConnectionManager::new(
            socket,
            pool.clone(),
            tx.clone(),
            probe_handles.clone(),
            global_timeout,
        )?;
        let probe_handles_local = probe_handles.clone();
        tokio::spawn(async move {
            match handle_connection(connection_manager).await {
                Ok(uuid) => {
                    probe_handles_local.write().await.remove(&uuid);
                }
                Err(err) => {
                    if let ServerErrorKind::ProbeNotAdopted = err.error_kind {
                        info!("Client {addr} tried to connect, but probe is not adopted");
                    } else {
                        error!("{err}");
                    }
                }
            }
        });
    }
}
