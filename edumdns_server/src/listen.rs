use crate::connection::ConnectionManager;
use crate::error::{ServerError, ServerErrorKind};
use crate::storage::PacketStorage;
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::deadpool::Pool;
use edumdns_core::app_packet::{AppPacket, CommandPacket, PacketTransmitRequestPacket};
use edumdns_core::bincode_types::{IpNetwork, MacAddr as MyMacAddr, Uuid};
use edumdns_core::connection::{TcpConnection, TcpConnectionHandle};
use edumdns_core::error::CoreError;
use futures::StreamExt;
use log::{debug, error, info, warn};
use pnet::datalink::MacAddr;
use std::collections::HashMap;
use std::process::exit;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::sleep;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use crate::parse_host;

async fn handle_connection(mut connection_manager: ConnectionManager) -> Result<(), ServerError> {
    connection_manager.connection_init_server().await?;
    connection_manager.transfer_packets().await?;
    debug!("Client disconnected");
    Ok(())
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
        let mut packet_storage =
            PacketStorage::new(rx, pool_local, probe_handles_local, global_timeout);
        packet_storage.handle_packets().await
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
        tokio::spawn(async move {
            if let Err(e) = handle_connection(connection_manager).await {
                if let ServerErrorKind::ProbeNotAdopted = e.error_kind {
                    warn!("Client {addr} tried to connect, but probe is not adopted");
                } else {
                    error!("{e}");
                }
            }
        });
    }
}
