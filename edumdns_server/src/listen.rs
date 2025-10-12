use crate::connection::ConnectionManager;
use crate::error::{ServerError, ServerErrorKind};
use crate::manager::PacketManager;
use crate::ordered_map::OrderedMap;
use crate::probe_tracker::{SharedProbeTracker, watchdog};
use crate::{ServerTlsConfig, parse_host, BUFFER_SIZE};
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::deadpool::Pool;
use edumdns_core::app_packet::AppPacket;
use edumdns_core::bincode_types::Uuid;
use edumdns_core::connection::TcpConnectionHandle;
use log::{debug, error, info, warn};
use rustls::ServerConfig;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::Instant;

pub type ProbeHandles = Arc<RwLock<HashMap<Uuid, TcpConnectionHandle>>>;

async fn handle_connection(mut connection_manager: ConnectionManager) -> Result<Uuid, ServerError> {
    let uuid = connection_manager.connection_init_server().await?;
    connection_manager.transfer_packets().await?;
    info!("Probe {uuid} disconnected");
    Ok(uuid)
}

pub async fn listen(
    pool: Pool<AsyncPgConnection>,
    (command_transmitter, command_receiver): (Sender<AppPacket>, Receiver<AppPacket>),
    config: Option<ServerTlsConfig>,
    global_timeout: Duration,
) -> Result<(), ServerError> {
    let host = parse_host();
    let listener = TcpListener::bind(host).await?;
    info!("Listening on {}", listener.local_addr()?);

    let probe_handles: ProbeHandles = Arc::new(RwLock::new(HashMap::new()));
    let tracker: SharedProbeTracker = Arc::new(RwLock::new(OrderedMap::new()));
    let data_channel = tokio::sync::mpsc::channel(BUFFER_SIZE);
    let pool_local = pool.clone();
    let probe_handles_local = probe_handles.clone();
    let _packet_storage_task = tokio::task::spawn(async move {
        match PacketManager::new(command_receiver, data_channel.1, pool_local, probe_handles_local, global_timeout) {
            Ok(mut manager) => manager.handle_packets().await,
            Err(e) => {
                error!("Could not initialize packet manager: {e}");
            }
        }
    });

    let tracker_local: SharedProbeTracker = tracker.clone();
    let probe_handles_local = probe_handles.clone();
    let _probe_watchdog_task = tokio::task::spawn(async move {
        info!("Starting the probe watchdog");
        watchdog(tracker_local, probe_handles_local, global_timeout).await;
    });
    info!("Packet storage initialized");

    let server_config = match config {
        None => None,
        Some(config) => {
            let certs =
                CertificateDer::pem_file_iter(&config.cert_path)?.collect::<Result<Vec<_>, _>>()?;
            let key = PrivateKeyDer::from_pem_file(&config.key_path)?;
            rustls::crypto::ring::default_provider()
                .install_default()
                .expect("Failed to install rustls crypto provider");
            Some(
                ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(certs, key)?,
            )
        }
    };

    loop {
        let (stream, addr) = listener.accept().await?;
        info!("Connection from {addr}");
        let connection_manager = match ConnectionManager::new(
            stream,
            server_config.clone(),
            pool.clone(),
            command_transmitter.clone(),
            data_channel.0.clone(),
            probe_handles.clone(),
            tracker.clone(),
            global_timeout,
        )
        .await
        {
            Ok(c) => c,
            Err(e) => {
                warn!("Invalid connection from {addr}: {e}");
                continue;
            }
        };
        let probe_handles_local = probe_handles.clone();
        tokio::spawn(async move {
            match handle_connection(connection_manager).await {
                Ok(uuid) => {
                    probe_handles_local.write().await.remove(&uuid);
                    debug!("Probe {uuid} removed from the map");
                }
                Err(err) => {
                    if let ServerErrorKind::ProbeNotAdopted = err.error_kind {
                        info!("Client {addr} tried to connect, but probe is not adopted");
                    } else {
                        warn!("{err}");
                    }
                }
            }
        });
    }
}
