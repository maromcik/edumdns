use crate::connection::ConnectionManager;
use crate::error::{ServerError, ServerErrorKind};
use crate::manager::PacketManager;
use crate::ordered_map::OrderedMap;
use crate::{parse_host, ServerTlsConfig};
use crate::probe_tracker::{SharedProbeLastSeen, watchdog};
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::deadpool::Pool;
use edumdns_core::app_packet::AppPacket;
use edumdns_core::bincode_types::Uuid;
use edumdns_core::connection::TcpConnectionHandle;
use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use rustls::ServerConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pki_types::pem::PemObject;
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
    (tx, rx): (Sender<AppPacket>, Receiver<AppPacket>),
    config: Option<ServerTlsConfig>,
    global_timeout: Duration,
) -> Result<(), ServerError> {
    let host = parse_host();
    let listener = TcpListener::bind(host).await?;
    info!("Listening on {}", listener.local_addr()?);

    let probe_handles: ProbeHandles = Arc::new(RwLock::new(HashMap::new()));
    let tracker: SharedProbeLastSeen = Arc::new(RwLock::new(OrderedMap::new()));

    let pool_local = pool.clone();
    let probe_handles_local = probe_handles.clone();
    let _packet_storage_task = tokio::task::spawn(async move {
        match PacketManager::new(rx, pool_local, probe_handles_local, global_timeout) {
            Ok(mut manager) => manager.handle_packets().await,
            Err(e) => {
                error!("Could not initialize packet manager: {e}");
            }
        }
    });

    let tracker_local: SharedProbeLastSeen = tracker.clone();
    let probe_handles_local = probe_handles.clone();
    let _probe_watchdog_task = tokio::task::spawn(async move {
        info!("Starting the probe watchdog");
        watchdog(tracker_local, probe_handles_local, global_timeout).await;
    });
    info!("Packet storage initialized");

    let domain = config.as_ref().map(|c| c.domain.clone());
    let server_config = match config {
        None => None,
        Some(config) => {
            let certs = CertificateDer::pem_file_iter(&config.cert_path)?.collect::<Result<Vec<_>, _>>()?;
            let key = PrivateKeyDer::from_pem_file(&config.key_path)?;
            Some(ServerConfig::builder().with_no_client_auth().with_single_cert(certs, key)?)
        }
    };

    loop {
        let (stream, addr) = listener.accept().await?;
        info!("Connection from {addr}");
        let connection_manager = ConnectionManager::new(
            stream,
            domain.as_ref(),
            server_config.clone(),
            pool.clone(),
            tx.clone(),
            probe_handles.clone(),
            tracker.clone(),
            global_timeout,
        ).await?;
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
