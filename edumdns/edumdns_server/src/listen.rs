//! TCP listener and TLS configuration for accepting probe connections.
//!
//! `ListenerSpawner` binds to configured addresses (with or without TLS) and
//! spawns per-connection tasks that run a `ConnectionManager`.

use crate::app_packet::AppPacket;
use crate::connection::ConnectionManager;
use crate::error::ServerError;
use crate::probe_tracker::SharedProbeTracker;
use crate::{ProbeHandles};
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::deadpool::Pool;
use edumdns_core::bincode_types::Uuid;
use log::{debug, error, info, warn};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig as RustlsServerConfig;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::mpsc::Sender;
use edumdns_core::utils::lookup_hosts;
use crate::config::{ServerConfig, TlsConfig};

#[derive(Debug, Clone)]
pub struct ServerTlsConfig {
    pub cert_path: String,
    pub key_path: String,
}

async fn handle_connection(mut connection_manager: ConnectionManager) -> Result<Uuid, ServerError> {
    let uuid = connection_manager.connection_init_server().await?;
    connection_manager.transfer_packets().await?;
    info!("Probe {uuid} disconnected");
    Ok(uuid)
}

pub struct ListenerSpawner {
    pool: Pool<AsyncPgConnection>,
    command_transmitter: Sender<AppPacket>,
    data_transmitter: Sender<AppPacket>,
    probe_handles: ProbeHandles,
    tracker: SharedProbeTracker,
    socket_addrs: Vec<SocketAddr>,
    server_config: ServerConfig,
}
impl ListenerSpawner {
    pub async fn new(
        pool: Pool<AsyncPgConnection>,
        command_transmitter: Sender<AppPacket>,
        data_transmitter: Sender<AppPacket>,
        probe_handles: ProbeHandles,
        tracker: SharedProbeTracker,
        server_config: ServerConfig
    ) -> Result<Self, ServerError> {
        let socket_addrs = lookup_hosts(server_config.hostnames.clone()).await?;
        
        Ok(Self {
            pool,
            command_transmitter,
            data_transmitter,
            probe_handles,
            tracker,
            socket_addrs,
            server_config,
        })
    }

    pub async fn start_listeners(self) -> Result<(), ServerError> {
        for socket_addr in self.socket_addrs {
            let pool_local = self.pool.clone();
            let command_transmitter_local = self.command_transmitter.clone();
            let data_channel_local = self.data_transmitter.clone();
            let probe_handles_local = self.probe_handles.clone();
            let tracker_local = self.tracker.clone();
            let timeout = self.server_config.connection.global_timeout;
            let config_local = self.server_config.tls.clone();
            tokio::spawn(async move {
                if let Err(e) = Self::listen(
                    pool_local,
                    command_transmitter_local,
                    data_channel_local,
                    probe_handles_local,
                    tracker_local,
                    config_local,
                    socket_addr,
                    timeout,
                )
                    .await
                {
                    error!("Could not start the server on {socket_addr}: {e}");
                }
            });
            
        }

        Ok(())
    }

    pub async fn listen(
        pool: Pool<AsyncPgConnection>,
        command_transmitter: Sender<AppPacket>,
        data_transmitter: Sender<AppPacket>,
        probe_handles: ProbeHandles,
        tracker: SharedProbeTracker,
        config: Option<TlsConfig>,
        hostname: SocketAddr,
        global_timeout: Duration,
    ) -> Result<(), ServerError> {
        let listener = TcpListener::bind(hostname).await?;
        let server_config = match config {
            None => {
                info!("Listening on {} without TLS", listener.local_addr()?);
                None
            }
            Some(config) => {
                info!("Listening on {} with TLS enabled", listener.local_addr()?);
                let certs = CertificateDer::pem_file_iter(&config.cert_path)?
                    .collect::<Result<Vec<_>, _>>()?;
                let key = PrivateKeyDer::from_pem_file(&config.key_path)?;
                Some(
                    RustlsServerConfig::builder()
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
                data_transmitter.clone(),
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
                        if let ServerError::ProbeNotAdopted = err {
                            info!("Client {addr} tried to connect, but probe is not adopted");
                        } else {
                            warn!("{err}");
                        }
                    }
                }
            });
        }
    }
}
