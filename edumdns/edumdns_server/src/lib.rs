use crate::app_packet::AppPacket;
use crate::database::DatabaseManager;
use crate::error::ServerError;
use crate::listen::{ProbeHandles, listen};
use crate::manager::PacketManager;
use crate::ordered_map::OrderedMap;
use crate::probe_tracker::{SharedProbeTracker, watchdog};
use crate::utilities::load_all_packet_transmit_requests;
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::deadpool::Pool;
use log::{error, info};
use std::collections::HashMap;
use std::env;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::sync::mpsc::{Receiver, Sender};

pub mod app_packet;
mod connection;
mod database;
mod ebpf;
pub mod error;
pub mod listen;
pub mod manager;
mod ordered_map;
mod probe_tracker;
mod transmitter;
mod utilities;

const DEFAULT_HOSTNAME: &str = "localhost";
const DEFAULT_PORT: &str = "5000";

const DEFAULT_INTERVAL_MULTIPLICATOR: u32 = 5;

pub const BUFFER_SIZE: usize = 1000;

pub struct ServerTlsConfig {
    pub cert_path: String,
    pub key_path: String,
}

pub async fn server_init(
    pool: Pool<AsyncPgConnection>,
    (tx, rx): (Sender<AppPacket>, Receiver<AppPacket>),
) -> Result<(), ServerError> {
    let global_timeout = Duration::from_secs(
        env::var("EDUMDNS_PROBE_GLOBAL_TIMEOUT")
            .unwrap_or("10".to_string())
            .parse::<u64>()?,
    );
    let cert = env::var("EDUMDNS_SERVER_CERT").ok();
    let key = env::var("EDUMDNS_SERVER_KEY").ok();
    let config = match (cert, key) {
        (Some(c), Some(k)) => Some(ServerTlsConfig {
            cert_path: c,
            key_path: k,
        }),
        (_, _) => None,
    };
    load_all_packet_transmit_requests(pool.clone(), tx.clone()).await?;
    spawn_server_tasks(pool.clone(), (tx.clone(), rx), config, global_timeout).await?;
    Ok(())
}

pub async fn spawn_server_tasks(
    pool: Pool<AsyncPgConnection>,
    (command_transmitter, command_receiver): (Sender<AppPacket>, Receiver<AppPacket>),
    config: Option<ServerTlsConfig>,
    global_timeout: Duration,
) -> Result<(), ServerError> {
    let probe_handles: ProbeHandles = Arc::new(RwLock::new(HashMap::new()));
    let tracker: SharedProbeTracker = Arc::new(RwLock::new(OrderedMap::new()));
    let data_channel = tokio::sync::mpsc::channel(BUFFER_SIZE);
    let db_channel = tokio::sync::mpsc::channel(BUFFER_SIZE);

    let pool_local = pool.clone();
    let probe_handles_local = probe_handles.clone();
    let command_transmitter_local = command_transmitter.clone();
    let _packet_manager_task = tokio::task::spawn(async move {
        match PacketManager::new(
            command_transmitter_local,
            command_receiver,
            data_channel.1,
            db_channel.0,
            pool_local,
            probe_handles_local,
            global_timeout,
        ) {
            Ok(mut manager) => manager.handle_packets().await,
            Err(e) => {
                error!("Could not initialize packet manager: {e}");
            }
        }
    });
    info!("Packet manager initialized");

    let pool_local = pool.clone();
    let _database_manager_task = tokio::task::spawn(async move {
        DatabaseManager::new(db_channel.1, pool_local)
            .handle_database()
            .await;
    });
    info!("DB manager initialized");

    let tracker_local: SharedProbeTracker = tracker.clone();
    let probe_handles_local = probe_handles.clone();
    let _probe_watchdog_task = tokio::task::spawn(async move {
        info!("Starting the probe watchdog");
        watchdog(tracker_local, probe_handles_local, global_timeout).await;
    });

    listen(
        pool,
        command_transmitter,
        data_channel.0,
        probe_handles,
        tracker,
        config,
        global_timeout,
    )
    .await?;
    Ok(())
}

pub fn parse_host() -> String {
    let hostname = env::var("EDUMDNS_SERVER_HOSTNAME").unwrap_or(DEFAULT_HOSTNAME.to_string());
    let port = env::var("EDUMDNS_SERVER_PORT").unwrap_or(DEFAULT_PORT.to_string());
    format!("{hostname}:{port}")
}
