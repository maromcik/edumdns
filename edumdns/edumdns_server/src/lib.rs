//! edumdns_server crate entry points and task management.
//!
//! This module wires together listeners, the packet manager, database manager,
//! and the watchdog that reaps stale probe connections. Public functions here
//! are used by the binary to initialize and spawn all server tasks.

use crate::app_packet::AppPacket;
use crate::config::ServerConfig;
use crate::database::DatabaseManager;
use crate::error::ServerError;
use crate::listen::ListenerSpawner;
use crate::manager::ServerManager;
use crate::ordered_map::OrderedMap;
use crate::probe_tracker::{SharedProbeTracker, watchdog};
use crate::utilities::load_all_packet_transmit_requests;
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::deadpool::Pool;
use edumdns_core::bincode_types::Uuid;
use edumdns_core::connection::TcpConnectionHandle;
use log::{info};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::sync::mpsc::{Receiver, Sender};

pub mod app_packet;
pub mod config;
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

pub type ProbeHandles = Arc<RwLock<HashMap<Uuid, TcpConnectionHandle>>>;

pub async fn server_init(
    pool: Pool<AsyncPgConnection>,
    (tx, rx): (Sender<AppPacket>, Receiver<AppPacket>),
    server_config: ServerConfig,
) -> Result<(), ServerError> {
    load_all_packet_transmit_requests(pool.clone(), tx.clone()).await?;
    spawn_server_tasks(pool.clone(), (tx.clone(), rx), server_config).await?;
    Ok(())
}

pub async fn spawn_server_tasks(
    pool: Pool<AsyncPgConnection>,
    (command_transmitter, command_receiver): (Sender<AppPacket>, Receiver<AppPacket>),
    server_config: ServerConfig,
) -> Result<(), ServerError> {
    let probe_handles: ProbeHandles = Arc::new(RwLock::new(HashMap::new()));
    let tracker: SharedProbeTracker = Arc::new(RwLock::new(OrderedMap::new()));
    let data_channel = tokio::sync::mpsc::channel(server_config.channel_buffer_capacity);
    let db_channel = tokio::sync::mpsc::channel(server_config.channel_buffer_capacity);

    let pool_local = pool.clone();
    let probe_handles_local = probe_handles.clone();
    let command_transmitter_local = command_transmitter.clone();
    let server_config_local = server_config.clone();
    let _server_manager_task = tokio::task::spawn(async move {
        let mut manager = ServerManager::new(
            command_transmitter_local,
            command_receiver,
            data_channel.1,
            db_channel.0,
            pool_local,
            probe_handles_local,
            server_config_local,
        );
        manager.handle_packets().await;
    });
    info!("Packet manager initialized");

    let pool_local = pool.clone();
    let _database_manager_task = tokio::task::spawn(async move {
        DatabaseManager::new(db_channel.1, pool_local)
            .handle_database()
            .await;
    });
    info!("DB manager initialized");
    let server_config_local = server_config.clone();
    let tracker_local: SharedProbeTracker = tracker.clone();
    let probe_handles_local = probe_handles.clone();
    let _probe_watchdog_task = tokio::task::spawn(async move {
        info!("Starting the probe watchdog");
        watchdog(
            tracker_local,
            probe_handles_local,
            server_config.connection.global_timeout,
        )
        .await;
    });

    ListenerSpawner::new(
        pool,
        command_transmitter,
        data_channel.0,
        probe_handles,
        tracker,
        server_config_local,
    )
    .await?
    .start_listeners()
    .await?;

    Ok(())
}
