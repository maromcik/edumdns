//! edumdns_server crate entry points and task management.
//!
//! This module wires together listeners, the packet manager, database manager,
//! and the watchdog that reaps stale probe connections. Public functions here
//! are used by the binary to initialize and spawn all server tasks.

use crate::app_packet::AppPacket;
use crate::config::ServerConfig;
use crate::database::spawn_database_task;
use crate::database::util::load_all_packet_transmit_requests;
use crate::error::ServerError;
use crate::connection::listen::ListenerSpawner;
use crate::server::spawn_server_task;
use crate::utils::ordered_map::OrderedMap;
use crate::utils::probe_tracker::{SharedProbeTracker, watchdog};
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::deadpool::Pool;
use edumdns_core::bincode_types::Uuid;
use edumdns_core::connection::TcpConnectionHandle;
use log::{info};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{RwLock};

pub mod app_packet;
pub mod config;
mod database;
pub mod error;
mod connection;
mod server;
mod transmit;
mod utils;

pub type ProbeHandles = Arc<RwLock<HashMap<Uuid, TcpConnectionHandle>>>;

pub async fn server_init(
    pool: Pool<AsyncPgConnection>,
    (tx, rx): (Sender<AppPacket>, Receiver<AppPacket>),
    server_config: ServerConfig,
) -> Result<(), ServerError> {
    load_all_packet_transmit_requests(pool.clone(), tx.clone()).await?;
    spawn_server_tasks(pool.clone(), (tx.clone(), rx), Arc::new(server_config)).await?;
    Ok(())
}

pub async fn spawn_server_tasks(
    pool: Pool<AsyncPgConnection>,
    (command_transmitter, command_receiver): (Sender<AppPacket>, Receiver<AppPacket>),
    server_config: Arc<ServerConfig>,
) -> Result<(), ServerError> {
    let probe_handles: ProbeHandles = Arc::new(RwLock::new(HashMap::new()));
    let tracker: SharedProbeTracker = Arc::new(RwLock::new(OrderedMap::new()));
    let data_channel = tokio::sync::mpsc::channel(server_config.channel_buffer_capacity);
    let db_channel = tokio::sync::mpsc::channel(server_config.channel_buffer_capacity);

    spawn_server_task(
        pool.clone(),
        probe_handles.clone(),
        (command_transmitter.clone(), command_receiver),
        data_channel.1,
        db_channel.0,
        server_config.clone(),
    )
    .await;

    spawn_database_task(db_channel.1, pool.clone()).await;

    let tracker_local: SharedProbeTracker = tracker.clone();
    let probe_handles_local = probe_handles.clone();

    let server_config_local = server_config.clone();
    let _probe_watchdog_task = tokio::task::spawn(async move {
        info!("Starting the probe watchdog");
        watchdog(
            tracker_local,
            probe_handles_local,
            server_config_local.connection.global_timeout,
        )
        .await;
    });

    ListenerSpawner::new(
        pool,
        command_transmitter,
        data_channel.0,
        probe_handles,
        tracker,
        server_config,
    )
    .await?
    .start_listeners()
    .await?;

    Ok(())
}
