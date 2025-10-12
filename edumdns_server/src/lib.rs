use crate::error::ServerError;
use crate::listen::listen;
use crate::utilities::load_all_packet_transmit_requests;
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::deadpool::Pool;
use edumdns_core::app_packet::{
    AppPacket, LocalAppPacket, LocalCommandPacket, PacketTransmitRequestPacket,
};
use edumdns_core::error::CoreError;
use edumdns_db::repositories::device::repository::PgDeviceRepository;
use log::warn;
use std::env;
use std::time::Duration;
use tokio::sync::mpsc::{Receiver, Sender};

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
    listen(pool, (tx, rx), config, global_timeout).await?;
    Ok(())
}

pub fn parse_host() -> String {
    let hostname = env::var("EDUMDNS_SERVER_HOSTNAME").unwrap_or(DEFAULT_HOSTNAME.to_string());
    let port = env::var("EDUMDNS_SERVER_PORT").unwrap_or(DEFAULT_PORT.to_string());
    format!("{hostname}:{port}")
}
