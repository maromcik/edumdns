use crate::error::ServerError;
use crate::listen::listen;
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::deadpool::Pool;
use edumdns_core::app_packet::AppPacket;
use std::env;
use std::time::Duration;
use tokio::sync::mpsc::{Receiver, Sender};

mod connection;
pub mod error;
pub mod handler;
pub mod listen;
mod transmitter;

const DEFAULT_HOSTNAME: &str = "localhost";
const DEFAULT_PORT: &str = "5000";

pub async fn server_init(
    pool: Pool<AsyncPgConnection>,
    command_channel: (Sender<AppPacket>, Receiver<AppPacket>),
) -> Result<(), ServerError> {
    let global_timeout = Duration::from_secs(
        env::var("EDUMDNS_PROBE_GLOBAL_TIMEOUT")
            .unwrap_or("10".to_string())
            .parse::<u64>()?,
    );

    listen(pool, command_channel, global_timeout).await?;
    Ok(())
}

pub fn parse_host() -> String {
    let hostname = env::var("EDUMDNS_SERVER_HOSTNAME").unwrap_or(DEFAULT_HOSTNAME.to_string());
    let port = env::var("EDUMDNS_SERVER_PORT").unwrap_or(DEFAULT_PORT.to_string());
    format!("{hostname}:{port}")
}
