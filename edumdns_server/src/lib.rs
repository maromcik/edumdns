use crate::error::ServerError;
use crate::listen::listen;
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::deadpool::Pool;
use edumdns_core::app_packet::AppPacket;
use edumdns_db::repositories::probe::repository::PgProbeRepository;
use std::env;
use std::time::Duration;
use tokio::sync::mpsc::{Receiver, Sender};

mod connection;
mod database;
pub mod error;
pub mod listen;
pub mod storage;
mod transmitter;

pub struct ServerConfig {}

pub async fn server_init(
    pool: Pool<AsyncPgConnection>,
    command_channel: (Sender<AppPacket>, Receiver<AppPacket>),
) -> Result<(), ServerError> {
    let global_timeout = Duration::from_secs(
        env::var("EDUMDNS_PROBE_GLOBAL_TIMOUT")
            .unwrap_or("10".to_string())
            .parse::<u64>()?,
    );

    listen(pool, command_channel, global_timeout).await?;
    Ok(())
}
