use tokio::sync::mpsc::{Receiver, Sender};
use crate::error::ServerError;
use crate::listen::listen;
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::deadpool::Pool;
use edumdns_core::app_packet::AppPacket;
use edumdns_db::repositories::probe::repository::PgProbeRepository;

mod connection;
mod database;
pub mod error;
pub mod listen;
pub mod storage;
mod transmitter;

pub struct ServerConfig {}

pub async fn server_init(pool: Pool<AsyncPgConnection>, command_channel: (Sender<AppPacket>, Receiver<AppPacket>)) -> Result<(), ServerError> {
    listen(pool, command_channel).await?;
    Ok(())
}
