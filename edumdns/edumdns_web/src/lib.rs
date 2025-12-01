use crate::error::WebError;
use crate::init::WebSpawner;
use actix_web::http::header;
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::deadpool::Pool;
use edumdns_server::app_packet::AppPacket;
use log::warn;

use tokio::sync::mpsc::Sender;

pub mod error;

mod forms;
mod handlers;
mod init;
mod middleware;
mod templates;
mod utils;

const DEFAULT_HOSTNAME: &str = "localhost";
const DEFAULT_PORT: &str = "8000";
const SECS_IN_MONTH: u64 = 60 * 60 * 24 * 30;
const SECS_IN_WEEK: u64 = 60 * 60 * 24 * 7;
const PAYLOAD_LIMIT: usize = 16 * 1024 * 1024 * 1024; // 16GiB

const FORM_LIMIT: usize = 16 * 1024 * 1024; // 16MiB

const PING_INTERVAL: u64 = 1;

pub async fn web_init(
    pool: Pool<AsyncPgConnection>,
    command_channel: Sender<AppPacket>,
) -> Result<(), WebError> {
    if let Err(e) = dotenvy::dotenv() {
        warn!("failed loading .env file: {e}");
    };

    WebSpawner::new(pool, command_channel)
        .await?
        .run_web()
        .await?;

    Ok(())
}
