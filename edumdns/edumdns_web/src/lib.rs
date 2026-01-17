//! Web interface module for the edumDNS system.
//!
//! This module provides the web-based user interface for administrators and users to interact
//! with the edumDNS system. It includes HTTP handlers for device management, probe configuration,
//! packet viewing, user administration, and authentication (both local and OpenID Connect).
//!
//! The module uses Actix Web as the web framework and Minijinja for template rendering.
//! It communicates with the server component through message channels to coordinate operations
//! such as packet transmission requests and probe management.

use crate::error::WebError;
use crate::init::WebSpawner;
use actix_web::http::header;
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::deadpool::Pool;
use edumdns_server::app_packet::AppPacket;

use crate::config::WebConfig;
use tokio::sync::mpsc::Sender;

pub mod error;

pub mod config;
mod forms;
mod handlers;
mod init;
mod middleware;
mod templates;
mod utils;

/// Initializes and starts the web server.
///
/// This function sets up the web interface by creating a `WebSpawner` instance and starting
/// the HTTP server. It loads environment variables from a `.env` file if present.
///
/// # Arguments
///
/// * `pool` - Database connection pool for accessing PostgreSQL
/// * `command_channel` - Channel sender for sending commands to the server component
/// * `web_config` - Global web configuration
/// # Returns
///
/// Returns `Ok(())` if the server starts successfully, or a `WebError` if initialization fails.
///
/// # Errors
///
/// This function will return an error if:
/// - The `.env` file cannot be loaded (non-fatal, logged as warning)
/// - The `WebSpawner` fails to initialize
/// - The HTTP server fails to bind to the configured address
pub async fn web_init(
    pool: Pool<AsyncPgConnection>,
    command_channel: Sender<AppPacket>,
    web_config: WebConfig,
) -> Result<(), WebError> {
    WebSpawner::new(pool, command_channel, web_config)
        .await
        .run_web()
        .await?;

    Ok(())
}
