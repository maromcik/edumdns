//! Main entry point for the edumdns server binary.
//!
//! This module orchestrates the initialization and startup of all system components:
//! - Parses command-line arguments for configuration file path
//! - Loads configuration from TOML file (with environment variable overrides)
//! - Initializes logging with configurable levels
//! - Sets up database connection pool
//! - Spawns server component task for probe management
//! - Starts web interface for user interaction
//!
//! The application uses a TOML configuration file for all settings, with optional
//! environment variable overrides using the `APP_` prefix.

use crate::config::AppConfig;
use crate::error::AppError;
use clap::Parser;
use edumdns_db::db_init;
use edumdns_server::server_init;
use edumdns_web::web_init;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

pub mod config;
mod error;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// Optional path to a `toml` configuration file, see edumdns-example.toml
    #[clap(
        short,
        long,
        value_name = "CONFIG_FILE",
        default_value = "edumdns.toml",
        env = "EDUMDNS_CONFIG_FILE"
    )]
    config: String,
}

/// Main entry point for the edumdns server.
///
/// This function:
/// 1. Installs the default rustls crypto provider
/// 2. Parses command-line arguments for configuration file path
/// 3. Loads and parses the TOML configuration file
/// 4. Initializes logging with configured levels
/// 5. Creates database connection pool
/// 6. Spawns server component task for probe management
/// 7. Starts web interface (blocks until shutdown)
///
/// # Arguments
///
/// Configuration is loaded from:
/// - TOML file specified by `--config` argument (default: `edumdns.toml`)
/// - Environment variables with `APP_` prefix (override TOML values)
///
/// # Returns
///
/// Returns `Ok(())` on successful shutdown, or an `AppError` if:
/// - Configuration file cannot be loaded or parsed
/// - Database initialization fails
/// - Server or web component initialization fails
///
/// # Environment Variables
///
/// - `EDUMDNS_CONFIG_FILE` - Path to configuration file (overrides `--config` argument)
#[actix_web::main]
async fn main() -> Result<(), AppError> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install the default rustls crypto provider");

    let cli = Cli::parse();

    let config = AppConfig::parse_config(&cli.config)?;
    let env = EnvFilter::new(format!(
        "edumdns={},{}",
        config.app_log_level, config.all_log_level
    ));
    let timer = tracing_subscriber::fmt::time::LocalTime::rfc_3339();
    tracing_subscriber::fmt()
        .with_timer(timer)
        .with_target(true)
        .with_env_filter(env)
        .init();

    info!("Config used: {}\n{config:#?}", cli.config);
    let command_channel = tokio::sync::mpsc::channel(config.server.channel_buffer_capacity);

    let pool = db_init(config.database).await?;
    let pool_local = pool.clone();
    let sender_local = command_channel.0.clone();

    tokio::spawn(async move {
        if let Err(e) = server_init(pool_local, command_channel, config.server).await {
            error!("{e}")
        }
    });

    let pool_local = pool.clone();
    web_init(pool_local, sender_local, config.web).await?;
    Ok(())
}
