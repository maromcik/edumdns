use crate::config::AppConfig;
use crate::error::AppError;
use clap::Parser;
use edumdns_db::db_init;
use edumdns_server::server_init;
use edumdns_web::web_init;
use tracing::info;
use tracing::log::error;
use tracing_subscriber::EnvFilter;

pub mod config;
mod error;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// Optional `.env` file path for loading environment variables.
    #[clap(short, long, value_name = "ENV_FILE", default_value = "edumdns.toml")]
    config: String,
}

#[actix_web::main]
async fn main() -> Result<(), AppError> {
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

    info!("Config used:\n{config:#?}");
    let command_channel = tokio::sync::mpsc::channel(config.server.connection.buffer_size);

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
