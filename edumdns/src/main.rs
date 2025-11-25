use crate::error::AppError;
use clap::Parser;
use edumdns_db::db_init;
use edumdns_server::{BUFFER_SIZE, server_init};
use edumdns_web::web_init;
use tracing::log::error;
use tracing_subscriber::EnvFilter;

mod error;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// Optional `.env` file path for loading environment variables.
    #[clap(short, long, value_name = "ENV_FILE")]
    env_file: Option<String>,
}

#[actix_web::main]
async fn main() -> Result<(), AppError> {
    dotenvy::dotenv().ok();
    let cli = Cli::parse();
    if let Some(env_file) = cli.env_file {
        dotenvy::from_filename(env_file).expect("failed to load .env file");
        Cli::parse();
    }
    let command_channel = tokio::sync::mpsc::channel(BUFFER_SIZE);
    let log_level = std::env::var("EDUMDNS_LOG_LEVEL").unwrap_or_else(|_| "info".to_string());
    let env = EnvFilter::new(format!("edumdns={},info", log_level));
    let timer = tracing_subscriber::fmt::time::LocalTime::rfc_3339();
    tracing_subscriber::fmt()
        .with_timer(timer)
        .with_target(true)
        .with_env_filter(env)
        .init();

    let pool = db_init().await?;
    let pool_local = pool.clone();
    let sender_local = command_channel.0.clone();

    tokio::spawn(async move {
        if let Err(e) = server_init(pool_local, command_channel).await {
            error!("{e}")
        }
    });

    let pool_local = pool.clone();
    web_init(pool_local, sender_local).await?;
    Ok(())
}
