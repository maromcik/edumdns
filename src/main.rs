use crate::error::AppError;
use clap::Parser;
use edumdns_db::db_init;
use edumdns_server::server_init;
use edumdns_web::web_init;
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
    let command_channel = tokio::sync::mpsc::channel(1000);
    let env = EnvFilter::try_from_env("EDUMDNS_LOG_LEVEL").unwrap_or(EnvFilter::new("info"));
    let timer = tracing_subscriber::fmt::time::LocalTime::rfc_3339();
    tracing_subscriber::fmt()
        .with_timer(timer)
        .with_target(true)
        .with_env_filter(env)
        .init();

    let pool = db_init().await?;
    tokio::select! {
        web = web_init(pool.clone(), command_channel.0.clone()) => web?,
        server = server_init(pool.clone(), command_channel) => server?,
    }

    Ok(())
}
