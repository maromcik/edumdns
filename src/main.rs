use crate::error::AppError;
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::deadpool::Pool;
use edumdns_db::db_init;
use edumdns_probe::probe_init;
use edumdns_server::server_init;
use edumdns_web::web_init;
use tracing_subscriber::EnvFilter;

mod error;

pub async fn run_probe() -> Result<(), AppError> {
    probe_init().await?;
    Ok(())
}

pub async fn run_server(pool: Pool<AsyncPgConnection>) -> Result<(), AppError> {
    server_init(pool).await?;
    Ok(())
}

pub async fn run_web(pool: Pool<AsyncPgConnection>) -> Result<(), AppError> {
    web_init(pool).await?;
    Ok(())
}

#[actix_web::main]
async fn main() -> Result<(), AppError> {
    dotenvy::dotenv().ok();

    let env = EnvFilter::try_from_env("EDUMDNS_LOG_LEVEL").unwrap_or(EnvFilter::new("info"));
    let timer = tracing_subscriber::fmt::time::LocalTime::rfc_3339();
    tracing_subscriber::fmt()
        .with_timer(timer)
        .with_target(true)
        .with_env_filter(env)
        .init();

    let pool = db_init().await?;

    tokio::select! {
        server = server_init(pool.clone()) => server?,
        probe = probe_init() => probe?
    }

    Ok(())
}
