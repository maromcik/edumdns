use crate::error::AppError;
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::deadpool::Pool;
use edumdns_db::db_init;
use edumdns_probe::probe_init;
use edumdns_server::server_init;
use edumdns_web::web_init;
use env_logger::Env;
use std::thread::sleep;
use std::time::Duration;

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
    env_logger::init_from_env(Env::default().default_filter_or("info"));
    let pool = db_init().await?;

    // tokio::select! {
    //     server = run_server(pool.clone()) => server,
    //     probe = run_probe() => probe
    // }?;
    // if let Err(e) = run_web(pool.clone()).await {
    //     println!("{}",e);
    // }

    // if let Err(e) = run_server(pool.clone()).await {
    //     println!("{}",e);
    // }
    // if let Err(e) = run_probe().await {
    //     println!("{}",e);
    // }
    // let (x, y) = tokio::join!(
    //     run_server(pool.clone()),
    //     run_probe());
    // x?;
    // y?;

    let server = tokio::spawn(async move { run_server(pool.clone()).await });
    let probe = tokio::spawn(async move { run_probe().await });

    server.await??;
    probe.await??;
    Ok(())
}
