use crate::error::AppError;
use edumdns_probe::capture_and_send;
use edumdns_server::listen::listen;

mod error;

pub async fn run_probe() -> Result<(), AppError> {
    capture_and_send().await?;
    Ok(())
}

pub async fn run_server() -> Result<(), AppError> {
    listen().await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), AppError> {
    let (x, y) = tokio::join!(run_server(), run_probe());
    x?;
    y?;

    Ok(())
}
