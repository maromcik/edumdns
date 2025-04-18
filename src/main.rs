use std::error::Error;
use edumdns_probe::run_core;
use crate::error::AppError;

mod error;


pub async fn run() -> Result<(), AppError> {
    run_core().await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), AppError> {
    let x = run().await;
    if let Err(e) = x {
        println!("{}", e);
    }
    Ok(())

}
