use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::deadpool::Pool;
use crate::error::ServerError;
use crate::listen::listen;

pub mod listen;
pub mod error;
pub mod storage;
mod transmitter;

pub struct ServerConfig {
    
}

pub async fn server_init(pool: Pool<AsyncPgConnection>) -> Result<(), ServerError> {
    listen(pool).await?;
    Ok(())
}