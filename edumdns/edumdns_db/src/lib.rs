use crate::config::DbConfig;
use crate::error::DbError;
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::deadpool::Pool;

pub mod config;
pub mod error;
mod init;
pub mod models;
pub mod repositories;
pub mod schema;

pub async fn db_init(database_config: DbConfig) -> Result<Pool<AsyncPgConnection>, DbError> {
    init::init(database_config).await
}
