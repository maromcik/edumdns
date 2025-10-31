use crate::error::DbError;
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::deadpool::Pool;

pub mod error;
mod init;
pub mod models;
pub mod repositories;
pub mod schema;

pub async fn db_init() -> Result<Pool<AsyncPgConnection>, DbError> {
    init::init().await
}
