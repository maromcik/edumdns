use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::deadpool::Pool;
use crate::error::DbError;

mod init;
pub mod repositories;
pub mod models;
pub mod schema;
pub mod error;

pub async fn db_init() -> Result<Pool<AsyncPgConnection>, DbError> {
    init::init().await
}