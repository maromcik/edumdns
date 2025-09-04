use crate::error::{DbError, DbErrorKind};
use diesel::Connection;
use diesel::PgConnection;
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::deadpool::Pool;
use diesel_migrations::{EmbeddedMigrations, MigrationHarness, embed_migrations};
use std::env;

const MIGRATIONS: EmbeddedMigrations = embed_migrations!();

pub async fn init() -> Result<Pool<AsyncPgConnection>, DbError> {
    run_migrations()?;
    set_up_database_pool()
}

/// Runs your embedded migrations
/// DATABASE_URL environment variable needs to be set with proper connection string.
pub fn run_migrations() -> Result<(), DbError> {
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let mut connection = PgConnection::establish(&database_url)?;

    connection
        .run_pending_migrations(MIGRATIONS)
        .map_err(|e| DbError::new(DbErrorKind::MigrationError, e.to_string().as_str()))?;
    Ok(())
}

fn set_up_database_pool() -> Result<Pool<AsyncPgConnection>, DbError> {
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let config = AsyncDieselConnectionManager::<AsyncPgConnection>::new(database_url);
    Pool::builder(config)
        .max_size(20)
        .build()
        .map_err(DbError::from)
}
