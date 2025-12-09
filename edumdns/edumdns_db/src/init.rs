use crate::config::DbConfig;
use crate::error::DbError;
use diesel::Connection;
use diesel::PgConnection;
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::deadpool::Pool;
use diesel_migrations::{EmbeddedMigrations, MigrationHarness, embed_migrations};
use log::info;

const MIGRATIONS: EmbeddedMigrations = embed_migrations!();

pub async fn init(database_config: DbConfig) -> Result<Pool<AsyncPgConnection>, DbError> {
    run_migrations(&database_config)?;
    set_up_database_pool(&database_config)
}


pub fn run_migrations(database_config: &DbConfig) -> Result<(), DbError> {
    let mut connection = PgConnection::establish(&database_config.connection_string)?;
    connection
        .run_pending_migrations(MIGRATIONS)
        .map_err(|e| DbError::MigrationError(e.to_string()))?;
    info!("Migrations ran successfully.");
    Ok(())
}

fn set_up_database_pool(database_config: &DbConfig) -> Result<Pool<AsyncPgConnection>, DbError> {
    let config = AsyncDieselConnectionManager::<AsyncPgConnection>::new(
        database_config.connection_string.to_string(),
    );
    Pool::builder(config)
        .max_size(database_config.pool_size)
        .build()
        .map_err(DbError::from)
}
