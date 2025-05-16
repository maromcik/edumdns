use diesel::Connection;
use std::env;
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
use std::sync::Once;
use diesel::PgConnection;
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::{deadpool, AsyncDieselConnectionManager};
use diesel_async::pooled_connection::deadpool::{Pool};

const MIGRATIONS: EmbeddedMigrations = embed_migrations!();
static INITIAL_MIGRATION: Once = Once::new();

pub async fn init() {
    INITIAL_MIGRATION.call_once(run_migrations);

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let config = AsyncDieselConnectionManager::<AsyncPgConnection>::new(database_url);
    let pool = Pool::builder(config)
        .max_size(20)
        .build()
        .expect("Failed to setup database pool");
    
    
}

/// Runs your embedded migrations
/// DATABASE_URL environment variable needs to be set with proper connection string.
pub fn run_migrations() {
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let mut connection = PgConnection::establish(&database_url)
        .expect("failed to establish connection for migrations");
    connection
        .run_pending_migrations(MIGRATIONS)
        .expect("failed migrating database");
}
