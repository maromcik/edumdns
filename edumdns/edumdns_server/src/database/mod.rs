use crate::database::actor::{DatabaseManager, DbCommand};
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::deadpool::Pool;
use log::info;
use tokio::sync::mpsc::Receiver;

pub(crate) mod actor;
pub(crate) mod util;

pub async fn spawn_database_task(receiver: Receiver<DbCommand>, pool: Pool<AsyncPgConnection>) {
    let _database_manager_task = tokio::task::spawn(async move {
        DatabaseManager::new(receiver, pool).handle_database().await;
        info!("DB manager initialized");
    });
}
