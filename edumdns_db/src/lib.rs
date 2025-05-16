mod init;
pub mod repositories;
pub mod models;
pub mod schema;
pub mod error;

pub async fn init() {
    init::init().await;
}