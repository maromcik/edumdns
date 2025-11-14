use edumdns_db::repositories::user::models::UserDisplay;
use serde::Serialize;

#[derive(Serialize)]
pub struct IndexTemplate {
    pub user: UserDisplay,
}

#[derive(Serialize)]
pub struct LoginTemplate {
    pub message: String,
    pub return_url: String,
}
