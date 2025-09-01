use edumdns_db::repositories::common::{Id, Pagination};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct GroupQuery {
    pub page: Option<i64>,
    pub name: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct CreateGroupForm {
    pub name: String,
    pub description: Option<String>,
}