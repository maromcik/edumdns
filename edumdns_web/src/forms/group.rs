use serde::{Deserialize, Serialize};
use edumdns_db::repositories::common::Pagination;

#[derive(Serialize, Deserialize)]
pub struct GroupQuery {
    pub page: Option<i64>,
    pub name: Option<String>,
}