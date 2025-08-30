use edumdns_db::repositories::common::Pagination;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct GroupQuery {
    pub page: Option<i64>,
    pub name: Option<String>,
}
