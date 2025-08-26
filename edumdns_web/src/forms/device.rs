use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use edumdns_db::repositories::common::Pagination;

#[derive(Serialize, Deserialize)]
pub struct DeviceQuery {
    pub page: Option<i64>,
    pub probe_id: Option<Uuid>,
    pub mac: Option<[u8; 6]>,
    pub ip: Option<IpNetwork>,
    pub port: Option<i32>,
}