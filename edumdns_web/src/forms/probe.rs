use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use edumdns_core::bincode_types::MacAddr;
use edumdns_db::repositories::common::{Id, Pagination};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeQuery {
    pub page: Option<i64>,
    pub owner_id: Option<Id>,
    pub location_id: Option<Id>,
    pub adopted: Option<bool>,
    pub mac: Option<MacAddr>,
    pub ip: Option<IpNetwork>,
}