use edumdns_core::bincode_types::MacAddr;
use edumdns_db::repositories::common::{Id, Pagination};
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeQuery {
    pub page: Option<i64>,
    pub owner_id: Option<Id>,
    pub location_id: Option<Id>,
    pub adopted: Option<bool>,
    pub mac: Option<MacAddr>,
    pub ip: Option<IpNetwork>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ProbeConfigForm {
    pub interface: String,
    // Option is easiest to handle blank filters (treat empty as None)
    #[serde(default)]
    pub filter: Option<String>,
}
