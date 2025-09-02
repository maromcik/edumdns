use edumdns_core::bincode_types::MacAddr;
use edumdns_db::repositories::common::{Id, Pagination, Permission};
use edumdns_db::repositories::probe::models::SelectManyProbes;
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
    pub name: Option<String>,
}

impl From<ProbeQuery> for SelectManyProbes {
    fn from(value: ProbeQuery) -> Self {
        Self::new(
            value.owner_id,
            value.location_id,
            value.adopted,
            value.mac.map(|addr| addr.to_octets()),
            value.ip,
            value.name,
            Some(Pagination::default_pagination(value.page)),
        )
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ProbeConfigForm {
    pub interface: String,
    // Option is easiest to handle blank filters (treat empty as None)
    #[serde(default)]
    pub filter: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ProbePermissionForm {
    pub group_id: Id,
    pub permission: Permission,
    #[serde(default)]
    pub value: bool,
}
