use crate::forms::device::DeviceQuery;
use crate::forms::probe::ProbeQuery;
use crate::templates::PageInfo;
use edumdns_db::models::{Group, ProbeConfig};
use edumdns_db::repositories::common::{Permission, Permissions};
use edumdns_db::repositories::device::models::DeviceDisplay;
use edumdns_db::repositories::probe::models::ProbeDisplay;
use edumdns_db::repositories::user::models::UserDisplay;
use serde::Serialize;

#[derive(Serialize)]
pub struct ProbeTemplate {
    pub user: UserDisplay,
    pub permissions: Permissions,
    pub probes: Vec<ProbeDisplay>,
    pub page_info: PageInfo,
    pub filters: ProbeQuery,
    pub query_string: String,
}

#[derive(Serialize)]
pub struct ProbeDetailTemplate {
    pub user: UserDisplay,
    pub permissions: Permissions,
    pub permission_matrix: Vec<(Vec<(Permission, bool)>, Group)>,
    pub probe: ProbeDisplay,
    pub devices: Vec<DeviceDisplay>,
    pub configs: Vec<ProbeConfig>,
    pub page_info: PageInfo,
    pub filters: DeviceQuery,
    pub query_string: String,
}
