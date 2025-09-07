use edumdns_db::models::{Group, Location, ProbeConfig};
use edumdns_db::repositories::common::{Permission, Permissions};
use edumdns_db::repositories::device::models::DeviceDisplay;
use edumdns_db::repositories::probe::models::ProbeDisplay;
use serde::Serialize;
use crate::forms::device::DeviceQuery;
use crate::forms::probe::ProbeQuery;
use crate::templates::PageInfo;

#[derive(Serialize)]
pub struct ProbeTemplate {
    pub logged_in: bool,
    pub is_admin: bool,
    pub permissions: Permissions,
    pub probes: Vec<(Option<Location>, ProbeDisplay)>,
    pub page_info: PageInfo,
    pub filters: ProbeQuery,
}

#[derive(Serialize)]
pub struct ProbeDetailTemplate {
    pub logged_in: bool,
    pub is_admin: bool,
    pub permissions: Permissions,
    pub permission_matrix: Vec<(Vec<(Permission, bool)>, Group)>,
    pub probe: ProbeDisplay,
    pub devices: Vec<DeviceDisplay>,
    pub configs: Vec<ProbeConfig>,
    pub admin: bool,
    pub page_info: PageInfo,
    pub filters: DeviceQuery
}
