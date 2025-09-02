use edumdns_db::models::{Group, GroupProbePermission, Location, ProbeConfig};
use edumdns_db::repositories::common::{Permission, Permissions};
use edumdns_db::repositories::device::models::DeviceDisplay;
use edumdns_db::repositories::probe::models::ProbeDisplay;
use serde::Serialize;
#[derive(Serialize)]
pub struct ProbeTemplate {
    pub logged_in: bool,
    pub is_admin: bool,
    pub permissions: Permissions,
    pub probes: Vec<(Option<Location>, ProbeDisplay)>,
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
}
