use crate::forms::probe::ProbeConfigForm;
use edumdns_db::models::{Location, ProbeConfig};
use edumdns_db::repositories::device::models::DeviceDisplay;
use edumdns_db::repositories::probe::models::ProbeDisplay;
use serde::Serialize;

#[derive(Serialize)]
pub struct ProbeTemplate {
    pub logged_in: bool,
    pub probes: Vec<(Option<Location>, ProbeDisplay)>
}

#[derive(Serialize)]
pub struct ProbeDetailTemplate {
    pub logged_in: bool,
    pub probe: ProbeDisplay,
    pub devices: Vec<DeviceDisplay>,
    pub configs: Vec<ProbeConfig>
}
