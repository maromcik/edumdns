use serde::Serialize;
use edumdns_db::models::{Location, Probe, User};
use crate::models::display::ProbeDisplay;

#[derive(Serialize)]
pub struct ProbeTemplate {
    pub logged_in: bool,
    pub probes: Vec<(Option<Location>, Option<User>, ProbeDisplay)>
}
