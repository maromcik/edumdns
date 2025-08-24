use edumdns_db::models::{Probe};
use serde::Serialize;
use crate::models::display::DeviceDisplay;

#[derive(Serialize)]
pub struct DeviceTemplate {
    pub logged_in: bool,
    pub devices: Vec<(Option<Probe>, DeviceDisplay)>
}
