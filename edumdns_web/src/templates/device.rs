use edumdns_db::models::{Probe};
use serde::Serialize;
use edumdns_db::repositories::device::models::DeviceDisplay;
use edumdns_db::repositories::packet::models::PacketDisplay;

#[derive(Serialize)]
pub struct DeviceTemplate {
    pub logged_in: bool,
    pub devices: Vec<(Option<Probe>, DeviceDisplay)>
}

#[derive(Serialize)]
pub struct DeviceDetailTemplate {
    pub logged_in: bool,
    pub device: DeviceDisplay,
    pub packets: Vec<PacketDisplay>
}