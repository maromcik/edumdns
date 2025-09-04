use edumdns_db::models::{PacketTransmitRequest, Probe};
use edumdns_db::repositories::common::Permissions;
use edumdns_db::repositories::device::models::DeviceDisplay;
use edumdns_db::repositories::packet::models::PacketDisplay;
use serde::Serialize;
#[derive(Serialize)]
pub struct DeviceTemplate {
    pub logged_in: bool,
    pub is_admin: bool,
    pub permissions: Permissions,
    pub devices: Vec<(Probe, DeviceDisplay)>,
}

#[derive(Serialize)]
pub struct DeviceDetailTemplate {
    pub logged_in: bool,
    pub is_admin: bool,
    pub permissions: Permissions,
    pub device: DeviceDisplay,
    pub packets: Vec<PacketDisplay>,
    pub packet_transmit_requests: Vec<PacketTransmitRequest>,
}

#[derive(Serialize)]
pub struct DeviceTransmitTemplate {
    pub logged_in: bool,
    pub device: DeviceDisplay,
    pub client_ip: String,
    pub packet_transmit_requests: Vec<PacketTransmitRequest>,
}
