use crate::forms::device::DeviceQuery;
use crate::forms::packet::PacketQuery;
use crate::templates::PageInfo;
use edumdns_db::models::{PacketTransmitRequest, Probe, User};
use edumdns_db::repositories::common::Permissions;
use edumdns_db::repositories::device::models::DeviceDisplay;
use edumdns_db::repositories::packet::models::PacketDisplay;
use serde::Serialize;
use uuid::Uuid;
use edumdns_db::repositories::user::models::UserDisplay;

#[derive(Serialize)]
pub struct DeviceTemplate {
    pub user: UserDisplay,
    pub permissions: Permissions,
    pub devices: Vec<(Probe, DeviceDisplay)>,
    pub page_info: PageInfo,
    pub filters: DeviceQuery,
    pub query_string: String,
}

#[derive(Serialize)]
pub struct DeviceDetailTemplate {
    pub user: UserDisplay,
    pub permissions: Permissions,
    pub device: DeviceDisplay,
    pub packets: Vec<PacketDisplay>,
    pub packet_transmit_requests: Vec<PacketTransmitRequest>,
    pub page_info: PageInfo,
    pub filters: PacketQuery,
    pub query_string: String,
}

#[derive(Serialize)]
pub struct DeviceTransmitTemplate {
    pub user: UserDisplay,
    pub device: DeviceDisplay,
    pub client_ip: String,
    pub packet_transmit_requests: Vec<PacketTransmitRequest>,
}

#[derive(Serialize)]
pub struct DeviceCreateTemplate {
    pub probe_id: Uuid
}