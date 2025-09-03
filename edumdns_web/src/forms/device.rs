use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use edumdns_core::bincode_types::MacAddr;
use edumdns_db::repositories::common::Pagination;
use edumdns_db::repositories::device::models::SelectManyDevices;

#[derive(Serialize, Deserialize)]
pub struct DeviceQuery {
    pub page: Option<i64>,
    pub probe_id: Option<Uuid>,
    pub mac: Option<MacAddr>,
    pub ip: Option<IpNetwork>,
    pub port: Option<i32>,
    pub name: Option<String>,
}

impl From<DeviceQuery> for SelectManyDevices {
    fn from(value: DeviceQuery) -> Self {
        Self {
            probe_id: value.probe_id,
            mac: value.mac.map(|addr| addr.to_octets()),
            ip: value.ip,
            port: value.port,
            name: value.name,
            pagination: Some(Pagination::default_pagination(value.page)),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct DevicePacketTransmitRequest {
    pub target_ip: String,
    pub target_port: u16,
    #[serde(default)]
    pub permanent: bool,
}

impl DevicePacketTransmitRequest {
    pub fn new(target_ip: String, target_port: u16, permanent: bool) -> Self {
        Self {
            target_ip,
            target_port,
            permanent,
        }
    }
}
