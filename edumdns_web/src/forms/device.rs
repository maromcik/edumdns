use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use edumdns_core::bincode_types::MacAddr;

#[derive(Serialize, Deserialize)]
pub struct DeviceQuery {
    pub page: Option<i64>,
    pub probe_id: Option<Uuid>,
    pub mac: Option<MacAddr>,
    pub ip: Option<IpNetwork>,
    pub port: Option<i32>,
}

#[derive(Serialize, Deserialize)]
pub struct DevicePacketTransmitRequest {
    pub target_ip: String,
    pub target_port: u16,
    #[serde(default)]
    pub permanent: bool,
}
