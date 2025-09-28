use edumdns_core::bincode_types::MacAddr;
use edumdns_db::repositories::common::{Id, Pagination};
use edumdns_db::repositories::packet::models::{CreatePacket, SelectManyPackets};
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PacketQuery {
    pub page: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub id: Option<Id>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub probe_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub src_mac: Option<MacAddr>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub dst_mac: Option<MacAddr>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub src_addr: Option<IpNetwork>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub dst_addr: Option<IpNetwork>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub src_port: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub dst_port: Option<i32>,
}

impl From<PacketQuery> for SelectManyPackets {
    fn from(value: PacketQuery) -> Self {
        Self {
            id: value.id,
            probe_id: value.probe_id,
            src_mac: value.src_mac.map(|addr| addr.to_octets()),
            dst_mac: value.dst_mac.map(|addr| addr.to_octets()),
            src_addr: value.src_addr,
            dst_addr: value.dst_addr,
            src_port: value.src_port,
            dst_port: value.dst_port,
            pagination: Some(Pagination::default_pagination(value.page)),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PacketDeviceDataForm {
    pub probe_id: Uuid,
    pub mac: MacAddr,
    pub ip: IpNetwork,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CreatePacketForm {
    pub probe_id: Uuid,
    pub src_mac: MacAddr,
    pub dst_mac: MacAddr,
    pub src_addr: IpNetwork,
    pub dst_addr: IpNetwork,
    pub src_port: i32,
    pub dst_port: i32,
    pub payload: Vec<u8>,
    pub payload_hash: String,
}
impl From<CreatePacketForm> for CreatePacket {
    fn from(value: CreatePacketForm) -> Self {
        Self {
            probe_id: value.probe_id,
            src_mac: value.src_mac.to_octets(),
            dst_mac: value.dst_mac.to_octets(),
            src_addr: value.src_addr,
            dst_addr: value.dst_addr,
            src_port: value.src_port,
            dst_port: value.dst_port,
            payload: value.payload,
            payload_hash: value.payload_hash,
        }
    }
}