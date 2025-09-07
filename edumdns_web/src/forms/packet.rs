use edumdns_core::bincode_types::MacAddr;
use edumdns_db::repositories::common::Pagination;
use edumdns_db::repositories::packet::models::SelectManyPackets;
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PacketQuery {
    pub page: Option<i64>,
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
