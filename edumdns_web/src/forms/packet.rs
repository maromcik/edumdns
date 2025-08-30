use edumdns_core::bincode_types::MacAddr;
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PacketQuery {
    pub page: Option<i64>,
    pub probe_id: Option<Uuid>,
    pub src_mac: Option<MacAddr>,
    pub dst_mac: Option<MacAddr>,
    pub src_addr: Option<IpNetwork>,
    pub dst_addr: Option<IpNetwork>,
    pub src_port: Option<i32>,
    pub dst_port: Option<i32>,
}
