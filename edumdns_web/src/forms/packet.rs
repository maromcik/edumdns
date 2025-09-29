use hickory_proto::op::Message;
use hickory_proto::rr::RecordType;
use edumdns_core::bincode_types::MacAddr;
use edumdns_db::repositories::common::{Id, Pagination};
use edumdns_db::repositories::packet::models::{CreatePacket, SelectManyPackets};
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::error::WebError;

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

pub enum DnsRecordType {
    A,
    AAAA
}

pub struct DnsRecord {
    pub record_type: RecordType,

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
    pub message: Message
}
impl CreatePacketForm {
    pub fn to_db_params(self) -> Result<CreatePacket, WebError> {
        let payload = self.message.to_vec()?;
        let payload_hash = edumdns_core::app_packet::calculate_hash(&payload);
        Ok(CreatePacket {
            probe_id: self.probe_id,
            src_mac: self.src_mac.to_octets(),
            dst_mac: self.dst_mac.to_octets(),
            src_addr: self.src_addr,
            dst_addr: self.dst_addr,
            src_port: self.src_port,
            dst_port: self.dst_port,
            payload,
            payload_hash,
        })
    }
}