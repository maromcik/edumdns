use crate::repositories::common::{Id, Pagination};
use diesel::{AsChangeset, Insertable};
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use edumdns_core::bincode_types::MacAddr;
use edumdns_core::error::CoreError;
use edumdns_core::network_packet::ApplicationPacket;
use crate::models::Packet;

#[derive(Serialize, Deserialize)]
pub struct SelectManyPackets {
    pub probe_id: Option<Uuid>,
    pub src_mac: Option<[u8; 6]>,
    pub dst_mac: Option<[u8; 6]>,
    pub src_addr: Option<IpNetwork>,
    pub dst_addr: Option<IpNetwork>,
    pub src_port: Option<i32>,
    pub dst_port: Option<i32>,
    pub pagination: Option<Pagination>,
}

impl SelectManyPackets {
    pub fn new(
        probe_id: Option<Uuid>,
        src_mac: Option<[u8; 6]>,
        dst_mac: Option<[u8; 6]>,
        src_addr: Option<IpNetwork>,
        dst_addr: Option<IpNetwork>,
        src_port: Option<i32>,
        dst_port: Option<i32>,
        pagination: Option<Pagination>,
    ) -> Self {
        Self {
            probe_id,
            src_mac,
            dst_mac,
            src_addr,
            dst_addr,
            src_port,
            dst_port,
            pagination,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct SelectSingleFilter {
    pub probe_id: Uuid,
    pub src_mac: [u8; 6],
    pub src_addr: IpNetwork,
}

impl SelectSingleFilter {
    pub fn new(
        probe_id: Uuid,
        src_mac: [u8; 6],
        src_addr: IpNetwork,

    ) -> Self {
        Self {
            probe_id,
            src_mac,
            src_addr,
        }
    }
}

#[derive(Serialize, Deserialize, AsChangeset, Insertable)]
#[diesel(table_name = crate::schema::packet)]
pub struct CreatePacket {
    pub probe_id: Uuid,
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub src_addr: IpNetwork,
    pub dst_addr: IpNetwork,
    pub src_port: i32,
    pub dst_port: i32,
    pub payload: Vec<u8>,
}

impl CreatePacket {
    pub fn new(
        probe_id: Uuid,
        src_mac: [u8; 6],
        dst_mac: [u8; 6],
        src_addr: IpNetwork,
        dst_addr: IpNetwork,
        src_port: u16,
        dst_port: u16,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            probe_id,
            src_mac,
            dst_mac,
            src_addr,
            dst_addr,
            src_port: src_port as i32,
            dst_port: dst_port as i32,
            payload,
        }
    }
}


#[derive(Serialize)]
pub struct PacketDisplay {
    pub id: Id,
    pub probe_id: Uuid,
    pub src_mac: MacAddr,
    pub dst_mac: MacAddr,
    pub src_addr: IpNetwork,
    pub dst_addr: IpNetwork,
    pub src_port: i32,
    pub dst_port: i32,
    pub payload: Vec<String>,
}

impl PacketDisplay {
    pub fn from(value: Packet) -> Result<PacketDisplay, CoreError> {
        let payload = ApplicationPacket::from_bytes(&value.payload)?;

        Ok(Self {
            id: value.id,
            probe_id: value.probe_id,
            src_mac: MacAddr::from_octets(value.src_mac),
            dst_mac: MacAddr::from_octets(value.dst_mac),
            src_addr: value.src_addr,
            dst_addr: value.dst_addr,
            src_port: value.src_port,
            dst_port: value.dst_port,
            payload: payload.read_content(),
        })
    }
}