use crate::repositories::common::{Id, Pagination};
use diesel::{AsChangeset, Insertable};
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
pub struct SelectManyFilter {
    pub probe_id: Option<Uuid>,
    pub src_mac: Option<[u8; 6]>,
    pub dst_mac: Option<[u8; 6]>,
    pub src_addr: Option<IpNetwork>,
    pub dst_addr: Option<IpNetwork>,
    pub src_port: Option<i32>,
    pub dst_port: Option<i32>,
    pub pagination: Option<Pagination>,
}

impl SelectManyFilter {
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
