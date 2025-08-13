use crate::repositories::common::Pagination;
use diesel::{AsChangeset, Insertable};
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
pub struct SelectManyFilter {
    pub probe_id: Option<Uuid>,
    pub mac: Option<[u8; 6]>,
    pub ip: Option<IpNetwork>,
    pub port: Option<i32>,
    pub pagination: Option<Pagination>,
}

impl SelectManyFilter {
    pub fn new(
        probe_id: Option<Uuid>,
        mac: Option<[u8; 6]>,
        ip: Option<IpNetwork>,
        port: Option<i32>,
        pagination: Option<Pagination>,
    ) -> Self {
        Self {
            probe_id,
            mac,
            ip,
            port,
            pagination,
        }
    }
}

#[derive(Serialize, Deserialize, AsChangeset, Insertable)]
#[diesel(table_name = crate::schema::device)]
pub struct CreateDevice {
    pub probe_id: Uuid,
    pub mac: [u8; 6],
    pub ip: IpNetwork,
    pub port: i32,
}

impl CreateDevice {
    pub fn new(probe_id: Uuid, mac: [u8; 6], ip: IpNetwork, port: u16) -> Self {
        Self {
            probe_id,
            mac,
            ip,
            port: port as i32,
        }
    }
}
