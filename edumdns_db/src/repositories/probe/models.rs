use crate::repositories::common::{Id, Pagination};
use diesel::{AsChangeset, Insertable, Queryable, Selectable};
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
pub struct SelectManyFilter {
    pub owner_id: Option<Id>,
    pub location_id: Option<Id>,
    pub adopted: Option<bool>,
    pub mac: Option<[u8; 6]>,
    pub ip: Option<IpNetwork>,
    pub port: Option<i32>,
    pub vlan: Option<i32>,
    pub pagination: Option<Pagination>,
}

impl SelectManyFilter {
    pub fn new(
        owner_id: Option<Id>,
        location_id: Option<Id>,
        adopted: Option<bool>,
        mac: Option<[u8; 6]>,
        ip: Option<IpNetwork>,
        port: Option<i32>,
        vlan: Option<i32>,
        pagination: Option<Pagination>,
    ) -> Self {
        Self {
            owner_id,
            location_id,
            adopted,
            mac,
            ip,
            port,
            vlan,
            pagination,
        }
    }
}

#[derive(Serialize, Deserialize, AsChangeset, Insertable)]
#[diesel(table_name = crate::schema::probe)]
pub struct CreateProbe {
    pub id: Uuid,
    pub mac: [u8; 6],
    pub ip: IpNetwork,
    pub port: i32,
}

impl CreateProbe {
    pub fn new(id: Uuid, mac: [u8; 6], ip: IpNetwork, port: i32) -> Self {
        Self {
            id,
            mac,
            ip,
            port,
        }
    }
}
