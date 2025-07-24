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
    pub pagination: Option<Pagination>,
}

impl SelectManyFilter {
    pub fn new(
        owner_id: Option<Id>,
        location_id: Option<Id>,
        adopted: Option<bool>,
        mac: Option<[u8; 6]>,
        ip: Option<IpNetwork>,
        pagination: Option<Pagination>,
    ) -> Self {
        Self {
            owner_id,
            location_id,
            adopted,
            mac,
            ip,
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
}

impl CreateProbe {
    pub fn new(id: edumdns_core::bincode_types::Uuid, mac: edumdns_core::bincode_types::MacAddr, ip: IpNetwork) -> Self {
        Self {
            id: id.0,
            mac: mac.0.octets(),
            ip }
    }
}
