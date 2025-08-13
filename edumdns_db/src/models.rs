use std::fmt::{Display, Formatter};
use crate::repositories::common::Id;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, PrimitiveDateTime, UtcDateTime};
use uuid::Uuid;

#[derive(Serialize, Deserialize, Queryable, Selectable)]
#[diesel(table_name = crate::schema::group)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Group {
    pub id: Id,
    pub name: String,
}

#[derive(Serialize, Deserialize, Queryable, Selectable)]
#[diesel(table_name = crate::schema::location)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Location {
    pub id: Id,
    pub name: String,
}

#[derive(Serialize, Deserialize, Queryable, Selectable)]
#[diesel(table_name = crate::schema::probe)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Probe {
    pub id: Uuid,
    pub owner_id: Option<Id>,
    pub location_id: Option<Id>,
    pub adopted: bool,
    pub mac: [u8; 6],
    pub ip: ipnetwork::IpNetwork,
}

#[derive(Serialize, Deserialize, Queryable, Selectable)]
#[diesel(table_name = crate::schema::probe_config)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct ProbeConfig {
    pub probe_id: Uuid,
    pub interface: String,
    pub filter: Option<String>,
}

#[derive(Serialize, Deserialize, Queryable, Selectable)]
#[diesel(table_name = crate::schema::device)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Device {
    pub id: Id,
    pub probe_id: Uuid,
    pub mac: [u8; 6],
    pub ip: ipnetwork::IpNetwork,
    pub port: i32,
    pub duration: Option<i64>,
    pub interval: Option<i64>,
}

#[derive(Serialize, Deserialize, Queryable, Selectable)]
#[diesel(table_name = crate::schema::packet)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Packet {
    pub probe_id: Uuid,
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub src_addr: ipnetwork::IpNetwork,
    pub dst_addr: ipnetwork::IpNetwork,
    pub src_port: i32,
    pub dst_port: i32,
    pub payload: Vec<u8>,
}

#[derive(Serialize, Deserialize, Queryable, Selectable)]
#[diesel(table_name = crate::schema::user)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct User {
    pub id: Id,
    pub email: String,
    pub name: String,
    pub surname: String,
    pub password_hash: String,
    pub password_salt: String,
    pub admin: bool,
    pub created_at: OffsetDateTime,
    pub edited_at: OffsetDateTime,
    pub deleted_at: Option<OffsetDateTime>,
}

impl Display for Device {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Device <ID: {}, MAC: {:?}, IP: {}", self.id, self.mac, self.ip)
    }
}