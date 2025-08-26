use crate::repositories::common::Id;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Queryable, Selectable, Identifiable)]
#[diesel(table_name = crate::schema::group)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Group {
    pub id: Id,
    pub name: String,
    pub description: Option<String>,
}

#[derive(Serialize, Deserialize, Queryable, Selectable, Identifiable)]
#[diesel(table_name = crate::schema::location)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Location {
    pub id: Id,
    pub name: String,
    pub building: Option<String>,
    pub floor: Option<i32>,
    pub room: Option<i32>,
    pub address: Option<String>,
    pub city: Option<String>,
    pub description: Option<String>,
}

#[derive(Serialize, Deserialize, Queryable, Selectable, Identifiable)]
#[diesel(table_name = crate::schema::permission)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Permission {
    pub id: Id,
    pub name: String,
    pub description: Option<String>,
}

#[derive(Queryable, Selectable, Associations, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::group_probe_permission)]
#[diesel(belongs_to(Probe))]
#[diesel(belongs_to(Group))]
#[diesel(belongs_to(Permission))]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct GroupProbePermission {
    pub group_id: Id,
    pub probe_id: Uuid,
    pub permission_id: Id,
}

#[derive(Serialize, Deserialize, Queryable, Selectable, Identifiable)]
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

#[derive(Serialize, Deserialize, Queryable, Selectable, Associations)]
#[diesel(belongs_to(Probe))]
#[diesel(table_name = crate::schema::probe_config)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct ProbeConfig {
    pub probe_id: Uuid,
    pub interface: String,
    pub filter: Option<String>,
}

#[derive(Serialize, Deserialize, Queryable, Selectable, Identifiable, Associations)]
#[diesel(table_name = crate::schema::device)]
#[diesel(belongs_to(Probe))]
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

#[derive(Serialize, Deserialize, Queryable, Selectable, Identifiable, Associations)]
#[diesel(table_name = crate::schema::packet)]
#[diesel(belongs_to(Probe))]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Packet {
    pub id: Id,
    pub probe_id: Uuid,
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub src_addr: ipnetwork::IpNetwork,
    pub dst_addr: ipnetwork::IpNetwork,
    pub src_port: i32,
    pub dst_port: i32,
    pub payload: Vec<u8>,
}

#[derive(Serialize, Deserialize, Queryable, Selectable, Associations)]
#[diesel(table_name = crate::schema::packet_transmit_request)]
#[diesel(check_for_backend(diesel::pg::Pg))]
#[diesel(belongs_to(Probe))]
pub struct PacketTransmitRequest {
    pub probe_id: Uuid,
    pub device_mac: [u8; 6],
    pub device_ip: ipnetwork::IpNetwork,
    pub target_ip: ipnetwork::IpNetwork,
    pub target_port: i32,
}

#[derive(Serialize, Deserialize, Queryable, Selectable, Identifiable)]
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
        write!(
            f,
            "Device <ID: {}, MAC: {:?}, IP: {}",
            self.id, self.mac, self.ip
        )
    }
}
