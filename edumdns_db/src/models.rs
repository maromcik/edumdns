use crate::repositories::common::{Id, Permission};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(
    Serialize, Deserialize, Queryable, Selectable, Identifiable, Eq, PartialEq, Hash, Debug,
)]
#[diesel(table_name = crate::schema::group)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Group {
    pub id: Id,
    pub name: String,
    pub description: Option<String>,
}

#[derive(Serialize, Deserialize, Queryable, Selectable, Associations)]
#[diesel(table_name = crate::schema::group_user)]
#[diesel(belongs_to(Group))]
#[diesel(belongs_to(User))]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct GroupUser {
    pub group_id: Id,
    pub user_id: Id,
}

#[derive(
    Serialize, Deserialize, Queryable, Selectable, Identifiable, Eq, PartialEq, Hash, Debug,
)]
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

#[derive(
    Queryable, Selectable, Associations, Serialize, Deserialize, Eq, PartialEq, Hash, Debug,
)]
#[diesel(table_name = crate::schema::group_probe_permission)]
#[diesel(belongs_to(Probe))]
#[diesel(belongs_to(Group))]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct GroupProbePermission {
    pub group_id: Id,
    pub probe_id: Uuid,
    pub permission: Permission,
}

impl GroupProbePermission {
    pub fn full() -> Self {
        Self {
            group_id: 0,
            probe_id: Uuid::nil(),
            permission: Permission::Full,
        }
    }

    pub fn empty(permission: Permission) -> Self {
        Self {
            group_id: 0,
            probe_id: Uuid::nil(),
            permission,
        }
    }

    pub fn create_web() -> Vec<Self> {
        vec![
            Self::empty(Permission::Read),
            Self::empty(Permission::Update),
            Self::empty(Permission::Delete),
            Self::empty(Permission::Create),
        ]
    }
}

#[derive(
    Serialize, Deserialize, Queryable, Selectable, Identifiable, Eq, PartialEq, Hash, Debug,
)]
#[diesel(table_name = crate::schema::probe)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Probe {
    pub id: Uuid,
    pub owner_id: Option<Id>,
    pub location_id: Option<Id>,
    pub adopted: bool,
    pub mac: [u8; 6],
    pub ip: ipnetwork::IpNetwork,
    pub name: Option<String>,
    pub pre_shared_key: Option<String>,
    pub first_connected_at: Option<OffsetDateTime>,
    pub last_connected_at: Option<OffsetDateTime>,
}

#[derive(Serialize, Deserialize, Queryable, Selectable, Associations)]
#[diesel(belongs_to(Probe))]
#[diesel(table_name = crate::schema::probe_config)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct ProbeConfig {
    pub id: Id,
    pub probe_id: Uuid,
    pub interface: String,
    pub filter: Option<String>,
}

#[derive(
    Serialize,
    Deserialize,
    Queryable,
    Selectable,
    Identifiable,
    Associations,
    Hash,
    Eq,
    PartialEq,
    Debug,
)]
#[diesel(table_name = crate::schema::device)]
#[diesel(belongs_to(Probe))]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Device {
    pub id: Id,
    pub probe_id: Uuid,
    pub mac: [u8; 6],
    pub ip: ipnetwork::IpNetwork,
    pub port: i32,
    pub name: Option<String>,
    pub duration: i64,
    pub interval: i64,
    pub published: bool,
    pub proxy: bool,
    pub acl_src_cidr: Option<ipnetwork::IpNetwork>,
    pub acl_pwd_hash: Option<String>,
    pub acl_pwd_salt: Option<String>,
    pub acl_ap_hostname_regex: Option<String>,
    pub discovered_at: Option<OffsetDateTime>,
}

#[derive(
    Serialize,
    Deserialize,
    Queryable,
    Selectable,
    Identifiable,
    Associations,
    Debug,
    Eq,
    PartialEq,
    Hash,
)]
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
    pub payload_hash: String,
    pub captured_at: Option<OffsetDateTime>,
}

#[derive(
    Serialize, Deserialize, Queryable, Selectable, Associations, AsChangeset, Insertable, Debug,
)]
#[diesel(table_name = crate::schema::packet_transmit_request)]
#[diesel(check_for_backend(diesel::pg::Pg))]
#[diesel(belongs_to(Device))]
pub struct PacketTransmitRequest {
    pub id: Id,
    pub device_id: Id,
    pub user_id: Id,
    pub target_ip: ipnetwork::IpNetwork,
    pub target_port: i32,
    pub permanent: bool,
}

#[derive(
    Serialize, Deserialize, Queryable, Selectable, Identifiable, AsChangeset, Clone, Debug,
)]
#[diesel(table_name = crate::schema::user)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct User {
    pub id: Id,
    pub email: String,
    pub name: String,
    pub surname: String,
    pub password_hash: Option<String>,
    pub password_salt: Option<String>,
    pub admin: bool,
    pub disabled: bool,
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
