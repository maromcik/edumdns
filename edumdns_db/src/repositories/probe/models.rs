use crate::models::Probe;
use crate::repositories::common::{Pagination, Permission};
use crate::repositories::utilities::{empty_string_is_none, format_time};
use diesel::{AsChangeset, Identifiable, Insertable};
use edumdns_core::app_packet::Id;
use edumdns_core::bincode_types::MacAddr;
use ipnetwork::{IpNetwork, Ipv4Network};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use uuid::{Timestamp, Uuid};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectManyProbes {
    pub id: Option<Uuid>,
    pub owner_id: Option<Id>,
    pub location_id: Option<Id>,
    pub adopted: Option<bool>,
    pub mac: Option<[u8; 6]>,
    pub ip: Option<IpNetwork>,
    pub name: Option<String>,
    pub pagination: Option<Pagination>,
}

impl SelectManyProbes {
    pub fn new(
        id: Option<Uuid>,
        owner_id: Option<Id>,
        location_id: Option<Id>,
        adopted: Option<bool>,
        mac: Option<[u8; 6]>,
        ip: Option<IpNetwork>,
        name: Option<String>,
        pagination: Option<Pagination>,
    ) -> Self {
        Self {
            id,
            owner_id,
            location_id,
            adopted,
            mac,
            ip,
            name,
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
    pub name: Option<String>,
    pub pre_shared_key: Option<String>,
    pub owner_id: Option<Id>,
}

impl CreateProbe {
    pub fn new_connect(
        id: edumdns_core::bincode_types::Uuid,
        mac: edumdns_core::bincode_types::MacAddr,
        ip: IpNetwork,
    ) -> Self {
        Self {
            id: id.0,
            mac: mac.0.octets(),
            ip,
            name: None,
            pre_shared_key: None,
            owner_id: None,
        }
    }

    pub fn new_web(name: &str, owner: &Id) -> CreateProbe {
        let ts = Timestamp::now(uuid::NoContext);
        let uuid = uuid::Uuid::new_v7(ts);
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let hex_string = hex::encode(bytes);
        Self {
            id: uuid,
            mac: MacAddr::default().to_octets(),
            ip: IpNetwork::V4(
                Ipv4Network::from_str("0.0.0.0/0").expect("Parsing hardcoded IP should not fail"),
            ),
            name: Some(name.to_string()),
            pre_shared_key: Some(hex_string),
            owner_id: Some(*owner),
        }
    }
}

#[derive(Serialize)]
pub struct ProbeDisplay {
    pub id: Uuid,
    pub owner_id: Option<Id>,
    pub location_id: Option<Id>,
    pub adopted: bool,
    pub mac: MacAddr,
    pub ip: IpNetwork,
    pub name: Option<String>,
    pub pre_shared_key: Option<String>,
    pub first_connected_at: Option<String>,
    pub last_connected_at: Option<String>,
}

impl From<Probe> for ProbeDisplay {
    fn from(value: Probe) -> Self {
        Self {
            id: value.id,
            owner_id: value.owner_id,
            location_id: value.location_id,
            adopted: value.adopted,
            mac: MacAddr::from_octets(value.mac),
            ip: value.ip,
            name: value.name,
            pre_shared_key: value.pre_shared_key,
            first_connected_at: value.first_connected_at.map(format_time),
            last_connected_at: value.last_connected_at.map(format_time),
        }
    }
}

pub struct SelectSingleProbeConfig {
    pub user_id: Id,
    pub id: Id,
    pub probe_id: Uuid,
}

impl SelectSingleProbeConfig {
    pub fn new(user_id: Id, id: Id, probe_id: Uuid) -> Self {
        Self {
            user_id,
            id,
            probe_id,
        }
    }
}

#[derive(Serialize, Deserialize, AsChangeset, Insertable)]
#[diesel(table_name = crate::schema::probe_config)]
pub struct CreateProbeConfig {
    pub probe_id: Uuid,
    pub interface: String,
    pub filter: Option<String>,
}

impl CreateProbeConfig {
    pub fn new(probe_id: Uuid, interface: String, filter: Option<String>) -> Self {
        Self {
            probe_id,
            interface,
            filter,
        }
    }
}

pub struct AlterProbePermission {
    pub user_id: Id,
    pub probe_id: Uuid,
    pub group_id: Id,
    pub permission: Permission,
    pub state: bool,
}

impl AlterProbePermission {
    pub fn new(
        user_id: Id,
        probe_id: Uuid,
        group_id: Id,
        permission: Permission,
        state: bool,
    ) -> Self {
        Self {
            user_id,
            probe_id,
            group_id,
            permission,
            state,
        }
    }
}

#[derive(Serialize, Deserialize, AsChangeset, Insertable)]
#[diesel(table_name = crate::schema::group_probe_permission)]
pub struct CreateGroupProbePermission {
    pub probe_id: Uuid,
    pub group_id: Id,
    pub permission: Permission,
}

impl CreateGroupProbePermission {
    pub fn new(probe_id: Uuid, group_id: Id, permission: Permission) -> Self {
        Self {
            probe_id,
            group_id,
            permission,
        }
    }
}

impl From<AlterProbePermission> for CreateGroupProbePermission {
    fn from(value: AlterProbePermission) -> Self {
        Self {
            probe_id: value.probe_id,
            group_id: value.group_id,
            permission: value.permission,
        }
    }
}
#[derive(Serialize, Deserialize, AsChangeset, Identifiable, Debug)]
#[diesel(table_name = crate::schema::probe)]
pub struct UpdateProbe {
    pub id: Uuid,
    #[serde(default, deserialize_with = "empty_string_is_none")]
    #[diesel(treat_none_as_null = true)]
    pub name: Option<String>,
    #[serde(default, deserialize_with = "empty_string_is_none")]
    #[diesel(treat_none_as_null = true)]
    pub pre_shared_key: Option<String>,
}
