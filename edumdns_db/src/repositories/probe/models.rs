use crate::models::Probe;
use crate::repositories::common::{Id, Pagination, Permission};
use diesel::{AsChangeset, Identifiable, Insertable};
use edumdns_core::bincode_types::MacAddr;
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectManyProbes {
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
        owner_id: Option<Id>,
        location_id: Option<Id>,
        adopted: Option<bool>,
        mac: Option<[u8; 6]>,
        ip: Option<IpNetwork>,
        name: Option<String>,
        pagination: Option<Pagination>,
    ) -> Self {
        Self {
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
}

impl CreateProbe {
    pub fn new(
        id: edumdns_core::bincode_types::Uuid,
        mac: edumdns_core::bincode_types::MacAddr,
        ip: IpNetwork,
    ) -> Self {
        Self {
            id: id.0,
            mac: mac.0.octets(),
            ip,
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
    pub name: Option<String>,
    pub location_id: Option<Id>,
}
