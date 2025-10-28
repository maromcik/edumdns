use edumdns_core::bincode_types::MacAddr;
use edumdns_core::app_packet::Id;
use edumdns_db::repositories::common::{Pagination, Permission};
use edumdns_db::repositories::probe::models::{SelectManyProbes, UpdateProbe};
use edumdns_db::repositories::utilities::empty_string_is_none;
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeQuery {
    pub page: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub owner_id: Option<Id>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub location_id: Option<Id>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub adopted: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub mac: Option<MacAddr>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ip: Option<IpNetwork>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub name: Option<String>,
}

impl From<ProbeQuery> for SelectManyProbes {
    fn from(value: ProbeQuery) -> Self {
        Self::new(
            value.id,
            value.owner_id,
            value.location_id,
            value.adopted,
            value.mac.map(|addr| addr.to_octets()),
            value.ip,
            value.name,
            Some(Pagination::default_pagination(value.page)),
        )
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ProbeConfigForm {
    pub interface: String,
    #[serde(default)]
    pub filter: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ProbePermissionForm {
    pub group_id: Id,
    pub permission: Permission,
    #[serde(default)]
    pub value: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CreateProbeForm {
    pub name: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UpdateProbeForm {
    pub id: Uuid,
    #[serde(default, deserialize_with = "empty_string_is_none")]
    pub name: Option<String>,
    #[serde(default, deserialize_with = "empty_string_is_none")]
    pub pre_shared_key: Option<String>,
}

impl From<UpdateProbeForm> for UpdateProbe {
    fn from(value: UpdateProbeForm) -> Self {
        Self {
            id: value.id,
            name: value.name,
            pre_shared_key: value.pre_shared_key,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UpdateProbeOwnerForm {
    pub id: Uuid,
    #[serde(default, deserialize_with = "empty_string_is_none")]
    pub owner_id: Option<Id>,
}
