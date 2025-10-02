use crate::error::WebError;
use edumdns_core::bincode_types::MacAddr;
use edumdns_db::repositories::common::{Id, Pagination};
use edumdns_db::repositories::device::models::{CreateDevice, SelectManyDevices, UpdateDevice};
use edumdns_db::repositories::utilities::empty_string_is_none;
use edumdns_db::repositories::utilities::{generate_salt, hash_password};
use ipnetwork::IpNetwork;
use log::error;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize, Deserialize, Clone)]
pub struct DeviceQuery {
    pub page: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub probe_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub mac: Option<MacAddr>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ip: Option<IpNetwork>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub port: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub published: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub proxy: Option<bool>,
}

impl From<DeviceQuery> for SelectManyDevices {
    fn from(value: DeviceQuery) -> Self {
        Self {
            id: value.id,
            probe_id: value.probe_id,
            mac: value.mac.map(|addr| addr.to_octets()),
            ip: value.ip,
            port: value.port,
            name: value.name,
            published: value.published,
            proxy: value.proxy,
            pagination: Some(Pagination::default_pagination(value.page)),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct DeviceCustomPacketTransmitRequest {
    pub target_ip: IpNetwork,
    pub target_port: u16,
    #[serde(default)]
    pub permanent: bool,
}

impl DeviceCustomPacketTransmitRequest {
    pub fn new(target_ip: IpNetwork, target_port: u16, permanent: bool) -> Self {
        Self {
            target_ip,
            target_port,
            permanent,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct DevicePacketTransmitRequest {
    #[serde(default)]
    pub acl_pwd: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UpdateDeviceForm {
    pub id: Id,
    #[serde(default, deserialize_with = "empty_string_is_none")]
    pub name: Option<String>,
    pub mac: Option<MacAddr>,
    #[serde(default, deserialize_with = "empty_string_is_none")]
    pub ip: Option<IpNetwork>,
    #[serde(default, deserialize_with = "empty_string_is_none")]
    pub port: Option<i32>,
    #[serde(default, deserialize_with = "empty_string_is_none")]
    pub duration: Option<i64>,
    #[serde(default, deserialize_with = "empty_string_is_none")]
    pub interval: Option<i64>,
    #[serde(default, deserialize_with = "empty_string_is_none")]
    pub acl_src_cidr: Option<IpNetwork>,
    #[serde(default, deserialize_with = "empty_string_is_none")]
    pub acl_ap_hostname_regex: Option<String>,
    #[serde(default, deserialize_with = "empty_string_is_none")]
    pub acl_password: Option<String>,
    #[serde(default)]
    pub published: bool,
    #[serde(default)]
    pub proxy: bool,
}

impl UpdateDeviceForm {
    pub fn to_db_params(self) -> Result<UpdateDevice, WebError> {
        let (hash, salt) = match self.acl_password {
            None => (None, None),
            Some(password) => {
                let salt = generate_salt();
                let password_hash = hash_password(password, &salt)?;
                (Some(password_hash), Some(salt.to_string()))
            }
        };

        Ok(UpdateDevice {
            id: self.id,
            name: self.name,
            mac: self.mac.map(|mac| mac.to_octets()),
            ip: self.ip,
            port: self.port,
            duration: self.duration,
            interval: self.interval,
            published: None,
            acl_src_cidr: self.acl_src_cidr,
            acl_ap_hostname_regex: self.acl_ap_hostname_regex,
            acl_pwd_hash: hash,
            acl_pwd_salt: salt,
            proxy: Some(self.proxy),
        })
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CreateDeviceForm {
    pub name: String,
    pub probe_id: Uuid,
    pub mac: MacAddr,
    pub ip: IpNetwork,
    pub port: i32,
}

impl From<CreateDeviceForm> for CreateDevice {
    fn from(value: CreateDeviceForm) -> Self {
        Self {
            probe_id: value.probe_id,
            mac: value.mac.to_octets(),
            ip: value.ip,
            port: value.port,
            name: Some(value.name),
        }
    }
}