use crate::models::Device;
use crate::repositories::common::{Id, Pagination};
use diesel::{AsChangeset, Identifiable, Insertable};
use edumdns_core::bincode_types::MacAddr;
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, format_description};
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
pub struct SelectManyDevices {
    pub id: Option<Id>,
    pub probe_id: Option<Uuid>,
    pub mac: Option<[u8; 6]>,
    pub ip: Option<IpNetwork>,
    pub port: Option<i32>,
    pub name: Option<String>,
    pub published: Option<bool>,
    pub proxy: Option<bool>,
    pub pagination: Option<Pagination>,
}

impl SelectManyDevices {
    pub fn new(
        id: Option<Id>,
        probe_id: Option<Uuid>,
        mac: Option<[u8; 6]>,
        ip: Option<IpNetwork>,
        port: Option<i32>,
        name: Option<&String>,
        published: Option<bool>,
        proxy: Option<bool>,
        pagination: Option<Pagination>,
    ) -> Self {
        Self {
            id,
            probe_id,
            mac,
            ip,
            port,
            name: name.map(|s| s.to_string()),
            published,
            proxy,
            pagination,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct SelectSingleDevice {
    pub probe_id: Uuid,
    pub mac: [u8; 6],
    pub ip: IpNetwork,
}

impl SelectSingleDevice {
    pub fn new(probe_id: Uuid, mac: [u8; 6], ip: IpNetwork) -> Self {
        Self { probe_id, mac, ip }
    }
}

#[derive(Serialize, Deserialize, AsChangeset, Insertable)]
#[diesel(table_name = crate::schema::device)]
pub struct CreateDevice {
    pub probe_id: Uuid,
    pub mac: [u8; 6],
    pub ip: IpNetwork,
    pub port: i32,
    pub name: Option<String>,
}

impl CreateDevice {
    pub fn new(probe_id: Uuid, mac: [u8; 6], ip: IpNetwork, port: u16, name: Option<&String>) -> Self {
        Self {
            probe_id,
            mac,
            ip,
            port: port as i32,
            name: name.map(|s| s.to_string()),
        }
    }
    pub fn new_discover(probe_id: Uuid, mac: [u8; 6], ip: IpNetwork, port: u16) -> Self {
        Self {
            probe_id,
            mac,
            ip,
            port: port as i32,
            name: None,
        }
    }
}

#[derive(Serialize)]
pub struct DeviceDisplay {
    pub id: Id,
    pub probe_id: Uuid,
    pub mac: MacAddr,
    pub ip: IpNetwork,
    pub port: i32,
    pub name: Option<String>,
    pub duration: i64,
    pub interval: i64,
    pub published: bool,
    pub proxy: bool,
    pub acl_src_cidr: Option<IpNetwork>,
    pub acl_pwd_hash: Option<String>,
    pub acl_ap_hostname_regex: Option<String>,
    pub discovered_at: Option<String>,
}

impl From<Device> for DeviceDisplay {
    fn from(value: Device) -> Self {
        let format = format_description::parse("[day]. [month]. [year] [hour]:[minute]:[second]")
            .unwrap_or_default();
        Self {
            id: value.id,
            probe_id: value.probe_id,
            mac: MacAddr::from_octets(value.mac),
            ip: value.ip,
            port: value.port,
            name: value.name,
            duration: value.duration,
            interval: value.interval,
            published: value.published,
            proxy: value.proxy,
            acl_src_cidr: value.acl_src_cidr,
            acl_pwd_hash: value.acl_pwd_hash,
            acl_ap_hostname_regex: value.acl_ap_hostname_regex,
            discovered_at: value
                .discovered_at
                .map(|t| t.format(&format).unwrap_or_default()),
        }
    }
}

#[derive(Serialize, Deserialize, AsChangeset, Insertable, Debug)]
#[diesel(table_name = crate::schema::packet_transmit_request)]
pub struct CreatePacketTransmitRequest {
    pub device_id: Id,
    pub target_ip: IpNetwork,
    pub target_port: i32,
    pub permanent: bool,
}

#[derive(Serialize, Deserialize, AsChangeset, Identifiable, Debug)]
#[diesel(table_name = crate::schema::device)]
pub struct UpdateDevice {
    pub id: Id,
    #[diesel(treat_none_as_null = true)]
    pub name: Option<String>,
    pub mac: Option<[u8; 6]>,
    pub ip: Option<IpNetwork>,
    pub port: Option<i32>,
    pub duration: Option<i64>,
    pub interval: Option<i64>,
    pub published: Option<bool>,
    pub proxy: Option<bool>,
    #[diesel(treat_none_as_null = true)]
    pub acl_src_cidr: Option<IpNetwork>,
    #[diesel(treat_none_as_null = true)]
    pub acl_pwd_hash: Option<String>,
    #[diesel(treat_none_as_null = true)]
    pub acl_pwd_salt: Option<String>,
    #[diesel(treat_none_as_null = true)]
    pub acl_ap_hostname_regex: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DeviceUpdatePassword {
    pub id: Id,
    pub new_password: String,
}
