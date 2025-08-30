use crate::models::Device;
use crate::repositories::common::{Id, Pagination};
use diesel::{AsChangeset, Insertable};
use edumdns_core::bincode_types::MacAddr;
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
pub struct SelectManyDevices {
    pub user_id: Option<Id>,
    pub probe_id: Option<Uuid>,
    pub mac: Option<[u8; 6]>,
    pub ip: Option<IpNetwork>,
    pub port: Option<i32>,
    pub pagination: Option<Pagination>,
}

impl SelectManyDevices {
    pub fn new(
        probe_id: Option<Uuid>,
        mac: Option<[u8; 6]>,
        ip: Option<IpNetwork>,
        port: Option<i32>,
        pagination: Option<Pagination>,
    ) -> Self {
        Self {
            user_id: None,
            probe_id,
            mac,
            ip,
            port,
            pagination,
        }
    }

    pub fn new_with_user_id(
        user_id: Id,
        probe_id: Option<Uuid>,
        mac: Option<[u8; 6]>,
        ip: Option<IpNetwork>,
        port: Option<i32>,
        pagination: Option<Pagination>,
    ) -> Self {
        Self {
            user_id: Some(user_id),
            probe_id,
            mac,
            ip,
            port,
            pagination,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct SelectSingleDevice {
    pub user_id: Option<Id>,
    pub probe_id: Uuid,
    pub mac: [u8; 6],
    pub ip: IpNetwork,
}

impl SelectSingleDevice {
    pub fn new(probe_id: Uuid, mac: [u8; 6], ip: IpNetwork) -> Self {
        Self {
            user_id: None,
            probe_id,
            mac,
            ip,
        }
    }

    pub fn new_with_user_id(user_id: Id, probe_id: Uuid, mac: [u8; 6], ip: IpNetwork) -> Self {
        Self {
            user_id: Some(user_id),
            probe_id,
            mac,
            ip,
        }
    }
}

#[derive(Serialize, Deserialize, AsChangeset, Insertable)]
#[diesel(table_name = crate::schema::device)]
pub struct CreateDevice {
    pub probe_id: Uuid,
    pub mac: [u8; 6],
    pub ip: IpNetwork,
    pub port: i32,
}

impl CreateDevice {
    pub fn new(probe_id: Uuid, mac: [u8; 6], ip: IpNetwork, port: u16) -> Self {
        Self {
            probe_id,
            mac,
            ip,
            port: port as i32,
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
    pub duration: i64,
    pub interval: i64,
}

impl From<Device> for DeviceDisplay {
    fn from(value: Device) -> Self {
        Self {
            id: value.id,
            probe_id: value.probe_id,
            mac: MacAddr::from_octets(value.mac),
            ip: value.ip,
            port: value.port,
            duration: value.duration,
            interval: value.interval,
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
