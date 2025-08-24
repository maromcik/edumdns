use serde::Serialize;
use uuid::Uuid;
use edumdns_core::bincode_types::MacAddr;
use edumdns_core::error::CoreError;
use edumdns_core::network_packet::ApplicationPacket;
use edumdns_db::models::{Device, Packet, Probe};
use edumdns_db::repositories::common::Id;

#[derive(Serialize)]
pub struct ProbeDisplay {
    pub id: Uuid,
    pub owner_id: Option<Id>,
    pub location_id: Option<Id>,
    pub adopted: bool,
    pub mac: MacAddr,
    pub ip: ipnetwork::IpNetwork,
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
        }
    }
}

#[derive(Serialize)]
pub struct DeviceDisplay {
    pub id: Id,
    pub probe_id: Uuid,
    pub mac: MacAddr,
    pub ip: ipnetwork::IpNetwork,
    pub port: i32,
    pub duration: Option<i64>,
    pub interval: Option<i64>,
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

#[derive(Serialize)]
pub struct PacketDisplay {
    pub id: Id,
    pub probe_id: Uuid,
    pub src_mac: MacAddr,
    pub dst_mac: MacAddr,
    pub src_addr: ipnetwork::IpNetwork,
    pub dst_addr: ipnetwork::IpNetwork,
    pub src_port: i32,
    pub dst_port: i32,
    pub payload: Vec<String>,
}

impl PacketDisplay {
    pub(crate) fn from(value: Packet) -> Result<PacketDisplay, CoreError> {
        let payload = ApplicationPacket::from_bytes(&value.payload)?;

        Ok(Self {
            id: value.id,
            probe_id: value.probe_id,
            src_mac: MacAddr::from_octets(value.src_mac),
            dst_mac: MacAddr::from_octets(value.dst_mac),
            src_addr: value.src_addr,
            dst_addr: value.dst_addr,
            src_port: value.src_port,
            dst_port: value.dst_port,
            payload: payload.read_content(),
        })
    }
}