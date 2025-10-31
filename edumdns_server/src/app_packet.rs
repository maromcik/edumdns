use std::fmt::{Display, Formatter};
use tokio::sync::{mpsc, oneshot};
use edumdns_core::app_packet::{EntityType, Id, NetworkAppPacket, ProbeResponse};
use edumdns_core::bincode_types::{MacAddr, Uuid};
use edumdns_db::models::Device;
use crate::error::ServerError;

#[derive(Debug)]
pub enum AppPacket {
    Network(NetworkAppPacket),
    Local(LocalAppPacket),
}

#[derive(Debug)]
pub enum LocalAppPacket {
    Command(LocalCommandPacket),
    Status(LocalStatusPacket),
}
#[derive(Debug)]
pub enum LocalCommandPacket {
    RegisterForEvents {
        probe_id: uuid::Uuid,
        session_id: uuid::Uuid,
        respond_to: mpsc::Sender<ProbeResponse>,
    },
    UnregisterFromEvents {
        probe_id: uuid::Uuid,
        session_id: uuid::Uuid,
    },
    ReconnectProbe(Uuid, Option<Uuid>),
    TransmitDevicePackets {
        request: PacketTransmitRequestPacket,
        respond_to: oneshot::Sender<Result<(), ServerError>>,
    },
    StopTransmitDevicePackets(i64),
    InvalidateCache(EntityType),
}

#[derive(Debug)]
pub enum LocalStatusPacket {
    GetLiveProbes,
    IsProbeLive {
        probe_id: uuid::Uuid,
        respond_to: oneshot::Sender<bool>,
    },
    OperationUpdateToWs {
        probe_id: Uuid,
        session_id: Option<Uuid>,
        message: String,
    },
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct PacketTransmitRequestDevice {
    pub id: Id,
    pub probe_id: uuid::Uuid,
    pub mac: [u8; 6],
    pub ip: ipnetwork::IpNetwork,
    pub proxy: bool,
    pub interval: u64,
    pub duration: u64,
}

impl PacketTransmitRequestDevice {
    pub fn new(
        id: Id,
        probe_id: uuid::Uuid,
        mac: [u8; 6],
        ip: ipnetwork::IpNetwork,
        proxy: bool,
        interval: Id,
        duration: Id,
    ) -> Self {
        Self {
            id,
            probe_id,
            mac,
            ip,
            proxy,
            interval: interval as u64,
            duration: duration as u64,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct PacketTransmitRequestPacket {
    pub id: Id,
    pub device: PacketTransmitRequestDevice,
    pub target_ip: ipnetwork::IpNetwork,
    pub target_port: u16,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct PacketTransmitTarget {
    pub ip: String,
    pub port: u16,
}

impl PacketTransmitRequestPacket {
    pub fn new(
        id: Id,
        device: PacketTransmitRequestDevice,
        target_ip: ipnetwork::IpNetwork,
        target_port: u16,
    ) -> Self {
        Self {
            id,
            device,
            target_ip,
            target_port,
        }
    }
}

impl Display for PacketTransmitRequestPacket {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Device Probe_ID: {}, MAC: {}, IP: {}; Target: {}:{}",
            self.device.probe_id,
            MacAddr::from_octets(self.device.mac),
            self.device.ip,
            self.target_ip,
            self.target_port
        )
    }
}

impl From<Device> for PacketTransmitRequestDevice {
    fn from(value: Device) -> Self {
        Self {
            id: value.id,
            probe_id: value.probe_id,
            mac: value.mac,
            ip: value.ip,
            proxy: value.proxy,
            interval: value.interval as u64,
            duration: value.duration as u64,
        }
    }
}