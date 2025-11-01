use crate::error::ServerError;
use edumdns_core::app_packet::{EntityType, NetworkAppPacket, ProbeResponse};
use edumdns_core::bincode_types::{MacAddr, Uuid};
use edumdns_db::models::{Device, PacketTransmitRequest};
use std::fmt::{Display, Formatter};
use tokio::sync::{mpsc, oneshot};

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
pub struct PacketTransmitRequestPacket {
    pub device: Device,
    pub request: PacketTransmitRequest,
}

impl PacketTransmitRequestPacket {
    pub fn new(device: Device, request: PacketTransmitRequest) -> Self {
        Self { device, request }
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
            self.request.target_ip,
            self.request.target_port
        )
    }
}
