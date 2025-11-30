//! Application-level packets used inside the edumdns_server.
//! 
//! This module defines the `AppPacket` enum that wraps packets exchanged between
//! server components and network probes, as well as "local" packets used for
//! intra-server commands, status queries, and data streaming. The goal is to have
//! a single strongly-typed channel payload that the server can route.

use crate::error::ServerError;
use edumdns_core::app_packet::{EntityType, Id, NetworkAppPacket, ProbeResponse};
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
    Data(LocalDataPacket),
}

#[derive(Debug)]
pub enum LocalDataPacket {
    TransmitterLiveUpdateData(Vec<u8>),
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
    StopTransmitDevicePackets(Id),
    InvalidateCache(EntityType),
    ExtendPacketTransmitRequest(Id),
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
