use crate::bincode_types::Uuid;
use crate::bincode_types::{IpNetwork, MacAddr};
use crate::error::CoreError;
use crate::metadata::{DataLinkMetadata, PacketMetadata, ProbeMetadata};
use crate::network_packet::{DataLinkPacket, NetworkPacket};
use bincode::{Decode, Encode};
use std::fmt::{Display, Formatter};
use std::hash::{DefaultHasher, Hash, Hasher};
use tokio::sync::{mpsc, oneshot};

pub type Id = i64;

#[derive(Debug)]
pub enum AppPacket {
    Network(NetworkAppPacket),
    Local(LocalAppPacket),
}

#[derive(Encode, Decode, Debug, Clone, Eq, PartialEq)]
pub enum NetworkAppPacket {
    Command(NetworkCommandPacket),
    Data(ProbePacket),
    Status(NetworkStatusPacket),
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
        respond_to: oneshot::Sender<Result<(), CoreError>>,
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

#[derive(Encode, Decode, Debug, Clone, Eq, PartialEq)]
pub enum NetworkCommandPacket {
    ReconnectThisProbe(Option<Uuid>),
}

#[derive(Encode, Decode, Debug, Clone, Eq, PartialEq)]
pub enum NetworkStatusPacket {
    PingRequest(Uuid),
    PingResponse,
    ProbeHello(ProbeMetadata, Option<String>),
    ProbeAdopted,
    ProbeUnknown,
    ProbeInvalidConnectionInitiation(String),
    ProbeRequestConfig(ProbeMetadata),
    ProbeResponseConfig(ProbeConfigPacket),
    ProbeResponse(Uuid, Option<Uuid>, ProbeResponse),
}

#[derive(Debug)]
pub enum EntityType {
    Probe {
        probe_id: Uuid,
    },
    Device {
        probe_id: Uuid,
        device_mac: MacAddr,
        device_ip: IpNetwork,
    },
    Packet(Id),
}

#[derive(Encode, Decode, Debug, Clone, Eq, PartialEq)]
pub struct ProbeResponse {
    pub response: Result<Option<String>, String>,
}

impl ProbeResponse {
    pub fn new(response: Result<Option<String>, String>) -> Self {
        Self { response }
    }

    pub fn new_ok() -> Self {
        Self { response: Ok(None) }
    }
    pub fn new_error(error: String) -> Self {
        Self {
            response: Err(error),
        }
    }
    pub fn new_ok_with_value(value: &str) -> Self {
        Self {
            response: Ok(Some(value.to_owned())),
        }
    }
}

impl Display for ProbeResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &self.response {
            Ok(Some(value)) => write!(f, "OK: {}", value),
            Ok(None) => write!(f, "OK"),
            Err(value) => write!(f, "Error: {}", value),
        }
    }
}

#[derive(Encode, Decode, Debug, Clone, Eq, PartialEq)]
pub struct ProbeConfigElement {
    pub interface_name: String,
    pub bpf_filter: Option<String>,
}

impl ProbeConfigElement {
    pub fn new(interface_name: String, bpf_filter: Option<String>) -> Self {
        Self {
            interface_name,
            bpf_filter,
        }
    }
}

impl Display for ProbeConfigElement {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "<interface: {}; filter: {}>",
            self.interface_name,
            self.bpf_filter.as_ref().unwrap_or(&"None".to_string())
        )
    }
}

#[derive(Encode, Decode, Debug, Clone, Eq, PartialEq)]
pub struct ProbeConfigPacket {
    pub interface_filter_map: Vec<ProbeConfigElement>,
}

#[derive(Encode, Decode, Debug, Clone)]
pub struct ProbePacket {
    pub probe_metadata: ProbeMetadata,
    pub packet_metadata: PacketMetadata,
    pub payload: Vec<u8>,
    pub payload_hash: u64,
}

impl ProbePacket {
    pub fn from_datalink_packet(
        probe_metadata: &ProbeMetadata,
        mut packet: DataLinkPacket<'_>,
    ) -> Option<Self> {
        let mac_metadata = packet.get_mac_metadata()?;
        let mut vlan_packet = packet.unpack_vlan()?;
        let vlan_metadata = vlan_packet.get_vlan_metadata();
        let mut ip_packet = vlan_packet.get_next_layer()?;
        let ip_metadata = ip_packet.get_ip_metadata().ok()?;
        let transport_packet = ip_packet.get_next_layer()?;
        let transport_metadata = transport_packet.get_transport_metadata()?;
        let payload = transport_packet.get_payload();
        let payload_hash = calculate_hash(payload);
        Some(Self {
            probe_metadata: probe_metadata.clone(),
            packet_metadata: PacketMetadata::new(
                DataLinkMetadata::new(mac_metadata, vlan_metadata),
                ip_metadata,
                transport_metadata,
            ),
            payload: payload.to_vec(),
            payload_hash,
        })
    }
}

impl Hash for ProbePacket {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.probe_metadata.id.hash(state);
        self.packet_metadata
            .datalink_metadata
            .mac_metadata
            .src_mac
            .hash(state);
        self.packet_metadata.ip_metadata.src_ip.hash(state);
        self.packet_metadata.ip_metadata.dst_ip.hash(state);
        self.packet_metadata.transport_metadata.dst_port.hash(state);
        self.payload_hash.hash(state);
    }
}

impl PartialEq for ProbePacket {
    fn eq(&self, other: &Self) -> bool {
        self.probe_metadata.id == other.probe_metadata.id
            && self.payload_hash == other.payload_hash
            && self.packet_metadata.datalink_metadata.mac_metadata.src_mac
                == other.packet_metadata.datalink_metadata.mac_metadata.src_mac
            && self.packet_metadata.ip_metadata.src_ip == other.packet_metadata.ip_metadata.src_ip
            && self.packet_metadata.ip_metadata.dst_ip == other.packet_metadata.ip_metadata.dst_ip
            && self.packet_metadata.transport_metadata.dst_port
                == other.packet_metadata.transport_metadata.dst_port
    }
}

impl Eq for ProbePacket {}

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

pub fn calculate_hash(value: &[u8]) -> u64 {
    let mut hasher = DefaultHasher::default();
    value.hash(&mut hasher);
    hasher.finish()
}
