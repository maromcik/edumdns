use crate::bincode_types::Uuid;
use crate::bincode_types::MacAddr;
use crate::metadata::{DataLinkMetadata, PacketMetadata, ProbeMetadata};
use crate::network_packet::{DataLinkPacket, NetworkPacket};
use bincode::{Decode, Encode};
use sha2::{Digest, Sha256};
use std::fmt::{Display, Formatter};
use std::hash::{Hash, Hasher};
use tokio::sync::{mpsc, oneshot};

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
#[derive(Debug, Clone)]
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
    TransmitDevicePackets(PacketTransmitRequestPacket),
    StopTransmitDevicePackets(PacketTransmitRequestPacket),
}

#[derive(Debug)]
pub enum LocalStatusPacket {
    GetLiveProbes,
    IsProbeLive {
        probe_id: uuid::Uuid,
        respond_to: oneshot::Sender<bool>,
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
    ProbeHello(ProbeMetadata),
    ProbeAdopted,
    ProbeUnknown,
    ProbeRequestConfig(ProbeMetadata),
    ProbeResponseConfig(ProbeConfigPacket),
    ProbeResponse(Uuid, Option<Uuid>, ProbeResponse),
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

// #[derive(Clone, Debug)]
// pub struct SenderWrapper(pub mpsc::Sender<AppPacket>);
//
// impl PartialEq for SenderWrapper {
//     fn eq(&self, other: &Self) -> bool {
//         self.0.same_channel(&other.0)
//     }
// }
// impl Eq for SenderWrapper {}
//
// impl Hash for SenderWrapper {
//     fn hash<H: Hasher>(&self, state: &mut H) {
//         // hash by pointer address
//         (&self.0 as *const mpsc::Sender<AppPacket>).hash(state);
//     }
// }
//

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
    pub payload_hash: String,
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
        self.payload.hash(state);
    }
}

impl PartialEq for ProbePacket {
    fn eq(&self, other: &Self) -> bool {
        self.probe_metadata.id == other.probe_metadata.id
            && self.payload == other.payload
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
pub struct PacketTransmitRequestPacket {
    pub probe_uuid: Uuid,
    pub device_mac: MacAddr,
    pub device_ip: ipnetwork::IpNetwork,
    pub target_ip: ipnetwork::IpNetwork,
    pub target_port: u16,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct PacketTransmitTarget {
    pub ip: String,
    pub port: u16,
}

// #[derive(Encode, Decode, Debug, Clone, Eq, PartialEq, Hash)]
// pub struct PacketTransmitDevice {
//     pub probe_uuid: Uuid,
//     pub mac: MacAddr,
//     pub ip: IpNetwork,
// }
//
impl PacketTransmitRequestPacket {
    pub fn new(
        probe_uuid: uuid::Uuid,
        device_mac: [u8; 6],
        device_ip: ipnetwork::IpNetwork,
        target_ip: ipnetwork::IpNetwork,
        target_port: u16,
    ) -> Self {
        Self {
            probe_uuid: Uuid(probe_uuid),
            device_mac: MacAddr::from_octets(device_mac),
            device_ip,
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
            self.probe_uuid, self.device_mac, self.device_ip, self.target_ip, self.target_port
        )
    }
}

pub fn calculate_hash(value: &[u8]) -> String {
    hex::encode(Sha256::digest(value))
}
