//! Application-level packets shared between server and probe.
//!
//! This module defines the enums and structures exchanged over the control/data
//! TCP channel between the server and probes:
//! - `NetworkAppPacket` wraps command, status, and data messages
//! - `NetworkCommandPacket` carries control commands (e.g., reconnect)
//! - `NetworkStatusPacket` covers handshake, ping, and config exchange
//! - `ProbeConfigElement` and `ProbeConfigPacket` describe capture settings
//! - `ProbePacket` encapsulates a captured network packet plus metadata and a
//!   content hash used for deduplication/indexed storage
//!
use crate::bincode_types::Uuid;
use crate::bincode_types::{IpNetwork, MacAddr};
use crate::metadata::{DataLinkMetadata, PacketMetadata, ProbeMetadata};
use crate::network_packet::{ApplicationPacket, DataLinkPacket, NetworkPacket};
use bincode::{Decode, Encode};
use hickory_proto::op::{Message, MessageType, OpCode};
use std::fmt;
use std::fmt::{Display, Formatter};
use std::hash::{DefaultHasher, Hash, Hasher};

pub type Id = i64;

#[derive(Encode, Decode, Debug, Clone, Eq, PartialEq)]
pub enum NetworkAppPacket {
    Command(NetworkCommandPacket),
    Data(ProbePacket),
    Status(NetworkStatusPacket),
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
            "[interface: {} | filter: {}]",
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
        ApplicationPacket::from_bytes(
            &payload,
            transport_metadata.src_port as i32,
            transport_metadata.dst_port as i32,
        )
        .ok()?;
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

pub fn calculate_hash(value: &[u8]) -> u64 {
    let mut hasher = DefaultHasher::default();
    value.hash(&mut hasher);
    hasher.finish()
}

pub struct HickoryDnsPacket<'a>(pub &'a Message);
impl Display for HickoryDnsPacket<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        let m = self.0;
        let write_query = |slice, f: &mut fmt::Formatter<'_>| -> Result<(), fmt::Error> {
            for d in slice {
                writeln!(f, ";; {d}")?;
            }

            Ok(())
        };

        let write_slice = |slice, f: &mut fmt::Formatter<'_>| -> Result<(), fmt::Error> {
            for d in slice {
                writeln!(f, "{d}")?;
            }

            Ok(())
        };

        writeln!(f, "; header {header}", header = m.header())?;

        if let Some(edns) = m.extensions() {
            writeln!(f, "; edns {edns}")?;
        }

        writeln!(f, "; query")?;
        write_query(m.queries(), f)?;

        if m.header().message_type() == MessageType::Response
            || m.header().op_code() == OpCode::Update
        {
            writeln!(f, "; answers {}", m.answer_count())?;
            write_slice(m.answers(), f)?;
            writeln!(f, "; nameservers {}", m.name_server_count())?;
            write_slice(m.name_servers(), f)?;
            writeln!(f, "; additionals {}", m.additional_count())?;
            write_slice(m.additionals(), f)?;
        }
        if m.header().message_type() == MessageType::Response && m.name_server_count() > 0 {
            writeln!(f, "; authorities {}", m.name_server_count())?;
            write_slice(m.name_servers(), f)?;
        }

        Ok(())
    }
}
