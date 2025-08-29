use crate::bincode_types::Uuid;
use crate::bincode_types::{IpNetwork, MacAddr};
use crate::metadata::{DataLinkMetadata, PacketMetadata, ProbeMetadata};
use crate::network_packet::{DataLinkPacket, NetworkPacket};
use bincode::{Decode, Encode};
use std::fmt::{Display, Formatter};
use std::hash::{Hash, Hasher};

#[derive(Encode, Decode, Debug, Clone, Eq, PartialEq)]
pub enum AppPacket {
    Command(CommandPacket),
    Data(ProbePacket),
    Status(StatusPacket),
}

#[derive(Encode, Decode, Debug, Clone, Eq, PartialEq)]
pub enum CommandPacket {
    TransmitDevicePackets(PacketTransmitRequestPacket),
    StopTransmitDevicePackets(PacketTransmitRequestPacket),
    ReconnectThisProbe,
    ReconnectProbe(Uuid),
}

#[derive(Encode, Decode, Debug, Clone, Eq, PartialEq)]
pub enum StatusPacket {
    PingRequest,
    PingResponse,
    ProbeHello(ProbeMetadata),
    ProbeAdopted,
    ProbeUnknown,
    ProbeRequestConfig(ProbeMetadata),
    ProbeResponseConfig(ProbeConfigPacket),
    ProbeInvalidConfig(String),
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
        Some(Self {
            probe_metadata: probe_metadata.clone(),
            packet_metadata: PacketMetadata::new(
                DataLinkMetadata::new(mac_metadata, vlan_metadata),
                ip_metadata,
                transport_metadata,
            ),
            payload: transport_packet.get_payload().to_vec(),
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
    }
}

impl Eq for ProbePacket {}

#[derive(Encode, Decode, Debug, Clone, Eq, PartialEq, Hash)]
pub struct PacketTransmitRequestPacket {
    pub probe_uuid: Uuid,
    pub device_mac: MacAddr,
    pub device_ip: IpNetwork,
    pub target_ip: String,
    pub target_port: u16,
}

#[derive(Encode, Decode, Debug, Clone, Eq, PartialEq, Hash)]
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
        target_ip: &str,
        target_port: u16,
    ) -> Self {
        Self {
            probe_uuid: Uuid(probe_uuid),
            device_mac: MacAddr::from_octets(device_mac),
            device_ip: IpNetwork(device_ip),
            target_ip: target_ip.to_string(),
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
