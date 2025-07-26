use crate::bincode_types::Uuid;
use crate::bincode_types::{IpNetwork, MacAddr};
use crate::metadata::{DataLinkMetadata, PacketMetadata, ProbeMetadata};
use crate::network_packet::{DataLinkPacket, NetworkPacket};
use bincode::{Decode, Encode};
use std::fmt::Display;
use std::hash::{Hash, Hasher};

#[derive(Encode, Decode, Debug, Clone)]
pub enum AppPacket {
    Command(CommandPacket),
    Data(ProbePacket),
    Status(StatusPacket),
}

#[derive(Encode, Decode, Debug, Clone)]
pub enum CommandPacket {
    TransmitDevicePackets(PacketTransmitRequest),
    ReconnectProbe,
}

#[derive(Encode, Decode, Debug, Clone)]
pub enum StatusPacket {
    PingRequest,
    PingResponse,
    ProbeHello(ProbeMetadata),
    ProbeAdopted,
    ProbeUnknown,
    ProbeRequestConfig(ProbeMetadata),
    ProbeResponseConfig(ProbeConfigPacket),
}

#[derive(Encode, Decode, Debug, Clone)]
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

#[derive(Encode, Decode, Debug, Clone)]
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
        let ip_metadata = ip_packet.get_ip_metadata();
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
        self.payload.hash(state);
    }
}

impl PartialEq for ProbePacket {
    fn eq(&self, other: &Self) -> bool {
        self.probe_metadata.id == other.probe_metadata.id && self.payload == other.payload
    }
}

impl Eq for ProbePacket {}

#[derive(Encode, Decode, Debug, Clone)]
pub struct PacketTransmitRequest {
    pub device: PacketTransmitDevice,
    pub target: PacketTransmitTarget,
}

#[derive(Encode, Decode, Debug, Clone)]
pub struct PacketTransmitTarget {
    pub ip: String,
    pub port: u16,
}

#[derive(Encode, Decode, Debug, Clone)]
pub struct PacketTransmitDevice {
    pub probe_uuid: Uuid,
    pub mac: MacAddr,
    pub ip: IpNetwork,
}

impl PacketTransmitRequest {
    pub fn new(
        probe_uuid: Uuid,
        device_mac: MacAddr,
        device_ip: IpNetwork,
        target_ip: String,
        target_port: u16,
    ) -> Self {
        Self {
            device: PacketTransmitDevice {
                probe_uuid,
                mac: device_mac,
                ip: device_ip,
            },
            target: PacketTransmitTarget {
                ip: target_ip,
                port: target_port,
            },
        }
    }
}

impl Display for PacketTransmitRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Device Probe_ID: {}, MAC: {}, IP: {}; Target: {}:{}",
            self.device.probe_uuid,
            self.device.mac,
            self.device.ip,
            self.target.ip,
            self.target.port
        )
    }
}
