use crate::bincode_types::MacAddr;
use crate::metadata::{DataLinkMetadata, PacketMetadata, ProbeMetadata};
use crate::network_packet::{DataLinkPacket, NetworkPacket};
use bincode::{Decode, Encode};
use std::fmt::Display;
use std::hash::{Hash, Hasher};
use uuid::Uuid;

#[derive(Encode, Decode, Debug, Clone)]
pub enum AppPacket {
    Command(CommandPacket),
    Data(ProbePacket),
}

#[derive(Encode, Decode, Debug, Clone)]
pub enum CommandPacket {
    TransmitDevicePackets(PacketTransmitTarget),
    PingRequest(),
    PingResponse(),
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
pub struct PacketTransmitTarget {
    pub mac: MacAddr,
    pub ip: String,
    pub port: u16,
}

impl PacketTransmitTarget {
    pub fn new(mac: MacAddr, ip: String, port: u16) -> Self {
        Self { mac, ip, port }
    }
}

impl Display for PacketTransmitTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Device MAC: {}; Target: {}:{}",
            self.mac, self.ip, self.port
        )
    }
}
