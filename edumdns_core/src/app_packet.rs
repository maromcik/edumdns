use std::hash::{Hash, Hasher};
use bincode::{Decode, Encode};
use crate::addr_types::MacAddr;
use crate::metadata::{DataLinkMetadata, PacketMetadata};
use crate::network_packet::{DataLinkPacket, NetworkPacket};

#[derive(Encode, Decode, Debug, Clone)]
pub enum AppPacket {
    Command(CommandPacket),
    Data(ProbePacket)
}


#[derive(Encode, Decode, Debug, Clone)]
pub enum CommandPacket {
    TransmitDevicePackets(MacAddr),
    PingRequest(),
    PingResponse(),
}

#[derive(Encode, Decode, Debug, Clone)]
pub struct ProbePacket {
    pub id: i32,
    pub payload: Vec<u8>,
    pub metadata: PacketMetadata,
}

impl ProbePacket {
    pub fn from_datalink_packet(id: i32, mut packet: DataLinkPacket<'_>) -> Option<Self> {
        let mac_metadata = packet.get_mac_metadata()?;
        let mut vlan_packet = packet.unpack_vlan()?;
        let vlan_metadata = vlan_packet.get_vlan_metadata();
        let mut ip_packet = vlan_packet.get_next_layer()?;
        let ip_metadata = ip_packet.get_ip_metadata();
        let transport_packet = ip_packet.get_next_layer()?;
        let transport_metadata = transport_packet.get_transport_metadata()?;
        Some(Self {
            id,
            payload: transport_packet.get_payload().to_vec(),
            metadata: PacketMetadata::new(
                DataLinkMetadata::new(mac_metadata, vlan_metadata),
                ip_metadata,
                transport_metadata,
            ),
        })
    }
}

impl Hash for ProbePacket {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state);
        self.payload.hash(state);
    }
}

impl PartialEq for ProbePacket {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.payload == other.payload
    }
}

impl Eq for ProbePacket {}
