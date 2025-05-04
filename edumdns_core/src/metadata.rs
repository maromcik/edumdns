use crate::packet::{DataLinkPacket, NetworkPacket};
use bincode::enc::Encoder;
use bincode::error::EncodeError;
use bincode::{Decode, Encode};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Encode, Decode, Debug)]
pub struct PacketMetadata {
    pub datalink_metadata: DataLinkMetadata,
    pub ip_metadata: IpMetadata,
    pub transport_metadata: PortMetadata,
}

impl PacketMetadata {
    pub fn from_datalink_packet(mut packet: DataLinkPacket<'_>) -> Option<Self> {
        let mac_metadata = packet.get_mac_metadata()?;
        let mut vlan_packet = packet.unpack_vlan()?;
        let vlan_metadata = vlan_packet.get_vlan_metadata();
        let mut ip_packet = vlan_packet.get_next_layer()?;
        let ip_metadata = ip_packet.get_ip_metadata();
        let transport_packet = ip_packet.get_next_layer()?;
        let transport_metadata = transport_packet.get_transport_metadata()?;
        Some(PacketMetadata::new(
            DataLinkMetadata::new(mac_metadata, vlan_metadata),
            ip_metadata,
            transport_metadata,
        ))
    }
}

impl PacketMetadata {
    pub fn new(
        datalink_metadata: DataLinkMetadata,
        ip_metadata: IpMetadata,
        transport_metadata: PortMetadata,
    ) -> Self {
        Self {
            datalink_metadata,
            ip_metadata,
            transport_metadata,
        }
    }
}

#[derive(Encode, Decode, Debug)]
pub enum IpMetadata {
    Ipv4(Ipv4Metadata),
    Ipv6(Ipv6Metadata),
}

#[derive(Default, Encode, Decode, Debug)]
pub struct DataLinkMetadata {
    pub mac_metadata: MacMetadata,
    pub vlan_metadata: Option<VlanMetadata>,
}

impl DataLinkMetadata {
    pub fn new(mac_metadata: MacMetadata, vlan_metadata: Option<VlanMetadata>) -> Self {
        Self {
            mac_metadata,
            vlan_metadata,
        }
    }
}

#[derive(Default, Encode, Decode, Debug)]
pub struct PortMetadata {
    pub src_port: u16,
    pub dst_port: u16,
}

impl PortMetadata {
    pub fn new(src_port: u16, dst_port: u16) -> Self {
        Self { src_port, dst_port }
    }
}

#[derive(Encode, Decode, Debug)]
pub struct Ipv4Metadata {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
}

#[derive(Encode, Decode, Debug)]
pub struct Ipv6Metadata {
    pub src_ip: Ipv6Addr,
    pub dst_ip: Ipv6Addr,
}

#[derive(Default, Encode, Decode, Debug)]
pub struct MacMetadata {
    pub src_mac: MacAddr,
    pub dst_mac: MacAddr,
}

#[derive(Default, Debug)]
pub struct MacAddr(pub pnet::datalink::MacAddr);

impl Encode for MacAddr {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        bincode::Encode::encode(&self.0.0, encoder)?;
        bincode::Encode::encode(&self.0.1, encoder)?;
        bincode::Encode::encode(&self.0.2, encoder)?;
        bincode::Encode::encode(&self.0.3, encoder)?;
        bincode::Encode::encode(&self.0.4, encoder)?;
        bincode::Encode::encode(&self.0.5, encoder)?;
        Ok(())
    }
}

impl<__Context> bincode::Decode<__Context> for MacAddr {
    fn decode<__D: bincode::de::Decoder<Context = __Context>>(
        decoder: &mut __D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let mac_addr = pnet::datalink::MacAddr::new(
            bincode::Decode::decode(decoder)?,
            bincode::Decode::decode(decoder)?,
            bincode::Decode::decode(decoder)?,
            bincode::Decode::decode(decoder)?,
            bincode::Decode::decode(decoder)?,
            bincode::Decode::decode(decoder)?,
        );
        Ok(Self(mac_addr))
    }
}

impl<'__de, __Context> ::bincode::BorrowDecode<'__de, __Context> for MacAddr {
    fn borrow_decode<__D: ::bincode::de::BorrowDecoder<'__de, Context = __Context>>(
        decoder: &mut __D,
    ) -> Result<Self, ::bincode::error::DecodeError> {
        let mac_addr = pnet::datalink::MacAddr::new(
            bincode::BorrowDecode::<'_, __Context>::borrow_decode(decoder)?,
            bincode::BorrowDecode::<'_, __Context>::borrow_decode(decoder)?,
            bincode::BorrowDecode::<'_, __Context>::borrow_decode(decoder)?,
            bincode::BorrowDecode::<'_, __Context>::borrow_decode(decoder)?,
            bincode::BorrowDecode::<'_, __Context>::borrow_decode(decoder)?,
            bincode::BorrowDecode::<'_, __Context>::borrow_decode(decoder)?,
        );
        Ok(Self(mac_addr))
    }
}

#[derive(Default, Encode, Decode, Debug)]
pub struct VlanMetadata {
    pub vlan_id: u16,
}

impl VlanMetadata {
    pub fn new(vlan_id: u16) -> Self {
        Self { vlan_id }
    }
}
