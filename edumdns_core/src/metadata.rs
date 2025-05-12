use crate::addr_types::MacAddr;
use bincode::{Decode, Encode};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Encode, Decode, Debug, Clone)]
pub struct PacketMetadata {
    pub datalink_metadata: DataLinkMetadata,
    pub ip_metadata: IpMetadata,
    pub transport_metadata: PortMetadata,
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

#[derive(Encode, Decode, Debug, Clone)]
pub enum IpMetadata {
    Ipv4(Ipv4Metadata),
    Ipv6(Ipv6Metadata),
}

#[derive(Encode, Decode, Debug, Clone)]
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

#[derive(Encode, Decode, Debug, Clone, Default)]
pub struct PortMetadata {
    pub src_port: u16,
    pub dst_port: u16,
}

impl PortMetadata {
    pub fn new(src_port: u16, dst_port: u16) -> Self {
        Self { src_port, dst_port }
    }
}

#[derive(Encode, Decode, Debug, Clone)]
pub struct Ipv4Metadata {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
}

#[derive(Encode, Decode, Debug, Clone)]
pub struct Ipv6Metadata {
    pub src_ip: Ipv6Addr,
    pub dst_ip: Ipv6Addr,
}

#[derive(Encode, Decode, Debug, Clone)]
pub struct MacMetadata {
    pub src_mac: MacAddr,
    pub dst_mac: MacAddr,
}

#[derive(Encode, Decode, Debug, Clone)]
pub struct VlanMetadata {
    pub vlan_id: u16,
}

impl VlanMetadata {
    pub fn new(vlan_id: u16) -> Self {
        Self { vlan_id }
    }
}
