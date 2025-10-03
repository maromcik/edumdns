use crate::bincode_types::{IpNetwork, MacAddr, Uuid};
use bincode::{Decode, Encode};
use std::net::IpAddr;

#[derive(Encode, Decode, Debug, Clone, Default)]
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

#[derive(Encode, Decode, Debug, Clone, Eq, PartialEq, Hash)]
pub struct ProbeMetadata {
    pub id: Uuid,
    pub mac: MacAddr,
    pub ip: IpAddr,
}

#[derive(Encode, Decode, Debug, Clone)]
pub struct IpMetadata {
    pub src_ip: IpNetwork,
    pub dst_ip: IpNetwork,
}

impl Default for IpMetadata {
    fn default() -> Self {
        Self {
            src_ip: IpNetwork::default_ipv4(),
            dst_ip: IpNetwork::default_ipv4(),
        }
    }
}

#[derive(Encode, Decode, Debug, Clone, Default)]
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

#[derive(Encode, Decode, Debug, Clone, Default)]
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
