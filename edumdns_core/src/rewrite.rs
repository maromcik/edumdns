use crate::error::CoreError;
use crate::packet::{ApplicationPacket, DataLinkPacket, NetworkPacket};
use pnet::datalink::MacAddr;
use pnet::datalink::ParseMacAddrErr;
use pnet::packet::ethernet::MutableEthernetPacket;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::ipv6::MutableIpv6Packet;
use pnet::packet::tcp::MutableTcpPacket;
use pnet::packet::udp::MutableUdpPacket;
use pnet::packet::vlan::MutableVlanPacket;
use std::net::{AddrParseError, Ipv4Addr, Ipv6Addr};

#[derive(Default)]
pub struct Rewrite {
    pub datalink_rewrite: Option<DataLinkRewrite>,
    pub ip_rewrite: Option<IpRewrite>,
    pub transport_rewrite: Option<PortRewrite>,
}

impl Rewrite {
    pub fn new(
        datalink_rewrite: Option<DataLinkRewrite>,
        ip_rewrite: Option<IpRewrite>,
        transport_rewrite: Option<PortRewrite>,
    ) -> Self {
        Self {
            datalink_rewrite,
            ip_rewrite,
            transport_rewrite,
        }
    }
}

pub struct IpRewrite {
    pub ipv4_rewrite: Option<Ipv4Rewrite>,
    pub ipv6_rewrite: Option<Ipv6Rewrite>,
}

impl IpRewrite {
    pub fn parse_ipv4_rewrite(
        src_ipv4: Option<&str>,
        dst_ipv4: Option<&str>,
    ) -> Result<IpRewrite, CoreError> {
        Ok(Self {
            ipv4_rewrite: Some(Ipv4Rewrite::parse(src_ipv4, dst_ipv4)?),
            ipv6_rewrite: None,
        })
    }

    pub fn parse_ipv6_rewrite(
        src_ipv6: Option<&str>,
        dst_ipv6: Option<&str>,
    ) -> Result<IpRewrite, CoreError> {
        Ok(Self {
            ipv4_rewrite: None,
            ipv6_rewrite: Some(Ipv6Rewrite::parse(src_ipv6, dst_ipv6)?),
        })
    }
}

pub struct DataLinkRewrite {
    pub mac_rewrite: Option<MacRewrite>,
    pub vlan_rewrite: Option<VlanRewrite>,
}

impl DataLinkRewrite {
    pub fn new(mac_rewrite: Option<MacRewrite>, vlan_rewrite: Option<VlanRewrite>) -> Self {
        Self {
            mac_rewrite,
            vlan_rewrite,
        }
    }
    pub fn parse_mac_rewrite(
        src_mac: Option<&str>,
        dst_mac: Option<&str>,
    ) -> Result<Self, CoreError> {
        Ok(Self::new(Some(MacRewrite::parse(src_mac, dst_mac)?), None))
    }
    pub fn new_vlan_rewrite(vlan: u16) -> Self {
        Self::new(None, Some(VlanRewrite::new(vlan)))
    }
}

#[derive(Default)]
pub struct PortRewrite {
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
}

impl PortRewrite {
    pub fn new(src_port: Option<u16>, dst_port: Option<u16>) -> Self {
        Self { src_port, dst_port }
    }
}

#[derive(Default)]
pub struct Ipv4Rewrite {
    pub src_ip: Option<Ipv4Addr>,
    pub dst_ip: Option<Ipv4Addr>,
}

impl Ipv4Rewrite {
    pub fn parse(src_ipv4: Option<&str>, dst_ipv4: Option<&str>) -> Result<Self, CoreError> {
        Ok(Self {
            src_ip: Self::parse_ipv4(src_ipv4.as_ref())?,
            dst_ip: Self::parse_ipv4(dst_ipv4.as_ref())?,
        })
    }
    fn parse_ipv4(ipv4: Option<&&str>) -> Result<Option<Ipv4Addr>, AddrParseError> {
        ipv4.map(|ip| ip.parse::<Ipv4Addr>()).transpose()
    }
}

#[derive(Default)]
pub struct Ipv6Rewrite {
    pub src_ip: Option<Ipv6Addr>,
    pub dst_ip: Option<Ipv6Addr>,
}

impl Ipv6Rewrite {
    pub fn parse(src_ipv6: Option<&str>, dst_ipv6: Option<&str>) -> Result<Self, CoreError> {
        Ok(Self {
            src_ip: Self::parse_ipv6(src_ipv6.as_ref())?,
            dst_ip: Self::parse_ipv6(dst_ipv6.as_ref())?,
        })
    }

    fn parse_ipv6(ipv6: Option<&&str>) -> Result<Option<Ipv6Addr>, AddrParseError> {
        ipv6.map(|ip| ip.parse::<Ipv6Addr>()).transpose()
    }
}

#[derive(Default)]
pub struct MacRewrite {
    pub src_mac: Option<MacAddr>,
    pub dst_mac: Option<MacAddr>,
}

impl MacRewrite {
    pub fn parse(src_mac: Option<&str>, dst_mac: Option<&str>) -> Result<Self, CoreError> {
        Ok(Self {
            src_mac: Self::parse_mac(src_mac.as_ref())?,
            dst_mac: Self::parse_mac(dst_mac.as_ref())?,
        })
    }
    fn parse_mac(mac: Option<&&str>) -> Result<Option<MacAddr>, ParseMacAddrErr> {
        mac.map(|mac| mac.parse::<MacAddr>()).transpose()
    }
}

#[derive(Default)]
pub struct VlanRewrite {
    pub vlan_id: u16,
}

impl VlanRewrite {
    pub fn new(vlan_id: u16) -> Self {
        Self { vlan_id }
    }
}

pub fn rewrite_packet<'a>(packet: DataLinkPacket<'a>, rewrite: &'a Rewrite) -> Option<()> {
    let mut data_link_packet = packet.rewrite(&rewrite.datalink_rewrite);
    let mut vlan_packet = data_link_packet
        .unpack_vlan()?
        .rewrite(&rewrite.datalink_rewrite);
    let mut ip_packet = vlan_packet.get_next_layer()?.rewrite(&rewrite.ip_rewrite);
    let transport_packet = ip_packet
        .get_next_layer()?
        .rewrite(&rewrite.transport_rewrite);

    let mut dns_packet = ApplicationPacket::new(&transport_packet)?;
    let new_dns_packet = dns_packet.application_packet_type.rewrite()?;
    // transport_packet.set_payload(new_dns_packet.as_slice());
    // let payload = transport_packet.get_packet().to_vec();
    // ip_packet.set_payload(payload.as_slice());
    // let payload = ip_packet.get_packet().to_vec();
    // data_link_packet.set_payload(payload.as_slice());

    Some(())
}

pub fn rewrite_mac(packet: &mut MutableEthernetPacket, rewrite: &DataLinkRewrite) {
    let Some(rewrite) = &rewrite.mac_rewrite else {
        return;
    };
    if let Some(src_mac) = rewrite.src_mac {
        println!(
            "src_mac: {}, dst_mac: {}, changing src to: {}",
            packet.get_source(),
            packet.get_destination(),
            src_mac
        );
        packet.set_source(src_mac);
    }

    if let Some(dst_mac) = rewrite.dst_mac {
        println!(
            "src_mac: {}, dst_mac: {}, changing dst to: {}",
            packet.get_source(),
            packet.get_destination(),
            dst_mac
        );
        packet.set_destination(dst_mac);
    }
}

pub fn rewrite_vlan(vlan_packet: &mut MutableVlanPacket, rewrite: &DataLinkRewrite) {
    let Some(rewrite) = &rewrite.vlan_rewrite else {
        return;
    };
    println!(
        "vlan_id: {}, changing to: {}",
        vlan_packet.get_vlan_identifier(),
        rewrite.vlan_id
    );
    vlan_packet.set_vlan_identifier(rewrite.vlan_id);
}

pub fn rewrite_ipv4(ipv4_packet: &mut MutableIpv4Packet, rewrite: &IpRewrite) {
    let Some(rewrite) = &rewrite.ipv4_rewrite else {
        return;
    };

    if let Some(src_ip) = rewrite.src_ip {
        println!(
            "src_ip: {}, dst_ip: {}, changing src to: {}",
            ipv4_packet.get_source(),
            ipv4_packet.get_destination(),
            src_ip
        );
        ipv4_packet.set_source(src_ip)
    }
    if let Some(dst_ip) = rewrite.dst_ip {
        println!(
            "src_ip: {}, dst_ip: {}, changing dst to: {}",
            ipv4_packet.get_source(),
            ipv4_packet.get_destination(),
            dst_ip
        );
        ipv4_packet.set_destination(dst_ip);
    };
}

pub fn rewrite_ipv6(ipv6_packet: &mut MutableIpv6Packet, rewrite: &IpRewrite) {
    let Some(rewrite) = &rewrite.ipv6_rewrite else {
        return;
    };

    if let Some(src_ip) = rewrite.src_ip {
        println!(
            "src_ip: {}, dst_ip: {}, changing src to: {}",
            ipv6_packet.get_source(),
            ipv6_packet.get_destination(),
            src_ip
        );
        ipv6_packet.set_source(src_ip)
    }
    if let Some(dst_ip) = rewrite.dst_ip {
        println!(
            "src_ip: {}, dst_ip: {}, changing dst to: {}",
            ipv6_packet.get_source(),
            ipv6_packet.get_destination(),
            dst_ip
        );
        ipv6_packet.set_destination(dst_ip);
    };
}

pub fn rewrite_udp(packet: &mut MutableUdpPacket, rewrite: &Option<PortRewrite>) {
    if let Some(rewrite) = rewrite {
        if let Some(src) = rewrite.src_port {
            println!(
                "src_port: {}, dst_port: {}, changing src to: {}",
                packet.get_source(),
                packet.get_destination(),
                src
            );
            packet.set_source(src);
        }
        if let Some(dst) = rewrite.dst_port {
            println!(
                "src_port: {}, dst_port: {}, changing dst to: {}",
                packet.get_source(),
                packet.get_destination(),
                dst
            );
            packet.set_destination(dst);
        }
    }
}

pub fn rewrite_tcp(packet: &mut MutableTcpPacket, rewrite: &Option<PortRewrite>) {
    if let Some(rewrite) = rewrite {
        if let Some(src) = rewrite.src_port {
            println!(
                "src_port: {}, dst_port: {}, changing src to: {}",
                packet.get_source(),
                packet.get_destination(),
                src
            );
            packet.set_source(src);
        }
        if let Some(dst) = rewrite.dst_port {
            println!(
                "src_port: {}, dst_port: {}, changing src to: {}",
                packet.get_source(),
                packet.get_destination(),
                dst
            );
            packet.set_destination(dst);
        }
    };
}
