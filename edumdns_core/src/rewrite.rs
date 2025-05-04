use crate::packet::{ApplicationPacket, DataLinkPacket, NetworkPacket};
use pnet::packet::ethernet::MutableEthernetPacket;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::ipv6::MutableIpv6Packet;
use pnet::packet::tcp::MutableTcpPacket;
use pnet::packet::udp::MutableUdpPacket;
use pnet::packet::vlan::MutableVlanPacket;
use log::debug;
use crate::metadata::{DataLinkMetadata, IpMetadata, PortMetadata, PacketMetadata};

pub fn rewrite_packet<'a>(packet: DataLinkPacket<'a>, rewrite: &'a PacketMetadata) -> Option<()> {
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

pub fn rewrite_mac(packet: &mut MutableEthernetPacket, rewrite: &DataLinkMetadata) {
    let Some(rewrite) = &rewrite.mac_rewrite else {
        return;
    };
    if let Some(src_mac) = &rewrite.src_mac {
        debug!(
            "src_mac: {}, dst_mac: {}, changing src to: {}",
            packet.get_source(),
            packet.get_destination(),
            src_mac.0
        );
        packet.set_source(src_mac.0);
    }

    if let Some(dst_mac) = &rewrite.dst_mac {
        debug!(
            "src_mac: {}, dst_mac: {}, changing dst to: {}",
            packet.get_source(),
            packet.get_destination(),
            dst_mac.0
        );
        packet.set_destination(dst_mac.0);
    }
}

pub fn rewrite_vlan(vlan_packet: &mut MutableVlanPacket, rewrite: &DataLinkMetadata) {
    let Some(rewrite) = &rewrite.vlan_rewrite else {
        return;
    };
    debug!(
        "vlan_id: {}, changing to: {}",
        vlan_packet.get_vlan_identifier(),
        rewrite.vlan_id
    );
    vlan_packet.set_vlan_identifier(rewrite.vlan_id);
}

pub fn rewrite_ipv4(ipv4_packet: &mut MutableIpv4Packet, rewrite: &IpMetadata) {
    let Some(rewrite) = &rewrite.ipv4_rewrite else {
        return;
    };

    if let Some(src_ip) = rewrite.src_ip {
        debug!(
            "src_ip: {}, dst_ip: {}, changing src to: {}",
            ipv4_packet.get_source(),
            ipv4_packet.get_destination(),
            src_ip
        );
        ipv4_packet.set_source(src_ip)
    }
    if let Some(dst_ip) = rewrite.dst_ip {
        debug!(
            "src_ip: {}, dst_ip: {}, changing dst to: {}",
            ipv4_packet.get_source(),
            ipv4_packet.get_destination(),
            dst_ip
        );
        ipv4_packet.set_destination(dst_ip);
    };
}

pub fn rewrite_ipv6(ipv6_packet: &mut MutableIpv6Packet, rewrite: &IpMetadata) {
    let Some(rewrite) = &rewrite.ipv6_rewrite else {
        return;
    };

    if let Some(src_ip) = rewrite.src_ip {
        debug!(
            "src_ip: {}, dst_ip: {}, changing src to: {}",
            ipv6_packet.get_source(),
            ipv6_packet.get_destination(),
            src_ip
        );
        ipv6_packet.set_source(src_ip)
    }
    if let Some(dst_ip) = rewrite.dst_ip {
        debug!(
            "src_ip: {}, dst_ip: {}, changing dst to: {}",
            ipv6_packet.get_source(),
            ipv6_packet.get_destination(),
            dst_ip
        );
        ipv6_packet.set_destination(dst_ip);
    };
}

pub fn rewrite_udp(packet: &mut MutableUdpPacket, rewrite: &Option<PortMetadata>) {
    if let Some(rewrite) = rewrite {
        if let Some(src) = rewrite.src_port {
            debug!(
                "src_port: {}, dst_port: {}, changing src to: {}",
                packet.get_source(),
                packet.get_destination(),
                src
            );
            packet.set_source(src);
        }
        if let Some(dst) = rewrite.dst_port {
            debug!(
                "src_port: {}, dst_port: {}, changing dst to: {}",
                packet.get_source(),
                packet.get_destination(),
                dst
            );
            packet.set_destination(dst);
        }
    }
}

pub fn rewrite_tcp(packet: &mut MutableTcpPacket, rewrite: &Option<PortMetadata>) {
    if let Some(rewrite) = rewrite {
        if let Some(src) = rewrite.src_port {
            debug!(
                "src_port: {}, dst_port: {}, changing src to: {}",
                packet.get_source(),
                packet.get_destination(),
                src
            );
            packet.set_source(src);
        }
        if let Some(dst) = rewrite.dst_port {
            debug!(
                "src_port: {}, dst_port: {}, changing src to: {}",
                packet.get_source(),
                packet.get_destination(),
                dst
            );
            packet.set_destination(dst);
        }
    };
}
