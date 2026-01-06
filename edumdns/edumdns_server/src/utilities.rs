//! Helper utilities: payload rewriting, filtering and bootstrapping transmit tasks.
//!
//! - DNS A/AAAA record rewriting utilities for proxy scenarios
//! - Filtering only valid DNS application packets when no proxy is used
//! - Loading persisted transmit requests from DB into running transmitter tasks

use crate::app_packet::{
    AppPacket, LocalAppPacket, LocalCommandPacket, PacketTransmitRequestPacket,
};
use crate::database::DbCommand;
use crate::error::ServerError;
use crate::manager::Proxy;
use edumdns_core::network_packet::ApplicationPacket;
use edumdns_db::models::Packet;
use hickory_proto::op::Message;
use hickory_proto::rr::{RData, Record};
use hickory_proto::serialize::binary::BinDecodable;
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::sync::mpsc::Sender;

pub(crate) fn rewrite_records(record: &mut Record, ipv4: Ipv4Addr, ipv6: Ipv6Addr) {
    if record.data().is_a() {
        record.set_data(RData::A(hickory_proto::rr::rdata::a::A::from(ipv4)));
    }
    if record.data().is_aaaa() {
        record.set_data(RData::AAAA(hickory_proto::rr::rdata::aaaa::AAAA::from(
            ipv6,
        )));
    }
}

pub(crate) fn rewrite_payload(payload: Vec<u8>, ipv4: Ipv4Addr, ipv6: Ipv6Addr) -> Option<Vec<u8>> {
    let mut message = Message::from_bytes(payload.as_slice()).ok()?;
    for ans in message.answers_mut() {
        rewrite_records(ans, ipv4, ipv6);
    }
    for add in message.additionals_mut() {
        rewrite_records(add, ipv4, ipv6);
    }
    message.to_vec().ok()
}

pub(crate) fn rewrite_payloads(
    payloads: Vec<Vec<u8>>,
    ipv4: Ipv4Addr,
    ipv6: Ipv6Addr,
) -> Vec<Vec<u8>> {
    payloads
        .into_iter()
        .filter_map(|p| rewrite_payload(p, ipv4, ipv6))
        .collect()
}

pub(crate) fn process_packets(
    packets: Vec<Packet>,
    proxy: &Option<Proxy>,
    use_proxy: bool,
) -> Vec<Vec<u8>> {
    match (proxy, use_proxy) {
        (Some(p), true) => {
            let payloads = packets.into_iter().map(|p| p.payload).collect::<Vec<_>>();
            rewrite_payloads(payloads, p.proxy_ip.ipv4, p.proxy_ip.ipv6)
        }
        _ => packets
            .into_iter()
            .filter_map(|p| {
                match ApplicationPacket::from_bytes(&p.payload, p.src_port, p.dst_port) {
                    Ok(_) => Some(p.payload),
                    Err(_) => None,
                }
            })
            .collect(),
    }
}

pub(crate) async fn load_all_packet_transmit_requests(
    tx: Sender<AppPacket>,
    db_transmitter: Sender<DbCommand>,
) -> Result<(), ServerError> {
    let chan = tokio::sync::oneshot::channel();
    db_transmitter
        .send(DbCommand::GetAllPacketTransmitRequests { respond_to: chan.0 })
        .await?;
    let requests = chan.1.await??;
    for (device, request) in requests {
        let packet_transmit_request = PacketTransmitRequestPacket::new(device, request);
        let channel = tokio::sync::oneshot::channel();
        tx.send(AppPacket::Local(LocalAppPacket::Command(
            LocalCommandPacket::TransmitDevicePackets {
                request: packet_transmit_request,
                respond_to: channel.0,
            },
        )))
        .await?;
    }
    Ok(())
}
