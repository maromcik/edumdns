use crate::app_packet::{
    AppPacket, LocalAppPacket, LocalCommandPacket, PacketTransmitRequestPacket,
};
use crate::error::ServerError;
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::deadpool::Pool;
use edumdns_db::models::Packet;
use edumdns_db::repositories::device::repository::PgDeviceRepository;
use hickory_proto::op::Message;
use hickory_proto::rr::{RData, Record};
use hickory_proto::serialize::binary::BinDecodable;
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::sync::mpsc::Sender;

pub fn rewrite_records(record: &mut Record, ipv4: Ipv4Addr, ipv6: Ipv6Addr) {
    if record.data().is_a() {
        record.set_data(RData::A(hickory_proto::rr::rdata::a::A::from(ipv4)));
    }
    if record.data().is_aaaa() {
        record.set_data(RData::AAAA(hickory_proto::rr::rdata::aaaa::AAAA::from(
            ipv6,
        )));
    }
}

pub fn rewrite_payloads(packets: Vec<Packet>, ipv4: Ipv4Addr, ipv6: Ipv6Addr) -> Vec<Vec<u8>> {
    let mut payloads = Vec::new();
    for packet in packets {
        let Ok(mut message) = Message::from_bytes(packet.payload.as_slice()) else {
            continue;
        };
        for ans in message.answers_mut() {
            rewrite_records(ans, ipv4, ipv6);
        }
        for add in message.additionals_mut() {
            rewrite_records(add, ipv4, ipv6);
        }
        if let Ok(bytes) = message.to_vec() {
            payloads.push(bytes);
        }
    }
    payloads
}

pub async fn load_all_packet_transmit_requests(
    pool: Pool<AsyncPgConnection>,
    tx: Sender<AppPacket>,
) -> Result<(), ServerError> {
    let device_repo = PgDeviceRepository::new(pool);
    let requests = device_repo.get_all_packet_transmit_requests().await?;
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
