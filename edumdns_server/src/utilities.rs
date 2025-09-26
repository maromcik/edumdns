use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};
use hickory_proto::op::Message;
use hickory_proto::rr::{RData, Record};
use hickory_proto::serialize::binary::BinDecodable;
use edumdns_db::models::Packet;

pub fn rewrite_records(record: &mut Record, ipv4: Ipv4Addr, ipv6: Ipv6Addr) {
    if record.data().is_a() {
        record.set_data(RData::A(hickory_proto::rr::rdata::a::A::from(
            ipv4,
        )));
    }
    if record.data().is_aaaa() {
        record.set_data(RData::AAAA(hickory_proto::rr::rdata::aaaa::AAAA::from(
            ipv6,
        )));
    }
}

pub fn rewrite_payloads(packets: Vec<Packet>, ipv4: Ipv4Addr, ipv6: Ipv6Addr) -> HashSet<Vec<u8>> {
    let mut payloads = HashSet::new();
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
            payloads.insert(bytes);
        }
    }
    payloads
}