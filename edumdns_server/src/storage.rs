use std::collections::{HashMap, HashSet};
use log::debug;
use tokio::sync::mpsc::Receiver;
use edumdns_core::addr_types::MacAddr;
use edumdns_core::packet::ProbePacket;

pub struct PacketStorage {
    pub packets: HashMap<MacAddr, HashSet<ProbePacket>>,
    pub packet_receiver: Receiver<ProbePacket>
}


impl PacketStorage {
    pub fn new(receiver: Receiver<ProbePacket>) -> Self {
        Self {
            packets: HashMap::new(),
            packet_receiver: receiver,
        }
    }

    pub async fn fill_packet_storage(&mut self) {

        while let Some(packet) = self.packet_receiver.recv().await {
            let src_mac = packet.metadata.datalink_metadata.mac_metadata.src_mac;
            self.packets.entry(src_mac).or_default().insert(packet);
        }

    }
}
