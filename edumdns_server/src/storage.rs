use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use log::debug;
use tokio::sync::mpsc::Receiver;
use edumdns_core::addr_types::MacAddr;
use edumdns_core::packet::ProbePacket;
use crate::connection::UdpConnection;
use crate::error::ServerError;
use crate::transmitter::PacketTransmitter;

pub struct PacketStorage {
    pub packets: HashMap<MacAddr, Arc<RwLock<HashSet<ProbePacket>>>>,
    pub packet_receiver: Receiver<ProbePacket>,
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
            self.packets.entry(src_mac).or_default().write().expect("Poisoned rwlock").insert(packet);
        }

    }
    
    pub async fn transmit_device_packets(&self, mac_addr: MacAddr) -> Result<(), ServerError> {
        let packets = self.packets.get(&mac_addr);
        
        if let Some(packets) = packets {
            let packets = packets.clone();
            tokio::task::spawn(
                async move {
                    let transmitter = PacketTransmitter::new(packets, Duration::default(), Duration::default()).await?;
                    transmitter.transmit().await;
                    Ok::<(), ServerError>(())
                },
            );        
        }
        
        Ok(())
    }
    
}
