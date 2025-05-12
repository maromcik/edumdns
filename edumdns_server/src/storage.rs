use crate::error::ServerError;
use crate::transmitter::PacketTransmitter;
use edumdns_core::addr_types::MacAddr;
use edumdns_core::app_packet::{AppPacket, CommandPacket, ProbePacket};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use log::{debug, error, info};
use tokio::sync::mpsc::Receiver;
use tokio::sync::RwLock;

pub struct PacketStorage {
    pub packets: HashMap<MacAddr, Arc<RwLock<HashSet<ProbePacket>>>>,
    pub packet_receiver: Receiver<AppPacket>,
}


impl PacketStorage {
    pub fn new(receiver: Receiver<AppPacket>) -> Self {
        Self {
            packets: HashMap::new(),
            packet_receiver: receiver,
        }
    }

    pub async fn handle_packets(&mut self) {

        while let Some(packet) = self.packet_receiver.recv().await {
            match packet {
                AppPacket::Command(command) => {
                    match command {
                        CommandPacket::TransmitDevicePackets(mac_addr) => {
                            // TODO write error to the database
                            self.transmit_device_packets(mac_addr).await;
                        }
                        CommandPacket::PingRequest() => {}
                        CommandPacket::PingResponse() => {}
                    }
                }
                AppPacket::Data(probe_packet) => {
                    let src_mac = probe_packet.metadata.datalink_metadata.mac_metadata.src_mac;
                    debug!("Packet stored: {:?}", probe_packet.id);
                    self.packets.entry(src_mac).or_default().write().await.insert(probe_packet);

                }
            }

        }
    }
    
    pub async fn transmit_device_packets(&self, mac_addr: MacAddr) -> Result<(), ServerError> {
        let packets = self.packets.get(&mac_addr);
        if let Some(packets) = packets {
            info!("Found packets for mac address: {:?}", mac_addr);
            let packets = packets.clone();
            let transmitter = PacketTransmitter::new(packets, Duration::from_secs(100), Duration::from_millis(100)).await?;
            tokio::task::spawn(
                async move {
                    transmitter.transmit().await?;
                    Ok::<(), ServerError>(())
                },
            );        
        }
        else {
            error!("Couldn't find packets for mac address: {:?}", mac_addr);
        }
        
        Ok(())
    }
    
}
