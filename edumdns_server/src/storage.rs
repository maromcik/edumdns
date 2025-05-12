use crate::error::ServerError;
use crate::transmitter::{PacketTransmitter, PacketTransmitterTask};
use edumdns_core::addr_types::MacAddr;
use edumdns_core::app_packet::{AppPacket, CommandPacket, PacketTransmitTarget, ProbePacket};
use log::{debug, error, info, warn};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::sync::mpsc::{Receiver, Sender};

pub struct PacketStorage {
    pub packets: HashMap<MacAddr, Arc<RwLock<HashSet<ProbePacket>>>>,
    pub packet_receiver: Receiver<AppPacket>,
    pub transmitter_tasks: Vec<PacketTransmitterTask>,
    pub error_sender: Sender<ServerError>,
}

impl PacketStorage {
    pub fn new(receiver: Receiver<AppPacket>, error_sender: Sender<ServerError>) -> Self {
        Self {
            packets: HashMap::new(),
            packet_receiver: receiver,
            transmitter_tasks: Vec::new(),
            error_sender,
        }
    }

    pub async fn handle_packets(&mut self) {
        while let Some(packet) = self.packet_receiver.recv().await {
            println!("Channel: {}", self.packet_receiver.len());
            if let Some(hash) = self.packets.get(&MacAddr(
                "00:00:00:00:00:00"
                    .parse::<pnet::datalink::MacAddr>()
                    .unwrap(),
            )) {
                let x = hash.read().await.len();
                println!("Hash: {}", x);
            }
            match packet {
                AppPacket::Command(command) => match command {
                    CommandPacket::TransmitDevicePackets(target) => {
                        if let Err(e) = self.transmit_device_packets(&target).await {
                            error!("Error while transmitting packets to target {}: {}", &target, e);
                        };
                    }
                    CommandPacket::PingRequest() => {}
                    CommandPacket::PingResponse() => {}
                },
                AppPacket::Data(probe_packet) => {
                    let src_mac = probe_packet.metadata.datalink_metadata.mac_metadata.src_mac;
                    debug!("Packet stored: {:?}", probe_packet.id);
                    self.packets
                        .entry(src_mac)
                        .or_default()
                        .write()
                        .await
                        .insert(probe_packet);
                }
            }
        }
    }

    pub async fn transmit_device_packets(
        &mut self,
        target: &PacketTransmitTarget,
    ) -> Result<(), ServerError> {
        let packets = self.packets.get(&target.mac);
        let Some(packets) = packets else {
            warn!("No packets found for mac address: {}", target.mac);
            return Ok(());
        };

        info!("Packets found for mac address: {}", target.mac);
        let packets = packets.clone();
        let transmitter = PacketTransmitter::new(
            packets,
            target,
            Duration::from_secs(60),
            Duration::from_millis(100),
        )
        .await?;
        self.transmitter_tasks
            .push(PacketTransmitterTask::new(transmitter));

        Ok(())
    }
}
