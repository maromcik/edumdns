use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use log::debug;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use edumdns_core::app_packet::{AppPacket, CommandPacket, PacketTransmitTarget, ProbePacket};
use crate::connection::UdpConnection;
use crate::error::ServerError;

pub struct PacketTransmitterTask {
    pub target: PacketTransmitTarget,
    pub transmitter_task: JoinHandle< Result<(), ServerError>>,
}

impl PacketTransmitterTask {
    pub fn new(transmitter: PacketTransmitter) -> Self {
        let target = transmitter.target.clone();
        let transmitter_task = tokio::task::spawn(
            async move {
                transmitter.transmit().await?;
                Ok::<(), ServerError>(())
            },
        );
        Self {
            target,
            transmitter_task,
        }
    }
}

pub struct PacketTransmitter {
    pub packets: Arc<RwLock<HashSet<ProbePacket>>>,
    pub target: PacketTransmitTarget,
    pub udp_connection: UdpConnection,
    pub duration: Duration,
    pub interval: Duration,
}

impl PacketTransmitter {
    pub async fn new(packets: Arc<RwLock<HashSet<ProbePacket>>>, target: &PacketTransmitTarget, duration: Duration, interval: Duration) -> Result<Self, ServerError> {
        Ok(Self {
            packets,
            target: target.clone(),
            udp_connection: UdpConnection::new().await?,
            duration,
            interval,
        }) 
    }
    
    pub async fn transmit(&self) -> Result<(), ServerError> {
        let mut current_time = Duration::default();
        let host = format!("{}:{}", self.target.ip, self.target.port);
        loop {
            let start_time = Instant::now();
            let packets = {
                let packets = self.packets.read().await;
                packets.clone()
            };
            for packet in packets.iter() {
                self.udp_connection.send_packet(host.as_str(), packet.payload.as_ref()).await?;
                tokio::time::sleep(self.interval).await;
                debug!("Packet sent: {:?}", packet.id);
            }
            let total = start_time.elapsed();
            current_time += total;
            if current_time >= self.duration {
                break;
            }
        }
        Ok(())
    }
}