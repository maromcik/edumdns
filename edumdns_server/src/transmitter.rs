use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use log::debug;
use tokio::sync::RwLock;
use tokio::time::Instant;
use edumdns_core::app_packet::{AppPacket, CommandPacket, ProbePacket};
use crate::connection::UdpConnection;
use crate::error::ServerError;

pub struct PacketTransmitter {
    pub packets: Arc<RwLock<HashSet<ProbePacket>>>,
    pub udp_connection: UdpConnection,
    pub duration: Duration,
    pub interval: Duration,
}

impl PacketTransmitter {
    pub async fn new(packets: Arc<RwLock<HashSet<ProbePacket>>>, duration: Duration, interval: Duration) -> Result<Self, ServerError> {
        Ok(Self {
            packets,
            udp_connection: UdpConnection::new().await?,
            duration,
            interval,
        }) 
    }
    
    pub async fn transmit(&self) -> Result<(), ServerError> {
        let mut current_time = Duration::default();
        loop {
            let start_time = Instant::now();
            for packet in self.packets.read().await.iter() {
                self.udp_connection.send_packet("192.168.4.80:5353", packet.payload.as_ref()).await?;
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