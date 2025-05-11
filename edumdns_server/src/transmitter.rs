use std::collections::HashSet;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use edumdns_core::packet::ProbePacket;
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
    
    pub async fn transmit(&self) {
        loop {
            for packet in self.packets.read().expect("Poisoned rwlock").iter() {

            }
        }
    }
}