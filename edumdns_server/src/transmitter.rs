use crate::error::{ServerError, ServerErrorKind};
use edumdns_core::app_packet::{
    AppPacket, CommandPacket, PacketTransmitRequestPacket, ProbePacket,
};
use edumdns_core::connection::UdpConnection;
use edumdns_core::error::CoreError;
use log::{debug, error};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio::time::Instant;

pub struct PacketTransmitterTask {
    pub transmitter_task: JoinHandle<()>,
}

impl PacketTransmitterTask {
    pub fn new(transmitter: PacketTransmitter) -> Self {
        let transmitter_task = tokio::task::spawn(async move { transmitter.transmit().await });
        Self { transmitter_task }
    }
}

pub struct PacketTransmitter {
    pub payloads: HashSet<Vec<u8>>,
    pub transmit_request: PacketTransmitRequestPacket,
    pub udp_connection: UdpConnection,
    pub duration: Duration,
    pub interval: Duration,
    pub global_timeout: Duration,
}

impl PacketTransmitter {
    pub async fn new(
        payloads: HashSet<Vec<u8>>,
        target: PacketTransmitRequestPacket,
        duration: Duration,
        interval: Duration,
        global_timeout: Duration,
    ) -> Result<Self, ServerError> {
        Ok(Self {
            payloads,
            transmit_request: target.clone(),
            udp_connection: UdpConnection::new(global_timeout).await?,
            duration,
            interval,
            global_timeout,
        })
    }

    pub async fn transmit(&self) {
        let mut current_time = Duration::default();
        let host = format!(
            "{}:{}",
            self.transmit_request.target_ip, self.transmit_request.target_port
        );

        loop {
            let start_time = Instant::now();
            for payload in self.payloads.iter() {
                match self
                    .udp_connection
                    .send_packet(host.as_str(), payload.as_ref())
                    .await
                {
                    Ok(_) => {}
                    Err(e) => {
                        error!("Error sending packet to: {host}: {e}");
                        return;
                    }
                }
                tokio::time::sleep(self.interval).await;
                debug!(
                    "Packet sent from device: {} to client: {}",
                    self.transmit_request.device_ip, self.transmit_request.target_ip
                );
            }
            let total = start_time.elapsed();
            current_time += total;
            if current_time >= self.duration {
                break;
            }
        }
    }
}
