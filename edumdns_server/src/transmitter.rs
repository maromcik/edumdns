use crate::error::ServerError;
use edumdns_core::app_packet::{NetworkCommandPacket, PacketTransmitRequestPacket, ProbePacket};
use edumdns_core::connection::UdpConnection;

use log::{debug, error, info};
use std::collections::HashSet;

use std::time::Duration;

use crate::DEFAULT_INTERVAL_MULTIPLICATOR;
use tokio::task::JoinHandle;

pub struct PacketTransmitterTask {
    pub transmitter_task: JoinHandle<()>,
}

impl PacketTransmitterTask {
    pub fn new(transmitter: PacketTransmitter) -> Self {
        let transmitter_task = tokio::task::spawn(async move {
            transmitter.transmit().await;
            info!("Transmitter task finished")
        });
        Self { transmitter_task }
    }
}

pub struct PacketTransmitter {
    pub payloads: HashSet<Vec<u8>>,
    pub transmit_request: PacketTransmitRequestPacket,
    pub udp_connection: UdpConnection,
    pub interval: Duration,
    pub global_timeout: Duration,
}

impl PacketTransmitter {
    pub async fn new(
        payloads: HashSet<Vec<u8>>,
        target: PacketTransmitRequestPacket,
        interval: Duration,
        global_timeout: Duration,
    ) -> Result<Self, ServerError> {
        Ok(Self {
            payloads,
            transmit_request: target.clone(),
            udp_connection: UdpConnection::new(global_timeout).await?,
            interval,
            global_timeout,
        })
    }

    pub async fn transmit(&self) {
        let host = format!(
            "{}:{}",
            self.transmit_request.target_ip.ip(),
            self.transmit_request.target_port
        );
        info!("Initiating packet transmission to: {}", host);
        loop {
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
                debug!(
                    "Packet sent from device: {} to client: {}",
                    self.transmit_request.device_ip, self.transmit_request.target_ip
                );
                tokio::time::sleep(self.interval).await;
            }
            debug!(
                "All packets sent; waiting for: {:?}",
                self.interval * DEFAULT_INTERVAL_MULTIPLICATOR
            );
            tokio::time::sleep(self.interval * DEFAULT_INTERVAL_MULTIPLICATOR).await;
            debug!("Repeating packet transmission...");
        }
    }
}
