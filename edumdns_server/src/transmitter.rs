use crate::error::ServerError;
use edumdns_core::app_packet::{AppPacket, CommandPacket, PacketTransmitRequest, ProbePacket};
use edumdns_core::connection::UdpConnection;
use log::debug;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio::time::Instant;

pub struct PacketTransmitterTask {
    pub target: PacketTransmitRequest,
    pub transmitter_task: JoinHandle<Result<(), ServerError>>,
}

impl PacketTransmitterTask {
    pub fn new(transmitter: PacketTransmitter) -> Self {
        let target = transmitter.transmit_request.clone();
        let transmitter_task = tokio::task::spawn(async move {
            transmitter.transmit().await?;
            Ok::<(), ServerError>(())
        });
        Self {
            target,
            transmitter_task,
        }
    }
}

pub struct PacketTransmitter {
    pub payloads: HashSet<Vec<u8>>,
    pub transmit_request: PacketTransmitRequest,
    pub udp_connection: UdpConnection,
    pub duration: Duration,
    pub interval: Duration,
    pub global_timeout: Duration,
}

impl PacketTransmitter {
    pub async fn new(
        payloads: HashSet<Vec<u8>>,
        target: PacketTransmitRequest,
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

    pub async fn transmit(&self) -> Result<(), ServerError> {
        let mut current_time = Duration::default();
        let host = format!(
            "{}:{}",
            self.transmit_request.target.ip, self.transmit_request.target.port
        );
        loop {
            let start_time = Instant::now();
            for payload in self.payloads.iter() {
                self.udp_connection
                    .send_packet(host.as_str(), payload.as_ref())
                    .await?;
                tokio::time::sleep(self.interval).await;
                debug!("Packet sent from device: {} to client: {}", self.transmit_request.device.ip, self.transmit_request.target.ip);
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
