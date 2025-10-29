use crate::error::ServerError;
use edumdns_core::app_packet::{
    AppPacket, LocalAppPacket, LocalCommandPacket, NetworkCommandPacket,
    PacketTransmitRequestPacket, ProbePacket,
};
use edumdns_core::connection::UdpConnection;

use log::{debug, error, info};
use std::collections::HashSet;

use crate::DEFAULT_INTERVAL_MULTIPLICATOR;
use edumdns_core::app_packet::Id;
use edumdns_core::error::CoreError;
use std::time::Duration;
use tokio::sync::mpsc::Sender;
use tokio::task::JoinHandle;
use tokio::time::Instant;

pub struct PacketTransmitterTask {
    pub transmitter_task: JoinHandle<()>,
}

impl PacketTransmitterTask {
    pub fn new(
        transmitter: PacketTransmitter,
        command_transmitter: Sender<AppPacket>,
        request_id: Id,
    ) -> Self {
        let transmitter_task = tokio::task::spawn(async move {
            transmitter.transmit().await;
            info!("Transmitter task finished");
            if let Err(e) = command_transmitter
                .send(AppPacket::Local(LocalAppPacket::Command(
                    LocalCommandPacket::StopTransmitDevicePackets(request_id),
                )))
                .await
                .map_err(CoreError::from)
            {
                error!("Error sending stop transmit command for reqeust {request_id}: {e}");
            }
        });
        Self { transmitter_task }
    }
}

pub struct PacketTransmitter {
    pub payloads: HashSet<Vec<u8>>,
    pub transmit_request: PacketTransmitRequestPacket,
    pub udp_connection: UdpConnection,
    pub global_timeout: Duration,
}

impl PacketTransmitter {
    pub async fn new(
        payloads: HashSet<Vec<u8>>,
        target: PacketTransmitRequestPacket,
        global_timeout: Duration,
    ) -> Result<Self, ServerError> {
        Ok(Self {
            payloads,
            transmit_request: target.clone(),
            udp_connection: UdpConnection::new(global_timeout).await?,
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
        let interval = Duration::from_millis(self.transmit_request.device.interval);
        let duration = Duration::from_secs(self.transmit_request.device.duration);
        let sleep_interval = interval * DEFAULT_INTERVAL_MULTIPLICATOR;
        let total_time = Instant::now();
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
                    self.transmit_request.device.ip, self.transmit_request.target_ip
                );
                if total_time.elapsed() > duration {
                    break;
                }
                tokio::time::sleep(interval).await;
            }
            if total_time.elapsed() > duration {
                return;
            }
            debug!("All packets sent; waiting for: {:?}", sleep_interval);
            tokio::time::sleep(sleep_interval).await;
            debug!("Repeating packet transmission...");
        }
    }
}
