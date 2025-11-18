use crate::DEFAULT_INTERVAL_MULTIPLICATOR;
use crate::app_packet::{
    AppPacket, LocalAppPacket, LocalCommandPacket, LocalDataPacket, PacketTransmitRequestPacket,
};
use crate::error::ServerError;
use crate::manager::ProxyIp;
use crate::utilities::rewrite_payload;
use edumdns_core::app_packet::Id;
use edumdns_core::connection::UdpConnection;
use log::{debug, error, info, trace, warn};
use std::time::Duration;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::task::JoinHandle;
use tokio::time::Instant;

pub struct PacketTransmitterTask {
    pub transmitter_task: JoinHandle<()>,
}

impl PacketTransmitterTask {
    pub fn new(
        mut transmitter: PacketTransmitter,
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
                .map_err(ServerError::from)
            {
                error!("Error sending stop transmit command for request {request_id}: {e}");
            }
        });
        Self { transmitter_task }
    }
}

pub struct PacketTransmitter {
    pub payloads: Vec<Vec<u8>>,
    pub proxy_ip: Option<ProxyIp>,
    pub transmit_request: PacketTransmitRequestPacket,
    pub udp_connection: UdpConnection,
    pub live_updates_receiver: Receiver<LocalAppPacket>,
}

impl PacketTransmitter {
    pub async fn new(
        payloads: Vec<Vec<u8>>,
        proxy_ip: Option<ProxyIp>,
        target: PacketTransmitRequestPacket,
        global_timeout: Duration,
        live_updater: Receiver<LocalAppPacket>,
    ) -> Result<Self, ServerError> {
        Ok(Self {
            payloads,
            proxy_ip,
            transmit_request: target.clone(),
            udp_connection: UdpConnection::new(global_timeout).await?,
            live_updates_receiver: live_updater,
        })
    }

    pub async fn transmit(&mut self) {
        let ips = self
            .transmit_request
            .request
            .target_ip
            .into_iter()
            .collect::<Vec<_>>();
        if ips.is_empty() {
            warn!(
                "No valid IP addresses found for target: {:?}",
                self.transmit_request.request
            );
            return;
        }
        let interval = Duration::from_millis(self.transmit_request.device.interval as u64);
        let duration = Duration::from_secs(self.transmit_request.device.duration as u64);
        let sleep_interval = interval * DEFAULT_INTERVAL_MULTIPLICATOR;
        let mut total_time = Instant::now();
        loop {
            while let Ok(update) = self.live_updates_receiver.try_recv() {
                match update {
                    LocalAppPacket::Command(command) => match command {
                        LocalCommandPacket::ExtendPacketTransmitRequest(_) => {
                            total_time = Instant::now()
                        }
                        _ => {}
                    },
                    LocalAppPacket::Status(_) => {}
                    LocalAppPacket::Data(data) => self.handle_data_packet(data).await,
                }

                if !self.transmit_request.request.permanent && total_time.elapsed() > duration {
                    debug!("Duration exceeded; stopping transmission in live updater");
                    return;
                }
            }
            for payload in self.payloads.iter() {
                for ip in &ips {
                    let host = format!("{}:{}", ip, self.transmit_request.request.target_port);
                    self.send_packet(host.as_str(), payload).await;
                }

                if !self.transmit_request.request.permanent && total_time.elapsed() > duration {
                    debug!("Duration exceeded; stopping transmission during packet transmission");
                    return;
                }
                tokio::time::sleep(interval).await;
            }
            if !self.transmit_request.request.permanent && total_time.elapsed() > duration {
                debug!("Duration exceeded; stopping transmission before repeating");
                return;
            }
            debug!("All packets sent; waiting for: {:?}", sleep_interval);
            tokio::time::sleep(sleep_interval).await;
            debug!("Repeating packet transmission...");
        }
    }

    async fn send_packet(&self, socket_addr: &str, payload: &[u8]) {
        match self.udp_connection.send_packet(socket_addr, payload).await {
            Ok(_) => {}
            Err(e) => {
                error!("Error sending packet to: {socket_addr}: {e}");
                return;
            }
        }
        trace!(
            "Packet sent from device: {} to client: {}",
            self.transmit_request.device.ip, self.transmit_request.request.target_ip
        );
    }

    async fn handle_data_packet(&mut self, packet: LocalDataPacket) {
        match packet {
            LocalDataPacket::TransmitterLiveUpdateData(payload) => match &self.proxy_ip {
                None => {
                    self.payloads.push(payload);
                    debug!("Packet from live update stored");
                }
                Some(proxy_ip) => {
                    if let Some(rewritten_payload) =
                        rewrite_payload(payload, proxy_ip.ipv4, proxy_ip.ipv6)
                    {
                        self.payloads.push(rewritten_payload);
                        debug!("Rewritten and stored packet from live update");
                    }
                }
            },
        }
    }
}
