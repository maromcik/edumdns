//! UDP packet transmission task that replays captured payloads to targets.
//!
//! The transmitter supports optional live updates (additional payloads) and
//! optional DNS A/AAAA rewriting when a proxy IP is configured. It stops either
//! when the request duration elapses or when a stop command is sent.

use crate::app_packet::{
    LocalAppPacket, LocalCommandPacket, LocalDataPacket, PacketTransmitRequestPacket,
};
use crate::config::ServerConfig;
use crate::database::util::get_device_packets;
use crate::error::ServerError;
use crate::server::ebpf::Proxy;
use crate::utils::processing::{process_packets, rewrite_payload};
use edumdns_core::connection::UdpConnection;
use edumdns_db::repositories::packet::repository::PgPacketRepository;
use ipnetwork::NetworkSize;
use log::{debug, error, trace, warn};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::Receiver;
use tokio::time::Instant;

/// UDP transmitter that replays captured payloads to one or more targets.
///
/// A `PacketTransmitter` holds the prepared payloads, targeting information,
/// an internal UDP connection with timeouts, and a channel to receive live
/// updates while running. Live updates may extend the running time or append
/// additional payloads (optionally rewritten for proxy deployments).
pub(crate) struct Transmitter {
    /// Payloads to be sent, in the order they should be replayed.
    pub(crate) payloads: Vec<Vec<u8>>,
    /// Optional proxy IP pair; when present, DNS A/AAAA answers in live-updated
    /// payloads are rewritten to these addresses.
    pub(crate) proxy: Option<Proxy>,
    /// Original transmit request describing device, target IP/port, interval and duration.
    pub(crate) transmit_request: Arc<PacketTransmitRequestPacket>,
    /// UDP connection wrapper that applies the configured global timeout.
    pub(crate) udp_connection: UdpConnection,
    /// Receiver for live updates and control commands (e.g., extend duration, add payload).
    pub(crate) live_updates_receiver: Receiver<LocalAppPacket>,
    pub(crate) server_config: Arc<ServerConfig>,
}

impl Transmitter {
    /// Construct a new `PacketTransmitter`.
    ///
    /// Parameters:
    /// - `payloads`: ordered list of UDP payloads to replay.
    /// - `proxy_ip`: when `Some`, live-updated DNS payloads will have A/AAAA
    ///   records rewritten to these addresses.
    /// - `target`: bundle containing device metadata and the transmit request
    ///   (target IPs/port, interval, duration, permanence).
    /// - `global_timeout`: timeout applied to UDP send operations.
    /// - `live_updater`: channel over which live updates and control commands
    ///   are received while transmission is in progress.
    ///
    /// Returns:
    /// - `Ok(Self)` when the UDP connection is created successfully.
    /// - `Err(ServerError)` if the UDP connection initialization fails.
    pub(crate) async fn new(
        proxy: Option<Proxy>,
        target: Arc<PacketTransmitRequestPacket>,
        live_updater: Receiver<LocalAppPacket>,
        server_config: Arc<ServerConfig>,
    ) -> Result<Self, ServerError> {
        Ok(Self {
            payloads: Vec::new(),
            proxy,
            transmit_request: target.clone(),
            udp_connection: UdpConnection::new(server_config.connection.global_timeout).await?,
            live_updates_receiver: live_updater,
            server_config,
        })
    }

    pub(crate) async fn validate(&self) -> Result<(), ServerError> {
        if self.proxy.is_none() && self.transmit_request.device.proxy {
            let err = "eBPF is not configured properly; contact your administrator";
            let err = ServerError::EbpfMapError(err.to_string());
            error!("{err} for target: {}", self.transmit_request);
            return Err(err);
        }

        if self.transmit_request.request.target_ip.size()
            > NetworkSize::V4(self.server_config.transmit.max_transmit_subnet_size)
        {
            let warning = format!(
                "the target subnet size ({}) is greater than the maximum allowed ({})",
                self.transmit_request.request.target_ip.size(),
                self.server_config.transmit.max_transmit_subnet_size
            );
            let warning = ServerError::DiscoveryRequestProcessingError(warning);
            warn!("{warning} for target: {}", self.transmit_request);
            return Err(warning);
        }

        if self.transmit_request.device.proxy
            && self.transmit_request.request.target_ip.size() > NetworkSize::V4(1)
        {
            let warning = "when proxy is enabled, the target IP must have prefix /32 for IPv4 or /128 for IPv6";
            warn!("{warning} for target: {}", self.transmit_request);
            let warning = ServerError::DiscoveryRequestProcessingError(warning.to_string());
            return Err(warning);
        }
        Ok(())
    }

    pub(crate) async fn configure_ebpf(&self) -> Result<(), ServerError> {
        if let Some(p) = &self.proxy
            && self.transmit_request.device.proxy
        {
            return match p.ebpf_updater.lock().await.add_ip(
                self.transmit_request.device.ip,
                self.transmit_request.request.target_ip,
            ) {
                Ok(_) => Ok(()),
                Err(e) => Err(e),
            };
        }
        Ok(())
    }

    pub(crate) async fn fetch_packets(
        &mut self,
        packet_repo: PgPacketRepository,
    ) -> Result<(), ServerError> {
        let packets = get_device_packets(packet_repo, &self.transmit_request).await?;
        let payloads = process_packets(packets, &self.proxy, self.transmit_request.device.proxy);
        if payloads.is_empty() {
            let warning = "no packets left after processing";
            warn!("{warning} for target: {}", self.transmit_request);
            let warning = ServerError::DiscoveryRequestProcessingError(warning.to_string());
            return Err(warning);
        }
        self.payloads = payloads;
        Ok(())
    }

    /// Run the transmission loop until duration elapses or a stop condition occurs.
    ///
    /// Behavior:
    /// - Validates target IP list; exits early if empty.
    /// - Computes per-payload interval and overall request duration from
    ///   `transmit_request`.
    /// - Drains the live-update channel opportunistically between bursts to:
    ///   - extend the duration (`ExtendPacketTransmitRequest`), or
    ///   - append additional payloads (`LocalDataPacket::TransmitterLiveUpdateData`).
    /// - Sends each payload to every target IP, waiting `interval` between
    ///   payloads; after a full round, sleeps `interval * DEFAULT_INTERVAL_MULTIPLICATOR`.
    /// - If `permanent` is false, stops once `duration` has elapsed since the
    ///   last extension.
    ///
    /// Side effects:
    /// - Performs UDP I/O; logs warnings/errors for invalid inputs and I/O issues.
    pub(crate) async fn transmit(&mut self) {
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
        let sleep_interval = interval
            * self
                .server_config
                .transmit
                .transmit_repeat_delay_multiplicator;
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

    /// Send a single UDP payload to the provided socket address.
    ///
    /// Parameters:
    /// - `socket_addr`: target in `IP:PORT` form (IPv4 or IPv6 with port).
    /// - `payload`: raw UDP payload bytes to transmit.
    ///
    /// Side effects:
    /// - Performs a UDP send via `udp_connection`; logs errors but does not
    ///   propagate them to the caller (non-fatal within the transmit loop).
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
            self.transmit_request.device.ip, socket_addr
        );
    }

    /// Handle a live-update data packet coming from the manager.
    ///
    /// Currently supported updates:
    /// - `LocalDataPacket::TransmitterLiveUpdateData(Vec<u8>)` — appends an
    ///   additional payload to the replay list. If a proxy IP is configured,
    ///   attempts to rewrite DNS A/AAAA records to the proxy addresses before
    ///   storing. If rewriting fails to parse the payload as DNS, the payload is
    ///   ignored when proxying; without proxying, the raw payload is always
    ///   appended.
    ///
    /// Parameters:
    /// - `packet`: the live update packet.
    ///
    /// Side effects:
    /// - Mutates `self.payloads` by pushing new payloads; logs debug messages.
    async fn handle_data_packet(&mut self, packet: LocalDataPacket) {
        match packet {
            LocalDataPacket::TransmitterLiveUpdateData(payload) => match &self.proxy {
                None => {
                    self.payloads.push(payload);
                    debug!("Packet from live update stored");
                }
                Some(proxy_ip) => {
                    if let Some(rewritten_payload) =
                        rewrite_payload(payload, proxy_ip.proxy_ip.ipv4, proxy_ip.proxy_ip.ipv6)
                    {
                        self.payloads.push(rewritten_payload);
                        debug!("Rewritten and stored packet from live update");
                    }
                }
            },
        }
    }
}
