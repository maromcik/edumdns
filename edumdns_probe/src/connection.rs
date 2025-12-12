//! Connection management for probe-to-server communication.
//!
//! This module handles the TCP connection between the probe and the central server,
//! including:
//! - Connection establishment with retry logic
//! - TLS handshake (if enabled)
//! - Connection initialization and authentication
//! - Packet transmission and reception
//! - Automatic reconnection on failures
//! - Ping/keepalive mechanism
//!

use crate::error::ProbeError;
use edumdns_core::app_packet::{
    NetworkAppPacket, NetworkCommandPacket, NetworkStatusPacket, ProbeConfigPacket,
};
use edumdns_core::bincode_types::{MacAddr, Uuid};
use edumdns_core::connection::{TcpConnectionHandle, TcpConnectionMessage};
use edumdns_core::error::CoreError;
use edumdns_core::metadata::ProbeMetadata;
use edumdns_core::retry;
use log::{debug, error, info, trace, warn};
use pnet::ipnetwork;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug)]
pub(crate) struct ConnectionLimits {
    pub(crate) max_retries: usize,
    pub(crate) retry_interval: Duration,
    pub(crate) global_timeout: Duration,
    pub(crate) buffer_capacity: usize,
}

#[derive(Clone, Debug)]
pub(crate) struct ConnectionInfo {
    pub(crate) host: String,
    pub(crate) server_conn_socket_addr: String,
    pub(crate) pre_shared_key: Option<String>,
    pub(crate) no_tls: bool,
}

pub(crate) struct ReceivePacketTargets {
    pub(crate) pinger: mpsc::Sender<NetworkAppPacket>,
}

pub(crate) struct ConnectionManager {
    pub(crate) handle: TcpConnectionHandle,
    pub(crate) probe_metadata: ProbeMetadata,
    pub(crate) conn_info: ConnectionInfo,
    pub(crate) conn_limits: ConnectionLimits,
}

#[hotpath::measure_all]
impl ConnectionManager {
    pub async fn connect(
        connection_info: &ConnectionInfo,
        connection_limits: &ConnectionLimits,
    ) -> Result<TcpConnectionHandle, ProbeError> {
        let handle = if connection_info.no_tls {
            retry!(
                TcpConnectionHandle::connect(
                    connection_info.server_conn_socket_addr.as_ref(),
                    connection_limits.global_timeout,
                    connection_limits.buffer_capacity,
                )
                .await,
                connection_limits.max_retries,
                connection_limits.retry_interval
            )?
        } else {
            let mut root_cert_store = rustls::RootCertStore::empty();
            root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let config = rustls::ClientConfig::builder()
                .with_root_certificates(root_cert_store)
                .with_no_client_auth();
            retry!(
                TcpConnectionHandle::connect_tls(
                    connection_info.server_conn_socket_addr.as_ref(),
                    connection_info.host.as_ref(),
                    Arc::new(config.clone()),
                    connection_limits.global_timeout,
                    connection_limits.buffer_capacity,
                )
                .await,
                connection_limits.max_retries,
                connection_limits.retry_interval
            )?
        };
        Ok(handle)
    }

    pub async fn new(
        uuid: Uuid,
        connection_info: ConnectionInfo,
        connection_limits: ConnectionLimits,
    ) -> Result<Self, ProbeError> {
        let handle = Self::connect(&connection_info, &connection_limits).await?;
        let local_addr = handle.connection_info.local_addr.ip();
        let probe_metadata = ProbeMetadata::new(uuid, determine_mac(&local_addr)?, local_addr);
        Ok(Self {
            handle,
            probe_metadata,
            conn_info: connection_info,
            conn_limits: connection_limits,
        })
    }

    /// Initializes the probe connection with the server and retrieves configuration.
    ///
    /// This function performs the initial handshake with the server:
    /// 1. Sends a ProbeHello packet with probe metadata and optional pre-shared key
    /// 2. Receives server response (ProbeAdopted, ProbeUnknown, or error)
    /// 3. If adopted, requests probe configuration
    /// 4. Receives and returns the ProbeConfigPacket
    ///
    /// # Returns
    ///
    /// Returns `Ok(ProbeConfigPacket)` containing the server's configuration for this
    /// probe (interface filters, capture settings), or a `ProbeError` if:
    /// - The probe is not adopted (ProbeUnknown) - triggers reconnection
    /// - Connection initiation is invalid - triggers reconnection
    /// - A probe with the same UUID is already connected
    /// - The probe did not provide a matching PSK, if a PSK is configured
    /// in the server database
    /// - Network I/O fails
    /// - Unexpected packet types are received
    ///
    /// # Behavior
    ///
    /// If the probe is not adopted or connection initiation fails, this function
    /// automatically triggers a reconnection after a delay.
    pub async fn connection_init_probe(&mut self) -> Result<ProbeConfigPacket, ProbeError> {
        let error = Err(ProbeError::InvalidConnectionInitiation(
            "Invalid connection initiation".to_string(),
        ));
        let hello_packet = NetworkAppPacket::Status(NetworkStatusPacket::ProbeHello(
            self.probe_metadata.clone(),
            self.conn_info.pre_shared_key.clone(),
        ));

        self.handle
            .send_message_with_response(|tx| TcpConnectionMessage::send_packet(tx, hello_packet))
            .await??;

        let packet = self.receive_init_packet().await?;

        if let NetworkAppPacket::Status(NetworkStatusPacket::ProbeUnknown) = packet {
            warn!("Probe is not adopted, make sure to adopt it in the web interface first");
            sleep(self.conn_limits.retry_interval).await;
            return Box::pin(self.reconnect()).await;
        }

        if let NetworkAppPacket::Status(NetworkStatusPacket::ProbeInvalidConnectionInitiation(
            error,
        )) = packet
        {
            warn!("Invalid connection initiation from server: {}", error);
            sleep(self.conn_limits.retry_interval).await;
            return Box::pin(self.reconnect()).await;
        }

        let NetworkAppPacket::Status(NetworkStatusPacket::ProbeAdopted) = packet else {
            return error;
        };
        let probe_packet = NetworkAppPacket::Status(NetworkStatusPacket::ProbeRequestConfig(
            self.probe_metadata.clone(),
        ));

        self.handle
            .send_message_with_response(|tx| TcpConnectionMessage::send_packet(tx, probe_packet))
            .await??;

        let packet = self.receive_init_packet().await?;

        let NetworkAppPacket::Status(NetworkStatusPacket::ProbeResponseConfig(config)) = packet
        else {
            return error;
        };
        info!(
            "Successfully connected to {} ({}) from local address {}",
            self.conn_info.host,
            self.handle.connection_info.peer_addr,
            self.handle.connection_info.local_addr
        );

        debug!("Obtained config <{config:?}>");
        Ok(config)
    }

    pub async fn receive_init_packet(&mut self) -> Result<NetworkAppPacket, ProbeError> {
        let packet = self
            .handle
            .send_message_with_response(|tx| {
                TcpConnectionMessage::receive_packet(tx, Some(self.conn_limits.global_timeout))
            })
            .await?;
        match packet {
            Ok(Some(app_packet)) => Ok(app_packet),
                Ok(None) => Err(ProbeError::InvalidConnectionInitiation(
                    "Invalid connection initiation".to_string())),
            Err(e) => Err(CoreError::ConnectionError(format!("{e}. Server probably uses TLS, and the probe does not. Try to remove the '-n' option.")).into())
        }
    }

    /// Reconnects to the server and re-initializes the connection.
    ///
    /// This function closes the current connection, establishes a new connection,
    /// updates the probe metadata (MAC address may change), and performs the full
    /// connection initialization sequence again.
    ///
    /// # Returns
    ///
    /// Returns `Ok(ProbeConfigPacket)` with the new configuration if reconnection
    /// succeeds, or a `ProbeError` if:
    /// - Connection establishment fails
    /// - Connection initialization fails
    ///
    /// # Side Effects
    ///
    /// - Closes the existing TCP connection
    /// - Updates `probe_metadata` with new MAC address (if interface changed)
    /// - Updates `handle` with the new connection
    pub async fn reconnect(&mut self) -> Result<ProbeConfigPacket, ProbeError> {
        self.handle.close().await?;
        match Self::connect(&self.conn_info, &self.conn_limits).await {
            Ok(connection) => {
                let local_addr = connection.connection_info.local_addr.ip();
                self.probe_metadata = ProbeMetadata::new(
                    self.probe_metadata.id,
                    determine_mac(&local_addr)?,
                    local_addr,
                );
                self.handle = connection;
                self.connection_init_probe().await
            }
            Err(e) => {
                error!("Failed to reconnect: {e}");
                Err(e)
            }
        }
    }


    pub async fn send_packet_with_reconnect(
        handle: &TcpConnectionHandle,
        command_transmitter: &mpsc::Sender<NetworkAppPacket>,
        max_retries: usize,
        retry_interval: Duration,
        packet: NetworkAppPacket,
    ) -> Result<(), ProbeError> {
        let mut counter = 0;
        loop {
            let res = match packet {
                NetworkAppPacket::Data(_) => {
                    handle
                        .send_message_with_response(|tx| {
                            TcpConnectionMessage::send_packet_buffered(tx, packet.clone())
                        })
                        .await?
                }
                _ => {
                    handle
                        .send_message_with_response(|tx| {
                            TcpConnectionMessage::send_packet(tx, packet.clone())
                        })
                        .await?
                }
            };
            match res {
                Ok(_) => return Ok(()),
                Err(e) => {
                    error!("Failed to send packet: {e}");
                    command_transmitter
                        .send(NetworkAppPacket::Command(
                            NetworkCommandPacket::ReconnectThisProbe(None),
                        ))
                        .await?;
                    if counter >= max_retries {
                        return Err(ProbeError::from(e));
                    }
                    counter += 1;
                    warn!("Retrying to send the packet; attempt: {counter} of {max_retries}");
                    sleep(retry_interval).await;
                }
            }
        }
    }

    pub async fn transmit_packets(
        join_set: &mut JoinSet<Result<(), ProbeError>>,
        handle: TcpConnectionHandle,
        data_receiver: mpsc::Receiver<NetworkAppPacket>,
        command_transmitter: mpsc::Sender<NetworkAppPacket>,
        cancellation_token: CancellationToken,
        max_retries: usize,
        retry_interval: Duration,
    ) -> Result<(), ProbeError> {
        join_set.spawn(async move {
            tokio::select! {
                _ = cancellation_token.cancelled() => {
                    info!("Transmit packets task cancelled");
                }
                result = ConnectionManager::transmit_packets_worker(handle, data_receiver, command_transmitter, max_retries, retry_interval) => {
                    result.map_err(|e| {
                        error!("Transmit packets task exited with error: {e}");
                        e
                    })?;
                        info!("Transmit packets task finished");
                }
            }
            Ok::<(), ProbeError>(())
        });
        Ok(())
    }
    
    async fn transmit_packets_worker(
        handle: TcpConnectionHandle,
        mut data_receiver: mpsc::Receiver<NetworkAppPacket>,
        command_transmitter: mpsc::Sender<NetworkAppPacket>,
        max_retries: usize,
        retry_interval: Duration,
    ) -> Result<(), ProbeError> {
        while let Some(packet) = data_receiver.recv().await {
            ConnectionManager::send_packet_with_reconnect(
                &handle,
                &command_transmitter,
                max_retries,
                retry_interval,
                packet,
            )
            .await?;
        }
        Ok(())
    }

    pub async fn receive_packets(
        join_set: &mut JoinSet<Result<(), ProbeError>>,
        handle: TcpConnectionHandle,
        target: ReceivePacketTargets,
        command_transmitter: mpsc::Sender<NetworkAppPacket>,
        cancellation_token: CancellationToken,
        global_limit: Duration,
    ) -> Result<(), ProbeError> {
        join_set.spawn(async move {
            tokio::select! {
                _ = cancellation_token.cancelled() => {
                    info!("Receive packets task cancelled");
                }
                result = ConnectionManager::receive_packets_worker(handle, target, command_transmitter, global_limit) => { result.map_err(|e| {
                        error!("Receive packets task exited with error: {e}");
                        e
                    })?;
                        info!("Receive packets task finished");
                }
            }
            Ok::<(), ProbeError>(())
        });
        Ok(())
    }

    async fn receive_packets_worker(
        handle: TcpConnectionHandle,
        target: ReceivePacketTargets,
        command_transmitter: mpsc::Sender<NetworkAppPacket>,
        global_limit: Duration,
    ) -> Result<(), ProbeError> {
        loop {
            let packet = handle
                .send_message_with_response(|tx| TcpConnectionMessage::receive_packet(tx, Some(global_limit)))
                .await??;
            match packet {
                None => return Ok(()),
                Some(app_packet) => match &app_packet {
                    NetworkAppPacket::Command(command_packet) => match command_packet {
                        NetworkCommandPacket::ReconnectThisProbe(_) => {
                            command_transmitter.send(app_packet).await?
                        }
                    },
                    NetworkAppPacket::Data(_) => {}
                    NetworkAppPacket::Status(status) => match status {
                        NetworkStatusPacket::PingResponse => target.pinger.send(app_packet).await?,
                        _ => {}
                    },
                },
            }
        }
    }

    pub async fn pinger(
        join_set: &mut JoinSet<Result<(), ProbeError>>,
        handle: TcpConnectionHandle,
        packet_receiver: mpsc::Receiver<NetworkAppPacket>,
        command_sender: mpsc::Sender<NetworkAppPacket>,
        uuid: Uuid,
        interval: Duration,
        cancellation_token: CancellationToken,
    ) -> Result<(), ProbeError> {
        join_set.spawn(async move {
            tokio::select! {
                _ = cancellation_token.cancelled() => {
                    info!("Pinger task cancelled");
                }
                result = ConnectionManager::pinger_worker(handle, packet_receiver, command_sender, uuid, interval) => {
                    result.map_err(|e| {
                        error!("Pinger task exited with error: {e}");
                        e
                    })?;
                        info!("Pinger task finished");
                }
            }
            Ok::<(), ProbeError>(())
        });
        Ok(())
    }

    async fn pinger_worker(
        handle: TcpConnectionHandle,
        mut packet_receiver: mpsc::Receiver<NetworkAppPacket>,
        command_sender: mpsc::Sender<NetworkAppPacket>,
        uuid: Uuid,
        interval: Duration,
    ) -> Result<(), ProbeError> {
        debug!("Starting pinger");
        loop {
            handle
                .send_message_with_response(|tx| {
                    TcpConnectionMessage::send_packet(
                        tx,
                        NetworkAppPacket::Status(NetworkStatusPacket::PingRequest(uuid)),
                    )
                })
                .await??;
            trace!("Ping request sent");
            let packet = packet_receiver.recv().await;
            trace!("Ping response received");
            if Some(NetworkAppPacket::Status(NetworkStatusPacket::PingResponse)) != packet {
                debug!("Not a ping response");
                command_sender
                    .send(NetworkAppPacket::Command(
                        NetworkCommandPacket::ReconnectThisProbe(None),
                    ))
                    .await?
            };
            sleep(interval).await;
        }
    }
}

pub(crate) fn determine_mac(bind_ip: &IpAddr) -> Result<MacAddr, ProbeError> {
    let probe_ip = bind_ip.to_string().parse::<ipnetwork::IpNetwork>()?;
    let interfaces = pnet::datalink::interfaces();
    let Some(interface) = interfaces
        .iter()
        .find(|i| i.is_up() && i.ips.iter().any(|ip| ip.ip() == probe_ip.ip()))
    else {
        return Err(ProbeError::ArgumentError(format!(
            "No interface found for IP: {} or interface is not up",
            bind_ip
        )));
    };

    Ok(MacAddr(interface.mac.unwrap_or_default()))
}
