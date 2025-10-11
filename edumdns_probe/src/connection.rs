use crate::error::{ProbeError, ProbeErrorKind};
use edumdns_core::app_packet::{
    NetworkAppPacket, NetworkCommandPacket, NetworkStatusPacket, ProbeConfigPacket,
};
use edumdns_core::bincode_types::Uuid;
use edumdns_core::connection::{TcpConnectionHandle, TcpConnectionMessage};
use edumdns_core::metadata::ProbeMetadata;
use edumdns_core::retry;
use log::{debug, error, info, trace, warn};
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
}

#[derive(Clone, Debug)]
pub(crate) struct ConnectionInfo {
    pub(crate) server_connection_string: String,
    pub(crate) bind_ip: String,
    pub(crate) domain: Option<String>,
    pub(crate) pre_shared_key: Option<String>,
}

pub struct ReceivePacketTargets {
    pub pinger: mpsc::Sender<NetworkAppPacket>,
}

pub(crate) struct ConnectionManager {
    pub(crate) handle: TcpConnectionHandle,
    probe_metadata: ProbeMetadata,
    conn_info: ConnectionInfo,
    conn_limits: ConnectionLimits,
}

impl ConnectionManager {
    pub async fn connect(
        connection_info: &ConnectionInfo,
        connection_limits: &ConnectionLimits,
    ) -> Result<TcpConnectionHandle, ProbeError> {
        let handle = match connection_info.domain.as_ref() {
            None => retry!(
                TcpConnectionHandle::connect(
                    connection_info.server_connection_string.as_ref(),
                    connection_info.bind_ip.as_ref(),
                    connection_limits.global_timeout
                )
                .await,
                connection_limits.max_retries,
                connection_limits.retry_interval
            )?,
            Some(d) => {
                let mut root_cert_store = rustls::RootCertStore::empty();
                root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                let config = rustls::ClientConfig::builder()
                    .with_root_certificates(root_cert_store)
                    .with_no_client_auth();
                retry!(
                    TcpConnectionHandle::connect_tls(
                        connection_info.server_connection_string.as_ref(),
                        connection_info.bind_ip.as_ref(),
                        d,
                        Arc::new(config.clone()),
                        connection_limits.global_timeout
                    )
                    .await,
                    connection_limits.max_retries,
                    connection_limits.retry_interval
                )?
            }
        };
        Ok(handle)
    }

    pub async fn new(
        probe_metadata: ProbeMetadata,
        connection_info: ConnectionInfo,
        connection_limits: ConnectionLimits,
    ) -> Result<Self, ProbeError> {
        let handle = Self::connect(&connection_info, &connection_limits).await?;
        Ok(Self {
            handle,
            probe_metadata,
            conn_info: connection_info,
            conn_limits: connection_limits,
        })
    }

    pub async fn connection_init_probe(&mut self) -> Result<ProbeConfigPacket, ProbeError> {
        let error = Err(ProbeError::new(
            ProbeErrorKind::InvalidConnectionInitiation,
            "Invalid connection initiation",
        ));
        let hello_packet =
            NetworkAppPacket::Status(NetworkStatusPacket::ProbeHello(self.probe_metadata.clone(), self.conn_info.pre_shared_key.clone()));

        self.handle
            .send_message_with_response(|tx| TcpConnectionMessage::send_packet(tx, hello_packet))
            .await??;

        let packet = self.receive_init_packet().await?;

        if let NetworkAppPacket::Status(NetworkStatusPacket::ProbeUnknown) = packet {
            warn!("Probe is not adopted, make sure to adopt it in the web interface first");
            sleep(self.conn_limits.retry_interval).await;
            return Box::pin(self.reconnect()).await;
        }

        if let NetworkAppPacket::Status(NetworkStatusPacket::ProbeInvalidConnectionInitiation(error)) = packet {
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
            "Connected to the server {}",
            self.conn_info.server_connection_string
        );
        debug!("Obtained config <{config:?}>");
        Ok(config)
    }

    pub async fn receive_init_packet(&mut self) -> Result<NetworkAppPacket, ProbeError> {
        let packet = self
            .handle
            .send_message_with_response(|tx| {
                TcpConnectionMessage::receive_packet(
                    tx,
                    Some(self.conn_limits.global_timeout),
                )
            })
            .await??;
        let Some(app_packet) = packet else {
            return Err(ProbeError::new(
                ProbeErrorKind::InvalidConnectionInitiation,
                "Invalid connection initiation",
            ));
        };
        Ok(app_packet)
    }

    pub async fn reconnect(&mut self) -> Result<ProbeConfigPacket, ProbeError> {
        self.handle.close().await?;
        match retry!(
            Self::connect(&self.conn_info, &self.conn_limits).await,
            self.conn_limits.max_retries,
            self.conn_limits.retry_interval
        ) {
            Ok(connection) => {
                self.handle = connection;
                self.connection_init_probe().await
            }
            Err(e) => {
                error!("Failed to reconnect: {e}");
                Err(e)
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
    ) -> Result<(), ProbeError> {
        join_set.spawn(async move {
            tokio::select! {
                _ = cancellation_token.cancelled() => {
                    info!("Receive packets task cancelled");
                }
                result = ConnectionManager::receive_packets_worker(handle, target, command_transmitter) => { result.map_err(|e| {
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
    ) -> Result<(), ProbeError> {
        loop {
            let packet = handle
                .send_message_with_response(|tx| TcpConnectionMessage::receive_packet(tx, None))
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

    pub async fn send_packet_with_reconnect(
        handle: &TcpConnectionHandle,
        command_transmitter: &mpsc::Sender<NetworkAppPacket>,
        max_retries: usize,
        retry_interval: Duration,
        packet: NetworkAppPacket,
    ) -> Result<(), ProbeError> {
        let mut counter = 0;
        loop {
            match handle
                .send_message_with_response(|tx| {
                    TcpConnectionMessage::send_packet(tx, packet.clone())
                })
                .await?
            {
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
