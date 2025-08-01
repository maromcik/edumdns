use crate::error::{ProbeError, ProbeErrorKind};
use edumdns_core::app_packet::{AppPacket, CommandPacket, ProbeConfigPacket, StatusPacket};
use edumdns_core::connection::{TcpConnection, TcpConnectionHandle, TcpConnectionMessage};
use edumdns_core::error::{CoreError, CoreErrorKind};
use edumdns_core::metadata::ProbeMetadata;
use edumdns_core::retry;
use futures::SinkExt;
use futures::stream::select_all;
use log::{debug, error, info, warn};
use pnet::packet;
use std::mem;
use std::pin::Pin;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::sleep;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;

// TODO switch to probe manager
// TODO spawn all tasks as tokio selects, when reconnect comes in, select dies and forces reconnect in probe manager's thread
pub struct ReceivePacketTargets {
    pub pinger: mpsc::Sender<AppPacket>,
}

pub struct ConnectionManager {
    probe_metadata: ProbeMetadata,
    server_connection_string: String,
    bind_ip: String,
    pub handle: TcpConnectionHandle,
    max_retries: usize,
    retry_interval: Duration,
    global_timeout: Duration,
}

impl ConnectionManager {
    pub async fn new(
        probe_metadata: ProbeMetadata,
        server_connection_string: &str,
        bind_ip: &str,
        max_retries: usize,
        retry_interval: Duration,
        global_timeout: Duration,
    ) -> Result<Self, ProbeError> {
        let handle = retry!(
            TcpConnectionHandle::connect(server_connection_string, bind_ip, global_timeout).await,
            max_retries,
            retry_interval
        )?;

        Ok(Self {
            probe_metadata,
            server_connection_string: server_connection_string.to_owned(),
            bind_ip: bind_ip.to_owned(),
            handle,
            max_retries,
            retry_interval,
            global_timeout,
        })
    }

    pub async fn connection_init_probe(&mut self) -> Result<ProbeConfigPacket, ProbeError> {
        let error = Err(ProbeError::new(
            ProbeErrorKind::InvalidConnectionInitiation,
            "Invalid connection initiation",
        ));
        let hello_packet = AppPacket::Status(StatusPacket::ProbeHello(self.probe_metadata.clone()));

        self.handle
            .send_message_with_response(|tx| TcpConnectionMessage::send_packet(tx, hello_packet))
            .await??;

        let packet = self.receive_init_packet().await?;

        if let AppPacket::Status(StatusPacket::ProbeUnknown) = packet {
            warn!("Probe is not adopted, make sure to adopt it in the web interface first");
            sleep(self.retry_interval).await;
            return Box::pin(self.reconnect()).await;
        }
        let AppPacket::Status(StatusPacket::ProbeAdopted) = packet else {
            return error;
        };
        let probe_packet = AppPacket::Status(StatusPacket::ProbeRequestConfig(
            self.probe_metadata.clone(),
        ));

        self.handle
            .send_message_with_response(|tx| TcpConnectionMessage::send_packet(tx, probe_packet))
            .await??;

        let packet = self.receive_init_packet().await?;

        let AppPacket::Status(StatusPacket::ProbeResponseConfig(config)) = packet else {
            return error;
        };
        info!("Connected to the server {}", self.server_connection_string);
        Ok(config)
    }

    pub async fn receive_init_packet(&mut self) -> Result<AppPacket, ProbeError> {
        let packet = self
            .handle
            .send_message_with_response(|tx| {
                TcpConnectionMessage::receive_packet(tx, Some(self.global_timeout))
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
        match retry!(
            TcpConnectionHandle::connect(
                &self.server_connection_string,
                &self.bind_ip,
                self.global_timeout
            )
            .await,
            self.max_retries,
            self.retry_interval
        ) {
            Ok(connection) => {
                self.handle = connection;
                self.connection_init_probe().await
            }
            Err(e) => {
                error!("Failed to reconnect: {e}");
                Err(ProbeError::from(e))
            }
        }
    }

    pub async fn transmit_packets(
        join_set: &mut JoinSet<Result<(), ProbeError>>,
        handle: TcpConnectionHandle,
        data_receiver: mpsc::Receiver<AppPacket>,
        command_transmitter: mpsc::Sender<AppPacket>,
        cancellation_token: CancellationToken,
        max_retries: usize,
        retry_interval: Duration,
    ) -> Result<(), ProbeError> {
        join_set.spawn(async move {
            tokio::select! {
                _ = cancellation_token.cancelled() => {
                    warn!("Transmit packets task cancelled");
                }
                _ = ConnectionManager::transmit_packets_worker(handle, data_receiver, command_transmitter, max_retries, retry_interval) => {
                    info!("Transmit packets task finished");
                }
            }
            Ok::<(), ProbeError>(())
        });
        Ok(())
    }

    async fn transmit_packets_worker(
        handle: TcpConnectionHandle,
        mut data_receiver: mpsc::Receiver<AppPacket>,
        command_transmitter: mpsc::Sender<AppPacket>,
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
        command_transmitter: mpsc::Sender<AppPacket>,
        cancellation_token: CancellationToken,
    ) -> Result<(), ProbeError> {
        join_set.spawn(async move {
            tokio::select! {
                _ = cancellation_token.cancelled() => {
                    warn!("Receive packets task cancelled");
                }
                _ = ConnectionManager::receive_packets_worker(handle, target, command_transmitter) => {
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
        command_transmitter: mpsc::Sender<AppPacket>,
    ) -> Result<(), ProbeError> {
        loop {
            let packet = handle
                .send_message_with_response(|tx| TcpConnectionMessage::receive_packet(tx, None))
                .await??;
            match packet {
                None => return Ok(()),
                Some(app_packet) => match &app_packet {
                    AppPacket::Command(command_packet) => match command_packet {
                        CommandPacket::ReconnectProbe => {
                            command_transmitter.send(app_packet).await?
                        }
                        _ => {}
                    },
                    AppPacket::Data(_) => {}
                    AppPacket::Status(status) => match status {
                        StatusPacket::PingResponse => target.pinger.send(app_packet).await?,
                        StatusPacket::ProbeHello(_) => {}
                        StatusPacket::ProbeAdopted => {}
                        StatusPacket::ProbeUnknown => {}
                        StatusPacket::ProbeRequestConfig(_) => {}
                        StatusPacket::ProbeResponseConfig(_) => {}
                        StatusPacket::PingRequest => {}
                    },
                },
            }
        }
    }

    pub async fn send_packet_with_reconnect(
        handle: &TcpConnectionHandle,
        command_transmitter: &mpsc::Sender<AppPacket>,
        max_retries: usize,
        retry_interval: Duration,
        packet: AppPacket,
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
                        .send(AppPacket::Command(CommandPacket::ReconnectProbe))
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
        packet_receiver: mpsc::Receiver<AppPacket>,
        command_sender: mpsc::Sender<AppPacket>,
        interval: Duration,
        cancellation_token: CancellationToken,
    ) -> Result<(), ProbeError> {
        join_set.spawn(async move {
            tokio::select! {
                _ = cancellation_token.cancelled() => {
                    warn!("Pinger task cancelled");
                }
                _ = ConnectionManager::pinger_worker(handle, packet_receiver, command_sender, interval) => {
                    info!("Pinger task finished");
                }
            }
            Ok::<(), ProbeError>(())
        });
        Ok(())
    }

    async fn pinger_worker(
        handle: TcpConnectionHandle,
        mut packet_receiver: mpsc::Receiver<AppPacket>,
        command_sender: mpsc::Sender<AppPacket>,
        interval: Duration,
    ) -> Result<(), ProbeError> {
        debug!("Starting pinger");
        loop {
            handle
                .send_message_with_response(|tx| {
                    TcpConnectionMessage::send_packet(
                        tx,
                        AppPacket::Status(StatusPacket::PingRequest),
                    )
                })
                .await??;
            debug!("Ping request sent");
            let packet = packet_receiver.recv().await;
            debug!("Ping response received");
            if Some(AppPacket::Status(StatusPacket::PingResponse)) != packet {
                warn!("Not a ping response");
                command_sender
                    .send(AppPacket::Command(CommandPacket::ReconnectProbe))
                    .await?
            };
            sleep(interval).await;
        }
    }
}
