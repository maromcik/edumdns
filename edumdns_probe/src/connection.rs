use crate::error::{ProbeError, ProbeErrorKind};
use edumdns_core::app_packet::{AppPacket, CommandPacket, ProbeConfigPacket, StatusPacket};
use edumdns_core::bincode_types::Uuid;
use edumdns_core::connection::TcpConnection;
use edumdns_core::metadata::ProbeMetadata;
use edumdns_core::retry;
use log::{debug, error, info, warn};
use pnet::packet;
use std::pin::Pin;
use std::time::Duration;
use tokio::sync::mpsc::Receiver;
use tokio::time::sleep;

pub struct ConnectionManager {
    probe_metadata: ProbeMetadata,
    server_connection_string: String,
    bind_ip: String,
    pub connection: TcpConnection,
    rx: Receiver<AppPacket>,
    max_retries: usize,
    retry_interval: Duration,
    global_timeout: Duration,
}

impl ConnectionManager {
    pub async fn new(
        probe_metadata: ProbeMetadata,
        server_connection_string: &str,
        bind_ip: &str,
        rx: Receiver<AppPacket>,
        max_retries: usize,
        retry_interval: Duration,
        global_timeout: Duration,
    ) -> Result<Self, ProbeError> {
        Ok(Self {
            probe_metadata,
            server_connection_string: server_connection_string.to_owned(),
            bind_ip: bind_ip.to_owned(),
            connection: retry!(
                TcpConnection::connect(server_connection_string, bind_ip, global_timeout).await,
                max_retries,
                retry_interval
            )?,
            rx,
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
        self.connection.send_packet(&hello_packet).await?;

        let packet = self.receive_init_packet().await?;

        if let AppPacket::Status(StatusPacket::ProbeUnknown) = packet {
            warn!("Probe is not adopted, make sure to adopt it in the web interface first");
            sleep(self.retry_interval).await;
            return Box::pin(self.reconnect()).await;
        }
        let AppPacket::Status(StatusPacket::ProbeAdopted) = packet else {
            return error;
        };

        self.connection
            .send_packet(&AppPacket::Status(StatusPacket::ProbeRequestConfig(
                self.probe_metadata.clone(),
            )))
            .await?;

        let packet = self.receive_init_packet().await?;

        let AppPacket::Status(StatusPacket::ProbeResponseConfig(config)) = packet else {
            return error;
        };
        info!("Connected to the server {}", self.server_connection_string);
        Ok(config)
    }

    pub async fn receive_init_packet(&mut self) -> Result<AppPacket, ProbeError> {
        let packet: Option<(AppPacket, usize)> = self.connection.receive_next().await?;
        let Some((app_packet, _)) = packet else {
            return Err(ProbeError::new(
                ProbeErrorKind::InvalidConnectionInitiation,
                "Invalid connection initiation",
            ));
        };
        Ok(app_packet)
    }

    pub async fn transmit_packets(&mut self) -> Result<(), ProbeError> {
        while let Some(packet) = self.rx.recv().await {
            self.send_packet_with_reconnect(&packet).await?;
        }
        Ok(())
    }

    pub async fn send_packet_with_reconnect(
        &mut self,
        packet: &AppPacket,
    ) -> Result<(), ProbeError> {
        let mut counter = 0;
        loop {
            match self.connection.send_packet(packet).await {
                Ok(_) => return Ok(()),
                Err(e) => {
                    error!("Failed to send packet: {e}");
                    self.reconnect().await?;
                    info!(
                        "Reconnected to the server {}",
                        self.server_connection_string
                    );

                    if counter >= self.max_retries {
                        return Err(ProbeError::from(e));
                    }
                    counter += 1;
                    warn!(
                        "Retrying to send the packet; attempt: {counter} of {}",
                        self.max_retries
                    );
                    sleep(self.retry_interval).await;
                    self.connection.send_packet(packet).await?;
                }
            }
        }
    }

    pub async fn reconnect(&mut self) -> Result<ProbeConfigPacket, ProbeError> {
        match retry!(
            TcpConnection::connect(
                &self.server_connection_string,
                &self.bind_ip,
                self.global_timeout
            )
            .await,
            self.max_retries,
            self.retry_interval
        ) {
            Ok(connection) => {
                self.connection = connection;
                self.connection_init_probe().await
            }
            Err(e) => {
                error!("Failed to reconnect: {e}");
                Err(ProbeError::from(e))
            }
        }
    }
}
