use crate::error::{ServerError, ServerErrorKind};
use crate::listen::ProbeHandles;
use crate::probe_tracker::{ProbeStat, SharedProbeTracker};
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::deadpool::Pool;
use edumdns_core::app_packet::{
    AppPacket, NetworkAppPacket, NetworkStatusPacket, ProbeConfigElement, ProbeConfigPacket,
};
use edumdns_core::bincode_types::Uuid;
use edumdns_core::connection::{TcpConnectionHandle, TcpConnectionMessage};
use edumdns_core::error::CoreError;
use edumdns_core::metadata::ProbeMetadata;
use edumdns_db::models::Probe;
use edumdns_db::repositories::common::DbCreate;
use edumdns_db::repositories::probe::models::CreateProbe;
use edumdns_db::repositories::probe::repository::PgProbeRepository;
use ipnetwork::IpNetwork;
use log::{trace, warn};
use rustls::ServerConfig;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::mpsc::Sender;

pub struct ConnectionManager {
    handle: TcpConnectionHandle,
    pg_probe_repository: PgProbeRepository,
    tx: Sender<AppPacket>,
    probe_handles: ProbeHandles,
    probe_last_seen: SharedProbeTracker,
    global_timeout: Duration,
}

impl ConnectionManager {
    pub async fn new(
        stream: TcpStream,
        config: Option<ServerConfig>,
        pool: Pool<AsyncPgConnection>,
        tx: Sender<AppPacket>,
        handles: ProbeHandles,
        probe_last_seen: SharedProbeTracker,
        global_timeout: Duration,
    ) -> Result<Self, ServerError> {
        let handle = match config {
            Some(config) => {
                TcpConnectionHandle::stream_to_framed_tls_server(
                    stream,
                    Arc::new(config),
                    global_timeout,
                )
                .await?
            }
            _ => TcpConnectionHandle::stream_to_framed(stream, global_timeout)?,
        };
        Ok(Self {
            handle,
            pg_probe_repository: PgProbeRepository::new(pool.clone()),
            tx,
            probe_handles: handles,
            probe_last_seen,
            global_timeout,
        })
    }

    pub async fn connection_init_server(&mut self) -> Result<Uuid, ServerError> {
        let error = Err(ServerError::new(
            ServerErrorKind::InvalidConnectionInitiation,
            "invalid connection initiation",
        ));
        let packet = self.receive_init_packet().await?;

        let NetworkAppPacket::Status(NetworkStatusPacket::ProbeHello(hello_metadata)) = packet
        else {
            return error;
        };

        if self.probe_handles.read().await.contains_key(&hello_metadata.id) {
            return Err(ServerError::new(ServerErrorKind::ProbeAlreadyConnected, format!("UUID: {}", hello_metadata.id).as_str()));
        }

        let probe = self.upsert_probe(&hello_metadata).await?;
        if probe.adopted {
            self.handle
                .send_message_with_response(|tx| {
                    TcpConnectionMessage::send_packet(
                        tx,
                        NetworkAppPacket::Status(NetworkStatusPacket::ProbeAdopted),
                    )
                })
                .await??;
        } else {
            self.handle
                .send_message_with_response(|tx| {
                    TcpConnectionMessage::send_packet(
                        tx,
                        NetworkAppPacket::Status(NetworkStatusPacket::ProbeUnknown),
                    )
                })
                .await??;
            return Err(ServerError::new(
                ServerErrorKind::ProbeNotAdopted,
                "adopt it in the web interface first",
            ));
        }

        let packet = self.receive_init_packet().await?;

        let NetworkAppPacket::Status(NetworkStatusPacket::ProbeRequestConfig(config_metadata)) =
            packet
        else {
            return error;
        };

        if config_metadata != hello_metadata {
            return error;
        }

        let config = self.get_probe_config(&config_metadata).await?;
        self.handle
            .send_message_with_response(|tx| {
                TcpConnectionMessage::send_packet(
                    tx,
                    NetworkAppPacket::Status(NetworkStatusPacket::ProbeResponseConfig(config)),
                )
            })
            .await??;

        self.probe_handles
            .write()
            .await
            .insert(config_metadata.id, self.handle.clone());

        Ok(config_metadata.id)
    }

    pub async fn receive_init_packet(&mut self) -> Result<NetworkAppPacket, ServerError> {
        let packet = self
            .handle
            .send_message_with_response(|tx| {
                TcpConnectionMessage::receive_packet(tx, Some(self.global_timeout))
            })
            .await??;
        let Some(app_packet) = packet else {
            return Err(ServerError::new(
                ServerErrorKind::InvalidConnectionInitiation,
                "invalid connection initiation",
            ));
        };
        Ok(app_packet)
    }

    pub async fn transfer_packets(&mut self) -> Result<(), ServerError> {
        loop {
            let packet = self
                .handle
                .send_message_with_response(|tx| TcpConnectionMessage::receive_packet(tx, None))
                .await??;
            match packet {
                None => return Ok(()),
                Some(app_packet) => match &app_packet {
                    NetworkAppPacket::Command(_) => {
                        self.tx
                            .send(AppPacket::Network(app_packet))
                            .await
                            .map_err(CoreError::from)?;
                    }
                    NetworkAppPacket::Data(_) => {
                        self.tx
                            .send(AppPacket::Network(app_packet))
                            .await
                            .map_err(CoreError::from)?;
                    }
                    NetworkAppPacket::Status(status) => match status {
                        NetworkStatusPacket::PingRequest(uuid) => {
                            let tracker = ProbeStat::new(*uuid);
                            trace!(
                                "Received ping request from probe {:?}, adding to the last seen tracker",
                                tracker
                            );
                            self.probe_last_seen.write().await.replace(*uuid, tracker);
                            self.handle
                                .send_message_with_response(|tx| {
                                    TcpConnectionMessage::send_packet(
                                        tx,
                                        NetworkAppPacket::Status(NetworkStatusPacket::PingResponse),
                                    )
                                })
                                .await??;
                        }
                        NetworkStatusPacket::ProbeResponse(_, _, _) => {
                            self.tx
                                .send(AppPacket::Network(app_packet))
                                .await
                                .map_err(CoreError::from)?;
                        }
                        _ => {}
                    },
                },
            }
        }
    }

    pub async fn upsert_probe(&self, probe_metadata: &ProbeMetadata) -> Result<Probe, ServerError> {
        Ok(self
            .pg_probe_repository
            .create(&CreateProbe::new_connect(
                probe_metadata.id,
                probe_metadata.mac,
                IpNetwork::from(probe_metadata.ip),
            ))
            .await?)
    }

    pub async fn get_probe_config(
        &self,
        probe_metadata: &ProbeMetadata,
    ) -> Result<ProbeConfigPacket, ServerError> {
        let config: Vec<ProbeConfigElement> = self
            .pg_probe_repository
            .get_probe_configs_no_auth(&probe_metadata.id.0)
            .await?
            .into_iter()
            .map(|c| ProbeConfigElement::new(c.interface, c.filter))
            .collect();
        Ok(ProbeConfigPacket {
            interface_filter_map: config,
        })
    }
}
