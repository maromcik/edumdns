use crate::error::{ServerError, ServerErrorKind};
use diesel_async::pooled_connection::deadpool::Pool;
use diesel_async::AsyncPgConnection;
use edumdns_core::app_packet::{
    AppPacket, ProbeConfigElement, ProbeConfigPacket, StatusPacket,
};
use edumdns_core::connection::{TcpConnectionHandle, TcpConnectionMessage};
use edumdns_core::metadata::ProbeMetadata;
use edumdns_db::models::Probe;
use edumdns_db::repositories::common::DbCreate;
use edumdns_db::repositories::probe::models::CreateProbe;
use edumdns_db::repositories::probe::repository::PgProbeRepository;
use ipnetwork::IpNetwork;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::mpsc::Sender;

pub struct ConnectionManager {
    handle: TcpConnectionHandle,
    pg_probe_repository: PgProbeRepository,
    global_timeout: Duration,
}

impl ConnectionManager {
    pub fn new(
        stream: TcpStream,
        pool: Pool<AsyncPgConnection>,
        global_timeout: Duration,
    ) -> Result<Self, ServerError> {
        Ok(Self {
            handle: TcpConnectionHandle::stream_to_framed(stream, global_timeout)?,
            pg_probe_repository: PgProbeRepository::new(pool.clone()),
            global_timeout,
        })
    }

    pub async fn connection_init_server(&mut self) -> Result<(), ServerError> {
        let error = Err(ServerError::new(
            ServerErrorKind::InvalidConnectionInitiation,
            "invalid connection initiation",
        ));
        let packet = self.receive_init_packet().await?;

        let AppPacket::Status(StatusPacket::ProbeHello(hello_metadata)) = packet else {
            return error;
        };

        let probe = self.upsert_probe(&hello_metadata).await?;
        if probe.adopted {
            self.handle
                .send_message_with_response(|tx| {
                    TcpConnectionMessage::send_packet(
                        tx,
                        AppPacket::Status(StatusPacket::ProbeAdopted),
                    )
                })
                .await??;
        } else {
            self.handle
                .send_message_with_response(|tx| {
                    TcpConnectionMessage::send_packet(
                        tx,
                        AppPacket::Status(StatusPacket::ProbeUnknown),
                    )
                })
                .await??;
            return Err(ServerError::new(
                ServerErrorKind::ProbeNotAdopted,
                "adopt it in the web interface first",
            ));
        }

        let packet = self.receive_init_packet().await?;

        let AppPacket::Status(StatusPacket::ProbeRequestConfig(config_metadata)) = packet else {
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
                    AppPacket::Status(StatusPacket::ProbeResponseConfig(config)),
                )
            })
            .await??;

        Ok(())
    }

    pub async fn receive_init_packet(&mut self) -> Result<AppPacket, ServerError> {
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

    pub async fn transfer_packets(&mut self, tx: Sender<AppPacket>) -> Result<(), ServerError> {
        loop {
            let packet = self
                .handle
                .send_message_with_response(|tx| TcpConnectionMessage::receive_packet(tx, None))
                .await??;
            match packet {
                None => return Ok(()),
                Some(app_packet) => {
                    match &app_packet {
                        AppPacket::Command(_) => {
                            tx.send(app_packet).await?;
                        }
                        AppPacket::Data(_) => {
                            tx.send(app_packet).await?;
                        }
                        AppPacket::Status(status) => {
                            match status {
                                StatusPacket::PingRequest => {
                                    // TODO log time since last ping, threshold for considering a probe dead.

                                    self.handle
                                        .send_message_with_response(|tx| {
                                            TcpConnectionMessage::send_packet(
                                                tx,
                                                AppPacket::Status(StatusPacket::PingResponse),
                                            )
                                        })
                                        .await??;
                                }
                                StatusPacket::PingResponse => {}
                                StatusPacket::ProbeHello(_) => {}
                                StatusPacket::ProbeAdopted => {}
                                StatusPacket::ProbeUnknown => {}
                                StatusPacket::ProbeRequestConfig(_) => {}
                                StatusPacket::ProbeResponseConfig(_) => {}
                            }
                        }
                    }
                }
            }
        }
    }

    pub async fn upsert_probe(&self, probe_metadata: &ProbeMetadata) -> Result<Probe, ServerError> {
        Ok(self
            .pg_probe_repository
            .create(&CreateProbe::new(
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
            .get_probe_config(&probe_metadata.id.0)
            .await?
            .into_iter()
            .map(|c| ProbeConfigElement::new(c.interface, c.filter))
            .collect();
        Ok(ProbeConfigPacket {
            interface_filter_map: config,
        })
    }
}
