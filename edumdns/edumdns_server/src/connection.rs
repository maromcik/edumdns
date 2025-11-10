use crate::ProbeHandles;
use crate::app_packet::AppPacket;
use crate::error::ServerError;
use crate::probe_tracker::{ProbeStat, SharedProbeTracker};
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::deadpool::Pool;
use edumdns_core::app_packet::{
    NetworkAppPacket, NetworkStatusPacket, ProbeConfigElement, ProbeConfigPacket,
};
use edumdns_core::bincode_types::Uuid;
use edumdns_core::connection::{TcpConnectionHandle, TcpConnectionMessage};
use edumdns_core::metadata::ProbeMetadata;
use edumdns_db::models::Probe;
use edumdns_db::repositories::common::{DbCreate, DbReadOne};
use edumdns_db::repositories::probe::models::CreateProbe;
use edumdns_db::repositories::probe::repository::PgProbeRepository;
use ipnetwork::IpNetwork;
use log::trace;
use rustls::ServerConfig;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::mpsc::Sender;

pub struct ConnectionManager {
    handle: TcpConnectionHandle,
    pg_probe_repository: PgProbeRepository,
    command_transmitter: Sender<AppPacket>,
    data_transmitter: Sender<AppPacket>,
    probe_handles: ProbeHandles,
    probe_last_seen: SharedProbeTracker,
    global_timeout: Duration,
}

impl ConnectionManager {
    pub async fn new(
        stream: TcpStream,
        config: Option<ServerConfig>,
        pool: Pool<AsyncPgConnection>,
        command_transmitter: Sender<AppPacket>,
        data_transmitter: Sender<AppPacket>,
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
            command_transmitter,
            data_transmitter,
            probe_handles: handles,
            probe_last_seen,
            global_timeout,
        })
    }

    pub async fn connection_init_server(&mut self) -> Result<Uuid, ServerError> {
        let error = |uuid, msg| {
            Err(ServerError::InvalidConnectionInitiation(format!(
                "Probe: {:?}; {}",
                uuid, msg
            )))
        };
        let packet = self.receive_init_packet().await?;

        let NetworkAppPacket::Status(NetworkStatusPacket::ProbeHello(
            hello_metadata,
            pre_shared_key,
        )) = packet
        else {
            return error(None, "expected a ProbeHello packet");
        };

        if self
            .probe_handles
            .read()
            .await
            .contains_key(&hello_metadata.id)
        {
            let msg = "probe with the same UUID already connected, please disconnect first";
            self.handle
                .send_message_with_response(|tx| {
                    TcpConnectionMessage::send_packet(
                        tx,
                        NetworkAppPacket::Status(
                            NetworkStatusPacket::ProbeInvalidConnectionInitiation(msg.to_string()),
                        ),
                    )
                })
                .await??;
            return error(Some(hello_metadata.id), msg);
        }

        if let Ok((p, _)) = self
            .pg_probe_repository
            .read_one(&hello_metadata.id.0)
            .await
            && p.pre_shared_key.is_some()
            && p.pre_shared_key != pre_shared_key
        {
            let msg = "invalid pre-shared key";
            self.handle
                .send_message_with_response(|tx| {
                    TcpConnectionMessage::send_packet(
                        tx,
                        NetworkAppPacket::Status(
                            NetworkStatusPacket::ProbeInvalidConnectionInitiation(msg.to_string()),
                        ),
                    )
                })
                .await??;
            return error(Some(hello_metadata.id), msg);
        };

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
            return Err(ServerError::ProbeNotAdopted);
        }

        let packet = self.receive_init_packet().await?;

        let NetworkAppPacket::Status(NetworkStatusPacket::ProbeRequestConfig(config_metadata)) =
            packet
        else {
            return error(
                Some(hello_metadata.id),
                "expected ProbeRequestConfig packet",
            );
        };

        if config_metadata != hello_metadata {
            return error(Some(config_metadata.id), format!("invalid config metadata after the second check; expected (hello_packet): {}, got (config_metadata) {}", hello_metadata.id, config_metadata.id).as_str(),
            );
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
            return Err(ServerError::InvalidConnectionInitiation(
                "could not receive a valid connection initiation packet".to_string(),
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
                        self.command_transmitter
                            .send(AppPacket::Network(app_packet))
                            .await?;
                    }
                    NetworkAppPacket::Data(_) => {
                        self.data_transmitter
                            .send(AppPacket::Network(app_packet))
                            .await?;
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
                            self.command_transmitter
                                .send(AppPacket::Network(app_packet))
                                .await?;
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
