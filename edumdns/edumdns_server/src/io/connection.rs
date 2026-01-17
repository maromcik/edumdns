//! TCP connection lifecycle: handshake, authentication, registration and data transfer.
//!
//! `ConnectionManager` encapsulates the server-side protocol for a probe connection:
//! - validate the initial hello and optional pre-shared key
//! - upsert the probe in the database and verify it's adopted
//! - send the runtime configuration to the probe
//! - register the probe handle so other subsystems can message it
//! - forward subsequent packets between network and local channels

use crate::ProbeHandles;
use crate::app_packet::AppPacket;
use crate::error::ServerError;
use crate::utils::probe_tracker::{ProbeStat, SharedProbeTracker};
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

/// Manages the lifecycle of a single probe TCP connection on the server.
///
/// A `ConnectionManager` encapsulates the server-side protocol for a probe
/// connection:
/// - performs the TLS/plain handshake and frames the stream
/// - validates the initial `ProbeHello` (including optional pre-shared key)
/// - upserts the probe record in the database and verifies it is adopted
/// - serves the runtime configuration to the probe
/// - registers the probe's TCP handle so other subsystems can message it
/// - forwards subsequent packets between the network and local channels
/// - responds to ping requests and updates the last-seen tracker
pub struct ConnectionManager {
    /// Framed TCP connection to the probe (TLS or plaintext) with helpers for
    /// request/response style messaging and timeouts.
    handle: TcpConnectionHandle,
    /// Repository used to read and upsert probe records and fetch configuration.
    pg_probe_repository: PgProbeRepository,
    /// Channel where command/status packets from the probe are forwarded.
    command_transmitter: Sender<AppPacket>,
    /// Channel where data packets from the probe are forwarded.
    data_transmitter: Sender<AppPacket>,
    /// Shared map of live probe connection handles keyed by probe `Uuid`.
    probe_handles: ProbeHandles,
    /// Tracker used by the watchdog to reap stale connections; updated on pings.
    probe_last_seen: SharedProbeTracker,
    /// Global I/O timeout used for initial handshake/receives.
    global_timeout: Duration,
}

impl ConnectionManager {
    /// Construct a new `ConnectionManager` for an accepted TCP stream.
    ///
    /// Depending on `config`, the stream is upgraded to TLS and wrapped into a
    /// framed connection with request/response helpers and the provided
    /// `global_timeout`.
    ///
    /// Parameters:
    /// - `stream`: accepted TCP connection from a probe.
    /// - `config`: optional TLS server configuration; when `Some`, TLS is
    ///   negotiated with the client.
    /// - `pool`: PostgreSQL pool used to build the probe repository.
    /// - `command_transmitter`: mpsc sender for forwarding command/status packets.
    /// - `data_transmitter`: mpsc sender for forwarding data packets.
    /// - `handles`: shared map used to register the probe's `TcpConnectionHandle`
    ///   after successful initiation.
    /// - `probe_last_seen`: shared tracker updated on ping requests.
    /// - `global_timeout`: default timeout used during handshake and receives.
    ///
    /// Returns:
    /// - `Ok(Self)` on success.
    /// - `Err(ServerError)` if the connection wrapping (including TLS) fails.
    pub async fn new(
        stream: TcpStream,
        config: Option<ServerConfig>,
        pool: Pool<AsyncPgConnection>,
        command_transmitter: Sender<AppPacket>,
        data_transmitter: Sender<AppPacket>,
        handles: ProbeHandles,
        probe_last_seen: SharedProbeTracker,
        global_timeout: Duration,
        connection_buffer_capacity: usize,
    ) -> Result<Self, ServerError> {
        let handle = match config {
            Some(config) => {
                TcpConnectionHandle::stream_to_framed_tls_server(
                    stream,
                    Arc::new(config),
                    global_timeout,
                    connection_buffer_capacity,
                )
                .await?
            }
            _ => TcpConnectionHandle::stream_to_framed(
                stream,
                global_timeout,
                connection_buffer_capacity,
            )?,
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

    /// Run the server-side connection initiation handshake.
    ///
    /// Steps:
    /// 1. Receive the initial packet and expect `NetworkStatusPacket::ProbeHello`.
    /// 2. If a probe with the same UUID is already connected, notify the client
    ///    with `ProbeInvalidConnectionInitiation` and return an error.
    /// 3. If a pre-shared key is configured in DB for this probe, validate it.
    /// 4. Upsert the probe in the database and verify that it is adopted; if not
    ///    adopted, inform the client with `ProbeUnknown` and return
    ///    `ServerError::ProbeNotAdopted`.
    /// 5. Receive and validate `ProbeRequestConfig` (metadata must match Hello).
    /// 6. Fetch probe configuration from DB and reply with `ProbeResponseConfig`.
    /// 7. Register the probe TCP handle in `probe_handles` for later messaging.
    ///
    /// Returns:
    /// - `Ok(Uuid)` with the probe ID when the handshake completes successfully.
    /// - `Err(ServerError)` describing the specific initiation error otherwise.
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

    /// Receive a single initiation packet with a timeout.
    ///
    /// Sends a receive request to the underlying `TcpConnectionHandle` with
    /// `self.global_timeout` and returns the decoded `NetworkAppPacket`.
    ///
    /// Returns:
    /// - `Ok(NetworkAppPacket)` when a packet is received and decoded.
    /// - `Err(ServerError::InvalidConnectionInitiation)` if `None` is received
    ///   (EOF or decode failure) during connection initiation.
    /// - Other `ServerError` variants if I/O or channel errors occur.
    async fn receive_init_packet(&mut self) -> Result<NetworkAppPacket, ServerError> {
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

    /// Forward packets from the probe to internal channels and handle pings.
    ///
    /// Enters a loop that receives packets from the TCP connection and routes
    /// them based on type:
    /// - `NetworkAppPacket::Command` → forwarded to `command_transmitter`.
    /// - `NetworkAppPacket::Data` → forwarded to `data_transmitter`.
    /// - `NetworkAppPacket::Status::PingRequest` → updates the last-seen tracker
    ///   and replies with `PingResponse`.
    /// - `NetworkAppPacket::Status::ProbeResponse` → forwarded to
    ///   `command_transmitter` so higher layers can deliver WS responses.
    ///
    /// The loop exits cleanly when `None` is received (connection closed).
    ///
    /// Returns:
    /// - `Ok(())` when the stream ends or on clean shutdown.
    /// - `Err(ServerError)` if receiving or forwarding fails.
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

    /// Upsert the probe record in the database on connection.
    ///
    /// Creates or updates a `Probe` using the metadata provided in the hello
    /// packet. The IP is stored as `IpNetwork` (single-host prefix) and the MAC
    /// and UUID are taken from the metadata.
    ///
    /// Parameters:
    /// - `probe_metadata`: identification and address information from the probe.
    ///
    /// Returns:
    /// - `Ok(Probe)` returned by the repository after insertion/update.
    /// - `Err(ServerError)` if the DB operation fails.
    async fn upsert_probe(&self, probe_metadata: &ProbeMetadata) -> Result<Probe, ServerError> {
        Ok(self
            .pg_probe_repository
            .create(&CreateProbe::new_connect(
                probe_metadata.id,
                probe_metadata.mac,
                IpNetwork::from(probe_metadata.ip),
            ))
            .await?)
    }

    /// Fetch the runtime configuration for the probe from the database.
    ///
    /// Queries the repository for interface/filter pairs associated with the
    /// probe and shapes them into a `ProbeConfigPacket` sent during initiation.
    /// This method uses the non-authenticated variant
    /// `get_probe_configs_no_auth`, assuming authentication was already validated
    /// (via pre-shared key) earlier in the handshake.
    ///
    /// Parameters:
    /// - `probe_metadata`: used to look up configuration by probe UUID.
    ///
    /// Returns:
    /// - `Ok(ProbeConfigPacket)` containing interface/filter mappings.
    /// - `Err(ServerError)` if the DB lookup fails.
    async fn get_probe_config(
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
