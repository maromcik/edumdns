//! Framed TCP/UDP connections with timeouts and optional TLS.
//!
//! This module provides an actor-like abstraction over TCP streams used by the
//! edumdns server and probe to exchange `NetworkAppPacket`s. It frames messages
//! with `LengthDelimitedCodec`, encodes/decodes them using `bincode`, and offers
//! request/response helpers with timeouts. TLS client/server variants are
//! supported via `rustls`.
//!
//! It also exposes a minimal `UdpConnection` for sending UDP payloads with a
//! global timeout, used by the server to replay captured packets.
use crate::BUFFER_CAPACITY;
use crate::app_packet::NetworkAppPacket;
use crate::error::CoreError;
use bincode::{Decode, Encode};
use bytes::{Bytes, BytesMut};
use futures::stream::{SplitSink, SplitStream};
use futures::{SinkExt, StreamExt};
use log::warn;
use rustls::{ClientConfig, ServerConfig};
use rustls_pki_types::ServerName;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::BufStream;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpSocket, TcpStream};
use tokio::net::{UdpSocket, lookup_host};
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

/// Actor that owns the sending half of a framed TCP connection.
///
/// This type runs in a dedicated task and consumes `TcpConnectionMessage`s from
/// an mpsc channel. It serializes `NetworkAppPacket`s with `bincode`, wraps them
/// into length‑delimited frames, and writes them to the socket within
/// `global_timeout`.
///
/// Fields:
/// - `receiver`: control channel from the multiplexer to this sender actor.
/// - `framed_sink`: the sink side of the `Framed<BufStream<S>, LengthDelimitedCodec>`.
/// - `global_timeout`: per‑operation timeout applied to `send`/`feed`.
pub struct TcpConnectionSender<S> {
    pub receiver: mpsc::Receiver<TcpConnectionMessage>,
    pub framed_sink: SplitSink<Framed<BufStream<S>, LengthDelimitedCodec>, Bytes>,
    pub global_timeout: Duration,
}

impl<S> TcpConnectionSender<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    /// Send an encoded frame to the socket with a timeout.
    ///
    /// Parameters:
    /// - `packet`: any type implementing `bincode::Encode` (typically `NetworkAppPacket`).
    /// - `immediate`: when `true`, uses `SinkExt::send` (flush immediately);
    ///   when `false`, uses `SinkExt::feed` to buffer and let the codec coalesce frames.
    ///
    /// Returns `Ok(())` on success or a `CoreError` on timeout or I/O failure.
    pub async fn send_packet<T>(&mut self, packet: T, immediate: bool) -> Result<(), CoreError>
    where
        T: Encode,
    {
        let encoded = Self::encode_frame(packet)?;
        let res = if immediate {
            timeout(
                self.global_timeout,
                self.framed_sink.send(Bytes::from(encoded)),
            )
            .await
        } else {
            timeout(
                self.global_timeout,
                self.framed_sink.feed(Bytes::from(encoded)),
            )
            .await
        };
        res.map_err(|_| CoreError::TimeoutError("Sending a packet timed out".to_string()))??;
        Ok(())
    }

    /// Encode a value into a length-delimited frame payload using `bincode`.
    ///
    /// This does not write to the socket; it only serializes the value into a
    /// `Vec<u8>` ready to be fed into the `LengthDelimitedCodec` sink.
    pub fn encode_frame<T>(packet: T) -> Result<Vec<u8>, CoreError>
    where
        T: Encode,
    {
        bincode::encode_to_vec(packet, bincode::config::standard()).map_err(CoreError::from)
    }
}

/// Actor that owns the receiving half of a framed TCP connection.
///
/// Reads length‑delimited frames from the socket, decodes them using `bincode`,
/// and replies to the requester over a oneshot channel. A per‑call optional
/// `timeout` can be supplied via the control message; otherwise the actor uses a
/// blocking `next()` on the stream.
pub struct TcpConnectionReceiver<S> {
    pub receiver: mpsc::Receiver<TcpConnectionMessage>,
    pub framed_stream: SplitStream<Framed<BufStream<S>, LengthDelimitedCodec>>,
    pub global_timeout: Duration,
}

impl<S> TcpConnectionReceiver<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    /// Receive and decode the next frame, with an optional timeout.
    ///
    /// Parameters:
    /// - `timeout`: when `Some(d)`, the read is bounded to `d`; when `None`,
    ///   the call waits until a frame arrives or the stream ends.
    ///
    /// Returns:
    /// - `Ok(Some(T))` on successful decode of the next frame.
    /// - `Ok(None)` when the stream is closed (EOF) before a frame is read.
    /// - `Err(CoreError)` on I/O failure, decode error, or timeout.
    pub async fn receive_next<T>(
        &mut self,
        timeout: Option<Duration>,
    ) -> Result<Option<T>, CoreError>
    where
        T: Decode<()>,
    {
        let packet = match timeout {
            None => self.framed_stream.next().await,
            Some(t) => tokio::time::timeout(t, self.framed_stream.next())
                .await
                .map_err(|_| CoreError::TimeoutError("Receiving a packet timed out".to_string()))?,
        };

        match packet {
            None => Ok(None),
            Some(frame) => {
                let decoded = Self::decode_frame(frame?)?;
                Ok(Some(decoded))
            }
        }
    }

    /// Decode a `bincode` value from a length-delimited `frame`.
    ///
    /// The `BytesMut` contains exactly one frame payload as produced by
    /// `LengthDelimitedCodec`. Returns the decoded value or a `CoreError` on
    /// decode failure.
    pub fn decode_frame<T>(frame: BytesMut) -> Result<T, CoreError>
    where
        T: Decode<()>,
    {
        let (packet, _) = bincode::decode_from_slice(frame.as_ref(), bincode::config::standard())
            .map_err(CoreError::from)?;
        Ok(packet)
    }
}

/// Control messages understood by the TCP connection actors.
///
/// Variants:
/// - `ReceivePacket { respond_to, timeout }` — ask the receiver actor to read
///   the next frame and decode it, replying on `respond_to`. When `timeout` is
///   `Some`, the read is bounded; otherwise it waits until a frame arrives.
/// - `SendPacket { respond_to, packet, immediate }` — ask the sender actor to
///   encode and write `packet`. When `immediate` is `true`, the frame is flushed
///   immediately; otherwise it is buffered (`feed`). A `Result` is returned on
///   `respond_to` to confirm I/O completion.
/// - `Close` — shut down both actors gracefully.
pub enum TcpConnectionMessage {
    ReceivePacket {
        respond_to: oneshot::Sender<Result<Option<NetworkAppPacket>, CoreError>>,
        timeout: Option<Duration>,
    },
    SendPacket {
        respond_to: oneshot::Sender<Result<(), CoreError>>,
        packet: NetworkAppPacket,
        immediate: bool,
    },
    Close,
}

impl TcpConnectionMessage {
    /// Convenience constructor for `SendPacket` with `immediate = true`.
    ///
    /// Use this when the caller expects the frame to be flushed right away.
    pub fn send_packet(
        respond_to: oneshot::Sender<Result<(), CoreError>>,
        packet: NetworkAppPacket,
    ) -> Self {
        Self::SendPacket {
            respond_to,
            packet,
            immediate: true,
        }
    }

    /// Convenience constructor for `SendPacket` with `immediate = false`.
    ///
    /// Use this to buffer the frame (using `feed`) and let the codec decide when
    /// to flush, which may improve throughput for bursts of small frames.
    pub fn send_packet_buffered(
        respond_to: oneshot::Sender<Result<(), CoreError>>,
        packet: NetworkAppPacket,
    ) -> Self {
        Self::SendPacket {
            respond_to,
            packet,
            immediate: false,
        }
    }

    pub fn receive_packet(
        respond_to: oneshot::Sender<Result<Option<NetworkAppPacket>, CoreError>>,
        timeout: Option<Duration>,
    ) -> Self {
        Self::ReceivePacket {
            respond_to,
            timeout,
        }
    }
}

/// Factory holding three internal channels wiring the connection actors.
///
/// A `TcpConnection` is split into three asynchronous actors:
/// - a message multiplexer that receives user commands and routes them to
///   either the send or receive actor,
/// - a sender actor that encodes and writes frames,
/// - a receiver actor that reads and decodes frames.
///
/// This struct simply groups the three mpsc channel pairs used to connect these
/// tasks together.
pub struct TcpConnectionActorChannels {
    pub command_channel: (
        mpsc::Sender<TcpConnectionMessage>,
        mpsc::Receiver<TcpConnectionMessage>,
    ),
    pub send_channel: (
        mpsc::Sender<TcpConnectionMessage>,
        mpsc::Receiver<TcpConnectionMessage>,
    ),
    pub recv_channel: (
        mpsc::Sender<TcpConnectionMessage>,
        mpsc::Receiver<TcpConnectionMessage>,
    ),
}

impl TcpConnectionActorChannels {
    /// Create three mpsc channel pairs with the given capacity.
    ///
    /// The capacity applies independently to the command, send, and receive
    /// channels. A larger capacity may improve burst handling at the cost of
    /// memory; typical values reuse `BUFFER_CAPACITY`.
    pub fn new(capacity: usize) -> Self {
        let command_channel = mpsc::channel(capacity);
        let send_channel = mpsc::channel(capacity);
        let recv_channel = mpsc::channel(capacity);

        Self {
            command_channel,
            send_channel,
            recv_channel,
        }
    }
}

/// Receive-loop actor entry point.
///
/// Consumes `TcpConnectionMessage::ReceivePacket` requests from its control
/// channel, performs the read/timeout, decodes the frame, and responds over the
/// provided oneshot. Terminates when a `Close` message is received or the
/// control channel is closed.
async fn run_tcp_connection_receive_loop<S>(
    mut actor: TcpConnectionReceiver<S>,
) -> Result<(), CoreError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    while let Some(msg) = actor.receiver.recv().await {
        match msg {
            TcpConnectionMessage::ReceivePacket {
                respond_to,
                timeout,
            } => {
                respond_to
                    .send(actor.receive_next(timeout).await)
                    .map_err(|e| {
                        CoreError::TokioOneshotChannelError(format!(
                            "Could not receive value {e:?}"
                        ))
                    })?;
            }
            TcpConnectionMessage::Close => {
                return Ok(());
            }
            _ => {}
        }
    }
    Ok(())
}

/// Send-loop actor entry point.
///
/// Consumes `TcpConnectionMessage::SendPacket` requests, encodes frames and
/// writes them to the socket, replying over the provided oneshot with the I/O
/// result. On `Close`, flushes and closes the sink then exits.
async fn run_tcp_connection_send_loop<S>(mut actor: TcpConnectionSender<S>) -> Result<(), CoreError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    while let Some(msg) = actor.receiver.recv().await {
        match msg {
            TcpConnectionMessage::SendPacket {
                respond_to,
                packet,
                immediate,
            } => {
                respond_to
                    .send(actor.send_packet(&packet, immediate).await)
                    .map_err(|e| {
                        CoreError::TokioOneshotChannelError(format!("Could not send value {e:?}"))
                    })?;
            }
            TcpConnectionMessage::Close => {
                actor.framed_sink.close().await.map_err(CoreError::from)?;
                return Ok(());
            }
            _ => {}
        }
    }
    Ok(())
}

/// Message router that fans user commands out to send/receive actors.
///
/// Receives `TcpConnectionMessage`s from the handle's public `sender` channel
/// and forwards them to the appropriate internal actor channel. On `Close`, it
/// propagates the shutdown signal to both actors and exits.
async fn run_message_multiplexer(
    mut receiver: mpsc::Receiver<TcpConnectionMessage>,
    send_channel: mpsc::Sender<TcpConnectionMessage>,
    recv_channel: mpsc::Sender<TcpConnectionMessage>,
) -> Result<(), CoreError> {
    while let Some(msg) = receiver.recv().await {
        match msg {
            TcpConnectionMessage::SendPacket { .. } => send_channel.send(msg).await?,
            TcpConnectionMessage::ReceivePacket { .. } => recv_channel.send(msg).await?,
            TcpConnectionMessage::Close => {
                send_channel.send(TcpConnectionMessage::Close).await?;
                recv_channel.send(TcpConnectionMessage::Close).await?;
                return Ok(());
            }
        }
    }
    Ok(())
}

#[derive(Clone)]
/// Public handle to a framed TCP connection backed by internal actors.
///
/// Cloning the handle clones the mpsc sender and the connection metadata, so it
/// can be shared across tasks. The handle exposes helpers to wrap/connect a
/// stream (plain or TLS), send typed messages and await responses, and close the
/// connection gracefully.
pub struct TcpConnectionHandle {
    pub sender: mpsc::Sender<TcpConnectionMessage>,
    pub connection_info: ConnectionInfo,
}

impl TcpConnectionHandle {
    /// Spawn the three internal actors (multiplexer, send loop, receive loop).
    ///
    /// Returns the `ConnectionInfo` copied from the internal connection so it
    /// can be placed onto the public handle.
    fn spawn_actors<S>(
        receiver: mpsc::Receiver<TcpConnectionMessage>,
        send_channel: mpsc::Sender<TcpConnectionMessage>,
        recv_channel: mpsc::Sender<TcpConnectionMessage>,
        connection: TcpConnection<S>,
    ) -> ConnectionInfo
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        tokio::spawn(async move {
            if let Err(e) = run_message_multiplexer(receiver, send_channel, recv_channel).await {
                warn!("I/O message multiplexer failed: {e}");
            }
        });
        tokio::spawn(async move {
            if let Err(e) = run_tcp_connection_send_loop(connection.sender).await {
                warn!("I/O send loop failed: {e}");
            }
        });
        tokio::spawn(async move {
            if let Err(e) = run_tcp_connection_receive_loop(connection.receiver).await {
                warn!("I/O receive loop failed: {e}");
            }
        });
        ConnectionInfo {
            local_addr: connection.connection_info.local_addr,
            peer_addr: connection.connection_info.peer_addr,
        }
    }

    /// Wrap an accepted plain TCP `stream` into a framed connection and spawn actors.
    ///
    /// Uses `LengthDelimitedCodec` over a buffered stream and starts the internal
    /// multiplexer/send/receive tasks. All I/O operations use `global_timeout`.
    pub fn stream_to_framed(
        stream: TcpStream,
        global_timeout: Duration,
    ) -> Result<Self, CoreError> {
        let channels = TcpConnectionActorChannels::new(BUFFER_CAPACITY);

        let actors: TcpConnection<TcpStream> = TcpConnection::<TcpStream>::stream_to_framed(
            channels.send_channel.1,
            channels.recv_channel.1,
            stream,
            global_timeout,
        )?;

        let connection_info = Self::spawn_actors(
            channels.command_channel.1,
            channels.send_channel.0,
            channels.recv_channel.0,
            actors,
        );

        Ok(Self {
            sender: channels.command_channel.0,
            connection_info,
        })
    }

    /// Resolve and connect to `conn_socket_addr`, then wrap into a framed connection.
    ///
    /// The address may resolve to multiple endpoints; the connector iterates them
    /// until one succeeds, applying `global_timeout` to each attempt. Spawns the
    /// internal actors on success.
    pub async fn connect(
        conn_socket_addr: &str,
        global_timeout: Duration,
    ) -> Result<Self, CoreError> {
        let channels = TcpConnectionActorChannels::new(BUFFER_CAPACITY);

        let actors: TcpConnection<TcpStream> = TcpConnection::<TcpStream>::connect(
            conn_socket_addr,
            channels.send_channel.1,
            channels.recv_channel.1,
            global_timeout,
        )
        .await?;

        let connection_info = Self::spawn_actors(
            channels.command_channel.1,
            channels.send_channel.0,
            channels.recv_channel.0,
            actors,
        );

        Ok(Self {
            sender: channels.command_channel.0,
            connection_info,
        })
    }

    /// Wrap an accepted TCP `stream` into a TLS client session and frame it.
    ///
    /// Performs a TLS client handshake for `domain` using the provided
    /// `client_config` within `global_timeout`, then starts the internal actors.
    pub async fn stream_to_framed_tls_client(
        stream: TcpStream,
        domain: &str,
        client_config: Arc<ClientConfig>,
        global_timeout: Duration,
    ) -> Result<Self, CoreError> {
        let channels = TcpConnectionActorChannels::new(BUFFER_CAPACITY);

        let actors = TcpConnection::<tokio_rustls::client::TlsStream<TcpStream>>::stream_to_framed_tls_client(
            channels.send_channel.1,
            channels.recv_channel.1,
            stream,
            domain,
            client_config,
            global_timeout,
        )
        .await?;

        let connection_info = Self::spawn_actors(
            channels.command_channel.1,
            channels.send_channel.0,
            channels.recv_channel.0,
            actors,
        );

        Ok(Self {
            sender: channels.command_channel.0,
            connection_info,
        })
    }

    /// Wrap an accepted TCP `stream` into a TLS server session and frame it.
    ///
    /// Performs a TLS server handshake using `server_config` within
    /// `global_timeout`, then starts the internal actors.
    pub async fn stream_to_framed_tls_server(
        stream: TcpStream,
        server_config: Arc<ServerConfig>,
        global_timeout: Duration,
    ) -> Result<Self, CoreError> {
        let channels = TcpConnectionActorChannels::new(BUFFER_CAPACITY);

        let connection = TcpConnection::<tokio_rustls::server::TlsStream<TcpStream>>::stream_to_framed_tls_server(
            channels.send_channel.1,
            channels.recv_channel.1,
            stream,
            server_config,
            global_timeout,
        )
        .await?;

        let connection_info = Self::spawn_actors(
            channels.command_channel.1,
            channels.send_channel.0,
            channels.recv_channel.0,
            connection,
        );
        Ok(Self {
            sender: channels.command_channel.0,
            connection_info,
        })
    }

    /// Resolve and connect to `conn_socket_addr` over TLS, then frame it.
    ///
    /// Performs TCP connect with retries over all resolved addresses, then a TLS
    /// client handshake for `domain` using `client_config` within
    /// `global_timeout`. Spawns internal actors on success.
    pub async fn connect_tls(
        conn_socket_addr: &str,
        domain: &str,
        client_config: Arc<ClientConfig>,
        global_timeout: Duration,
    ) -> Result<Self, CoreError> {
        let channels = TcpConnectionActorChannels::new(BUFFER_CAPACITY);

        let actors = TcpConnection::<tokio_rustls::client::TlsStream<TcpStream>>::connect_tls(
            conn_socket_addr,
            domain,
            client_config,
            channels.send_channel.1,
            channels.recv_channel.1,
            global_timeout,
        )
        .await?;

        let connection_info = Self::spawn_actors(
            channels.command_channel.1,
            channels.send_channel.0,
            channels.recv_channel.0,
            actors,
        );

        Ok(Self {
            sender: channels.command_channel.0,
            connection_info,
        })
    }

    pub async fn send_message_with_response<T>(
        &self,
        message_creator: impl FnOnce(oneshot::Sender<T>) -> TcpConnectionMessage,
    ) -> Result<T, CoreError> {
        let (tx, rx) = oneshot::channel();
        self.sender.send(message_creator(tx)).await?;
        rx.await.map_err(Into::into)
    }

    pub async fn close(&self) -> Result<(), CoreError> {
        self.sender.send(TcpConnectionMessage::Close).await?;
        Ok(())
    }
}

#[derive(Clone)]
/// Socket addresses associated with a live TCP connection.
///
/// Useful for logging and diagnostics; carried on the `TcpConnectionHandle` so
/// callers can inspect local/peer endpoints.
pub struct ConnectionInfo {
    pub local_addr: SocketAddr,
    pub peer_addr: SocketAddr,
}

/// Internal connection state shared by the three actors.
///
/// This type is not exposed publicly; it holds the split framed stream
/// (sender/receiver halves) and basic connection metadata used to initialize the
/// public `TcpConnectionHandle`.
struct TcpConnection<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    sender: TcpConnectionSender<S>,
    receiver: TcpConnectionReceiver<S>,
    connection_info: ConnectionInfo,
}

impl<S> TcpConnection<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn stream_to_framed_generic<T>(
        message_channel_sender: mpsc::Receiver<TcpConnectionMessage>,
        message_channel_receiver: mpsc::Receiver<TcpConnectionMessage>,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        stream: T,
        global_timeout: Duration,
    ) -> Result<TcpConnection<T>, CoreError>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let buffered = BufStream::new(stream);
        let framed = Framed::new(buffered, LengthDelimitedCodec::new()).split();
        Ok(TcpConnection {
            sender: TcpConnectionSender {
                receiver: message_channel_sender,
                framed_sink: framed.0,
                global_timeout,
            },
            receiver: TcpConnectionReceiver {
                receiver: message_channel_receiver,
                framed_stream: framed.1,
                global_timeout,
            },
            connection_info: ConnectionInfo {
                local_addr,
                peer_addr,
            },
        })
    }

    async fn resolve_and_connect(
        addr: &str,
        global_timeout: Duration,
    ) -> Result<TcpStream, CoreError> {
        let addrs = lookup_host(addr).await?;
        let mut last_err = None;
        for addr in addrs {
            let socket = if addr.is_ipv4() {
                TcpSocket::new_v4()?
            } else {
                TcpSocket::new_v6()?
            };

            socket.set_keepalive(true)?;
            match tokio::time::timeout(global_timeout, socket.connect(addr)).await {
                Ok(Ok(stream)) => return Ok(stream),
                Ok(Err(e)) => {
                    warn!("Connection to {addr} failed: {e}");
                    last_err = Some(CoreError::from(e));
                }
                Err(_) => {
                    let e = CoreError::TimeoutError(format!("Connection to {addr} timed out"));
                    warn!("{e}");
                    last_err = Some(e);
                }
            };
        }
        Err(last_err.unwrap_or(CoreError::ConnectionError(
            "Could not resolve any address".to_string(),
        )))
    }

    fn stream_to_framed(
        message_channel_sender: mpsc::Receiver<TcpConnectionMessage>,
        message_channel_receiver: mpsc::Receiver<TcpConnectionMessage>,
        stream: TcpStream,
        global_timeout: Duration,
    ) -> Result<TcpConnection<TcpStream>, CoreError> {
        Self::stream_to_framed_generic(
            message_channel_sender,
            message_channel_receiver,
            stream.local_addr()?,
            stream.peer_addr()?,
            stream,
            global_timeout,
        )
    }

    async fn stream_to_framed_tls_client(
        message_channel_sender: mpsc::Receiver<TcpConnectionMessage>,
        message_channel_receiver: mpsc::Receiver<TcpConnectionMessage>,
        stream: TcpStream,
        domain: &str,
        client_config: Arc<ClientConfig>,
        global_timeout: Duration,
    ) -> Result<TcpConnection<tokio_rustls::client::TlsStream<TcpStream>>, CoreError> {
        let connector = TlsConnector::from(client_config);
        let dnsname = ServerName::try_from(domain)?.to_owned();
        let local_addr = stream.local_addr()?;
        let peer_addr = stream.peer_addr()?;
        let tls_stream = timeout(global_timeout, connector.connect(dnsname, stream))
            .await
            .map_err(|_| CoreError::TimeoutError("TLS handshake timed out".to_string()))??;

        Self::stream_to_framed_generic(
            message_channel_sender,
            message_channel_receiver,
            local_addr,
            peer_addr,
            tls_stream,
            global_timeout,
        )
    }

    async fn stream_to_framed_tls_server(
        message_channel_sender: mpsc::Receiver<TcpConnectionMessage>,
        message_channel_receiver: mpsc::Receiver<TcpConnectionMessage>,
        stream: TcpStream,
        server_config: Arc<ServerConfig>,
        global_timeout: Duration,
    ) -> Result<TcpConnection<tokio_rustls::server::TlsStream<TcpStream>>, CoreError> {
        let connector = TlsAcceptor::from(server_config);
        let local_addr = stream.local_addr()?;
        let peer_addr = stream.peer_addr()?;
        let tls_stream = timeout(global_timeout, connector.accept(stream))
            .await
            .map_err(|_| CoreError::TimeoutError("TLS handshake timed out".to_string()))??;

        Self::stream_to_framed_generic(
            message_channel_sender,
            message_channel_receiver,
            local_addr,
            peer_addr,
            tls_stream,
            global_timeout,
        )
    }

    async fn connect(
        addr: &str,
        message_channel_sender: mpsc::Receiver<TcpConnectionMessage>,
        message_channel_receiver: mpsc::Receiver<TcpConnectionMessage>,
        global_timeout: Duration,
    ) -> Result<TcpConnection<TcpStream>, CoreError> {
        let stream = Self::resolve_and_connect(addr, global_timeout).await?;
        Self::stream_to_framed(
            message_channel_sender,
            message_channel_receiver,
            stream,
            global_timeout,
        )
    }

    async fn connect_tls(
        addr: &str,
        domain: &str,
        client_config: Arc<ClientConfig>,
        message_channel_sender: mpsc::Receiver<TcpConnectionMessage>,
        message_channel_receiver: mpsc::Receiver<TcpConnectionMessage>,
        global_timeout: Duration,
    ) -> Result<TcpConnection<tokio_rustls::client::TlsStream<TcpStream>>, CoreError> {
        let stream = Self::resolve_and_connect(addr, global_timeout).await?;

        Self::stream_to_framed_tls_client(
            message_channel_sender,
            message_channel_receiver,
            stream,
            domain,
            client_config,
            global_timeout,
        )
        .await
    }
}

/// Minimal UDP sender with a global timeout applied to each send.
///
/// Used by the server to replay captured UDP payloads to target addresses.
pub struct UdpConnection {
    pub socket: UdpSocket,
    pub global_timeout: Duration,
}

impl UdpConnection {
    /// Create a new UDP connection bound to an ephemeral local port.
    ///
    /// The socket is created in non-connected mode and can send to arbitrary
    /// remote endpoints via `send_packet`. All sends are bounded by
    /// `global_timeout`.
    pub async fn new(global_timeout: Duration) -> Result<Self, CoreError> {
        let socket = UdpSocket::bind("[::]:0").await?;
        Ok(Self {
            socket,
            global_timeout,
        })
    }

    pub async fn send_packet(&self, target: &str, buf: &[u8]) -> Result<(), CoreError> {
        timeout(self.global_timeout, self.socket.send_to(buf, target))
            .await
            .map_err(|_| {
                CoreError::TimeoutError(format!("Sending UDP packets to {target} timed out"))
            })??;
        Ok(())
    }
}
