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
pub struct TcpConnectionHandle {
    pub sender: mpsc::Sender<TcpConnectionMessage>,
}

impl TcpConnectionHandle {
    pub fn spawn_actors<S>(
        receiver: mpsc::Receiver<TcpConnectionMessage>,
        send_channel: mpsc::Sender<TcpConnectionMessage>,
        recv_channel: mpsc::Sender<TcpConnectionMessage>,
        actors: (TcpConnectionSender<S>, TcpConnectionReceiver<S>),
    ) where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        tokio::spawn(async move {
            if let Err(e) = run_message_multiplexer(receiver, send_channel, recv_channel).await {
                warn!("I/O message multiplexer failed: {e}");
            }
        });
        tokio::spawn(async move {
            if let Err(e) = run_tcp_connection_send_loop(actors.0).await {
                warn!("I/O send loop failed: {e}");
            }
        });
        tokio::spawn(async move {
            if let Err(e) = run_tcp_connection_receive_loop(actors.1).await {
                warn!("I/O receive loop failed: {e}");
            }
        });
    }
    /// Unchanged public API: create connection handle from a plain TcpStream
    pub fn stream_to_framed(
        stream: TcpStream,
        global_timeout: Duration,
    ) -> Result<Self, CoreError> {
        let channels = TcpConnectionActorChannels::new(BUFFER_CAPACITY);

        let actors = TcpConnection::stream_to_framed_plain(
            channels.send_channel.1,
            channels.recv_channel.1,
            stream,
            global_timeout,
        )?;

        Self::spawn_actors(
            channels.command_channel.1,
            channels.send_channel.0,
            channels.recv_channel.0,
            actors,
        );

        Ok(Self {
            sender: channels.command_channel.0,
        })
    }

    /// Unchanged public API: connect (plain TCP)
    pub async fn connect(
        conn_socket_addr: &str,
        bind_socket_addr: &str,
        global_timeout: Duration,
    ) -> Result<Self, CoreError> {
        let channels = TcpConnectionActorChannels::new(BUFFER_CAPACITY);

        let actors = TcpConnection::connect_plain(
            conn_socket_addr,
            bind_socket_addr,
            channels.send_channel.1,
            channels.recv_channel.1,
            global_timeout,
        )
        .await?;

        Self::spawn_actors(
            channels.command_channel.1,
            channels.send_channel.0,
            channels.recv_channel.0,
            actors,
        );

        Ok(Self {
            sender: channels.command_channel.0,
        })
    }

    /// New optional helper: create a connection handle from an already-established TcpStream,
    /// performing a rustls client handshake to produce a TLS-wrapped stream.
    pub async fn stream_to_framed_tls(
        stream: TcpStream,
        domain: &str,
        client_config: Arc<ClientConfig>,
        global_timeout: Duration,
    ) -> Result<Self, CoreError> {
        let channels = TcpConnectionActorChannels::new(BUFFER_CAPACITY);

        let actors = TcpConnection::stream_to_framed_tls(
            channels.send_channel.1,
            channels.recv_channel.1,
            stream,
            domain,
            client_config,
            global_timeout,
        )
        .await?;

        Self::spawn_actors(
            channels.command_channel.1,
            channels.send_channel.0,
            channels.recv_channel.0,
            actors,
        );

        Ok(Self {
            sender: channels.command_channel.0,
        })
    }

    pub async fn stream_to_framed_tls_server(
        stream: TcpStream,
        server_config: Arc<ServerConfig>,
        global_timeout: Duration,
    ) -> Result<Self, CoreError> {
        let channels = TcpConnectionActorChannels::new(BUFFER_CAPACITY);

        let actors = TcpConnection::stream_to_framed_tls_server(
            channels.send_channel.1,
            channels.recv_channel.1,
            stream,
            server_config,
            global_timeout,
        )
        .await?;

        Self::spawn_actors(
            channels.command_channel.1,
            channels.send_channel.0,
            channels.recv_channel.0,
            actors,
        );

        Ok(Self {
            sender: channels.command_channel.0,
        })
    }

    /// New optional helper: connect and then upgrade the stream with rustls.
    pub async fn connect_tls(
        conn_socket_addr: &str,
        bind_socket_addr: &str,
        domain: &str,
        client_config: Arc<ClientConfig>,
        global_timeout: Duration,
    ) -> Result<Self, CoreError> {
        let channels = TcpConnectionActorChannels::new(BUFFER_CAPACITY);

        let actors = TcpConnection::connect_tls(
            conn_socket_addr,
            bind_socket_addr,
            domain,
            client_config,
            channels.send_channel.1,
            channels.recv_channel.1,
            global_timeout,
        )
        .await?;

        Self::spawn_actors(
            channels.command_channel.1,
            channels.send_channel.0,
            channels.recv_channel.0,
            actors,
        );

        Ok(Self {
            sender: channels.command_channel.0,
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

pub struct TcpConnectionSender<S> {
    pub receiver: mpsc::Receiver<TcpConnectionMessage>,
    pub framed_sink: SplitSink<Framed<BufStream<S>, LengthDelimitedCodec>, Bytes>,
    pub global_timeout: Duration,
}

impl<S> TcpConnectionSender<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
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

    pub fn encode_frame<T>(packet: T) -> Result<Vec<u8>, CoreError>
    where
        T: Encode,
    {
        bincode::encode_to_vec(packet, bincode::config::standard()).map_err(CoreError::from)
    }
}

pub struct TcpConnectionReceiver<S> {
    pub receiver: mpsc::Receiver<TcpConnectionMessage>,
    pub framed_stream: SplitStream<Framed<BufStream<S>, LengthDelimitedCodec>>,
    pub global_timeout: Duration,
}

impl<S> TcpConnectionReceiver<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
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

    pub fn decode_frame<T>(frame: BytesMut) -> Result<T, CoreError>
    where
        T: Decode<()>,
    {
        let (packet, _) = bincode::decode_from_slice(frame.as_ref(), bincode::config::standard())
            .map_err(CoreError::from)?;
        Ok(packet)
    }
}

// ---------- TcpConnection helpers (plain & TLS) ----------

pub struct TcpConnection {}

impl TcpConnection {
    async fn resolve_and_connect(
        addr: &str,
        bind: &str,
        global_timeout: Duration,
    ) -> Result<TcpStream, CoreError> {
        let addrs = lookup_host(addr).await?;
        let mut last_err = None;
        for addr in addrs {
            let socket = TcpSocket::new_v4()?;
            let bind_ip = bind.parse()?;
            socket.bind(bind_ip)?;
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

    fn stream_to_framed_generic<S>(
        message_channel_sender: mpsc::Receiver<TcpConnectionMessage>,
        message_channel_receiver: mpsc::Receiver<TcpConnectionMessage>,
        stream: S,
        global_timeout: Duration,
    ) -> Result<(TcpConnectionSender<S>, TcpConnectionReceiver<S>), CoreError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let buffered = BufStream::new(stream);
        let framed = Framed::new(buffered, LengthDelimitedCodec::new()).split();
        Ok((
            TcpConnectionSender {
                receiver: message_channel_sender,
                framed_sink: framed.0,
                global_timeout,
            },
            TcpConnectionReceiver {
                receiver: message_channel_receiver,
                framed_stream: framed.1,
                global_timeout,
            },
        ))
    }

    pub fn stream_to_framed_plain(
        message_channel_sender: mpsc::Receiver<TcpConnectionMessage>,
        message_channel_receiver: mpsc::Receiver<TcpConnectionMessage>,
        stream: TcpStream,
        global_timeout: Duration,
    ) -> Result<
        (
            TcpConnectionSender<TcpStream>,
            TcpConnectionReceiver<TcpStream>,
        ),
        CoreError,
    > {
        Self::stream_to_framed_generic(
            message_channel_sender,
            message_channel_receiver,
            stream,
            global_timeout,
        )
    }

    pub async fn stream_to_framed_tls(
        message_channel_sender: mpsc::Receiver<TcpConnectionMessage>,
        message_channel_receiver: mpsc::Receiver<TcpConnectionMessage>,
        stream: TcpStream,
        domain: &str,
        client_config: Arc<ClientConfig>,
        global_timeout: Duration,
    ) -> Result<
        (
            TcpConnectionSender<tokio_rustls::client::TlsStream<TcpStream>>,
            TcpConnectionReceiver<tokio_rustls::client::TlsStream<TcpStream>>,
        ),
        CoreError,
    > {
        let connector = TlsConnector::from(client_config);
        let dnsname = ServerName::try_from(domain)?.to_owned();
        let tls_stream = timeout(global_timeout, connector.connect(dnsname, stream))
            .await
            .map_err(|_| CoreError::TimeoutError("TLS handshake timed out".to_string()))??;

        Self::stream_to_framed_generic(
            message_channel_sender,
            message_channel_receiver,
            tls_stream,
            global_timeout,
        )
    }

    pub async fn stream_to_framed_tls_server(
        message_channel_sender: mpsc::Receiver<TcpConnectionMessage>,
        message_channel_receiver: mpsc::Receiver<TcpConnectionMessage>,
        stream: TcpStream,
        server_config: Arc<ServerConfig>,
        global_timeout: Duration,
    ) -> Result<
        (
            TcpConnectionSender<tokio_rustls::server::TlsStream<TcpStream>>,
            TcpConnectionReceiver<tokio_rustls::server::TlsStream<TcpStream>>,
        ),
        CoreError,
    > {
        let connector = TlsAcceptor::from(server_config);
        let tls_stream = timeout(global_timeout, connector.accept(stream))
            .await
            .map_err(|_| CoreError::TimeoutError("TLS handshake timed out".to_string()))??;

        Self::stream_to_framed_generic(
            message_channel_sender,
            message_channel_receiver,
            tls_stream,
            global_timeout,
        )
    }

    /// Plain connect (unchanged public behavior)
    pub async fn connect_plain(
        addr: &str,
        bind: &str,
        message_channel_sender: mpsc::Receiver<TcpConnectionMessage>,
        message_channel_receiver: mpsc::Receiver<TcpConnectionMessage>,
        global_timeout: Duration,
    ) -> Result<
        (
            TcpConnectionSender<TcpStream>,
            TcpConnectionReceiver<TcpStream>,
        ),
        CoreError,
    > {
        let stream = Self::resolve_and_connect(addr, bind, global_timeout).await?;
        Self::stream_to_framed_plain(
            message_channel_sender,
            message_channel_receiver,
            stream,
            global_timeout,
        )
    }

    /// Connect + TLS handshake (new optional helper)
    pub async fn connect_tls(
        addr: &str,
        bind: &str,
        domain: &str,
        client_config: Arc<ClientConfig>,
        message_channel_sender: mpsc::Receiver<TcpConnectionMessage>,
        message_channel_receiver: mpsc::Receiver<TcpConnectionMessage>,
        global_timeout: Duration,
    ) -> Result<
        (
            TcpConnectionSender<tokio_rustls::client::TlsStream<TcpStream>>,
            TcpConnectionReceiver<tokio_rustls::client::TlsStream<TcpStream>>,
        ),
        CoreError,
    > {
        let stream = Self::resolve_and_connect(addr, bind, global_timeout).await?;

        Self::stream_to_framed_tls(
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

// ---------- UDP helpers (unchanged) ----------

pub struct UdpConnection {
    pub socket: UdpSocket,
    pub global_timeout: Duration,
}

impl UdpConnection {
    pub async fn new(global_timeout: Duration) -> Result<Self, CoreError> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
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
