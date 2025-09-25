use std::net::SocketAddr;
use std::sync::Arc;
use crate::app_packet::NetworkAppPacket;
use crate::error::{CoreError, CoreErrorKind};
use bincode::{Decode, Encode};
use bytes::{Bytes, BytesMut};
use futures::stream::{SplitSink, SplitStream};
use futures::{SinkExt, StreamExt};
use log::error;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::net::{TcpSocket, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use rustls::{ClientConfig, ServerConfig};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use rustls_pki_types::{DnsName, ServerName};


// ---------- Message Multiplexers & Run loops (generic over stream S) ----------

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
                        CoreError::new(
                            CoreErrorKind::TokioOneshotChannelError,
                            format!("Could not send value {e:?}").as_str(),
                        )
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

async fn run_tcp_connection_send_loop<S>(
    mut actor: TcpConnectionSender<S>,
) -> Result<(), CoreError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    while let Some(msg) = actor.receiver.recv().await {
        match msg {
            TcpConnectionMessage::SendPacket { respond_to, packet } => {
                respond_to
                    .send(actor.send_packet(&packet).await)
                    .map_err(|e| {
                        CoreError::new(
                            CoreErrorKind::TokioOneshotChannelError,
                            format!("Could not send value {e:?}").as_str(),
                        )
                    })?;
            }
            TcpConnectionMessage::Close {} => {
                actor
                    .framed_sink
                    .close()
                    .await
                    .map_err(CoreError::from)?;
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

// ---------- Messages & Handle (unchanged public API) ----------

pub enum TcpConnectionMessage {
    ReceivePacket {
        respond_to: oneshot::Sender<Result<Option<NetworkAppPacket>, CoreError>>,
        timeout: Option<Duration>,
    },
    SendPacket {
        respond_to: oneshot::Sender<Result<(), CoreError>>,
        packet: NetworkAppPacket,
    },
    Close,
}

impl TcpConnectionMessage {
    pub fn send_packet(
        respond_to: oneshot::Sender<Result<(), CoreError>>,
        packet: NetworkAppPacket,
    ) -> Self {
        Self::SendPacket { respond_to, packet }
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

#[derive(Clone)]
pub struct TcpConnectionHandle {
    pub sender: mpsc::Sender<TcpConnectionMessage>,
}

impl TcpConnectionHandle {
    /// Unchanged public API: create connection handle from a plain TcpStream
    pub fn stream_to_framed(
        stream: TcpStream,
        global_timeout: Duration,
    ) -> Result<Self, CoreError> {
        let (sender, receiver) = mpsc::channel(1000);
        let send_channel = mpsc::channel(1000);
        let recv_channel = mpsc::channel(1000);

        // Use the plain TcpStream variant
        let actors = TcpConnection::stream_to_framed_plain(
            send_channel.1,
            recv_channel.1,
            stream,
            global_timeout,
        )?;

        // spawn multiplexer and loops (they are generic but concrete here)
        tokio::spawn(async move {
            if let Err(e) = run_message_multiplexer(receiver, send_channel.0, recv_channel.0).await
            {
                error!("I/O message multiplexer failed: {e}");
            }
        });
        tokio::spawn(async move {
            if let Err(e) = run_tcp_connection_send_loop(actors.0).await {
                error!("I/O send loop failed: {e}");
            }
        });
        tokio::spawn(async move {
            if let Err(e) = run_tcp_connection_receive_loop(actors.1).await {
                error!("I/O receive loop failed: {e}");
            }
        });

        Ok(Self { sender })
    }

    /// Unchanged public API: connect (plain TCP)
    pub async fn connect(
        addr: &str,
        bind_ip: &str,
        global_timeout: Duration,
    ) -> Result<Self, CoreError> {
        let (sender, receiver) = mpsc::channel(1000);
        let send_channel = mpsc::channel(1000);
        let recv_channel = mpsc::channel(1000);

        let actors = TcpConnection::connect_plain(
            addr,
            bind_ip,
            send_channel.1,
            recv_channel.1,
            global_timeout,
        )
            .await?;

        tokio::spawn(async move {
            if let Err(e) = run_message_multiplexer(receiver, send_channel.0, recv_channel.0).await
            {
                error!("I/O message multiplexer failed: {e}");
            }
        });
        tokio::spawn(async move {
            if let Err(e) = run_tcp_connection_send_loop(actors.0).await {
                error!("I/O send loop failed: {e}");
            }
        });
        tokio::spawn(async move {
            if let Err(e) = run_tcp_connection_receive_loop(actors.1).await {
                error!("I/O receive loop failed: {e}");
            }
        });

        Ok(Self { sender })
    }

    /// New optional helper: create a connection handle from an already-established TcpStream,
    /// performing a rustls client handshake to produce a TLS-wrapped stream.
    pub async fn stream_to_framed_tls(
        stream: TcpStream,
        domain: &str,
        client_config: Arc<ClientConfig>,
        global_timeout: Duration,
    ) -> Result<Self, CoreError> {
        let (sender, receiver) = mpsc::channel(1000);
        let send_channel = mpsc::channel(1000);
        let recv_channel = mpsc::channel(1000);

        let actors = TcpConnection::stream_to_framed_tls(
            send_channel.1,
            recv_channel.1,
            stream,
            domain,
            client_config,
            global_timeout,
        )
            .await?;

        tokio::spawn(async move {
            if let Err(e) = run_message_multiplexer(receiver, send_channel.0, recv_channel.0).await
            {
                error!("I/O message multiplexer failed: {e}");
            }
        });
        tokio::spawn(async move {
            if let Err(e) = run_tcp_connection_send_loop(actors.0).await {
                error!("I/O send loop failed: {e}");
            }
        });
        tokio::spawn(async move {
            if let Err(e) = run_tcp_connection_receive_loop(actors.1).await {
                error!("I/O receive loop failed: {e}");
            }
        });

        Ok(Self { sender })
    }

    pub async fn stream_to_framed_tls_server(
        stream: TcpStream,
        domain: &str,
        server_config: Arc<ServerConfig>,
        global_timeout: Duration,
    ) -> Result<Self, CoreError> {
        let (sender, receiver) = mpsc::channel(1000);
        let send_channel = mpsc::channel(1000);
        let recv_channel = mpsc::channel(1000);

        let actors = TcpConnection::stream_to_framed_tls_server(
            send_channel.1,
            recv_channel.1,
            stream,
            domain,
            server_config,
            global_timeout,
        )
            .await?;

        tokio::spawn(async move {
            if let Err(e) = run_message_multiplexer(receiver, send_channel.0, recv_channel.0).await
            {
                error!("I/O message multiplexer failed: {e}");
            }
        });
        tokio::spawn(async move {
            if let Err(e) = run_tcp_connection_send_loop(actors.0).await {
                error!("I/O send loop failed: {e}");
            }
        });
        tokio::spawn(async move {
            if let Err(e) = run_tcp_connection_receive_loop(actors.1).await {
                error!("I/O receive loop failed: {e}");
            }
        });

        Ok(Self { sender })
    }

    /// New optional helper: connect and then upgrade the stream with rustls.
    pub async fn connect_tls(
        addr: &str,
        bind_ip: &str,
        domain: &str,
        client_config: Arc<ClientConfig>,
        global_timeout: Duration,
    ) -> Result<Self, CoreError> {
        let (sender, receiver) = mpsc::channel(1000);
        let send_channel = mpsc::channel(1000);
        let recv_channel = mpsc::channel(1000);

        let actors = TcpConnection::connect_tls(
            addr,
            bind_ip,
            domain,
            client_config,
            send_channel.1,
            recv_channel.1,
            global_timeout,
        )
            .await?;

        tokio::spawn(async move {
            if let Err(e) = run_message_multiplexer(receiver, send_channel.0, recv_channel.0).await
            {
                error!("I/O message multiplexer failed: {e}");
            }
        });
        tokio::spawn(async move {
            if let Err(e) = run_tcp_connection_send_loop(actors.0).await {
                error!("I/O send loop failed: {e}");
            }
        });
        tokio::spawn(async move {
            if let Err(e) = run_tcp_connection_receive_loop(actors.1).await {
                error!("I/O receive loop failed: {e}");
            }
        });

        Ok(Self { sender })
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

// ---------- Generic Sender/Receiver implementations ----------

pub struct TcpConnectionSender<S> {
    pub receiver: mpsc::Receiver<TcpConnectionMessage>,
    pub framed_sink: SplitSink<Framed<S, LengthDelimitedCodec>, Bytes>,
    pub global_timeout: Duration,
}

impl<S> TcpConnectionSender<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    pub async fn send_packet<T>(&mut self, packet: T) -> Result<(), CoreError>
    where
        T: Encode,
    {
        let encoded = Self::encode_frame(packet)?;
        timeout(
            self.global_timeout,
            self.framed_sink.send(Bytes::from(encoded)),
        )
            .await
            .map_err(|_| CoreError::new(CoreErrorKind::TimeoutError, "Sending a packet timed out"))??;
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
    pub framed_stream: SplitStream<Framed<S, LengthDelimitedCodec>>,
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
                .map_err(|_| {
                    CoreError::new(CoreErrorKind::TimeoutError, "Receiving a packet timed out")
                })?,
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
    pub fn stream_to_framed_generic<S>(
        message_channel_sender: mpsc::Receiver<TcpConnectionMessage>,
        message_channel_receiver: mpsc::Receiver<TcpConnectionMessage>,
        stream: S,
        global_timeout: Duration,
    ) -> Result<(TcpConnectionSender<S>, TcpConnectionReceiver<S>), CoreError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let framed = Framed::new(stream, LengthDelimitedCodec::new()).split();
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
    ) -> Result<(TcpConnectionSender<TcpStream>, TcpConnectionReceiver<TcpStream>), CoreError> {
        Self::stream_to_framed_generic(message_channel_sender, message_channel_receiver, stream, global_timeout)
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
        let tls_stream = timeout(
            global_timeout,
            connector.connect(dnsname, stream),
        )
            .await
            .map_err(|_| CoreError::new(CoreErrorKind::TimeoutError, "TLS handshake timed out"))??;

        Self::stream_to_framed_generic(message_channel_sender, message_channel_receiver, tls_stream, global_timeout)
    }

    pub async fn stream_to_framed_tls_server(
        message_channel_sender: mpsc::Receiver<TcpConnectionMessage>,
        message_channel_receiver: mpsc::Receiver<TcpConnectionMessage>,
        stream: TcpStream,
        domain: &str,
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
        let dnsname = ServerName::try_from(domain)?.to_owned();
        let tls_stream = timeout(
            global_timeout,
            connector.accept(stream),
        )
            .await
            .map_err(|_| CoreError::new(CoreErrorKind::TimeoutError, "TLS handshake timed out"))??;

        Self::stream_to_framed_generic(message_channel_sender, message_channel_receiver, tls_stream, global_timeout)
    }

    /// Plain connect (unchanged public behavior)
    pub async fn connect_plain(
        addr: &str,
        bind_ip: &str,
        message_channel_sender: mpsc::Receiver<TcpConnectionMessage>,
        message_channel_receiver: mpsc::Receiver<TcpConnectionMessage>,
        global_timeout: Duration,
    ) -> Result<(TcpConnectionSender<TcpStream>, TcpConnectionReceiver<TcpStream>), CoreError> {
        let socket = TcpSocket::new_v4()?;
        let bind_ip = bind_ip.parse()?;
        socket.bind(bind_ip)?;
        socket.set_keepalive(true)?;
        // parse addr into SocketAddr
        let addr: SocketAddr = addr.parse()?;
        let stream = tokio::time::timeout(global_timeout, socket.connect(addr))
            .await
            .map_err(|_| {
                CoreError::new(
                    CoreErrorKind::TimeoutError,
                    format!("Connection to {addr} timed out").as_str(),
                )
            })??;
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
        bind_ip: &str,
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
        let socket = TcpSocket::new_v4()?;
        let bind_ip = bind_ip.parse()?;
        socket.bind(bind_ip)?;
        socket.set_keepalive(true)?;
        let addr: SocketAddr = addr.parse()?;
        let stream = tokio::time::timeout(global_timeout, socket.connect(addr))
            .await
            .map_err(|_| {
                CoreError::new(
                    CoreErrorKind::TimeoutError,
                    format!("Connection to {addr} timed out").as_str(),
                )
            })??;

        // perform TLS handshake and create framed
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
                CoreError::new(
                    CoreErrorKind::TimeoutError,
                    format!("Sending UDP packets to {target} timed out").as_str(),
                )
            })??;
        Ok(())
    }
}
