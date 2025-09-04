use crate::app_packet::NetworkAppPacket;
use crate::error::{CoreError, CoreErrorKind};
use bincode::{Decode, Encode};
use bytes::{Bytes, BytesMut};
use futures::stream::{SplitSink, SplitStream};
use futures::{SinkExt, StreamExt};
use log::{error};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::net::{TcpSocket, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

async fn run_tcp_connection_receive_loop(
    mut actor: TcpConnectionReceiver,
) -> Result<(), CoreError> {
    while let Some(msg) = actor.receiver.recv().await {
        if let TcpConnectionMessage::ReceivePacket {
            respond_to,
            timeout,
        } = msg
        {
            respond_to
                .send(actor.receive_next(timeout).await)
                .map_err(|e| {
                    CoreError::new(
                        CoreErrorKind::TokioOneshotChannelError,
                        format!("Could not send value {e:?}").as_str(),
                    )
                })?;
        }
    }
    Ok(())
}

async fn run_tcp_connection_send_loop(mut actor: TcpConnectionSender) -> Result<(), CoreError> {
    while let Some(msg) = actor.receiver.recv().await {
        if let TcpConnectionMessage::SendPacket { respond_to, packet } = msg {
            respond_to
                .send(actor.send_packet(&packet).await)
                .map_err(|e| {
                    CoreError::new(
                        CoreErrorKind::TokioOneshotChannelError,
                        format!("Could not send value {e:?}").as_str(),
                    )
                })?;
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
        }
    }
    Ok(())
}

pub enum TcpConnectionMessage {
    ReceivePacket {
        respond_to: oneshot::Sender<Result<Option<NetworkAppPacket>, CoreError>>,
        timeout: Option<Duration>,
    },
    SendPacket {
        respond_to: oneshot::Sender<Result<(), CoreError>>,
        packet: NetworkAppPacket,
    },
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
    pub fn stream_to_framed(
        stream: TcpStream,
        global_timeout: Duration,
    ) -> Result<Self, CoreError> {
        let (sender, receiver) = mpsc::channel(1000);
        let send_channel = mpsc::channel(1000);
        let recv_channel = mpsc::channel(1000);

        let actors = TcpConnection::stream_to_framed(
            send_channel.1,
            recv_channel.1,
            stream,
            global_timeout,
        )?;

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

    pub async fn connect(
        addr: &str,
        bind_ip: &str,
        global_timeout: Duration,
    ) -> Result<Self, CoreError> {
        let (sender, receiver) = mpsc::channel(1000);
        let send_channel = mpsc::channel(1000);
        let recv_channel = mpsc::channel(1000);

        let actors = TcpConnection::connect(
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

    pub async fn send_message_with_response<T>(
        &self,
        message_creator: impl FnOnce(oneshot::Sender<T>) -> TcpConnectionMessage,
    ) -> Result<T, CoreError> {
        let (tx, rx) = oneshot::channel();
        self.sender.send(message_creator(tx)).await?;
        rx.await.map_err(Into::into)
    }
}

pub struct TcpConnectionSender {
    pub receiver: mpsc::Receiver<TcpConnectionMessage>,
    pub framed_sink: SplitSink<Framed<TcpStream, LengthDelimitedCodec>, Bytes>,
    pub global_timeout: Duration,
}

impl TcpConnectionSender {
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

pub struct TcpConnectionReceiver {
    pub receiver: mpsc::Receiver<TcpConnectionMessage>,
    pub framed_stream: SplitStream<Framed<TcpStream, LengthDelimitedCodec>>,
    pub global_timeout: Duration,
}

impl TcpConnectionReceiver {
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

pub struct TcpConnection {}

impl TcpConnection {
    pub fn stream_to_framed(
        message_channel_sender: mpsc::Receiver<TcpConnectionMessage>,
        message_channel_receiver: mpsc::Receiver<TcpConnectionMessage>,
        stream: TcpStream,
        global_timeout: Duration,
    ) -> Result<(TcpConnectionSender, TcpConnectionReceiver), CoreError> {
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

    pub async fn connect(
        addr: &str,
        bind_ip: &str,
        message_channel_sender: mpsc::Receiver<TcpConnectionMessage>,
        message_channel_receiver: mpsc::Receiver<TcpConnectionMessage>,
        global_timeout: Duration,
    ) -> Result<(TcpConnectionSender, TcpConnectionReceiver), CoreError> {
        let socket = TcpSocket::new_v4()?;
        let bind_ip = bind_ip.parse()?;
        socket.bind(bind_ip)?;
        let stream = tokio::time::timeout(global_timeout, socket.connect(addr.parse()?))
            .await
            .map_err(|_| {
                CoreError::new(
                    CoreErrorKind::TimeoutError,
                    format!("Connection to {bind_ip} timed out").as_str(),
                )
            })??;
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
}

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
