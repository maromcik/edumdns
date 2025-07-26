use crate::app_packet::{AppPacket, StatusPacket};
use crate::error::{CoreError, CoreErrorKind};
use bincode::{Decode, Encode};
use bytes::{Bytes, BytesMut};
use futures::{SinkExt, StreamExt};
use log::{debug, error, warn};
use std::fmt::Debug;
use std::io::Error;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::net::{TcpSocket, TcpStream};
use tokio::time::error::Elapsed;
use tokio::time::{sleep, timeout};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

pub struct TcpConnection {
    pub framed: Framed<TcpStream, LengthDelimitedCodec>,
    pub global_timeout: Duration,
}

impl TcpConnection {
    pub async fn stream_to_framed(
        stream: TcpStream,
        global_timeout: Duration,
    ) -> Result<Self, CoreError> {
        Ok(Self {
            framed: Framed::new(stream, LengthDelimitedCodec::new()),
            global_timeout,
        })
    }

    pub async fn connect(
        addr: &str,
        bind_ip: &str,
        global_timeout: Duration,
    ) -> Result<Self, CoreError> {
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

        Ok(Self {
            framed: Framed::new(stream, LengthDelimitedCodec::new()),
            global_timeout,
        })
    }

    pub async fn pinger(&mut self) -> Result<(), CoreError> {
        let ping = AppPacket::Status(StatusPacket::PingRequest);

        self.send_packet(&ping).await?;

        let response: Option<(AppPacket, usize)> = self.receive_next().await?;

        let Some((AppPacket::Status(StatusPacket::PingResponse), _)) = response else {
            return Err(CoreError::new(
                CoreErrorKind::PingError,
                "Ping response has not been received",
            ));
        };

        Ok(())
    }

    pub async fn send_packet<T>(&mut self, packet: &T) -> Result<(), CoreError>
    where
        T: Encode,
    {
        let encoded = TcpConnection::encode_frame(packet)?;
        timeout(self.global_timeout, self.framed.send(Bytes::from(encoded)))
            .await
            .map_err(|_| {
                CoreError::new(CoreErrorKind::TimeoutError, "Sending a packet timed out")
            })??;
        Ok(())
    }

    pub async fn reconnect(&mut self, addr: &str) -> Result<(), CoreError> {
        let stream = TcpStream::connect(addr).await?;
        self.framed = Framed::new(stream, LengthDelimitedCodec::new());
        Ok(())
    }

    pub async fn send_with_reconnect<T>(
        &mut self,
        addr: &str,
        packet: &T,
        max_retries: usize,
    ) -> Result<(), CoreError>
    where
        T: Encode,
    {
        let mut counter = 0;

        loop {
            match self.send_packet(&packet).await {
                Ok(_) => return Ok(()),
                Err(e) => {
                    error!("Failed to send packet: {e}");
                    if counter >= max_retries {
                        return Err(e);
                    }
                    counter += 1;
                    warn!("Retrying to send the packet; attempt: {counter} of {max_retries}");
                    sleep(Duration::from_secs(1)).await;
                    if let Err(reconnect_error) = self.reconnect(addr).await {
                        error!("Failed to reconnect: {reconnect_error}");
                    }
                }
            }
        }
    }

    pub async fn receive_next<T>(&mut self) -> Result<Option<(T, usize)>, CoreError>
    where
        T: Decode<()>,
    {
        match timeout(self.global_timeout, self.framed.next())
            .await
            .map_err(|_| {
                CoreError::new(CoreErrorKind::TimeoutError, "Receiving a packet timed out")
            })? {
            None => Ok(None),
            Some(frame) => {
                let decoded = Self::decode_frame(frame?)?;
                Ok(Some(decoded))
            }
        }
    }

    pub fn decode_frame<T>(frame: BytesMut) -> Result<(T, usize), CoreError>
    where
        T: Decode<()>,
    {
        bincode::decode_from_slice(frame.as_ref(), bincode::config::standard())
            .map_err(CoreError::from)
    }

    pub fn encode_frame<T>(packet: &T) -> Result<Vec<u8>, CoreError>
    where
        T: Encode,
    {
        bincode::encode_to_vec(packet, bincode::config::standard()).map_err(CoreError::from)
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
        debug!("Packet to {target} successfully sent");
        Ok(())
    }
}
