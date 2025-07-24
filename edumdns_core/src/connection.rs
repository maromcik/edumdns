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
use tokio::time::sleep;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

pub struct TcpConnection {
    pub framed: Framed<TcpStream, LengthDelimitedCodec>,
}

impl TcpConnection {
    pub async fn stream_to_framed(stream: TcpStream) -> Result<Self, CoreError> {
        Ok(Self {
            framed: Framed::new(stream, LengthDelimitedCodec::new()),
        })
    }

    pub async fn connect(addr: &str, bind_ip: &str) -> Result<Self, CoreError> {
        // Use timeout instead of select
        let socket = TcpSocket::new_v4()?;

        let bind_ip = bind_ip.parse()?;
        socket.bind(bind_ip)?;
        match tokio::time::timeout(Duration::from_secs(1), socket.connect(addr.parse()?)).await {
            Ok(Ok(stream)) => Ok(Self {
                framed: Framed::new(stream, LengthDelimitedCodec::new()),
            }),
            Ok(Err(e)) => Err(CoreError::new(
                CoreErrorKind::ConnectionError,
                &e.to_string(),
            )),
            Err(_) => Err(CoreError::new(
                CoreErrorKind::ConnectionError,
                "Connection timed out",
            )),
        }
    }

    pub async fn send_packet<T>(&mut self, packet: &T) -> Result<(), CoreError>
    where
        T: Encode,
    {
        let encoded = TcpConnection::encode_frame(packet)?;
        self.framed.send(Bytes::from(encoded)).await?;
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
        match self.framed.next().await {
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
}

impl UdpConnection {
    pub async fn new() -> Result<Self, CoreError> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        Ok(Self { socket })
    }

    pub async fn send_packet(&self, target: &str, buf: &[u8]) -> Result<(), CoreError> {
        self.socket.send_to(buf, target).await?;
        debug!("Packet to {} successfully sent", target);
        Ok(())
    }
}
