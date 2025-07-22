use crate::app_packet::AppPacket;
use crate::error::{CoreError, CoreErrorKind};
use bincode::{Decode, Encode};
use bytes::Bytes;
use futures::SinkExt;
use log::{debug, error, warn};
use std::fmt::Debug;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::net::unix::SocketAddr;
use tokio::net::{TcpSocket, TcpStream};
use tokio::time::sleep;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

pub struct TcpConnection {
    pub framed: Framed<TcpStream, LengthDelimitedCodec>,
}

impl TcpConnection {
    pub async fn new(addr: &str, device: &str) -> Result<Self, CoreError> {
        // Use timeout instead of select
        let socket = TcpSocket::new_v4()?;
        socket.bind_device(Some(device.as_bytes()))?;
        match tokio::time::timeout(
            Duration::from_secs(1),
            socket.connect(addr.parse::<core::net::SocketAddr>()?),
        )
        .await
        {
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
        T: Encode + Debug + Clone,
    {
        let encoded = bincode::encode_to_vec(packet, bincode::config::standard())?;
        self.framed.send(Bytes::from(encoded)).await?;
        Ok(())
    }

    pub async fn reconnect(&mut self, addr: &str) -> Result<(), CoreError> {
        let stream = TcpStream::connect(addr).await?;
        self.framed = Framed::new(stream, LengthDelimitedCodec::new());
        Ok(())
    }

    pub async fn send_with_reconnect<T>(&mut self, addr: &str, packet: &T, max_retries: usize) -> Result<(), CoreError>
    where T: Encode + Debug + Clone {
        let mut counter = 0;

        loop {
            match self.send_packet(&packet).await {
                Ok(_) => { return Ok(()) }
                Err(e) => {
                    error!("Failed to send packet: {e}");
                    if counter >= max_retries {
                        return Err(e);
                    }
                    counter += 1;
                    warn!("Retrying to send the packet; attempt: {} of {}", counter, max_retries);
                    sleep(Duration::from_secs(1)).await;
                    if let Err(reconnect_error) = self.reconnect(addr).await {
                        error!("Failed to reconnect: {reconnect_error}");
                    }

                }
            }
        }
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
