use log::debug;
use tokio::net::UdpSocket;
use crate::error::ServerError;

pub struct UdpConnection {
    pub socket: UdpSocket
}

impl UdpConnection {
    pub async fn new() -> Result<Self, ServerError> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        Ok(Self { socket })
    }

    pub async fn send_packet(&self, target: &str, buf: &[u8]) -> Result<(), ServerError> {
        self.socket.send_to(buf, target).await?;
        debug!("Packet to {} successfully sent", target);
        Ok(())
    }
}
