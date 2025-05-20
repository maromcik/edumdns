use crate::error::{ProbeError, ProbeErrorKind};
use bytes::Bytes;
use edumdns_core::app_packet::AppPacket;
use futures::SinkExt;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

pub struct Connection {
    pub framed: Framed<TcpStream, LengthDelimitedCodec>,
}

impl Connection {
    pub async fn new(addr: &str) -> Result<Self, ProbeError> {
        // Use timeout instead of select
        match tokio::time::timeout(Duration::from_secs(1), TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => Ok(Self {
                framed: Framed::new(stream, LengthDelimitedCodec::new()),
            }),
            Ok(Err(e)) => Err(ProbeError::new(ProbeErrorKind::ConnectionError, &e.to_string())),
            Err(_) => Err(ProbeError::new(ProbeErrorKind::ConnectionError, "Connection timed out")),
        }
    }


    pub async fn send_packet(&mut self, packet: &AppPacket) -> Result<(), ProbeError> {
        let encoded = bincode::encode_to_vec(packet, bincode::config::standard())?;
        self.framed.send(Bytes::from(encoded)).await?;
        Ok(())
    }

    pub async fn reconnect(&mut self, addr: &str) -> Result<(), ProbeError> {
        let stream = TcpStream::connect(addr).await?;
        self.framed = Framed::new(stream, LengthDelimitedCodec::new());
        Ok(())
    }
}
