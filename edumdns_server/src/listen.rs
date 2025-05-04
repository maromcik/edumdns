use crate::error::ServerError;
use edumdns_core::error::CoreError;
use edumdns_core::packet::{ProbePacket};
use futures::StreamExt;
use log::{debug, error, info};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use crate::connection::UdpConnection;

async fn handle_connection(socket: TcpStream) -> Result<(), ServerError> {
    let mut framed = Framed::new(socket, LengthDelimitedCodec::new());
    let udp_connection = UdpConnection::new().await?;
    while let Some(Ok(frame)) = framed.next().await {
        let (packet, size): (ProbePacket, usize) =
            bincode::decode_from_slice(frame.as_ref(), bincode::config::standard())
                .map_err(CoreError::from)?;
        debug!("ID: {}, Data: {:?}", packet.id, packet.metadata);
        udp_connection.send_packet("192.168.4.80:5353", packet.payload.as_slice()).await?;
    }
    debug!("Client disconnected");
    Ok(())
}

pub async fn listen() -> Result<(), ServerError> {
    let listener = TcpListener::bind("127.0.0.1:5000").await?;

    loop {
        let (socket, addr) = listener.accept().await?;
        debug!("Connection from {}", addr);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(socket).await {
                error!("E: {}", e);
            }
        });
    }
}
