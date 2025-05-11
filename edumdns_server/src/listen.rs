use crate::error::ServerError;
use edumdns_core::error::CoreError;
use edumdns_core::packet::{ProbePacket};
use futures::StreamExt;
use log::{debug, error, info};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::Sender;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use crate::connection::UdpConnection;
use crate::storage::PacketStorage;

async fn handle_connection(socket: TcpStream, packet_sender: Sender<ProbePacket>) -> Result<(), ServerError> {
    let mut framed = Framed::new(socket, LengthDelimitedCodec::new());
    let udp_connection = UdpConnection::new().await?;
    while let Some(Ok(frame)) = framed.next().await {
        let (packet, size): (ProbePacket, usize) =
            bincode::decode_from_slice(frame.as_ref(), bincode::config::standard())
                .map_err(CoreError::from)?;
        
        // debug!("ID: {}, Data: {:?}", packet.id, packet.metadata);
        packet_sender.send(packet).await.expect("Poisoned");
        
    }
    debug!("Client disconnected");
    Ok(())
}

pub async fn listen() -> Result<(), ServerError> {
    let listener = TcpListener::bind("127.0.0.1:5000").await?;
    info!("Listening on {}", listener.local_addr()?);
    let (tx, rx) = tokio::sync::mpsc::channel(1000);
    let mut packet_storage = PacketStorage::new(rx);
    let packet_storage = tokio::task::spawn(
        async move { packet_storage.fill_packet_storage().await },
    );
    
    info!("Packet storage initialized");
    loop {
        let (socket, addr) = listener.accept().await?;
        debug!("Connection from {}", addr);
        let tx_local = tx.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(socket, tx_local).await {
                error!("E: {}", e);
            }
        });
    }
}
