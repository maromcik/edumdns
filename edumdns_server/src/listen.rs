use crate::error::{ServerError, ServerErrorKind};
use crate::storage::PacketStorage;
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::deadpool::Pool;
use edumdns_core::app_packet::{AppPacket, CommandPacket, PacketTransmitTarget};
use edumdns_core::bincode_types::MacAddr as MyMacAddr;
use edumdns_core::connection::TcpConnection;
use edumdns_core::error::CoreError;
use futures::StreamExt;
use log::{debug, error, info};
use pnet::datalink::MacAddr;
use std::process::exit;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::Sender;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use crate::connection::ConnectionManager;

async fn handle_connection(
    stream: TcpStream,
    packet_sender: Sender<AppPacket>,
) -> Result<(), ServerError> {
    let mut connection_manager = ConnectionManager::new(stream).await?;
    connection_manager.connection_init_server().await?;
    connection_manager.transfer_packets(packet_sender).await?;
    debug!("Client disconnected");
    Ok(())
}

pub async fn listen(pool: Pool<AsyncPgConnection>) -> Result<(), ServerError> {
    let listener = TcpListener::bind("127.0.0.1:5000").await?;
    info!("Listening on {}", listener.local_addr()?);
    let (tx, rx) = tokio::sync::mpsc::channel(1000);
    let (tx_err, rx_err) = tokio::sync::mpsc::channel(100);
    let packet_storage_task = tokio::task::spawn(async move {
        let mut packet_storage = PacketStorage::new(rx, tx_err, pool.clone());
        packet_storage.handle_packets().await
    });
    info!("Packet storage initialized");

    let packet_target = PacketTransmitTarget::new(
        MyMacAddr("b8:7b:d4:98:29:64".parse::<MacAddr>().unwrap()),
        "127.0.0.1".to_string(),
        7654,
    );
    loop {
        let (socket, addr) = listener.accept().await?;
        debug!("Connection from {}", addr);
        let tx_local = tx.clone();
        let tx_local2 = tx.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(socket, tx_local).await {
                error!("E: {}", e);
            }
        });
        tokio::time::sleep(Duration::from_secs(2)).await;
        tx_local2
            .send(AppPacket::Command(CommandPacket::TransmitDevicePackets(
                packet_target.clone(),
            )))
            .await
            .unwrap();
        tx_local2
            .send(AppPacket::Command(CommandPacket::TransmitDevicePackets(
                packet_target.clone(),
            )))
            .await
            .unwrap();
        tx_local2
            .send(AppPacket::Command(CommandPacket::TransmitDevicePackets(
                packet_target.clone(),
            )))
            .await
            .unwrap();
        tx_local2
            .send(AppPacket::Command(CommandPacket::TransmitDevicePackets(
                packet_target.clone(),
            )))
            .await
            .unwrap();
        tx_local2
            .send(AppPacket::Command(CommandPacket::TransmitDevicePackets(
                packet_target.clone(),
            )))
            .await
            .unwrap();
        tx_local2
            .send(AppPacket::Command(CommandPacket::TransmitDevicePackets(
                packet_target.clone(),
            )))
            .await
            .unwrap();
        tx_local2
            .send(AppPacket::Command(CommandPacket::TransmitDevicePackets(
                packet_target.clone(),
            )))
            .await
            .unwrap();
        tx_local2
            .send(AppPacket::Command(CommandPacket::TransmitDevicePackets(
                packet_target.clone(),
            )))
            .await
            .unwrap();
    }
}
