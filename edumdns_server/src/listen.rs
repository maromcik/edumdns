use crate::connection::ConnectionManager;
use crate::error::{ServerError, ServerErrorKind};
use crate::storage::PacketStorage;
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::deadpool::Pool;
use edumdns_core::app_packet::{AppPacket, CommandPacket, PacketTransmitRequest};
use edumdns_core::bincode_types::{IpNetwork, MacAddr as MyMacAddr, Uuid};
use edumdns_core::connection::TcpConnection;
use edumdns_core::error::CoreError;
use futures::StreamExt;
use log::{debug, error, info, warn};
use pnet::datalink::MacAddr;
use std::process::exit;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::Sender;
use tokio::time::sleep;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

async fn handle_connection(
    stream: TcpStream,
    packet_sender: Sender<AppPacket>,
    pool: Pool<AsyncPgConnection>,
) -> Result<(), ServerError> {
    let mut connection_manager = ConnectionManager::new(stream, pool, Duration::from_secs(10))?;
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
    let pool_local = pool.clone();
    let _packet_storage_task = tokio::task::spawn(async move {
        let mut packet_storage = PacketStorage::new(rx, tx_err, pool_local);
        packet_storage.handle_packets().await
    });
    info!("Packet storage initialized");

    let packet_target = PacketTransmitRequest::new(
        Uuid(uuid::Uuid::from_u128(32)),
        MyMacAddr("42:ba:e5:56:9a:66".parse::<MacAddr>().unwrap()),
        IpNetwork("100.66.2.58".parse::<ipnetwork::IpNetwork>().unwrap()),
        "127.0.0.1".to_string(),
        7654,
    );
    loop {
        let (socket, addr) = listener.accept().await?;
        info!("Connection from {addr}");
        let tx_local = tx.clone();
        let tx_local2 = tx.clone();
        let pool_local = pool.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(socket, tx_local, pool_local).await {
                if let ServerErrorKind::ProbeNotAdopted = e.error_kind {
                    warn!("Client {addr} tried to connect, but probe is not adopted");
                } else {
                    error!("{e}");
                }
            }
        });
        sleep(Duration::from_secs(10)).await;
        tx_local2
            .send(AppPacket::Command(CommandPacket::TransmitDevicePackets(
                packet_target.clone(),
            )))
            .await
            .unwrap();
    }
}
