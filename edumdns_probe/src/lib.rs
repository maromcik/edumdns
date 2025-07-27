use crate::capture::listen_and_send;
use crate::connection::ConnectionManager;
use crate::error::{ProbeError, ProbeErrorKind};
use crate::probe::ProbeCapture;
use edumdns_core::bincode_types::{MacAddr, Uuid};
use edumdns_core::capture::PacketCaptureGeneric;
use edumdns_core::connection::TcpConnection;
use edumdns_core::metadata::ProbeMetadata;
use edumdns_core::retry;
use log::{debug, error, warn};
use pcap::Active;
use pnet::datalink::interfaces;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use edumdns_core::app_packet::{AppPacket, CommandPacket};

pub mod capture;
pub mod connection;
pub mod error;
pub mod probe;

pub async fn probe_init() -> Result<(), ProbeError> {
    let uuid = Uuid(uuid::Uuid::from_u128(32));
    let bind_ip = "192.168.6.254:0";
    let server_addr_port = "127.0.0.1:5000";

    let (send_transmitter, send_receiver) = tokio::sync::mpsc::channel(1000);

    let probe_metadata = ProbeMetadata {
        id: uuid,
        ip: "127.0.0.1".parse::<IpAddr>()?,
        mac: MacAddr::from_octets([1, 0, 0, 0, 0, 0]),
    };

    let mut connection_manager = ConnectionManager::new(
        probe_metadata.clone(),
        server_addr_port,
        bind_ip,
        send_receiver,
        5,
        Duration::from_secs(1),
        Duration::from_secs(10))
        .await?;

    let config = connection_manager
        .connection_init_probe()
        .await?;

    let probe_capture = ProbeCapture::new(send_transmitter.clone(), probe_metadata, config);
    probe_capture.start_captures().await?;

    // let pinger_task = tokio::spawn(async move {
    //     connection_manager_local.lock().await.pinger().await?;
    //     Ok::<(), ProbeError>(())
    // });
    //
    // let watcher_task = tokio::spawn(async move {
    //     connection_manager_local.lock().await.watcher().await?;
    //     Ok::<(), ProbeError>(())
    // });

    let transmit_task = tokio::spawn(async move {
        connection_manager.transmit_packets().await?;
        Ok::<(), ProbeError>(())
    });
    
    // tokio::spawn(async move {
    //     ConnectionManager::pinger(send_transmitter, receive_receiver, command_transmitter, Duration::from_secs(1)).await?;
    //     Ok::<(), ProbeError>(())
    // });
    //
    //

    transmit_task.await??;
    // pinger_task.await??;
    // watcher_task.await??;

    Ok(())
}

// pub async fn dump() {
//     let interface = interfaces()
//         .iter()
//         .find(|i| i.name == if_name)
//         .ok_or(ProbeError::new(
//             ProbeErrorKind::InterfaceError,
//             format!("Interface {data_interface_name} not found").as_str(),
//         ))?
//         .clone();
//     if !interface.is_up() {
//         return Err(ProbeError::new(
//             ProbeErrorKind::InterfaceError,
//             format!("Interface {if_name} is not up").as_str(),
//         ));
//     }
//
//     ip: interface
//         .ips
//         .first()
//         .ok_or(ProbeError::new(
//             ProbeErrorKind::InterfaceError,
//             format!("Interface {data_interface_name} has no IPs").as_str(),
//         ))?
//         .ip(),
// }
