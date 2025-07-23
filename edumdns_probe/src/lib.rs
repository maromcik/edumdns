use std::net::IpAddr;
use crate::capture::listen_and_send;
use crate::error::{ProbeError, ProbeErrorKind};
use edumdns_core::bincode_types::Uuid;
use edumdns_core::capture::PacketCaptureGeneric;
use edumdns_core::metadata::ProbeMetadata;
use pcap::Active;
use pnet::datalink::interfaces;
use edumdns_core::connection::TcpConnection;
use edumdns_core::retry;
use log::{debug, error, warn};
use crate::connection::ConnectionManager;
use crate::probe::ProbeCapture;

pub mod error;
pub mod capture;
pub mod connection;
pub mod probe;


pub async fn probe_init() -> Result<(), ProbeError> {
    let uuid = Uuid(uuid::Uuid::from_u128(32));
    let bind_ip = "192.168.4.65:0";
    let server_addr_port = "127.0.0.1:5000";

    let (tx, rx) = tokio::sync::mpsc::channel(1000);

    let probe_metadata = ProbeMetadata {
        id: uuid,
        ip: "127.0.0.1".parse::<IpAddr>()?,
        port: 0,
    };

    let mut connection_manager = ConnectionManager::new(probe_metadata.clone(), server_addr_port, bind_ip, rx, 5).await?;

    let config = connection_manager.connection_init_probe().await?;


    let probe_capture = ProbeCapture::new(tx, probe_metadata, config);
    probe_capture.start_captures().await?;


    let transmit_task = tokio::spawn(async move {
        if let Err(e) = connection_manager.transmit_packets().await {
            error!("Transmit error: {e}, retrying...");

        }

        Ok::<(), ProbeError>(())
    });
    transmit_task.await??;

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