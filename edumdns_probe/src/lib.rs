use crate::connection::ConnectionManager;
use crate::error::ProbeError;
use crate::probe::ProbeCapture;
use edumdns_core::bincode_types::{MacAddr, Uuid};
use edumdns_core::metadata::ProbeMetadata;
use std::net::IpAddr;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

pub mod capture;
pub mod connection;
pub mod error;
pub mod probe;

pub async fn probe_init() -> Result<(), ProbeError> {
    let uuid = Uuid(uuid::Uuid::from_u128(32));
    let bind_ip = "192.168.80.41:0";
    let server_addr_port = "127.0.0.1:5000";

    let (send_transmitter, send_receiver) = mpsc::channel(1000);

    let probe_metadata = ProbeMetadata {
        id: uuid,
        ip: "127.0.0.1".parse::<IpAddr>()?,
        mac: MacAddr::from_octets([1, 0, 0, 0, 0, 0]),
    };
    
    
    let retry_interval = Duration::from_secs(1);
    let global_timeout = Duration::from_secs(10);
    
    let mut connection_manager = ConnectionManager::new(
        probe_metadata.clone(),
        server_addr_port,
        bind_ip,
        5,
        retry_interval,
        global_timeout)
        .await?;
    let config = connection_manager
        .connection_init_probe()
        .await?;

    let handle_local = connection_manager.handle.clone();
    let command_channel = mpsc::channel(1000);

    let (receive_transmitter, receive_receiver) = mpsc::channel(1000);

    tokio::spawn(async move {
        ConnectionManager::pinger(handle_local, receive_receiver, command_channel.0, retry_interval).await?;
        Ok::<(), ProbeError>(())
    });
    
    let probe_capture = ProbeCapture::new(send_transmitter.clone(), probe_metadata, config);
    probe_capture.start_captures().await?;
    

    let transmit_task = tokio::spawn(async move {
        connection_manager.transmit_packets(send_receiver, command_channel.1).await?;
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
