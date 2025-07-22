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

pub mod error;
pub mod capture;
pub mod connection;


pub async fn probe_init() -> Result<(), ProbeError> {
    let listen_interfaces_names = vec![("wlp2s0", Some("port 5201".to_string()))];
    let data_interface_name = "lo";
    let server_addr_port = "127.0.0.1:5000";
    let _ = interfaces()
        .iter()
        .find(|i| i.name == data_interface_name)
        .ok_or(ProbeError::new(
            ProbeErrorKind::InterfaceError,
            format!("Interface {data_interface_name} not found").as_str(),
        ))?;

    let mut interface_tasks = Vec::default();
    let (tx, rx) = tokio::sync::mpsc::channel(1000);

    let mut connection_manager = ConnectionManager::new(server_addr_port, data_interface_name, rx, 5).await?;
    
    let config = connection_manager.connection_init_probe(Uuid(uuid::Uuid::from_u128(32))).await?;
    


    for (if_name, filter) in listen_interfaces_names {
        let interface = interfaces()
            .iter()
            .find(|i| i.name == if_name)
            .ok_or(ProbeError::new(
                ProbeErrorKind::InterfaceError,
                format!("Interface {data_interface_name} not found").as_str(),
            ))?
            .clone();
        if !interface.is_up() {
            return Err(ProbeError::new(
                ProbeErrorKind::InterfaceError,
                format!("Interface {if_name} is not up").as_str(),
            ));
        }
        let probe_metadata = ProbeMetadata {
            id: Uuid(uuid::Uuid::from_u128(32)),
            ip: interface
                .ips
                .first()
                .ok_or(ProbeError::new(
                    ProbeErrorKind::InterfaceError,
                    format!("Interface {data_interface_name} has no IPs").as_str(),
                ))?
                .ip(),
            port: 0,
        };

        // let capture = PacketCaptureGeneric::<Active>::open_device_capture(if_name, filter)?;

        let capture = PacketCaptureGeneric::<Active>::open_file_capture(
            "/home/roman/UNI/DP/pcap/streamer2.pcap",
            None,
        )?;
        let tx_local = tx.clone();

        let task = tokio::spawn(async move {
            listen_and_send(capture, &probe_metadata, tx_local).await
        });

        interface_tasks.push(task);
    }

    drop(tx);
    let transmit_task = tokio::spawn(async move {
        connection_manager.transmit_packets().await
    });
    transmit_task.await??;
    for task in interface_tasks {
        task.await??;
    }
    Ok(())
}
