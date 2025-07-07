use crate::error::{ProbeError, ProbeErrorKind};
use crate::listen::listen_and_send;
use edumdns_core::bincode_types::Uuid;
use edumdns_core::capture::PacketCaptureGeneric;
use edumdns_core::metadata::ProbeMetadata;
use pcap::Active;
use pnet::datalink::{NetworkInterface, interfaces};
use std::net::{IpAddr, Ipv4Addr};

pub mod connection;
pub mod error;
pub mod listen;
pub mod packet;
use std::thread;

pub async fn probe_init() -> Result<(), ProbeError> {
    let listen_interfaces_names = vec![("wlp2s0", Some("port 5201".to_string()))];
    let data_interface_name = "wlp2s0";

    let _ = interfaces()
        .iter()
        .find(|i| i.name == data_interface_name)
        .ok_or(ProbeError::new(
            ProbeErrorKind::InterfaceError,
            format!("Interface {data_interface_name} not found").as_str(),
        ))?;

    let mut interface_tasks = Vec::default();
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

        let task = tokio::spawn(async move {
            listen_and_send(capture, &probe_metadata, data_interface_name).await
        });

        interface_tasks.push(task);
    }

    for task in interface_tasks {
        task.await??;
    }

    Ok(())
}
