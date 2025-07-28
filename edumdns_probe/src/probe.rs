use std::time::Duration;
use log::{info, warn};
use crate::capture::listen_and_send;
use crate::error::{ProbeError, ProbeErrorKind};
use edumdns_core::app_packet::{AppPacket, ProbeConfigElement, ProbeConfigPacket};
use edumdns_core::bincode_types::Uuid;
use edumdns_core::capture::PacketCaptureGeneric;
use edumdns_core::metadata::ProbeMetadata;
use pcap::{Active, Direction};
use pnet::datalink::interfaces;
use tokio::sync::mpsc::Sender;
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;

pub struct ProbeCapture {
    tx: Sender<AppPacket>,
    probe_metadata: ProbeMetadata,
    probe_config: ProbeConfigPacket,
}

impl ProbeCapture {
    pub fn new(
        tx: Sender<AppPacket>,
        probe_metadata: ProbeMetadata,
        probe_config: ProbeConfigPacket,
    ) -> Self {
        Self {
            tx,
            probe_metadata,
            probe_config,
        }
    }
    pub async fn start_captures(&self, join_set: &mut JoinSet<Result<(), ProbeError>>, cancellation_token: CancellationToken) -> Result<(), ProbeError> {
        let listen_interfaces_names = vec![("wlp2s0", Some("port 5201".to_string()))];

        for config_element in &self.probe_config.interface_filter_map {
            let interface = interfaces()
                .iter()
                .find(|i| i.name == config_element.interface_name)
                .ok_or(ProbeError::new(
                    ProbeErrorKind::InterfaceError,
                    format!("Interface {} not found", config_element.interface_name).as_str(),
                ))?
                .clone();
            if !interface.is_up() {
                return Err(ProbeError::new(
                    ProbeErrorKind::InterfaceError,
                    format!("Interface {} is not up", config_element.interface_name).as_str(),
                ));
            }

            // let capture = PacketCaptureGeneric::<Active>::open_device_capture(
            //     config_element.interface_name.as_str(),
            //     config_element.bpf_filter.as_deref(),
            // )?;

            let capture = PacketCaptureGeneric::<Active>::open_file_capture(
                "/home/roman/UNI/DP/pcap/streamer2.pcap",
                None,
            )?;
            let tx_local = self.tx.clone();
            let probe_metadata_local = self.probe_metadata.clone();
            let cancellation_token_local = cancellation_token.clone();
            let config_element_local = config_element.clone();
            join_set.spawn(async move {
                tokio::select! {
                    _ = cancellation_token_local.cancelled() => {
                        warn!("Probe capture for {config_element_local} cancelled");
                    }
                    _ = listen_and_send(capture, probe_metadata_local, tx_local) => {
                        info!("Probe capture for {config_element_local} finished");
                    }
                }
                Ok::<(), ProbeError>(())
            });
        }
        Ok(())
    }
}
