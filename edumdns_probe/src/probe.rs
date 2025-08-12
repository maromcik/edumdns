use crate::capture::listen_and_send;
use crate::error::{ProbeError, ProbeErrorKind};
use edumdns_core::app_packet::{AppPacket, ProbeConfigElement, ProbeConfigPacket};
use edumdns_core::bincode_types::Uuid;
use edumdns_core::capture::PacketCaptureGeneric;
use edumdns_core::connection::TcpConnectionHandle;
use edumdns_core::metadata::ProbeMetadata;
use log::{info, warn};
use pcap::{Active, Direction};
use pnet::datalink::interfaces;
use std::collections::HashSet;
use std::time::Duration;
use tokio::sync::mpsc::Sender;
use tokio::task::{Id, JoinHandle, JoinSet};
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
    pub async fn start_captures(
        &self,
        join_set: &mut JoinSet<Result<(), ProbeError>>,
        cancellation_token: CancellationToken,
    ) -> Result<HashSet<Id>, ProbeError> {
        let mut handles = HashSet::new();
        for config_element in &self.probe_config.interface_filter_map {
            let tx_local = self.tx.clone();
            let probe_metadata_local = self.probe_metadata.clone();
            let cancellation_token_local = cancellation_token.clone();
            let config_element_local = config_element.clone();
            let handle = join_set.spawn_blocking({
                || {
                    let capture = PacketCaptureGeneric::<Active>::open_device_capture(
                        config_element_local.interface_name.as_str(),
                        config_element_local.bpf_filter.as_deref(),
                    )?;
                    listen_and_send(
                        capture,
                        probe_metadata_local,
                        tx_local,
                        cancellation_token_local,
                        config_element_local,
                    )?;
                    Ok::<(), ProbeError>(())
                }
            });
            handles.insert(handle.id());
        }
        Ok(handles)
    }
}
