use crate::capture::{capture_and_transmit, PacketCaptureGeneric};
use crate::error::ProbeError;
use edumdns_core::app_packet::{NetworkAppPacket, ProbeConfigPacket};
use edumdns_core::metadata::ProbeMetadata;
use pcap::Active;
use std::collections::HashSet;
use tokio::sync::mpsc::Sender;
use tokio::task::{Id, JoinSet};
use tokio_util::sync::CancellationToken;

pub struct ProbeCapture {
    tx: Sender<NetworkAppPacket>,
    probe_metadata: ProbeMetadata,
    probe_config: ProbeConfigPacket,
}

impl ProbeCapture {
    pub fn new(
        tx: Sender<NetworkAppPacket>,
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
        server_host: &str,
        cancellation_token: CancellationToken,
    ) -> Result<HashSet<Id>, ProbeError> {
        let mut handles = HashSet::new();
        for config_element in &self.probe_config.interface_filter_map {
            let tx_local = self.tx.clone();
            let probe_metadata_local = self.probe_metadata.clone();
            let cancellation_token_local = cancellation_token.clone();
            let config_element_local = config_element.clone();
            let mut filter = format!("(host not {})", server_host);
            if let Some(f) = &config_element_local.bpf_filter
                && !f.is_empty()
            {
                filter.push_str(&format!(" and {}", f));
            }
            let handle = join_set.spawn_blocking({
                move || {
                    let capture = PacketCaptureGeneric::<Active>::open_device_capture(
                        config_element_local.interface_name.as_str(),
                        Some(filter.as_str()),
                    )?;
                    capture_and_transmit(
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
