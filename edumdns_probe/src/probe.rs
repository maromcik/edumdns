//! Probe capture orchestration and interface management.
//!
//! This module manages the packet capture process for the probe. It coordinates
//! multiple capture threads (one per configured interface), applies BPF filters
//! that exclude server traffic, and spawns capture tasks in a JoinSet for
//! coordinated lifecycle management.

use crate::capture::{PacketCaptureGeneric, capture_and_transmit};
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
    /// Starts packet capture on all configured interfaces.
    ///
    /// This function spawns blocking capture tasks for each interface specified in
    /// the probe configuration. Each task applies a BPF filter that excludes packets
    /// destined for the server to prevent capture loops.
    ///
    /// # Arguments
    ///
    /// * `join_set` - JoinSet for managing capture task lifecycle
    /// * `server_host` - Hostname or IP of the server (excluded from capture)
    /// * `cancellation_token` - Token for cancelling all captures
    ///
    /// # Returns
    ///
    /// Returns `Ok(HashSet<Id>)` containing the task IDs of all spawned capture tasks,
    /// or a `ProbeError` if interface opening fails.
    ///
    /// # BPF Filter
    ///
    /// Each capture applies a filter: `(host not {server_host}) and {custom_filter}`
    /// This ensures that:
    /// - Packets to/from the server are not captured (prevents loops)
    /// - Any custom BPF filter from configuration is also applied
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
