//! Packet capture functionality using libpcap.
//!
//! This module provides packet capture capabilities for the probe using the libpcap
//! library. It supports:
//! - Capturing packets from network interfaces
//! - Applying BPF (Berkeley Packet Filter) filters
//! - Parsing captured packets into ProbePacket format
//! - Transmitting captured packets to the server via channels
//!
//! The capture process runs in blocking threads and filters out packets destined for
//! the server to avoid capture loops.

use crate::error::ProbeError;
use edumdns_core::app_packet::{NetworkAppPacket, ProbeConfigElement, ProbePacket};
use edumdns_core::metadata::ProbeMetadata;
use edumdns_core::network_packet::DataLinkPacket;
use log::{debug, info, warn};
use pcap::{Activated, Error, State};
use pcap::{Active, Capture, Device, Offline};
use std::thread::sleep;
use tokio::sync::mpsc::Sender;
use tokio_util::sync::CancellationToken;

/// Captures packets from a network interface and transmits them to the server.
///
/// This function runs the main capture loop for a single interface. It applies the
/// configured BPF filter, captures packets, parses them into ProbePacket format, and
/// sends them through the channel to the transmission worker.
///
/// # Arguments
///
/// * `capture` - Packet capture instance (device or file-based)
/// * `probe_metadata` - Metadata identifying the probe (UUID, MAC, IP)
/// * `tx` - Channel sender for transmitting captured packets
/// * `cancellation_token` - Token for cooperative cancellation
/// * `config_element` - Configuration for this interface (name, filter)
///
/// # Returns
///
/// Returns `Ok(())` when the capture loop exits normally (cancellation or end of file),
/// or a `ProbeError` if capture setup or packet parsing fails.
///
/// # Behavior
///
/// - Applies the BPF filter to the capture interface
/// - Loops continuously, capturing packets until cancellation
/// - Skips non-TCP/IP packets
/// - Sends ProbePackets through the channel (blocking send)
/// - Handles timeout errors gracefully by continuing the loop
pub fn capture_and_transmit<T>(
    mut capture: impl PacketCapture<T>,
    probe_metadata: ProbeMetadata,
    tx: Sender<NetworkAppPacket>,
    cancellation_token: CancellationToken,
    config_element: ProbeConfigElement,
) -> Result<(), ProbeError>
where
    T: State + Activated,
{
    capture
        .apply_filter()
        .map_err(|e| ProbeError::CaptureError(format!("{config_element} failed; {e}")))?;
    let mut cap = capture.get_capture();
    info!("Capture ready!");

    loop {
        if cancellation_token.is_cancelled() {
            info!("Probe capture for {config_element} cancelled");
            return Ok(());
        }
        let cap_packet = match cap.next_packet() {
            Ok(packet) => packet,
            Err(e) => match e {
                Error::TimeoutExpired => {
                    sleep(std::time::Duration::from_micros(200));
                    continue;
                }
                Error::NoMorePackets => return Ok(()),
                e => {
                    return Err(ProbeError::from(e));
                }
            },
        };
        let mut packet_data = cap_packet.data.to_vec();
        let datalink_packet = DataLinkPacket::from_slice(&mut packet_data)?;

        let Some(probe_packet) =
            ProbePacket::from_datalink_packet(&probe_metadata, datalink_packet)
        else {
            debug!("Not a TCP/IP packet, skipping");
            continue;
        };
        debug!("Probe packet received: {:?}, payload hash: {}", probe_packet.probe_metadata, probe_packet.payload_hash);
        let app_packet = NetworkAppPacket::Data(probe_packet);
        if let Err(e) = tx.blocking_send(app_packet) {
            warn!("Failed to send packet: {e}");
            return Ok(());
        };
    }
}

pub trait PacketCapture<T>
where
    T: State + Activated,
{
    fn get_capture(self) -> Capture<T>;
    fn apply_filter(&mut self) -> Result<(), ProbeError>;
}

pub struct PacketCaptureGeneric<T>
where
    T: State + Activated,
{
    pub capture: Capture<T>,
    pub filter: Option<String>,
}

impl<T> PacketCaptureGeneric<T>
where
    T: State + Activated,
{
    /// Opens a packet capture on a network device.
    ///
    /// This function finds the specified network interface and opens a libpcap capture
    /// on it. The capture is configured for promiscuous mode, immediate mode, and a
    /// 10-second timeout. The capture is set to non-blocking mode.
    ///
    /// # Arguments
    ///
    /// * `device_name` - Name of the network interface to capture on (e.g., "eth0")
    /// * `filter` - Optional BPF filter string to apply to captured packets
    ///
    /// # Returns
    ///
    /// Returns `Ok(PacketCaptureGeneric<Active>)` if the device is found and capture
    /// is successfully opened, or a `ProbeError` if:
    /// - The device is not found in the system interfaces
    /// - Capture initialization fails
    /// - Setting non-blocking mode fails
    pub fn open_device_capture(
        device_name: &str,
        filter: Option<&str>,
    ) -> Result<PacketCaptureGeneric<Active>, ProbeError> {
        let devices = Device::list()?;
        let target =
            devices
                .into_iter()
                .find(|d| d.name == device_name)
                .ok_or(ProbeError::CaptureError(format!(
                    "Capture device {} not found",
                    device_name
                )))?;
        let target_name = target.name.clone();
        let capture = Capture::from_device(target)?
            .promisc(true)
            .timeout(10000)
            .immediate_mode(true)
            .open()?;
        let capture = capture.setnonblock()?;
        info!("Listening on: {:?}", target_name);

        Ok(PacketCaptureGeneric {
            capture,
            filter: filter.map(|s| s.to_string()),
        })
    }

    pub fn open_file_capture(
        file_path: &str,
        filter: Option<String>,
    ) -> Result<PacketCaptureGeneric<Offline>, ProbeError> {
        Ok(PacketCaptureGeneric {
            capture: Capture::from_file(file_path)?,
            filter,
        })
    }
}

impl<T> PacketCapture<T> for PacketCaptureGeneric<T>
where
    T: State + Activated,
{
    fn get_capture(self) -> Capture<T> {
        self.capture
    }
    fn apply_filter(&mut self) -> Result<(), ProbeError> {
        if let Some(filter) = &self.filter {
            self.capture
                .filter(filter, true)
                .map_err(|e| ProbeError::CaptureFilterError(e.to_string()))?;
            info!("Filter applied: {filter}");
        }
        Ok(())
    }
}
