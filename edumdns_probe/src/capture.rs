
use crate::error::ProbeError;
use edumdns_core::app_packet::{NetworkAppPacket, ProbeConfigElement, ProbePacket};
use edumdns_core::capture::PacketCapture;
use edumdns_core::error::{CoreError, CoreErrorKind};
use edumdns_core::metadata::ProbeMetadata;
use edumdns_core::network_packet::DataLinkPacket;
use log::{debug, info, warn};
use pcap::{Activated, Error, State};
use std::thread::sleep;
use tokio::sync::mpsc::Sender;
use tokio_util::sync::CancellationToken;

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
    capture.apply_filter().map_err(|e| {
        CoreError::new(
            CoreErrorKind::CaptureError,
            format!(
                "Capture on {} failed: {}",
                config_element,
                e.message.as_str()
            )
            .as_str(),
        )
    })?;
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
                    return Err(ProbeError::from(CoreError::from(e)));
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
        let app_packet = NetworkAppPacket::Data(probe_packet);
        if let Err(e) = tx.blocking_send(app_packet) {
            warn!("Failed to send packet: {e}");
            return Ok(());
        };
    }
}
