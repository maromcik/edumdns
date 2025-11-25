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
