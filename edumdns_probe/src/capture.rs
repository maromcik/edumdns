use crate::error::ProbeError;
use edumdns_core::capture::PacketCapture;
use edumdns_core::error::{CoreError};
use edumdns_core::network_packet::{DataLinkPacket};
use edumdns_core::app_packet::{AppPacket, ProbePacket};
use log::{debug, info};
use pcap::{Activated, Error, State};
use tokio::sync::mpsc::Sender;
use edumdns_core::metadata::ProbeMetadata;

pub async fn listen_and_send<T>(mut capture: impl PacketCapture<T>, probe_metadata: ProbeMetadata, tx: Sender<AppPacket>) -> Result<(), ProbeError>
where
    T: State + Activated,
{
    capture.apply_filter()?;
    let mut cap = capture.get_capture();
    info!("Capture ready!");

    loop {
        let cap_packet = match cap.next_packet() {
            Ok(packet) => packet,
            Err(e) => match e {
                Error::TimeoutExpired => {
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

        let Some(probe_packet) = ProbePacket::from_datalink_packet(&probe_metadata, datalink_packet) else {
            debug!("Not a TCP/IP packet, skipping");
            continue;
        };
        let app_packet = AppPacket::Data(probe_packet);
        tx.send(app_packet).await.expect("Poisoned");

    }
}
