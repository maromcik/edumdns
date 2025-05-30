use std::time::Duration;
use crate::error::ProbeError;
use edumdns_core::capture::PacketCapture;
use edumdns_core::error::{CoreError};
use edumdns_core::network_packet::{DataLinkPacket};
use edumdns_core::app_packet::{AppPacket, CommandPacket, ProbePacket};
use log::{debug, error, info};
use pcap::{Activated, Error, State};
use tokio::time::sleep;
use crate::connection::Connection;

pub async fn listen_and_send<T>(mut capture: impl PacketCapture<T>) -> Result<(), ProbeError>
where
    T: State + Activated,
{
    capture.apply_filter()?;
    let mut cap = capture.get_capture();
    info!("Capture ready!");
    let mut i = 0;
    let server_addr = "127.0.0.1:5000";
    let mut connection = Connection::new(server_addr).await?;
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
        let Some(probe_packet) = ProbePacket::from_datalink_packet(i, datalink_packet) else {
            debug!("Not a TCP/IP packet, skipping");
            continue;
        };
        let app_packet = AppPacket::Data(probe_packet);
        
        match connection.send_packet(&app_packet).await {
            Ok(_) => i += 1,
            Err(e) => {
                error!("Failed to send packet: {}", e);
                sleep(Duration::from_secs(1)).await;
                if let Err(e) = connection.reconnect(server_addr).await {
                    error!("Failed to reconnect: {}", e);
                    continue;
                }
                // Retry sending the packet
                if let Err(e) = connection.send_packet(&app_packet).await {
                    error!("Failed to send packet after reconnection: {}", e);
                }
            }
        }

    }

}
