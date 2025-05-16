use crate::error::ProbeError;
use crate::listen::listen_and_send;
use edumdns_core::capture::PacketCaptureGeneric;
use pcap::Active;

pub mod listen;
pub mod error;
pub mod packet;
pub mod connection;

pub async fn probe_init() -> Result<(), ProbeError> {
    let capture = PacketCaptureGeneric::<Active>::open_file_capture("/home/roman/UNI/DP/pcap/streamer2.pcap", None)?;
    // let capture = PacketCaptureGeneric::<Active>::open_device_capture("lo", Some("port 5201".to_string()))?;
    listen_and_send(capture).await?;
    Ok(())
}