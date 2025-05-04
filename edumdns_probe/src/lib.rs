use crate::error::ProbeError;
use crate::listen::listen_and_send;
use edumdns_core;
use edumdns_core::capture::PacketCaptureGeneric;
use pcap::Active;

pub mod listen;
pub mod error;
mod packet;

pub async fn capture_and_send() -> Result<(), ProbeError> {
    let capture = PacketCaptureGeneric::<Active>::open_file_capture("/home/roman/UNI/DP/pcap/streamer2.pcap", None)?;
    listen_and_send(capture).await?;
    Ok(())
}