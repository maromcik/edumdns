use crate::error::ProbeError;
use bincode;
use bytes::Bytes;
use edumdns_core::capture::PacketCapture;
use edumdns_core::error::{CoreError};
use edumdns_core::metadata::PacketMetadata;
use edumdns_core::packet::{DataLinkPacket, ProbePacket};
use futures::SinkExt;
use log::{info, warn};
use pcap::{Activated, Error, State};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

pub async fn listen_and_send<T>(mut capture: impl PacketCapture<T>) -> Result<(), ProbeError>
where
    T: State + Activated,
{
    capture.apply_filter()?;
    let mut cap = capture.get_capture();
    info!("Capture ready!");
    let mut i = 0;
    loop {
        let mut cap_packet = match cap.next_packet() {
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
        let packet_metadata = PacketMetadata::from_datalink_packet(datalink_packet).unwrap();

        let app_packet = ProbePacket {
            id: i,
            payload: packet_data,
            metadata: packet_metadata,
        };

        i += 1;

        let encoded = bincode::encode_to_vec(&app_packet, bincode::config::standard())?;
        let stream = tokio::net::TcpStream::connect("127.0.0.1:8080").await?;

        let mut framed = Framed::new(stream, LengthDelimitedCodec::new());
        framed.send(Bytes::from(encoded)).await?;
        println!("sent");
    }
}
