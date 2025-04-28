use crate::error::ProbeError;
use bincode;
use bytes::Bytes;
use edumdns_core::capture::PacketCapture;
use edumdns_core::error::{CoreError, CoreErrorKind};
use edumdns_core::packet::AppPacket;
use futures::SinkExt;
use pcap::{Activated, Error, State};
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::Packet;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use log::{info, warn};


pub async fn listen_and_send<T>(
    mut capture: impl PacketCapture<T>,
) -> Result<(), ProbeError>
where
    T: State + Activated,
{
    capture.apply_filter()?;
    let mut cap = capture.get_capture();
    info!("Capture ready!");
    let mut i = 0;
    loop {
        let cap_packet = match cap.next_packet() {
            Ok(packet) => packet,
            Err(e) => match e {
                Error::TimeoutExpired => {
                    continue;
                },
                Error::NoMorePackets => {
                    return Ok(())
                },
                e => {
                    return Err(ProbeError::from(CoreError::from(e)));
                }
            },
        };
        let packet = EthernetPacket::new(cap_packet.data).ok_or(CoreError::new(
            CoreErrorKind::PacketConstructionError,
            "Invalid EthernetPacket",
        ))?;


        let app_packet = AppPacket {
            id: i,
            payload: packet.packet().to_vec(),
            metadata: "pes".to_string(),
        };
        i+=1;

        let encoded = bincode::encode_to_vec(&app_packet, bincode::config::standard()).unwrap();
        // println!("Encoded AppPacket {:?}", &encoded);

        let stream = tokio::net::TcpStream::connect("127.0.0.1:8080").await?;

        let mut framed = Framed::new(stream, LengthDelimitedCodec::new());
        framed.send(Bytes::from(encoded)).await?;
        println!("sent");
    }
}
