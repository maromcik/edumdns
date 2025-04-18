use bincode;
use bincode::Encode;
use edumdns_core::capture::PacketCapture;
use edumdns_core::error::{CoreError, CoreErrorKind};
use edumdns_core::interface::get_transport_channel;
use pcap::{Activated, Error, State};
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::Packet;
use serde::{Deserialize, Serialize};
use crate::error::ProbeError;

#[derive(Deserialize, Serialize, Encode)]
pub struct AppPacket {
    pub id: i32,
    #[serde(with = "serde_bytes")]
    pub payload: Vec<u8>,
}

pub async fn listen_and_send<T>(
    mut capture: impl PacketCapture<T>,
) -> Result<(), ProbeError>
where
    T: State + Activated,
{
    capture.apply_filter()?;
    let mut channel = get_transport_channel()?;

    let mut cap = capture.get_capture();
    println!("Capture ready");
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
            id: 0,
            payload: packet.packet().to_vec(),
        };

        let encoded = bincode::encode_to_vec(app_packet, bincode::config::standard().with_big_endian()).unwrap();
        println!("Encoded AppPacket {:?}", &encoded);

        tokio::net::TcpStream::connect("127.0.0.1:8080").await?;


        // let bytes = app_packet
        //
        // let mut buffer = vec![0; packet.packet().len()];
        //
        // let new_packet = MutableTcpPacket::new(&mut buffer[..]).ok_or(NetworkError::new(
        //     NetworkErrorKind::PacketConstructionError,
        //     "Could not construct an EthernetPacket",
        // ))?;
        //
        // let eth_packet = new_packet.to_immutable();
        //
        // if net_config.straight || packet != eth_packet {
        //     channel.tx.send_to(eth_packet.packet(), None);
        //     println!("Packet sent")
        // }
        // if let Some(delay) = net_config.interval {
        //     sleep(delay);
        // }
    }
}
