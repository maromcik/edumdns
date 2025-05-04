use crate::error::ServerError;
use edumdns_core::error::CoreError;
use edumdns_core::metadata::{DataLinkMetadata, IpMetadata, PacketMetadata, PortMetadata};
use edumdns_core::packet::{DataLinkPacket, NetworkPacket, ProbePacket};
use futures::StreamExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use edumdns_core::rewrite::{DataLinkRewrite, IpRewrite, PacketRewrite, PortRewrite};

pub fn unwrap_packet<'a>(packet: DataLinkPacket<'a>, rewrite: &PacketRewrite) -> Option<(Vec<u8>)> {
    let mut data_link_packet = packet.rewrite(&rewrite.datalink_rewrite);
    let mut vlan_packet = data_link_packet
        .unpack_vlan()?
        .rewrite(&rewrite.datalink_rewrite);
    let mut ip_packet = vlan_packet.get_next_layer()?.rewrite(&rewrite.ip_rewrite);
    let transport_packet = ip_packet
        .get_next_layer()?
        .rewrite(&rewrite.transport_rewrite);

    Some(transport_packet.get_payload().to_vec())
}
async fn transmit_packet(target: &str, buf: &[u8]) -> Result<(), ServerError> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.send_to(buf, target).await?;
    Ok(())
}

async fn handle_connection(socket: TcpStream) -> Result<(), ServerError> {
    let mut framed = Framed::new(socket, LengthDelimitedCodec::new());

    let Some(Ok(frame)) = framed.next().await else {
        return Ok(());
    };
    let (mut packet, size): (ProbePacket, usize) =
        bincode::decode_from_slice(frame.as_ref(), bincode::config::standard())
            .map_err(CoreError::from)?;
    println!("ID: {}, Data: {:?}", packet.id, packet.metadata);
    let packet = DataLinkPacket::from_slice(packet.payload.as_mut())?;
    let datalink_rewrite = Some(DataLinkRewrite::parse_mac_rewrite(
        Some("86:b3:6e:1b:5b:54"),
        None,
    )?);
    let ip_rewrite = Some(IpRewrite::parse_ipv4_rewrite(Some("192.168.4.65"), None)?);
    let port_rewrite = Some(PortRewrite::new(Some(3456), None));
    let rewrite = PacketRewrite::new(datalink_rewrite, ip_rewrite, port_rewrite);
    if let Some(p) = unwrap_packet(packet, &rewrite) {
        transmit_packet("192.168.4.80:5353", p.as_slice()).await?;
    }
    Ok(())
}

pub async fn listen() -> Result<(), ServerError> {
    let listener = TcpListener::bind("127.0.0.1:8080").await?;

    loop {
        println!("waiting");
        let (socket, addr) = listener.accept().await?;

        tokio::spawn(async move {
            if let Err(e) = handle_connection(socket).await {
                println!("E: {}", e);
            }
        });
    }
}
