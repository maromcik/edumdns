use crate::app_packet::{
    AppPacket, LocalAppPacket, LocalCommandPacket, PacketTransmitRequestPacket,
};
use crate::error::ServerError;
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::deadpool::Pool;
use edumdns_db::models::Packet;
use edumdns_db::repositories::device::repository::PgDeviceRepository;
use edumdns_db::repositories::packet::models::SelectManyPackets;
use edumdns_db::repositories::packet::repository::PgPacketRepository;
use log::{info, warn};
use std::sync::Arc;
use tokio::sync::mpsc::Sender;

pub(crate) async fn load_all_packet_transmit_requests(
    pool: Pool<AsyncPgConnection>,
    tx: Sender<AppPacket>,
) -> Result<(), ServerError> {
    let device_repo = PgDeviceRepository::new(pool);
    let requests = device_repo.get_all_packet_transmit_requests().await?;
    for (device, request) in requests {
        let packet_transmit_request = PacketTransmitRequestPacket::new(device, request);
        let channel = tokio::sync::oneshot::channel();
        tx.send(AppPacket::Local(LocalAppPacket::Command(
            LocalCommandPacket::TransmitDevicePackets {
                request: Arc::new(packet_transmit_request),
                respond_to: channel.0,
            },
        )))
        .await?;
    }
    Ok(())
}

pub async fn get_device_packets(
    packet_repo: PgPacketRepository,
    transmit_request: &PacketTransmitRequestPacket,
) -> Result<Vec<Packet>, ServerError> {
    let packets = match packet_repo
        .read_many(&SelectManyPackets::new(
            None,
            Some(transmit_request.device.probe_id),
            Some(transmit_request.device.mac),
            None,
            Some(transmit_request.device.ip),
            None,
            None,
            None,
            None,
            None,
        ))
        .await
    {
        Ok(p) => p,
        Err(e) => {
            warn!("No packets found for target: {}: {}", transmit_request, e);
            return Err(ServerError::from(e));
        }
    };

    info!("Packets found for target: {}", transmit_request);
    Ok(packets)
}
