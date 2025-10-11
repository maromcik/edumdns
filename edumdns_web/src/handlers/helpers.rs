use crate::error::{WebError, WebErrorKind};
use crate::forms::device::DeviceCustomPacketTransmitRequest;
use actix_session::Session;
use actix_web::web;
use edumdns_core::app_packet::{
    AppPacket, LocalAppPacket, LocalCommandPacket, PacketTransmitRequestPacket,
};
use edumdns_core::bincode_types::Uuid;
use edumdns_core::error::CoreError;
use edumdns_db::models::Device;
use edumdns_db::repositories::common::{DbCreate, Id};
use edumdns_db::repositories::device::models::CreatePacketTransmitRequest;
use edumdns_db::repositories::device::repository::PgDeviceRepository;
use log::warn;
use tokio::sync::mpsc::Sender;

pub async fn request_packet_transmit_helper(
    device_repo: web::Data<PgDeviceRepository>,
    device: &Device,
    user_id: &Id,
    command_channel: Sender<AppPacket>,
    form: &DeviceCustomPacketTransmitRequest,
) -> Result<(), WebError> {
    let packet = PacketTransmitRequestPacket::new(
        device.probe_id,
        device.mac,
        device.ip,
        form.target_ip,
        form.target_port,
        device.proxy,
        device.interval,
    );

    let request = CreatePacketTransmitRequest {
        device_id: device.id,
        user_id: *user_id,
        target_ip: form.target_ip,
        target_port: form.target_port as i32,
        permanent: form.permanent,
    };

    let packet_transmit_request = match device_repo.create(&request).await {
        Ok(p) => p,
        Err(_) => {
            return Err(WebError::new(
                WebErrorKind::BadRequest,
                "Transmission already in progress to the same client, please try again later.",
            ));
        }
    };
    let command_channel_local = command_channel.clone();
    let packet_local = packet.clone();
    let device_duration = device.duration as u64;
    if !form.permanent {
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(device_duration)).await;
            if let Err(e) = device_repo
                .delete_packet_transmit_request(&packet_transmit_request.id)
                .await
            {
                warn!(
                    "Could not delete packet transmit request {:?}: {}",
                    request,
                    WebError::from(e)
                );
            }

            command_channel_local
                .send(AppPacket::Local(LocalAppPacket::Command(
                    LocalCommandPacket::StopTransmitDevicePackets(packet_local),
                )))
                .await
        });
    }

    command_channel
        .send(AppPacket::Local(LocalAppPacket::Command(
            LocalCommandPacket::TransmitDevicePackets(packet),
        )))
        .await
        .map_err(CoreError::from)?;
    Ok(())
}

pub async fn reconnect_probe(
    command_channel: Sender<AppPacket>,
    probe_id: uuid::Uuid,
    session: Session,
) -> Result<(), WebError> {
    let uuid = session.get::<uuid::Uuid>("session_id")?.map(Uuid);
    command_channel
        .send(AppPacket::Local(LocalAppPacket::Command(
            LocalCommandPacket::ReconnectProbe(Uuid(probe_id), uuid),
        )))
        .await
        .map_err(CoreError::from)?;
    Ok(())
}
