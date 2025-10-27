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
use edumdns_db::repositories::common::Id;
use edumdns_db::repositories::device::models::CreatePacketTransmitRequest;
use edumdns_db::repositories::device::repository::PgDeviceRepository;
use time::OffsetDateTime;
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
        device.duration,
    );

    let request = CreatePacketTransmitRequest {
        device_id: device.id,
        user_id: *user_id,
        target_ip: form.target_ip,
        target_port: form.target_port as i32,
        permanent: form.permanent,
        created_at: (!form.permanent).then_some(OffsetDateTime::now_utc()),
    };

    match device_repo.create_packet_transmit_request(&request).await {
        Ok(p) => p,
        Err(_) => {
            return Err(WebError::new(
                WebErrorKind::BadRequest,
                "Transmission already in progress to another client, please try again later.",
            ));
        }
    };
    
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
