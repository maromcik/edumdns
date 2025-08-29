use crate::error::WebError;
use crate::handlers::helpers::get_template_name;
use crate::templates::device::{DeviceDetailTemplate, DeviceTemplate};
use crate::utils::AppState;
use actix_identity::Identity;
use actix_web::{HttpRequest, HttpResponse, get, web, post};
use actix_web::http::header::LOCATION;
use ipnetwork::IpNetwork;
use edumdns_core::app_packet::{AppPacket, CommandPacket, PacketTransmitRequestPacket};
use edumdns_core::error::CoreError;
use edumdns_db::models::PacketTransmitRequest;
use edumdns_db::repositories::common::{DbReadMany, DbReadOne, Id, Pagination};
use edumdns_db::repositories::device::models::{DeviceDisplay, SelectManyDevices};
use edumdns_db::repositories::device::repository::PgDeviceRepository;
use edumdns_db::repositories::packet::models::{PacketDisplay, SelectManyPackets};
use edumdns_db::repositories::packet::repository::PgPacketRepository;
use crate::forms::device::{DevicePacketTransmitRequest, DeviceQuery};
use crate::forms::packet::PacketQuery;

#[get("")]
pub async fn get_devices(
    request: HttpRequest,
    identity: Option<Identity>,
    device_repo: web::Data<PgDeviceRepository>,
    packet_repo: web::Data<PgPacketRepository>,
    state: web::Data<AppState>,
    query: web::Query<DeviceQuery>
) -> Result<HttpResponse, WebError> {
    let devices = device_repo
        .read_many(&SelectManyDevices::new(
            query.probe_id,
            query.mac,
            query.ip,
            query.port,
            Some(Pagination::default_pagination(query.page))))
        .await?
        .into_iter()
        .map(|(p, d)| (p, DeviceDisplay::from(d)))
        .collect();

    let template_name = get_template_name(&request, "device");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let body = template.render(DeviceTemplate {
        logged_in: identity.is_some(),
        devices,
    })?;

    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}

#[get("{id}")]
pub async fn get_device(
    request: HttpRequest,
    identity: Option<Identity>,
    device_repo: web::Data<PgDeviceRepository>,
    packet_repo: web::Data<PgPacketRepository>,
    path: web::Path<(Id,)>,
    state: web::Data<AppState>,
    query: web::Query<PacketQuery>,
) -> Result<HttpResponse, WebError> {
    let device = device_repo.read_one(&path.into_inner().0).await?;

    let packets = packet_repo
        .read_many(&SelectManyPackets::new(
            Some(device.probe_id),
            Some(device.mac),
            None,
            Some(device.ip),
            None,
            None,
            None,
            Some(Pagination::default_pagination(query.page))
        ))
        .await?
        .into_iter()
        .map(PacketDisplay::from)
        .filter_map(Result::ok)
        .collect();

    let template_name = get_template_name(&request, "device/detail");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let body = template.render(DeviceDetailTemplate {
        logged_in: identity.is_some(),
        device: DeviceDisplay::from(device),
        packets,
    })?;

    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}

#[post("{id}/transmit")]
pub async fn device_request_packet_transmit(
    request: HttpRequest,
    identity: Option<Identity>,
    device_repo: web::Data<PgDeviceRepository>,
    packet_repo: web::Data<PgPacketRepository>,
    path: web::Path<(Id,)>,
    state: web::Data<AppState>,
    query: web::Query<PacketQuery>,
    form: web::Form<DevicePacketTransmitRequest>,
) -> Result<HttpResponse, WebError> {
    let device_id = path.into_inner().0;
    let device = device_repo.read_one(&device_id).await?;

    let packet = PacketTransmitRequestPacket::new(device.probe_id, device.mac, device.ip, &form.target_ip, form.target_port);

    let request =  PacketTransmitRequest {
        device_id: device.id,
        target_ip: form.target_ip.parse::<IpNetwork>().map_err(CoreError::from)?,
        target_port: form.target_port as i32,
    };



    state.command_channel.send(AppPacket::Command(CommandPacket::TransmitDevicePackets(packet))).await.map_err(CoreError::from)?;


    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, format!("/device/{}", device_id)))
        .finish())
}
