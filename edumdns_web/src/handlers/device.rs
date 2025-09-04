use crate::authorized;
use crate::error::{WebError, WebErrorKind};
use crate::forms::device::{DevicePacketTransmitRequest, DeviceQuery};
use crate::forms::packet::PacketQuery;
use crate::handlers::helpers::{get_template_name, parse_user_id, request_packet_transmit_helper};
use crate::templates::device::{DeviceDetailTemplate, DeviceTemplate, DeviceTransmitTemplate};
use crate::utils::AppState;
use actix_identity::Identity;
use actix_session::Session;
use actix_web::http::header::LOCATION;
use actix_web::{HttpRequest, HttpResponse, delete, get, post, rt, web};
use edumdns_core::app_packet::{
    AppPacket, LocalAppPacket, LocalCommandPacket, NetworkAppPacket, NetworkCommandPacket,
    PacketTransmitRequestPacket,
};
use edumdns_core::error::CoreError;
use edumdns_db::repositories::common::{DbDelete, DbReadMany, DbReadOne, DbUpdate, Id, Pagination};
use edumdns_db::repositories::device::models::{DeviceDisplay, SelectManyDevices, UpdateDevice};
use edumdns_db::repositories::device::repository::PgDeviceRepository;
use edumdns_db::repositories::packet::models::{PacketDisplay, SelectManyPackets};
use edumdns_db::repositories::packet::repository::PgPacketRepository;
use std::collections::HashMap;

#[get("")]
pub async fn get_devices(
    request: HttpRequest,
    identity: Option<Identity>,
    device_repo: web::Data<PgDeviceRepository>,
    state: web::Data<AppState>,
    query: web::Query<DeviceQuery>,
    session: Session,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request.path());
    let devices = device_repo
        .read_many_auth(
            &SelectManyDevices::from(query.into_inner()),
            &parse_user_id(&i)?,
        )
        .await?;
    let devices_parsed = devices
        .data
        .into_iter()
        .map(|(p, d)| (p, DeviceDisplay::from(d)))
        .collect();

    let template_name = get_template_name(&request, "device");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let body = template.render(DeviceTemplate {
        logged_in: true,
        permissions: devices.permissions,
        devices: devices_parsed,
        is_admin: session.get::<bool>("is_admin")?.unwrap_or(false),
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
    session: Session,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request.path());
    let device = device_repo
        .read_one_auth(&path.0, &parse_user_id(&i)?)
        .await?;

    let packets = packet_repo
        .read_many(&SelectManyPackets::new(
            Some(device.data.probe_id),
            Some(device.data.mac),
            None,
            Some(device.data.ip),
            None,
            None,
            None,
            Some(Pagination::default_pagination(query.page)),
        ))
        .await?
        .into_iter()
        .map(PacketDisplay::from)
        .filter_map(Result::ok)
        .collect();

    let packet_transmit_requests = device_repo
        .read_packet_transmit_requests(&device.data.id)
        .await?;

    let template_name = get_template_name(&request, "device/detail");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let body = template.render(DeviceDetailTemplate {
        logged_in: true,
        permissions: device.permissions,
        device: DeviceDisplay::from(device.data),
        packets,
        packet_transmit_requests,
        is_admin: session.get::<bool>("is_admin")?.unwrap_or(false),
    })?;

    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}

#[post("update")]
pub async fn update_device(
    request: HttpRequest,
    identity: Option<Identity>,
    device_repo: web::Data<PgDeviceRepository>,
    form: web::Form<UpdateDevice>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request.path());
    device_repo.update_auth(&form, &parse_user_id(&i)?).await?;
    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, format!("/device/{}", form.id)))
        .finish())
}

#[delete("{id}/delete")]
pub async fn delete_device(
    request: HttpRequest,
    identity: Option<Identity>,
    device_repo: web::Data<PgDeviceRepository>,
    path: web::Path<(Id,)>,
    query: web::Query<HashMap<String, String>>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request.path());

    let return_url = query
        .get("return_url")
        .map(String::as_str)
        .unwrap_or("/device");

    device_repo
        .delete_auth(&path.0, &parse_user_id(&i)?)
        .await?;
    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, return_url))
        .finish())
}

#[post("{id}/transmit-custom")]
pub async fn request_custom_packet_transmit(
    request: HttpRequest,
    identity: Option<Identity>,
    device_repo: web::Data<PgDeviceRepository>,
    path: web::Path<(Id,)>,
    state: web::Data<AppState>,
    form: web::Form<DevicePacketTransmitRequest>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request.path());
    let device = device_repo
        .read_one_auth(&path.0, &parse_user_id(&i)?)
        .await?;

    request_packet_transmit_helper(
        device_repo.clone(),
        &device.data,
        state.command_channel.clone(),
        &form,
    )
    .await?;

    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, format!("/device/{}", device.data.id)))
        .finish())
}

#[delete("{device_id}/transmit/{request_id}")]
pub async fn delete_request_packet_transmit(
    request: HttpRequest,
    identity: Option<Identity>,
    device_repo: web::Data<PgDeviceRepository>,
    path: web::Path<(Id, Id)>,
    state: web::Data<AppState>,
) -> Result<HttpResponse, WebError> {
    let device_id = path.0;
    let request_id = path.1;
    let i = authorized!(identity, request.path());
    let device = device_repo
        .read_one_auth(&path.0, &parse_user_id(&i)?)
        .await?;

    let request = device_repo
        .delete_packet_transmit_request(&request_id)
        .await?;

    let Some(r) = request.first() else {
        return Ok(HttpResponse::SeeOther()
            .insert_header((LOCATION, format!("/device/{}", device_id)))
            .finish());
    };

    let packet = PacketTransmitRequestPacket::new(
        device.data.probe_id,
        device.data.mac,
        device.data.ip,
        &r.target_ip.ip().to_string(),
        r.target_port as u16,
    );

    state
        .command_channel
        .send(AppPacket::Local(LocalAppPacket::Command(
            LocalCommandPacket::StopTransmitDevicePackets(packet),
        )))
        .await
        .map_err(CoreError::from)?;

    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, format!("/device/{}", device_id)))
        .finish())
}

#[post("{id}/transmit")]
pub async fn request_packet_transmit(
    request: HttpRequest,
    identity: Option<Identity>,
    device_repo: web::Data<PgDeviceRepository>,
    path: web::Path<(Id,)>,
    state: web::Data<AppState>,
) -> Result<HttpResponse, WebError> {
    let _ = authorized!(identity, request.path());
    let device = device_repo.read_one(&path.0).await?;

    let target_ip = request
        .connection_info()
        .realip_remote_addr()
        .map(|a| a.to_string());
    let target_ip = target_ip.ok_or(WebError::new(
        WebErrorKind::InternalServerError,
        "Could not determine target ip",
    ))?;

    let form = DevicePacketTransmitRequest::new(target_ip, device.port as u16, false);
    request_packet_transmit_helper(
        device_repo.clone(),
        &device,
        state.command_channel.clone(),
        &form,
    )
    .await?;

    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, format!("/device/{}/transmit", device.id)))
        .finish())
}

#[get("{id}/transmit")]
pub async fn get_device_for_transmit(
    request: HttpRequest,
    identity: Option<Identity>,
    device_repo: web::Data<PgDeviceRepository>,
    path: web::Path<(Id,)>,
    state: web::Data<AppState>,
) -> Result<HttpResponse, WebError> {
    let _ = authorized!(identity, request.path());
    let device = device_repo.read_one(&path.0).await?;
    let target_ip = request
        .connection_info()
        .realip_remote_addr()
        .map(|a| a.to_string());
    let target_ip = target_ip.ok_or(WebError::new(
        WebErrorKind::InternalServerError,
        "Could not determine target ip",
    ))?;

    let packet_transmit_requests = device_repo
        .read_packet_transmit_requests(&device.id)
        .await?;

    let template_name = get_template_name(&request, "device/public");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let body = template.render(DeviceTransmitTemplate {
        logged_in: true,
        device: DeviceDisplay::from(device),
        client_ip: target_ip,
        packet_transmit_requests,
    })?;

    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}
