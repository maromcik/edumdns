use crate::error::WebError;
use crate::handlers::helpers::get_template_name;
use crate::templates::device::{DeviceDetailTemplate, DeviceTemplate};
use crate::utils::AppState;
use actix_identity::Identity;
use actix_web::{HttpRequest, HttpResponse, get, web};
use edumdns_db::repositories::common::{DbReadMany, DbReadOne, Id};
use edumdns_db::repositories::device::models::{DeviceDisplay, SelectManyDevices};
use edumdns_db::repositories::device::repository::PgDeviceRepository;
use edumdns_db::repositories::packet::models::{PacketDisplay, SelectManyPackets};
use edumdns_db::repositories::packet::repository::PgPacketRepository;

#[get("")]
pub async fn get_devices(
    request: HttpRequest,
    identity: Option<Identity>,
    device_repo: web::Data<PgDeviceRepository>,
    packet_repo: web::Data<PgPacketRepository>,
    state: web::Data<AppState>,
) -> Result<HttpResponse, WebError> {
    let devices = device_repo
        .read_many(&SelectManyDevices::new(None, None, None, None, None))
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
            None,
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
