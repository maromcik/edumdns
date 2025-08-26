use crate::error::WebError;
use crate::handlers::helpers::get_template_name;
use crate::templates::probe::{ProbeDetailTemplate, ProbeTemplate};
use crate::utils::AppState;
use actix_identity::Identity;
use actix_web::http::header::LOCATION;
use actix_web::{HttpRequest, HttpResponse, get, web};
use diesel_async::RunQueryDsl;
use edumdns_core::app_packet::{AppPacket, CommandPacket};
use edumdns_core::error::CoreError;
use edumdns_db::models::Probe;
use edumdns_db::repositories::common::{DbReadMany, DbReadOne, Id};
use edumdns_db::repositories::device::models::{DeviceDisplay, SelectManyDevices};
use edumdns_db::repositories::device::repository::PgDeviceRepository;
use edumdns_db::repositories::probe::models::{ProbeDisplay, SelectManyProbes};
use edumdns_db::repositories::probe::repository::PgProbeRepository;
use uuid::Uuid;

#[get("")]
pub async fn get_probes(
    request: HttpRequest,
    identity: Option<Identity>,
    probe_repo: web::Data<PgProbeRepository>,
    state: web::Data<AppState>,
) -> Result<HttpResponse, WebError> {
    let probes = probe_repo
        .read_many(&SelectManyProbes::new(None, None, None, None, None, None))
        .await?
        .into_iter()
        .map(|(l, u, p)| (l, u, ProbeDisplay::from(p)))
        .collect();

    let template_name = get_template_name(&request, "probe");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let body = template.render(ProbeTemplate {
        logged_in: identity.is_some(),
        probes,
    })?;

    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}

#[get("{id}")]
pub async fn get_probe(
    request: HttpRequest,
    identity: Option<Identity>,
    probe_repo: web::Data<PgProbeRepository>,
    state: web::Data<AppState>,
    path: web::Path<(Uuid,)>,
) -> Result<HttpResponse, WebError> {
    let (probe, devices) = probe_repo
        .read_probe_and_devices(&path.into_inner().0)
        .await?;

    let template_name = get_template_name(&request, "probe/detail");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let body = template.render(ProbeDetailTemplate {
        logged_in: identity.is_some(),
        probe: ProbeDisplay::from(probe),
        devices: devices.into_iter().map(DeviceDisplay::from).collect(),
    })?;

    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}

#[get("{id}/adopt")]
pub async fn adopt(
    request: HttpRequest,
    identity: Option<Identity>,
    probe_repo: web::Data<PgProbeRepository>,
    state: web::Data<AppState>,
    path: web::Path<(Uuid,)>,
) -> Result<HttpResponse, WebError> {
    probe_repo.adopt(&path.0).await?;

    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, "/probe"))
        .finish())
}

#[get("{id}/forget")]
pub async fn forget(
    request: HttpRequest,
    identity: Option<Identity>,
    probe_repo: web::Data<PgProbeRepository>,
    state: web::Data<AppState>,
    path: web::Path<(Uuid,)>,
) -> Result<HttpResponse, WebError> {
    probe_repo.forget(&path.0).await?;
    state
        .command_channel
        .send(AppPacket::Command(CommandPacket::ReconnectProbe(edumdns_core::bincode_types::Uuid(path.0))))
        .await
        .map_err(CoreError::from)?;

    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, "/probe"))
        .finish())
}

#[get("{id}/restart")]
pub async fn restart(
    request: HttpRequest,
    identity: Option<Identity>,
    probe_repo: web::Data<PgProbeRepository>,
    state: web::Data<AppState>,
    path: web::Path<(Uuid,)>,
) -> Result<HttpResponse, WebError> {
    state
        .command_channel
        .send(AppPacket::Command(CommandPacket::ReconnectProbe(edumdns_core::bincode_types::Uuid(path.0))))
        .await
        .map_err(CoreError::from)?;

    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, format!("/probe/{}", path.0)))
        .finish())
}
