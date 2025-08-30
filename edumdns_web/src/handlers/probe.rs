use std::convert::identity;
use crate::error::WebError;
use crate::forms::probe::{ProbeConfigForm, ProbeQuery};
use crate::handlers::helpers::{get_template_name, parse_user_id};
use crate::templates::probe::{ProbeDetailTemplate, ProbeTemplate};
use crate::utils::AppState;
use actix_identity::Identity;
use actix_web::http::header::LOCATION;
use actix_web::{delete, get, post, put, web, HttpRequest, HttpResponse};
use log::error;
use edumdns_core::app_packet::{AppPacket, CommandPacket};
use edumdns_core::error::CoreError;
use edumdns_db::repositories::common::{DbReadMany, DbReadOne, Id, Pagination};
use edumdns_db::repositories::device::models::DeviceDisplay;
use edumdns_db::repositories::probe::models::{SelectSingleProbe, ProbeDisplay, SelectManyProbes, SelectSingleProbeConfig, CreateProbeConfig};
use edumdns_db::repositories::probe::repository::PgProbeRepository;
use uuid::Uuid;
use edumdns_db::models::ProbeConfig;
use crate::authorized;

#[get("")]
pub async fn get_probes(
    request: HttpRequest,
    identity: Option<Identity>,
    probe_repo: web::Data<PgProbeRepository>,
    state: web::Data<AppState>,
    query: web::Query<ProbeQuery>
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request.path());

    let probes = probe_repo
        .read_many(&SelectManyProbes::new(
            parse_user_id(&i)?,
            query.owner_id,
            query.location_id,
            query.adopted,
            query.mac.map(|addr| addr.to_octets()),
            query.ip,
            Some(Pagination::default_pagination(query.page))))
        .await?
        .into_iter()
        .map(|(l, p)| (l, ProbeDisplay::from(p)))
        .collect();

    let template_name = get_template_name(&request, "probe");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let body = template.render(ProbeTemplate {
        logged_in: true,
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
    let i = authorized!(identity, request.path());

    let (probe, devices, configs) = probe_repo
        .read_one(&SelectSingleProbe::new(parse_user_id(&i)?, path.0))
        .await?;

    let template_name = get_template_name(&request, "probe/detail");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let body = template.render(ProbeDetailTemplate {
        logged_in: true,
        probe: ProbeDisplay::from(probe),
        devices: devices.into_iter().map(DeviceDisplay::from).collect(),
        configs
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
    let i = authorized!(identity, request.path());
    let params = SelectSingleProbe::new(parse_user_id(&i)?, path.0);
    probe_repo.adopt(&params).await?;
    state
        .command_channel
        .send(AppPacket::Command(CommandPacket::ReconnectProbe(
            edumdns_core::bincode_types::Uuid(path.0),
        )))
        .await
        .map_err(CoreError::from)?;
    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, format!("/probe/{}", path.0)))
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
    let i = authorized!(identity, request.path());
    let params = SelectSingleProbe::new(parse_user_id(&i)?, path.0);
    probe_repo.forget(&params).await?;
    state
        .command_channel
        .send(AppPacket::Command(CommandPacket::ReconnectProbe(
            edumdns_core::bincode_types::Uuid(path.0),
        )))
        .await
        .map_err(CoreError::from)?;

    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, format!("/probe/{}", path.0)))
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
    let i = authorized!(identity, request.path());
    let params = SelectSingleProbe::new(parse_user_id(&i)?, path.0);
    probe_repo.check_permissions_for_restart(&params).await?;
    state
        .command_channel
        .send(AppPacket::Command(CommandPacket::ReconnectProbe(
            edumdns_core::bincode_types::Uuid(path.0),
        )))
        .await
        .map_err(CoreError::from)?;

    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, format!("/probe/{}", path.0)))
        .finish())
}

#[post("{probe_id}/config")]
pub async fn create_config(
    request: HttpRequest,
    identity: Option<Identity>,
    probe_repo: web::Data<PgProbeRepository>,
    state: web::Data<AppState>,
    form: web::Form<ProbeConfigForm>,
    path: web::Path<(Uuid, )>,
) -> Result<HttpResponse, WebError> {
    let probe_id = path.0;
    let i = authorized!(identity, request.path());
    let user_id = parse_user_id(&i)?;
    probe_repo.create_probe_config(&CreateProbeConfig::new(probe_id, form.interface.clone(), form.filter.clone()), user_id).await?;

    state
        .command_channel
        .send(AppPacket::Command(CommandPacket::ReconnectProbe(
            edumdns_core::bincode_types::Uuid(path.0),
        )))
        .await
        .map_err(CoreError::from)?;

    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, format!("/probe/{}", path.0)))
        .finish())
}

#[put("{probe_id}/config/{config_id}")]
pub async fn save_config(
    request: HttpRequest,
    identity: Option<Identity>,
    probe_repo: web::Data<PgProbeRepository>,
    state: web::Data<AppState>,
    form: web::Form<ProbeConfigForm>,
    path: web::Path<(Uuid, Id)>,
) -> Result<HttpResponse, WebError> {
    let probe_id = path.0;
    let config_id = path.1;
    let i = authorized!(identity, request.path());
    let user_id = parse_user_id(&i)?;
    probe_repo.delete_probe_config(&SelectSingleProbeConfig::new(user_id, config_id, probe_id)).await?;
    probe_repo.create_probe_config(&CreateProbeConfig::new(probe_id, form.interface.clone(), form.filter.clone()), user_id).await?;

    state
        .command_channel
        .send(AppPacket::Command(CommandPacket::ReconnectProbe(
            edumdns_core::bincode_types::Uuid(path.0),
        )))
        .await
        .map_err(CoreError::from)?;

    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, format!("/probe/{}", path.0)))
        .finish())
}

#[delete("{probe_id}/config/{config_id}")]
pub async fn delete_config(
    request: HttpRequest,
    identity: Option<Identity>,
    probe_repo: web::Data<PgProbeRepository>,
    state: web::Data<AppState>,
    path: web::Path<(Uuid,Id,)>,
) -> Result<HttpResponse, WebError> {
    let probe_id = path.0;
    let config_id = path.1;
    let i = authorized!(identity, request.path());
    probe_repo.delete_probe_config(&SelectSingleProbeConfig::new(parse_user_id(&i)?, config_id, probe_id)).await?;

    state
        .command_channel
        .send(AppPacket::Command(CommandPacket::ReconnectProbe(
            edumdns_core::bincode_types::Uuid(path.0),
        )))
        .await
        .map_err(CoreError::from)?;

    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, format!("/probe/{}", path.0)))
        .finish())
}