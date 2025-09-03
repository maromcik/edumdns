use itertools;
use crate::authorized;
use crate::error::WebError;
use crate::forms::probe::{ProbeConfigForm, ProbePermissionForm, ProbeQuery};
use crate::handlers::helpers::{get_template_name, parse_user_id};
use crate::templates::probe::{ProbeDetailTemplate, ProbeTemplate};
use crate::utils::AppState;
use actix_identity::Identity;
use actix_session::Session;
use actix_web::http::header::LOCATION;
use actix_web::{HttpRequest, HttpResponse, delete, get, post, put, web};
use edumdns_core::app_packet::{AppPacket, CommandPacket};
use edumdns_core::error::CoreError;
use edumdns_db::models::{Group, Location, Probe};
use edumdns_db::repositories::common::{
    DbDelete, DbReadMany, DbReadOne, DbUpdate, Id, Pagination, Permission,
};
use edumdns_db::repositories::device::models::{DeviceDisplay, UpdateDevice};
use edumdns_db::repositories::device::repository::PgDeviceRepository;
use edumdns_db::repositories::group::models::SelectManyGroups;
use edumdns_db::repositories::group::repository::PgGroupRepository;
use edumdns_db::repositories::packet::repository::PgPacketRepository;
use edumdns_db::repositories::probe::models::{
    AlterProbePermission, CreateProbeConfig, ProbeDisplay, SelectManyProbes,
    SelectSingleProbeConfig, UpdateProbe,
};
use edumdns_db::repositories::probe::repository::PgProbeRepository;
use std::collections::{HashMap, HashSet};
use itertools::Itertools;
use strum::IntoEnumIterator;
use uuid::Uuid;

#[get("")]
pub async fn get_probes(
    request: HttpRequest,
    identity: Option<Identity>,
    probe_repo: web::Data<PgProbeRepository>,
    state: web::Data<AppState>,
    query: web::Query<ProbeQuery>,
    session: Session,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request.path());

    let not_adopted_probes = probe_repo.read_many(&SelectManyProbes::new(
        query.owner_id,
        query.location_id,
        Some(false),
        query.mac.map(|mac| mac.to_octets()),
        query.ip,
        query.name.clone(),
        Some(Pagination::default_pagination(query.page)),
    )).await?;

    let probes = probe_repo
        .read_many_auth(
            &SelectManyProbes::from(query.into_inner()),
            &parse_user_id(&i)?,
        )
        .await?;

    let mut all_probes: HashSet<(Option<Location>, Probe)> = HashSet::from_iter(probes.data);
    all_probes.extend(not_adopted_probes);

    let all_probes = all_probes.into_iter().sorted_by_key(|(l, p)| (l.is_some(), p.id)).collect_vec();

    let probes_parsed = all_probes
        .into_iter()
        .map(|(l, p)| (l, ProbeDisplay::from(p)))
        .collect();

    let template_name = get_template_name(&request, "probe");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let body = template.render(ProbeTemplate {
        logged_in: true,
        is_admin: session.get::<bool>("is_admin")?.unwrap_or(false),
        permissions: probes.permissions,
        probes: probes_parsed,
    })?;

    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}

#[get("{id}")]
pub async fn get_probe(
    request: HttpRequest,
    identity: Option<Identity>,
    probe_repo: web::Data<PgProbeRepository>,
    group_repo: web::Data<PgGroupRepository>,
    state: web::Data<AppState>,
    path: web::Path<(Uuid,)>,
    session: Session,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request.path());
    let probe = probe_repo
        .read_one_auth(&path.0, &parse_user_id(&i)?)
        .await?;

    let granted: HashSet<(Id, Permission)> = probe_repo
        .get_permissions(&path.0)
        .await?
        .iter()
        .map(|x| (x.group_id, x.permission))
        .collect();

    let matrix = group_repo
        .read_many(&SelectManyGroups::new(None, None))
        .await?
        .into_iter()
        .map(|g| {
            (
                {
                    Permission::iter()
                        .map(|p| (p, granted.contains(&(g.id, p))))
                        .collect::<Vec<(Permission, bool)>>()
                },
                g,
            )
        })
        .collect::<Vec<(Vec<(Permission, bool)>, Group)>>();

    let template_name = get_template_name(&request, "probe/detail");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let body = template.render(ProbeDetailTemplate {
        logged_in: true,
        is_admin: session.get::<bool>("is_admin")?.unwrap_or(false),
        permissions: probe.permissions,
        permission_matrix: matrix,
        probe: ProbeDisplay::from(probe.data.0),
        devices: probe.data.1.into_iter().map(DeviceDisplay::from).collect(),
        configs: probe.data.2,
        admin: probe.admin,
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
    probe_repo.adopt(&path.0, &parse_user_id(&i)?).await?;
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
    probe_repo.forget(&path.0, &parse_user_id(&i)?).await?;
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
    probe_repo
        .check_permissions_for_restart(&path.0, &parse_user_id(&i)?)
        .await?;
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
    path: web::Path<(Uuid,)>,
) -> Result<HttpResponse, WebError> {
    let probe_id = path.0;
    let i = authorized!(identity, request.path());
    let user_id = parse_user_id(&i)?;
    probe_repo
        .create_probe_config(
            &CreateProbeConfig::new(probe_id, form.interface.clone(), form.filter.clone()),
            &user_id,
        )
        .await?;

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
    probe_repo
        .delete_probe_config(&SelectSingleProbeConfig::new(user_id, config_id, probe_id))
        .await?;
    probe_repo
        .create_probe_config(
            &CreateProbeConfig::new(probe_id, form.interface.clone(), form.filter.clone()),
            &user_id,
        )
        .await?;

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
    path: web::Path<(Uuid, Id)>,
) -> Result<HttpResponse, WebError> {
    let probe_id = path.0;
    let config_id = path.1;
    let i = authorized!(identity, request.path());
    probe_repo
        .delete_probe_config(&SelectSingleProbeConfig::new(
            parse_user_id(&i)?,
            config_id,
            probe_id,
        ))
        .await?;

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

#[post("{probe_id}/permission/toggle")]
pub async fn change_probe_permission(
    request: HttpRequest,
    identity: Option<Identity>,
    probe_repo: web::Data<PgProbeRepository>,
    form: web::Form<ProbePermissionForm>,
    path: web::Path<(Uuid,)>,
) -> Result<HttpResponse, WebError> {
    let probe_id = path.0;
    let i = authorized!(identity, request.path());

    probe_repo
        .alter_permission(AlterProbePermission::new(
            parse_user_id(&i)?,
            probe_id,
            form.group_id,
            form.permission,
            form.value,
        ))
        .await?;

    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, format!("/probe/{}", path.0)))
        .finish())
}

#[post("update")]
pub async fn update_probe(
    request: HttpRequest,
    identity: Option<Identity>,
    probe_repo: web::Data<PgProbeRepository>,
    form: web::Form<UpdateProbe>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request.path());
    probe_repo.update_auth(&form, &parse_user_id(&i)?).await?;
    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, format!("/probe/{}", form.id)))
        .finish())
}

#[delete("{id}/delete")]
pub async fn delete_probe(
    request: HttpRequest,
    identity: Option<Identity>,
    probe_repo: web::Data<PgProbeRepository>,
    path: web::Path<(Uuid,)>,
    query: web::Query<HashMap<String, String>>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request.path());
    let user_id = parse_user_id(&i)?;

    let return_url = query
        .get("return_url")
        .map(String::as_str)
        .unwrap_or("/probe");

    probe_repo.delete_auth(&path.0, &user_id).await?;
    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, return_url))
        .finish())
}
