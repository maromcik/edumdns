use crate::{authorized, PING_INTERVAL};
use crate::error::WebError;
use crate::forms::device::DeviceQuery;
use crate::forms::probe::{ProbeConfigForm, ProbePermissionForm, ProbeQuery};
use crate::handlers::helpers::{get_template_name, parse_user_id, reconnect_probe};
use crate::templates::PageInfo;
use crate::templates::probe::{ProbeDetailTemplate, ProbeTemplate};
use crate::utils::AppState;
use actix_identity::Identity;
use actix_session::Session;
use actix_web::http::header::LOCATION;
use actix_web::{HttpRequest, HttpResponse, delete, get, post, put, rt, web};
use actix_ws::AggregatedMessage;
use edumdns_core::app_packet::{AppPacket, LocalAppPacket, LocalCommandPacket, LocalStatusPacket};
use edumdns_core::error::CoreError;
use edumdns_db::models::{Group, Probe};
use edumdns_db::repositories::common::{
    DbDelete, DbReadMany, DbReadOne, DbUpdate, Id, PAGINATION_ELEMENTS_PER_PAGE, Pagination,
    Permission,
};
use edumdns_db::repositories::device::models::{DeviceDisplay, SelectManyDevices};
use edumdns_db::repositories::device::repository::PgDeviceRepository;
use edumdns_db::repositories::group::models::SelectManyGroups;
use edumdns_db::repositories::group::repository::PgGroupRepository;
use edumdns_db::repositories::probe::models::{
    AlterProbePermission, CreateProbeConfig, ProbeDisplay, SelectManyProbes,
    SelectSingleProbeConfig, UpdateProbe,
};
use edumdns_db::repositories::probe::repository::PgProbeRepository;
use itertools;
use log::{debug, info, warn};
use std::collections::{HashMap, HashSet};
use strum::IntoEnumIterator;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::SendError;
use uuid::{Timestamp, Uuid};

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
    let page = query.page.unwrap_or(1);

    let query = query.into_inner();
    let params = SelectManyProbes::from(query.clone());
    let probes = probe_repo
        .read_many_auth(&params, &parse_user_id(&i)?)
        .await?;

    let probes_parsed = probes
        .data
        .into_iter()
        .map(|(l, p)| (l, ProbeDisplay::from(p)))
        .collect();

    let probe_count = probe_repo.get_probe_count(params).await?;
    let total_pages = (probe_count as f64 / PAGINATION_ELEMENTS_PER_PAGE as f64).ceil() as i64;

    let template_name = get_template_name(&request, "probe");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let query_string = request.uri().query().unwrap_or("").to_string();
    let body = template.render(ProbeTemplate {
        logged_in: true,
        is_admin: session.get::<bool>("is_admin")?.unwrap_or(false),
        permissions: probes.permissions,
        probes: probes_parsed,
        page_info: PageInfo::new(page, total_pages),
        filters: query,
        query_string,
    })?;

    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}

#[get("{id}")]
pub async fn get_probe(
    request: HttpRequest,
    identity: Option<Identity>,
    probe_repo: web::Data<PgProbeRepository>,
    group_repo: web::Data<PgGroupRepository>,
    device_repo: web::Data<PgDeviceRepository>,
    state: web::Data<AppState>,
    path: web::Path<(Uuid,)>,
    query: web::Query<DeviceQuery>,
    session: Session,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request.path());
    let probe_id = path.0;
    let page = query.page.unwrap_or(1);
    let probe = probe_repo
        .read_one_auth(&probe_id, &parse_user_id(&i)?)
        .await?;

    let granted: HashSet<(Id, Permission)> = probe_repo
        .get_permissions(&probe_id)
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

    let query = query.into_inner();
    let mut params = SelectManyDevices::from(query.clone());
    params.probe_id = Some(probe_id);
    let devices = device_repo.read_many(&params).await?;
    let device_count = device_repo.get_device_count(params).await?;
    let total_pages = (device_count as f64 / PAGINATION_ELEMENTS_PER_PAGE as f64).ceil() as i64;

    let template_name = get_template_name(&request, "probe/detail");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let query_string = request.uri().query().unwrap_or("").to_string();
    let body = template.render(ProbeDetailTemplate {
        logged_in: true,
        is_admin: session.get::<bool>("is_admin")?.unwrap_or(false),
        permissions: probe.permissions,
        permission_matrix: matrix,
        probe: ProbeDisplay::from(probe.data.0),
        devices: devices
            .into_iter()
            .map(|d| DeviceDisplay::from(d.1))
            .collect(),
        configs: probe.data.1,
        admin: probe.admin,
        page_info: PageInfo::new(page, total_pages),
        filters: query,
        query_string,
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
    session: Session,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request.path());
    probe_repo.adopt(&path.0, &parse_user_id(&i)?).await?;
    reconnect_probe(state.command_channel.clone(), path.0, session).await?;
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
    session: Session,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request.path());
    probe_repo.forget(&path.0, &parse_user_id(&i)?).await?;
    reconnect_probe(state.command_channel.clone(), path.0, session).await?;
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
    session: Session,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request.path());
    probe_repo
        .check_permissions_for_restart(&path.0, &parse_user_id(&i)?)
        .await?;

    reconnect_probe(state.command_channel.clone(), path.0, session).await?;
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
    session: Session,
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

    reconnect_probe(state.command_channel.clone(), path.0, session).await?;
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
    session: Session,
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

    reconnect_probe(state.command_channel.clone(), path.0, session).await?;

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
    session: Session,
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
    reconnect_probe(state.command_channel.clone(), path.0, session).await?;
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
    state: web::Data<AppState>,
    query: web::Query<HashMap<String, String>>,
    session: Session,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request.path());
    let user_id = parse_user_id(&i)?;

    let return_url = query
        .get("return_url")
        .map(String::as_str)
        .unwrap_or("/probe");

    probe_repo.delete_auth(&path.0, &user_id).await?;
    reconnect_probe(state.command_channel.clone(), path.0, session).await?;
    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, return_url))
        .finish())
}

#[get("{id}/ws")]
pub async fn get_probe_ws(
    request: HttpRequest,
    identity: Option<Identity>,
    state: web::Data<AppState>,
    path: web::Path<(Uuid,)>,
    stream: web::Payload,
    session: Session,
) -> Result<HttpResponse, WebError> {
    let _ = authorized!(identity, request.path());
    let probe_id = path.0;

    let ts = Timestamp::now(uuid::NoContext);
    let session_id = Uuid::new_v7(ts);

    let (res, mut ws_session, stream) = actix_ws::handle(&request, stream)?;
    let mut stream = stream
        .aggregate_continuations()
        .max_continuation_size(2_usize.pow(20));
    let mut channel = mpsc::channel(100);
    let unregister_packet = LocalCommandPacket::UnregisterFromEvents {
            probe_id,
            session_id,
        };
    let sender = channel.0.clone();
    state
        .command_channel
        .send(AppPacket::Local(LocalAppPacket::Command(
            LocalCommandPacket::RegisterForEvents {
                probe_id,
                session_id,
                respond_to: sender,
            },
        )))
        .await
        .map_err(CoreError::from)?;
    let command_channel = state.command_channel.clone();
    let unregister_packet_local = unregister_packet.clone();
    session.insert("session_id", session_id.to_string())?;
    let mut ws_session_local = ws_session.clone();
    rt::spawn(async move {
        while let Some(packet) = channel.1.recv().await {
            let Err(_) = ws_session_local.text(packet.to_string()).await else {
                continue;
            };
            warn!("WebSocket closed, probe_id: {probe_id}, session_id: {session_id}");

            let Err(e) = command_channel
                .send(AppPacket::Local(LocalAppPacket::Command(unregister_packet_local.clone())))
                .await
            else {
                continue;
            };
            warn!("Error unregistering from events: {e}");
        }
    });
    let command_channel = state.command_channel.clone();
    let unregister_packet_local = unregister_packet.clone();
    rt::spawn(async move {
        while let Some(msg) = stream.recv().await {
            match msg {
                Ok(AggregatedMessage::Close(_)) | Err(_) => {
                    let _ = command_channel.send(AppPacket::Local(LocalAppPacket::Command(unregister_packet_local))).await;
                    break;
                }
                _ => {}
            }
        }
    });
    let command_channel = state.command_channel.clone();
    let mut ws_session_local = ws_session.clone();
    rt::spawn(async move {
        loop {
            let respond_to_channel = tokio::sync::oneshot::channel();
            if let Err(e) = command_channel.send(AppPacket::Local(LocalAppPacket::Status(LocalStatusPacket::IsProbeLive { probe_id, respond_to: respond_to_channel.0} ))).await {
                    warn!("Error sending request for checking probe liveness: {e}");
                    continue;
                }
            let response = respond_to_channel.1.await.ok();
            match response {
                None => {
                    if ws_session_local.text("false").await.is_err() {
                        info!("WebSocket closed, probe_id: {probe_id}, session_id: {session_id}");
                        return;
                    };
                },
                Some(is_alive) => {
                    if ws_session_local.text(is_alive.to_string()).await.is_err() {
                        info!("WebSocket closed, probe_id: {probe_id}, session_id: {session_id}");
                        return;
                    };
                },
            }
            tokio::time::sleep(std::time::Duration::from_secs(PING_INTERVAL)).await;
        }
    });
    Ok(res)
}
