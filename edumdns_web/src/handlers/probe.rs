use crate::authorized;
use crate::error::WebError;
use crate::forms::probe::{ProbeConfigForm, ProbePermissionForm, ProbeQuery};
use crate::handlers::helpers::{
    get_probe_helper, get_template_name, parse_user_id, reconnect_probe,
};
use crate::templates::probe::ProbeTemplate;
use crate::utils::AppState;
use actix_identity::Identity;
use actix_session::Session;
use actix_web::http::header::LOCATION;
use actix_web::{HttpRequest, HttpResponse, delete, get, post, put, rt, web};
use actix_ws::AggregatedMessage;
use edumdns_core::app_packet::{AppPacket, LocalAppPacket, LocalCommandPacket};
use edumdns_core::error::CoreError;
use edumdns_db::models::{Location, Probe};
use edumdns_db::repositories::common::{DbDelete, DbReadMany, DbUpdate, Id, Pagination};
use edumdns_db::repositories::group::repository::PgGroupRepository;
use edumdns_db::repositories::probe::models::{
    AlterProbePermission, CreateProbeConfig, ProbeDisplay, SelectManyProbes,
    SelectSingleProbeConfig, UpdateProbe,
};
use edumdns_db::repositories::probe::repository::PgProbeRepository;
use itertools;
use itertools::Itertools;
use log::{debug, warn};
use std::collections::{HashMap, HashSet};
use tokio::sync::mpsc;
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

    let not_adopted_probes = probe_repo
        .read_many(&SelectManyProbes::new(
            query.owner_id,
            query.location_id,
            Some(false),
            query.mac.map(|mac| mac.to_octets()),
            query.ip,
            query.name.clone(),
            Some(Pagination::default_pagination(query.page)),
        ))
        .await?;

    let probes = probe_repo
        .read_many_auth(
            &SelectManyProbes::from(query.into_inner()),
            &parse_user_id(&i)?,
        )
        .await?;

    let mut all_probes: HashSet<(Option<Location>, Probe)> = HashSet::from_iter(probes.data);
    all_probes.extend(not_adopted_probes);

    let all_probes = all_probes
        .into_iter()
        .sorted_by_key(|(l, p)| (l.is_some(), p.id))
        .collect_vec();

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
    get_probe_helper(
        request, identity, probe_repo, group_repo, state, path, session,
    )
    .await
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
    reconnect_probe(state.command_channel.clone(), path.0).await?;
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
    reconnect_probe(state.command_channel.clone(), path.0).await?;
    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, format!("/probe/{}", path.0)))
        .finish())
}

#[get("{id}/restart")]
pub async fn restart(
    request: HttpRequest,
    identity: Option<Identity>,
    probe_repo: web::Data<PgProbeRepository>,
    group_repo: web::Data<PgGroupRepository>,
    state: web::Data<AppState>,
    path: web::Path<(Uuid,)>,
    session: Session,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request.path());
    probe_repo
        .check_permissions_for_restart(&path.0, &parse_user_id(&i)?)
        .await?;

    reconnect_probe(state.command_channel.clone(), path.0).await?;
    get_probe_helper(
        request,
        Some(i),
        probe_repo,
        group_repo,
        state,
        path,
        session,
    )
    .await
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

    reconnect_probe(state.command_channel.clone(), path.0).await?;
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

    reconnect_probe(state.command_channel.clone(), path.0).await?;

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
    reconnect_probe(state.command_channel.clone(), path.0).await?;
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
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request.path());
    let user_id = parse_user_id(&i)?;

    let return_url = query
        .get("return_url")
        .map(String::as_str)
        .unwrap_or("/probe");

    probe_repo.delete_auth(&path.0, &user_id).await?;
    reconnect_probe(state.command_channel.clone(), path.0).await?;
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
) -> Result<HttpResponse, WebError> {
    let _ = authorized!(identity, request.path());
    let probe_id = path.0;

    let ts = Timestamp::now(uuid::NoContext);
    let session_uuid = Uuid::new_v7(ts);

    let (res, mut session, stream) = actix_ws::handle(&request, stream)?;
    let mut stream = stream
        .aggregate_continuations()
        .max_continuation_size(2_usize.pow(20));

    let mut channel = mpsc::channel(100);
    let unregister_packet = AppPacket::Local(LocalAppPacket::Command(
        LocalCommandPacket::UnregisterFromEvents {
            probe_id,
            session_id: session_uuid,
        },
    ));
    let sender = channel.0.clone();
    state
        .command_channel
        .send(AppPacket::Local(LocalAppPacket::Command(
            LocalCommandPacket::RegisterForEvents {
                probe_id,
                session_id: session_uuid,
                respond_to: sender,
            },
        )))
        .await
        .map_err(CoreError::from)?;
    let command_channel_local = state.command_channel.clone();
    let unregister_packet_local = unregister_packet.clone();
    rt::spawn(async move {
        while let Some(packet) = channel.1.recv().await {
            let Err(_) = session.text(packet.to_string()).await else {
                continue;
            };
            debug!("WebSocket closed, probe_id: {probe_id}, session_id: {session_uuid}");

            let Err(e) = command_channel_local
                .send(unregister_packet_local.clone())
                .await
            else {
                continue;
            };
            warn!("Error unregistering from events: {e}");
        }
    });
    let command_channel = state.command_channel.clone();
    rt::spawn(async move {
        while let Some(msg) = stream.recv().await {
            match msg {
                Ok(AggregatedMessage::Close(_)) | Err(_) => {
                    let _ = command_channel.send(unregister_packet).await;
                    break;
                }
                _ => {}
            }
        }
    });
    Ok(res)
}
