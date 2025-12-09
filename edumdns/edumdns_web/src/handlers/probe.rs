//! Probe management handlers.
//!
//! This module provides HTTP handlers for managing remote probes:
//! - Probe listing with filtering and pagination
//! - Probe detail viewing with associated devices and configurations
//! - Probe creation, updates, and deletion
//! - Probe adoption (registering new probes)
//! - Probe reconnection commands
//! - Configuration management (create, update, delete)
//! - Permission management for probe access
//! - WebSocket endpoint for real-time probe status updates
//!
//! These handlers coordinate with the server component to send commands to probes
//! and manage probe state in the database.

use crate::authorized;
use crate::error::WebError;
use crate::forms::device::DeviceQuery;
use crate::forms::probe::{
    CreateProbeForm, ProbeConfigForm, ProbePermissionForm, ProbeQuery, UpdateProbeForm,
    UpdateProbeOwnerForm,
};
use crate::handlers::helpers::{get_probe_content, reconnect_probe};
use crate::handlers::utilities::{get_template_name, parse_user_id, validate_has_groups};
use crate::templates::PageInfo;
use crate::templates::probe::ProbeTemplate;
use crate::utils::AppState;
use actix_identity::Identity;
use actix_session::Session;
use actix_web::http::header::LOCATION;
use actix_web::{HttpRequest, HttpResponse, delete, get, post, put, rt, web};
use actix_ws::AggregatedMessage;
use edumdns_core::app_packet::{EntityType, Id};
use edumdns_core::bincode_types::Uuid;
use edumdns_core::error::CoreError;
use edumdns_db::repositories::common::{
    DbCreate, DbDelete, DbReadOne, DbUpdate, PAGINATION_ELEMENTS_PER_PAGE,
};
use edumdns_db::repositories::device::repository::PgDeviceRepository;
use edumdns_db::repositories::group::repository::PgGroupRepository;
use edumdns_db::repositories::probe::models::{
    AlterProbePermission, CreateProbe, CreateProbeConfig, ProbeDisplay, SelectManyProbes,
    SelectSingleProbeConfig, UpdateProbe,
};
use edumdns_db::repositories::probe::repository::PgProbeRepository;
use edumdns_db::repositories::user::repository::PgUserRepository;
use edumdns_server::app_packet::{
    AppPacket, LocalAppPacket, LocalCommandPacket, LocalStatusPacket,
};
use log::{info, warn};
use std::collections::HashMap;
use tokio::sync::mpsc;

/// Lists all probes with filtering and pagination.
///
/// Retrieves probes accessible to the authenticated user, applies filters from query parameters,
/// and renders them in a paginated list view.
///
/// # Arguments
///
/// * `request` - HTTP request for template name detection
/// * `identity` - Optional user identity (required for access)
/// * `probe_repo` - Probe repository for database operations
/// * `user_repo` - User repository for user information
/// * `state` - Application state containing template engine
/// * `query` - Query parameters for filtering and pagination
///
/// # Returns
///
/// Returns an HTML response with the probe list page, or redirects to login if not authenticated.
#[get("")]
pub async fn get_probes(
    request: HttpRequest,
    identity: Option<Identity>,
    probe_repo: web::Data<PgProbeRepository>,
    user_repo: web::Data<PgUserRepository>,
    state: web::Data<AppState>,
    query: web::Query<ProbeQuery>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let page = query.page.unwrap_or(1);
    let user_id = parse_user_id(&i)?;
    let user = user_repo.read_one(&user_id).await?;
    validate_has_groups(&user)?;
    let query = query.into_inner();
    let params = SelectManyProbes::from(query.clone());
    let probes = probe_repo.read_many_auth(&params, &user_id).await?;

    let probes_parsed = probes.into_iter().map(ProbeDisplay::from).collect();

    let probe_count = probe_repo.get_probe_count(params, &user_id).await?;
    let total_pages = (probe_count as f64 / PAGINATION_ELEMENTS_PER_PAGE as f64).ceil() as i64;

    let template_name = get_template_name(&request, "probe");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let query_string = request.uri().query().unwrap_or("").to_string();
    let body = template.render(ProbeTemplate {
        user,
        probes: probes_parsed,
        page_info: PageInfo::new(page, total_pages),
        filters: query,
        query_string,
    })?;

    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}

/// Displays detailed information about a specific probe.
///
/// Shows probe details, associated devices, configuration, and permission matrix.
/// Delegates to the `get_probe_content` helper function.
///
/// # Arguments
///
/// * `request` - HTTP request for template name detection
/// * `identity` - Optional user identity (required for access)
/// * `probe_repo` - Probe repository for database operations
/// * `group_repo` - Group repository for permission matrix
/// * `device_repo` - Device repository for associated devices
/// * `user_repo` - User repository for user information
/// * `state` - Application state containing template engine
/// * `path` - Path parameter containing probe UUID
/// * `query` - Query parameters for device filtering and pagination
///
/// # Returns
///
/// Returns an HTML response with the probe detail page.
#[get("{id}")]
pub async fn get_probe(
    request: HttpRequest,
    identity: Option<Identity>,
    probe_repo: web::Data<PgProbeRepository>,
    group_repo: web::Data<PgGroupRepository>,
    device_repo: web::Data<PgDeviceRepository>,
    user_repo: web::Data<PgUserRepository>,
    state: web::Data<AppState>,
    path: web::Path<(uuid::Uuid,)>,
    query: web::Query<DeviceQuery>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let user_id = parse_user_id(&i)?;
    let user = user_repo.read_one(&user_id).await?;
    get_probe_content(
        request,
        probe_repo,
        group_repo,
        device_repo,
        state,
        user,
        path.0,
        query,
    )
    .await
}

/// Adopts a probe, registering it for use in the system.
///
/// Marks a probe as adopted in the database and sends a reconnect command to the probe
/// to establish a connection. After adoption, the probe will be able to connect to the server.
///
/// # Arguments
///
/// * `request` - HTTP request for template name detection
/// * `identity` - Optional user identity (required for access)
/// * `probe_repo` - Probe repository for database operations
/// * `state` - Application state containing command channel
/// * `path` - Path parameter containing probe UUID
/// * `group_repo` - Group repository for permission matrix
/// * `device_repo` - Device repository for associated devices
/// * `user_repo` - User repository for user information
/// * `query` - Query parameters for device filtering
/// * `session` - Session for storing session ID
///
/// # Returns
///
/// Returns an HTML response with the probe detail page after adoption.
#[get("{id}/adopt")]
pub async fn adopt(
    request: HttpRequest,
    identity: Option<Identity>,
    probe_repo: web::Data<PgProbeRepository>,
    state: web::Data<AppState>,
    path: web::Path<(uuid::Uuid,)>,
    group_repo: web::Data<PgGroupRepository>,
    device_repo: web::Data<PgDeviceRepository>,
    user_repo: web::Data<PgUserRepository>,
    query: web::Query<DeviceQuery>,
    session: Session,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let user_id = parse_user_id(&i)?;
    let user = user_repo.read_one(&user_id).await?;
    probe_repo.adopt(&path.0, &user_id).await?;
    reconnect_probe(state.command_channel.clone(), path.0, session).await?;
    get_probe_content(
        request,
        probe_repo,
        group_repo,
        device_repo,
        state,
        user,
        path.0,
        query,
    )
    .await
}

/// Forgets a probe, unregistering it from the system.
///
/// Marks a probe as forgotten in the database and sends a reconnect command. After being
/// forgotten, the probe will be rejected when attempting to connect until it is adopted again.
///
/// # Arguments
///
/// * `request` - HTTP request for template name detection
/// * `identity` - Optional user identity (required for access)
/// * `probe_repo` - Probe repository for database operations
/// * `state` - Application state containing command channel
/// * `path` - Path parameter containing probe UUID
/// * `group_repo` - Group repository for permission matrix
/// * `device_repo` - Device repository for associated devices
/// * `user_repo` - User repository for user information
/// * `query` - Query parameters for device filtering
/// * `session` - Session for storing session ID
///
/// # Returns
///
/// Returns an HTML response with the probe detail page after forgetting.
#[get("{id}/forget")]
pub async fn forget(
    request: HttpRequest,
    identity: Option<Identity>,
    probe_repo: web::Data<PgProbeRepository>,
    state: web::Data<AppState>,
    path: web::Path<(uuid::Uuid,)>,
    group_repo: web::Data<PgGroupRepository>,
    device_repo: web::Data<PgDeviceRepository>,
    user_repo: web::Data<PgUserRepository>,
    query: web::Query<DeviceQuery>,
    session: Session,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let user_id = parse_user_id(&i)?;
    let user = user_repo.read_one(&user_id).await?;
    probe_repo.forget(&path.0, &user_id).await?;
    reconnect_probe(state.command_channel.clone(), path.0, session).await?;
    get_probe_content(
        request,
        probe_repo,
        group_repo,
        device_repo,
        state,
        user,
        path.0,
        query,
    )
    .await
}

/// Sends a reconnect command to a probe.
///
/// Forces the probe to disconnect and reconnect to the server. This is useful for applying
/// configuration changes or recovering from connection issues. The user must have permission
/// to reconnect the probe.
///
/// # Arguments
///
/// * `request` - HTTP request for template name detection
/// * `identity` - Optional user identity (required for access)
/// * `path` - Path parameter containing probe UUID
/// * `session` - Session for storing session ID
/// * `probe_repo` - Probe repository for permission checking
/// * `group_repo` - Group repository for permission matrix
/// * `device_repo` - Device repository for associated devices
/// * `user_repo` - User repository for user information
/// * `query` - Query parameters for device filtering
/// * `state` - Application state containing command channel and template engine
///
/// # Returns
///
/// Returns an HTML response with the probe detail page after sending the reconnect command.
#[get("{id}/reconnect")]
pub async fn reconnect(
    request: HttpRequest,
    identity: Option<Identity>,
    path: web::Path<(uuid::Uuid,)>,
    session: Session,
    probe_repo: web::Data<PgProbeRepository>,
    group_repo: web::Data<PgGroupRepository>,
    device_repo: web::Data<PgDeviceRepository>,
    user_repo: web::Data<PgUserRepository>,
    query: web::Query<DeviceQuery>,
    state: web::Data<AppState>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    probe_repo
        .check_permissions_for_reconnect(&path.0, &parse_user_id(&i)?)
        .await?;

    reconnect_probe(state.command_channel.clone(), path.0, session).await?;
    let user_id = parse_user_id(&i)?;
    let user = user_repo.read_one(&user_id).await?;
    get_probe_content(
        request,
        probe_repo,
        group_repo,
        device_repo,
        state,
        user,
        path.0,
        query,
    )
    .await
}

/// Creates a new capture configuration for a probe.
///
/// Adds a new interface and BPF filter configuration to a probe. The probe will be
/// reconnected to apply the new configuration.
///
/// # Arguments
///
/// * `request` - HTTP request
/// * `identity` - Optional user identity (required for access)
/// * `probe_repo` - Probe repository for database operations
/// * `state` - Application state containing command channel
/// * `form` - Form data containing interface name and BPF filter
/// * `path` - Path parameter containing probe UUID
/// * `session` - Session for storing session ID
///
/// # Returns
///
/// Returns a redirect response to the probe detail page after creating the configuration.
#[post("{probe_id}/config")]
pub async fn create_config(
    request: HttpRequest,
    identity: Option<Identity>,
    probe_repo: web::Data<PgProbeRepository>,
    state: web::Data<AppState>,
    form: web::Form<ProbeConfigForm>,
    path: web::Path<(uuid::Uuid,)>,
    session: Session,
) -> Result<HttpResponse, WebError> {
    let probe_id = path.0;
    let i = authorized!(identity, request);
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

/// Updates an existing capture configuration for a probe.
///
/// Replaces an existing configuration by deleting the old one and creating a new one with
/// the updated values. The probe will be reconnected to apply the changes.
///
/// # Arguments
///
/// * `request` - HTTP request
/// * `identity` - Optional user identity (required for access)
/// * `probe_repo` - Probe repository for database operations
/// * `state` - Application state containing command channel
/// * `form` - Form data containing updated interface name and BPF filter
/// * `path` - Path parameters containing probe UUID and configuration ID
/// * `session` - Session for storing session ID
///
/// # Returns
///
/// Returns a redirect response to the probe detail page after updating the configuration.
#[put("{probe_id}/config/{config_id}")]
pub async fn save_config(
    request: HttpRequest,
    identity: Option<Identity>,
    probe_repo: web::Data<PgProbeRepository>,
    state: web::Data<AppState>,
    form: web::Form<ProbeConfigForm>,
    path: web::Path<(uuid::Uuid, Id)>,
    session: Session,
) -> Result<HttpResponse, WebError> {
    let probe_id = path.0;
    let config_id = path.1;
    let i = authorized!(identity, request);
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

/// Deletes a capture configuration from a probe.
///
/// Removes an interface and BPF filter configuration. The probe will be reconnected to
/// apply the changes.
///
/// # Arguments
///
/// * `request` - HTTP request
/// * `identity` - Optional user identity (required for access)
/// * `probe_repo` - Probe repository for database operations
/// * `state` - Application state containing command channel
/// * `path` - Path parameters containing probe UUID and configuration ID
/// * `session` - Session for storing session ID
///
/// # Returns
///
/// Returns a redirect response to the probe detail page after deleting the configuration.
#[delete("{probe_id}/config/{config_id}")]
pub async fn delete_config(
    request: HttpRequest,
    identity: Option<Identity>,
    probe_repo: web::Data<PgProbeRepository>,
    state: web::Data<AppState>,
    path: web::Path<(uuid::Uuid, Id)>,
    session: Session,
) -> Result<HttpResponse, WebError> {
    let probe_id = path.0;
    let config_id = path.1;
    let i = authorized!(identity, request);
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

/// Toggles a permission for a group on a probe.
///
/// Adds or removes a permission (Read, Write, Full) for a specific group on a probe.
/// This controls which groups can access the probe and its associated devices.
///
/// # Arguments
///
/// * `request` - HTTP request
/// * `identity` - Optional user identity (required for access)
/// * `probe_repo` - Probe repository for database operations
/// * `form` - Form data containing group ID, permission type, and toggle value
/// * `path` - Path parameter containing probe UUID
///
/// # Returns
///
/// Returns a redirect response to the probe detail page after updating permissions.
#[post("{probe_id}/permission/toggle")]
pub async fn change_probe_permission(
    request: HttpRequest,
    identity: Option<Identity>,
    probe_repo: web::Data<PgProbeRepository>,
    form: web::Form<ProbePermissionForm>,
    path: web::Path<(uuid::Uuid,)>,
) -> Result<HttpResponse, WebError> {
    let probe_id = path.0;
    let i = authorized!(identity, request);

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

/// Updates probe information.
///
/// Modifies probe properties such as name and description. The user must have permission
/// to update the probe.
///
/// # Arguments
///
/// * `request` - HTTP request
/// * `identity` - Optional user identity (required for access)
/// * `probe_repo` - Probe repository for database operations
/// * `form` - Form data containing updated probe information
///
/// # Returns
///
/// Returns a redirect response to the probe detail page after updating.
#[post("update")]
pub async fn update_probe(
    request: HttpRequest,
    identity: Option<Identity>,
    probe_repo: web::Data<PgProbeRepository>,
    form: web::Form<UpdateProbeForm>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let probe_id = form.id;
    probe_repo
        .update_auth(&UpdateProbe::from(form.into_inner()), &parse_user_id(&i)?)
        .await?;
    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, format!("/probe/{}", probe_id)))
        .finish())
}

/// Updates the owner of a probe.
///
/// Transfers ownership of a probe to a different user. The current user must have
/// permission to change ownership.
///
/// # Arguments
///
/// * `request` - HTTP request
/// * `identity` - Optional user identity (required for access)
/// * `probe_repo` - Probe repository for database operations
/// * `form` - Form data containing probe ID and new owner ID
///
/// # Returns
///
/// Returns a redirect response to the probe detail page after updating ownership.
#[post("update-owner")]
pub async fn update_probe_owner(
    request: HttpRequest,
    identity: Option<Identity>,
    probe_repo: web::Data<PgProbeRepository>,
    form: web::Form<UpdateProbeOwnerForm>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    probe_repo
        .update_owner_auth(&form.id, &form.owner_id, &parse_user_id(&i)?)
        .await?;
    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, format!("/probe/{}", form.id)))
        .finish())
}

/// Deletes a probe from the system.
///
/// Removes the probe from the database, invalidates its cache, and sends a reconnect command.
/// Sends a WebSocket update to notify clients of the deletion.
///
/// # Arguments
///
/// * `request` - HTTP request
/// * `identity` - Optional user identity (required for access)
/// * `probe_repo` - Probe repository for database operations
/// * `path` - Path parameter containing probe UUID
/// * `state` - Application state containing command channel
/// * `query` - Query parameters containing optional return URL
/// * `session` - Session for retrieving session ID for WebSocket updates
///
/// # Returns
///
/// Returns a redirect response to the return URL (or probe list) after deletion.
#[delete("{id}/delete")]
pub async fn delete_probe(
    request: HttpRequest,
    identity: Option<Identity>,
    probe_repo: web::Data<PgProbeRepository>,
    path: web::Path<(uuid::Uuid,)>,
    state: web::Data<AppState>,
    query: web::Query<HashMap<String, String>>,
    session: Session,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let user_id = parse_user_id(&i)?;
    let probe_id = path.0;
    let return_url = query
        .get("return_url")
        .map(String::as_str)
        .unwrap_or("/probe");

    let uuid = session.get::<Uuid>("session_id")?;
    let _ = state
        .command_channel
        .send(AppPacket::Local(LocalAppPacket::Status(
            LocalStatusPacket::OperationUpdateToWs {
                probe_id: Uuid(probe_id),
                session_id: uuid,
                message: format!("Deleting probe {} in the background.", probe_id),
            },
        )))
        .await;

    let _ = state
        .command_channel
        .send(AppPacket::Local(LocalAppPacket::Command(
            LocalCommandPacket::InvalidateCache(EntityType::Probe {
                probe_id: Uuid(probe_id),
            }),
        )))
        .await;

    probe_repo.delete_auth(&probe_id, &user_id).await?;
    reconnect_probe(state.command_channel.clone(), probe_id, session).await?;
    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, return_url))
        .finish())
}

/// Establishes a WebSocket connection for real-time probe status updates.
///
/// Creates a WebSocket connection that receives real-time updates about probe status,
/// including connection state and probe responses. The connection is registered with the
/// server manager to receive events for the specified probe.
///
/// # Arguments
///
/// * `request` - HTTP request for WebSocket upgrade
/// * `identity` - Optional user identity (required for access)
/// * `state` - Application state containing command channel
/// * `path` - Path parameter containing probe UUID
/// * `stream` - WebSocket payload stream
/// * `session` - Session for storing session ID
///
/// # Returns
///
/// Returns a WebSocket response that upgrades the HTTP connection to WebSocket.
///
/// # Behavior
///
/// - Registers the WebSocket session with the server manager
/// - Spawns tasks to handle incoming messages and probe status updates
/// - Periodically checks probe liveness and sends updates to the client
/// - Automatically unregisters the session when the connection closes
#[get("{id}/ws")]
pub async fn get_probe_ws(
    request: HttpRequest,
    identity: Option<Identity>,
    state: web::Data<AppState>,
    path: web::Path<(uuid::Uuid,)>,
    stream: web::Payload,
    session: Session,
) -> Result<HttpResponse, WebError> {
    let _ = authorized!(identity, request);
    let probe_id = path.0;

    let ts = uuid::Timestamp::now(uuid::NoContext);
    let session_id = uuid::Uuid::new_v7(ts);

    let (res, ws_session, stream) = actix_ws::handle(&request, stream)?;
    let mut stream = stream
        .aggregate_continuations()
        .max_continuation_size(2_usize.pow(20));
    let mut channel = mpsc::channel(100);
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
    session.insert("session_id", session_id.to_string())?;
    let mut ws_session_local = ws_session.clone();
    rt::spawn(async move {
        while let Some(packet) = channel.1.recv().await {
            let Err(_) = ws_session_local.text(packet.to_string()).await else {
                continue;
            };
            warn!("WebSocket closed, probe_id: {probe_id}, session_id: {session_id}");

            let Err(e) = command_channel
                .send(AppPacket::Local(LocalAppPacket::Command(
                    LocalCommandPacket::UnregisterFromEvents {
                        probe_id,
                        session_id,
                    },
                )))
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
                    let _ = command_channel
                        .send(AppPacket::Local(LocalAppPacket::Command(
                            LocalCommandPacket::UnregisterFromEvents {
                                probe_id,
                                session_id,
                            },
                        )))
                        .await;
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
            if let Err(e) = command_channel
                .send(AppPacket::Local(LocalAppPacket::Status(
                    LocalStatusPacket::IsProbeLive {
                        probe_id,
                        respond_to: respond_to_channel.0,
                    },
                )))
                .await
            {
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
                }
                Some(is_alive) => {
                    if ws_session_local.text(is_alive.to_string()).await.is_err() {
                        info!("WebSocket closed, probe_id: {probe_id}, session_id: {session_id}");
                        return;
                    };
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(
                state.web_config.limits.probe_ping_interval,
            ))
            .await;
        }
    });
    Ok(res)
}

/// Creates a new probe in the database.
///
/// Creates a probe record that can be adopted by a remote probe with a matching UUID.
/// The user must be assigned to at least one group to create probes.
///
/// # Arguments
///
/// * `request` - HTTP request
/// * `identity` - Optional user identity (required for access)
/// * `probe_repo` - Probe repository for database operations
/// * `user_repo` - User repository for user information and group validation
/// * `form` - Form data containing probe name
///
/// # Returns
///
/// Returns a redirect response to the newly created probe's detail page.
#[post("create")]
pub async fn create_probe(
    request: HttpRequest,
    identity: Option<Identity>,
    probe_repo: web::Data<PgProbeRepository>,
    user_repo: web::Data<PgUserRepository>,
    form: web::Form<CreateProbeForm>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let user_id = parse_user_id(&i)?;
    let user = user_repo.read_one(&user_id).await?;
    validate_has_groups(&user)?;
    let probe_create = CreateProbe::new_web(form.name.as_str(), &user_id);
    let _ = probe_repo.create_auth(&probe_create, &user_id).await?;
    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, format!("/probe/{}", probe_create.id)))
        .finish())
}
