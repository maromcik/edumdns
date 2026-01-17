//! Device management handlers.
//!
//! This module provides HTTP handlers for managing smart devices discovered by probes:
//! - Device listing with filtering and pagination
//! - Device detail viewing with associated packets
//! - Device creation and updates
//! - Device deletion with cleanup of active transmissions
//! - Packet transmission requests (custom and automatic)
//! - Device publishing and hiding
//! - ACL (Access Control List) validation for transmission requests
//!
//! These handlers coordinate with the server component to manage packet transmission
//! and cache invalidation.

use crate::authorized;
use crate::error::WebError;
use crate::forms::device::{
    CreateDeviceForm, DeviceCustomPacketTransmitRequest, DevicePacketTransmitRequest, DeviceQuery,
    UpdateDeviceForm,
};
use crate::forms::packet::PacketQuery;
use crate::handlers::helpers::{authorize_packet_transmit_request, request_packet_transmit_helper};
use crate::handlers::utilities::{get_template_name, parse_user_id, validate_has_groups};
use crate::templates::PageInfo;
use crate::templates::device::{
    DeviceCreateTemplate, DeviceDetailTemplate, DeviceTemplate, DeviceTransmitTemplate,
};
use crate::utils::AppState;
use actix_identity::Identity;
use actix_web::http::header::LOCATION;
use actix_web::{HttpRequest, HttpResponse, delete, get, post, web};
use edumdns_core::app_packet::{EntityType, Id};
use edumdns_core::bincode_types::{IpNetwork, MacAddr};
use edumdns_core::error::CoreError;
use edumdns_db::repositories::common::{
    DbCreate, DbDelete, DbReadOne, DbUpdate, PAGINATION_ELEMENTS_PER_PAGE, Pagination,
};
use edumdns_db::repositories::device::models::{
    CreateDevice, DeviceDisplay, PacketTransmitRequestDisplay, SelectManyDevices,
};
use edumdns_db::repositories::device::repository::PgDeviceRepository;
use edumdns_db::repositories::packet::models::{PacketDisplay, SelectManyPackets};
use edumdns_db::repositories::packet::repository::PgPacketRepository;
use edumdns_db::repositories::user::repository::PgUserRepository;
use edumdns_server::app_packet::{AppPacket, LocalAppPacket, LocalCommandPacket};
use std::collections::HashMap;
use uuid::Uuid;

/// Lists all devices with filtering and pagination.
///
/// Retrieves devices accessible to the authenticated user, applies filters from query parameters,
/// and renders them in a paginated list view.
///
/// # Arguments
///
/// * `request` - HTTP request for template name detection
/// * `identity` - Optional user identity (required for access)
/// * `device_repo` - Device repository for database operations
/// * `user_repo` - User repository for user information
/// * `state` - Application state containing template engine
/// * `query` - Query parameters for filtering and pagination
///
/// # Returns
///
/// Returns an HTML response with the device list page, or redirects to login if not authenticated.
#[get("")]
pub async fn get_devices(
    request: HttpRequest,
    identity: Option<Identity>,
    device_repo: web::Data<PgDeviceRepository>,
    user_repo: web::Data<PgUserRepository>,
    state: web::Data<AppState>,
    query: web::Query<DeviceQuery>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let user_id = parse_user_id(&i)?;
    let user = user_repo.read_one(&user_id).await?;
    validate_has_groups(&user)?;
    let page = query.page.unwrap_or(1);
    let query = query.into_inner();
    let params = SelectManyDevices::from(query.clone());
    let devices = device_repo.read_many_auth(&params, &user_id).await?;
    let devices_parsed = devices.into_iter().map(DeviceDisplay::from).collect();

    let device_count = device_repo.get_device_count(params, &user_id).await?;
    let total_pages = (device_count as f64 / PAGINATION_ELEMENTS_PER_PAGE as f64).ceil() as i64;

    let template_name = get_template_name(&request, "device");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let query_string = request.uri().query().unwrap_or("").to_string();
    let body = template.render(DeviceTemplate {
        devices: devices_parsed,
        user,
        page_info: PageInfo::new(page, total_pages),
        filters: query,
        query_string,
    })?;

    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}

/// Displays detailed information about a specific device.
///
/// Shows device details, associated packets (with pagination), and active packet transmission
/// requests. The user must have permission to view the device.
///
/// # Arguments
///
/// * `request` - HTTP request for template name detection
/// * `identity` - Optional user identity (required for access)
/// * `device_repo` - Device repository for database operations
/// * `packet_repo` - Packet repository for retrieving associated packets
/// * `user_repo` - User repository for user information
/// * `path` - Path parameter containing device ID
/// * `state` - Application state containing template engine
/// * `query` - Query parameters for packet filtering and pagination
///
/// # Returns
///
/// Returns an HTML response with the device detail page, or an error if the device is not found
/// or the user lacks permission.
#[get("{id}")]
pub async fn get_device(
    request: HttpRequest,
    identity: Option<Identity>,
    device_repo: web::Data<PgDeviceRepository>,
    packet_repo: web::Data<PgPacketRepository>,
    user_repo: web::Data<PgUserRepository>,
    path: web::Path<(Id,)>,
    state: web::Data<AppState>,
    query: web::Query<PacketQuery>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let user_id = parse_user_id(&i)?;
    let user = user_repo.read_one(&user_id).await?;
    let device = device_repo.read_one_auth(&path.0, &user_id).await?;
    let page = query.page.unwrap_or(1);
    let params = SelectManyPackets::new(
        query.id,
        Some(device.data.probe_id),
        Some(device.data.mac),
        query.dst_mac.map(|mac| mac.to_octets()),
        Some(device.data.ip),
        query.dst_addr,
        query.src_port,
        query.dst_port,
        query.payload_string.clone(),
        Some(Pagination::default_pagination(query.page)),
    );
    let packets = packet_repo
        .read_many(&params)
        .await?
        .into_iter()
        .map(PacketDisplay::from)
        .filter_map(Result::ok)
        .collect();

    let packet_transmit_requests = device_repo
        .read_packet_transmit_requests_by_device(&device.data.id)
        .await?
        .into_iter()
        .map(|r| PacketTransmitRequestDisplay::from(r, device.data.duration))
        .collect();

    let packet_count = packet_repo.get_packet_count(params, &user_id).await?;
    let total_pages = (packet_count as f64 / PAGINATION_ELEMENTS_PER_PAGE as f64).ceil() as i64;
    let query_string = request.uri().query().unwrap_or("").to_string();
    let template_name = get_template_name(&request, "device/detail");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let body = template.render(DeviceDetailTemplate {
        user,
        permissions: device.permissions,
        device: DeviceDisplay::from(device.data),
        packets,
        packet_transmit_requests,
        page_info: PageInfo::new(page, total_pages),
        filters: query.into_inner(),
        query_string,
    })?;

    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}

/// Updates device information.
///
/// Modifies device properties such as name, description, ACL settings, and other metadata.
/// The user must have permission to update the device.
///
/// # Arguments
///
/// * `request` - HTTP request
/// * `identity` - Optional user identity (required for access)
/// * `device_repo` - Device repository for database operations
/// * `form` - Form data containing updated device information
///
/// # Returns
///
/// Returns a redirect response to the device detail page after successful update.
#[post("update")]
pub async fn update_device(
    request: HttpRequest,
    identity: Option<Identity>,
    device_repo: web::Data<PgDeviceRepository>,
    form: web::Form<UpdateDeviceForm>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let params = form.into_inner().to_db_params()?;
    device_repo
        .update_auth(&params, &parse_user_id(&i)?)
        .await?;
    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, format!("/device/{}", params.id)))
        .finish())
}

/// Deletes a device and cleans up associated resources.
///
/// This function stops all active packet transmission requests for the device, deletes
/// the device from the database, and invalidates the server's cache for the device.
/// It sends commands to the server to stop transmissions and clear cached packets.
///
/// # Arguments
///
/// * `request` - HTTP request
/// * `identity` - Optional user identity
/// * `device_repo` - Device repository for database operations
/// * `state` - Application state containing command channel
/// * `path` - Path parameter containing device ID
/// * `query` - Query parameters containing optional return URL
///
/// # Returns
///
/// Returns a redirect response to the return URL (or "/device" by default) after
/// successfully deleting the device and cleaning up resources.
///
/// # Side Effects
///
/// - Stops all active packet transmission requests for the device
/// - Deletes the device from the database
/// - Sends cache invalidation commands to the server
#[delete("{id}/delete")]
pub async fn delete_device(
    request: HttpRequest,
    identity: Option<Identity>,
    device_repo: web::Data<PgDeviceRepository>,
    state: web::Data<AppState>,
    path: web::Path<(Id,)>,
    query: web::Query<HashMap<String, String>>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let device_id = path.0;
    let return_url = query
        .get("return_url")
        .map(String::as_str)
        .unwrap_or("/device");
    let requests = device_repo
        .read_packet_transmit_requests_by_device(&device_id)
        .await?;
    for request in requests {
        let _ = state
            .command_channel
            .send(AppPacket::Local(LocalAppPacket::Command(
                LocalCommandPacket::StopTransmitDevicePackets(request.id),
            )))
            .await;
    }
    let devices = device_repo
        .delete_auth(&device_id, &parse_user_id(&i)?)
        .await?;

    for device in devices {
        let _ = state
            .command_channel
            .send(AppPacket::Local(LocalAppPacket::Command(
                LocalCommandPacket::InvalidateCache(EntityType::Device {
                    probe_id: edumdns_core::bincode_types::Uuid(device.probe_id),
                    device_mac: MacAddr::from_octets(device.mac),
                    device_ip: IpNetwork(device.ip),
                }),
            )))
            .await;
    }

    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, return_url))
        .finish())
}

/// Creates a custom packet transmission request for a device.
///
/// Initiates packet transmission to a custom target IP and port specified by the user.
/// This is used for administrative control over packet transmission.
///
/// # Arguments
///
/// * `request` - HTTP request
/// * `identity` - Optional user identity (required for access)
/// * `device_repo` - Device repository for database operations
/// * `path` - Path parameter containing device ID
/// * `state` - Application state containing command channel
/// * `form` - Form data containing target IP, port, and permanent flag
///
/// # Returns
///
/// Returns a redirect response to the device detail page after initiating transmission.
#[post("{id}/transmit-custom")]
pub async fn request_custom_packet_transmit(
    request: HttpRequest,
    identity: Option<Identity>,
    device_repo: web::Data<PgDeviceRepository>,
    path: web::Path<(Id,)>,
    state: web::Data<AppState>,
    form: web::Form<DeviceCustomPacketTransmitRequest>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let user_id = parse_user_id(&i)?;
    let device = device_repo.read_one_auth(&path.0, &user_id).await?;
    let device_id = device.data.id;
    request_packet_transmit_helper(
        device_repo.clone(),
        device.data,
        &user_id,
        state.command_channel.clone(),
        &form,
    )
    .await?;

    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, format!("/device/{}", device_id)))
        .finish())
}

/// Displays the packet transmission request page for a device.
///
/// Shows a form for requesting packet transmission. For published devices, this page is publicly
/// accessible. For unpublished devices, the user must have permission to view the device.
///
/// # Arguments
///
/// * `request` - HTTP request containing client IP information
/// * `identity` - Optional user identity (required for unpublished devices)
/// * `device_repo` - Device repository for database operations
/// * `user_repo` - User repository for user information
/// * `path` - Path parameter containing device ID
/// * `state` - Application state containing template engine
///
/// # Returns
///
/// Returns an HTML response with the transmission request form, showing the client's IP address
/// and any existing transmission requests.
#[get("{id}/transmit")]
pub async fn get_device_for_transmit(
    request: HttpRequest,
    identity: Option<Identity>,
    device_repo: web::Data<PgDeviceRepository>,
    user_repo: web::Data<PgUserRepository>,
    path: web::Path<(Id,)>,
    state: web::Data<AppState>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let device = device_repo.read_one(&path.0).await?;
    let user_id = parse_user_id(&i)?;
    if !device.published {
        device_repo.read_one_auth(&path.0, &user_id).await?;
    }
    let target_ip = request
        .connection_info()
        .realip_remote_addr()
        .map(|a| a.to_string());
    let target_ip = target_ip.ok_or(WebError::InternalServerError(
        "Could not determine target ip".to_string(),
    ))?;

    let in_progress = if device.exclusive || device.proxy {
        device_repo
            .read_packet_transmit_requests_by_device(&device.id)
            .await?
            .into_iter()
            .map(|r| PacketTransmitRequestDisplay::from(r, device.duration))
            .next()
    } else {
        None
    };

    let packet_transmit_request = device_repo
        .read_packet_transmit_request_by_user(&device.id, &user_id)
        .await?
        .into_iter()
        .map(|r| PacketTransmitRequestDisplay::from(r, device.duration))
        .next();

    let user = user_repo.read_one(&user_id).await?;

    let template_name = get_template_name(&request, "device/public");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let body = template.render(DeviceTransmitTemplate {
        user,
        device: DeviceDisplay::from(device),
        client_ip: target_ip,
        packet_transmit_request,
        in_progress,
    })?;

    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}

/// Creates a packet transmission request from a public device page.
///
/// Validates ACL rules (CIDR, password, AP hostname) and initiates packet transmission to the
/// client's IP address. This is the public-facing endpoint for device discovery requests.
///
/// # Arguments
///
/// * `request` - HTTP request containing client IP information
/// * `identity` - Optional user identity (required for unpublished devices)
/// * `device_repo` - Device repository for database operations
/// * `path` - Path parameter containing device ID
/// * `state` - Application state containing command channel and external auth database config
/// * `form` - Form data potentially containing ACL password
///
/// # Returns
///
/// Returns a redirect response to the transmission page after initiating transmission.
#[post("{id}/transmit")]
pub async fn request_packet_transmit(
    request: HttpRequest,
    identity: Option<Identity>,
    device_repo: web::Data<PgDeviceRepository>,
    path: web::Path<(Id,)>,
    state: web::Data<AppState>,
    form: web::Form<DevicePacketTransmitRequest>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let user_id = parse_user_id(&i)?;
    let device = device_repo.read_one(&path.0).await?;
    if !device.published {
        device_repo.read_one_auth(&path.0, &user_id).await?;
    }
    let device_id = device.id;

    let target_ip = authorize_packet_transmit_request(
        &request,
        &device,
        &form,
        &state.web_config.external_auth_database,
    )
    .await?;

    let form = DeviceCustomPacketTransmitRequest::new(target_ip, device.port as u16, false);
    request_packet_transmit_helper(
        device_repo.clone(),
        device,
        &user_id,
        state.command_channel.clone(),
        &form,
    )
    .await?;

    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, format!("/device/{}/transmit", device_id)))
        .finish())
}

/// Stops and deletes an active packet transmission request.
///
/// Sends a command to the server to stop transmission and removes the request from the database.
/// The user must own the request or have permission to manage the device.
///
/// # Arguments
///
/// * `request` - HTTP request
/// * `identity` - Optional user identity (required for access)
/// * `device_repo` - Device repository for database operations
/// * `path` - Path parameters containing device ID and request ID
/// * `state` - Application state containing command channel
/// * `query` - Query parameters containing optional return URL
///
/// # Returns
///
/// Returns a redirect response to the return URL (or device detail page) after stopping transmission.
#[delete("{device_id}/transmit/{request_id}")]
pub async fn delete_request_packet_transmit(
    request: HttpRequest,
    identity: Option<Identity>,
    device_repo: web::Data<PgDeviceRepository>,
    path: web::Path<(Id, Id)>,
    state: web::Data<AppState>,
    mut query: web::Query<HashMap<String, String>>,
) -> Result<HttpResponse, WebError> {
    let device_id = path.0;
    let request_id = path.1;
    let i = authorized!(identity, request);
    let user_id = parse_user_id(&i)?;

    let request = device_repo
        .read_packet_transmit_request_by_user(&device_id, &user_id)
        .await?;

    let _ = match request.first() {
        None => device_repo.read_one_auth(&device_id, &user_id).await?.data,
        Some(_) => device_repo.read_one(&device_id).await?,
    };

    state
        .command_channel
        .send(AppPacket::Local(LocalAppPacket::Command(
            LocalCommandPacket::StopTransmitDevicePackets(request_id),
        )))
        .await
        .map_err(CoreError::from)?;

    let return_url = query
        .remove("return_url")
        .unwrap_or(format!("/device/{}", device_id));

    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, return_url))
        .finish())
}

/// Extends the duration of an active packet transmission request.
///
/// Validates ACL rules again and extends the transmission duration. The user must own the
/// request or have permission to manage the device.
///
/// # Arguments
///
/// * `request` - HTTP request containing client IP information
/// * `identity` - Optional user identity (required for access)
/// * `device_repo` - Device repository for database operations
/// * `state` - Application state containing command channel and external auth database config
/// * `form` - Form data potentially containing ACL password
/// * `path` - Path parameters containing device ID and request ID
///
/// # Returns
///
/// Returns a redirect response to the transmission page after extending the request.
#[post("{device_id}/transmit/{request_id}/extend")]
pub async fn extend_request_packet_transmit(
    request: HttpRequest,
    identity: Option<Identity>,
    device_repo: web::Data<PgDeviceRepository>,
    state: web::Data<AppState>,
    form: web::Form<DevicePacketTransmitRequest>,
    path: web::Path<(Id, Id)>,
) -> Result<HttpResponse, WebError> {
    let form = form.into_inner();
    let device_id = path.0;
    let request_id = path.1;
    let i = authorized!(identity, request);
    let user_id = parse_user_id(&i)?;

    let packet_transmit_request = device_repo
        .read_packet_transmit_request_by_user(&device_id, &user_id)
        .await?;

    let device = match packet_transmit_request.first() {
        None => device_repo.read_one_auth(&device_id, &user_id).await?.data,
        Some(_) => device_repo.read_one(&device_id).await?,
    };

    authorize_packet_transmit_request(
        &request,
        &device,
        &form,
        &state.web_config.external_auth_database,
    )
    .await?;

    device_repo
        .extend_packet_transmit_request(&request_id)
        .await?;

    state
        .command_channel
        .send(AppPacket::Local(LocalAppPacket::Command(
            LocalCommandPacket::ExtendPacketTransmitRequest(request_id),
        )))
        .await
        .map_err(CoreError::from)?;

    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, format!("/device/{}/transmit", device_id)))
        .finish())
}

/// Extends the duration of a custom packet transmission request.
///
/// Extends the transmission duration without re-validating ACL rules (admin-only operation).
/// The user must have permission to manage the device.
///
/// # Arguments
///
/// * `request` - HTTP request
/// * `identity` - Optional user identity (required for access)
/// * `device_repo` - Device repository for database operations
/// * `state` - Application state containing command channel
/// * `path` - Path parameters containing device ID and request ID
///
/// # Returns
///
/// Returns a redirect response to the device detail page after extending the request.
#[post("{device_id}/transmit-custom/{request_id}/extend")]
pub async fn extend_custom_request_packet_transmit(
    request: HttpRequest,
    identity: Option<Identity>,
    device_repo: web::Data<PgDeviceRepository>,
    state: web::Data<AppState>,
    path: web::Path<(Id, Id)>,
) -> Result<HttpResponse, WebError> {
    let device_id = path.0;
    let request_id = path.1;
    let i = authorized!(identity, request);
    let user_id = parse_user_id(&i)?;
    let _ = device_repo.read_one_auth(&device_id, &user_id).await?;
    device_repo
        .extend_packet_transmit_request(&request_id)
        .await?;

    state
        .command_channel
        .send(AppPacket::Local(LocalAppPacket::Command(
            LocalCommandPacket::ExtendPacketTransmitRequest(request_id),
        )))
        .await
        .map_err(CoreError::from)?;

    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, format!("/device/{}", device_id)))
        .finish())
}

/// Publishes a device, making it publicly accessible.
///
/// Sets the device's published flag to true, allowing unauthenticated users to request
/// packet transmission from the device's public page.
///
/// # Arguments
///
/// * `request` - HTTP request
/// * `identity` - Optional user identity (required for access)
/// * `device_repo` - Device repository for database operations
/// * `path` - Path parameter containing device ID
///
/// # Returns
///
/// Returns a redirect response to the device detail page after publishing.
#[get("{id}/publish")]
pub async fn publish_device(
    request: HttpRequest,
    identity: Option<Identity>,
    device_repo: web::Data<PgDeviceRepository>,
    path: web::Path<(Id,)>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let user_id = parse_user_id(&i)?;
    let device_id = path.0;

    device_repo
        .toggle_publicity(&device_id, &user_id, true)
        .await?;

    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, format!("/device/{}", device_id)))
        .finish())
}

/// Hides a device, making it accessible only to authorized users.
///
/// Sets the device's published flag to false, restricting access to users with appropriate
/// permissions.
///
/// # Arguments
///
/// * `request` - HTTP request
/// * `identity` - Optional user identity (required for access)
/// * `device_repo` - Device repository for database operations
/// * `path` - Path parameter containing device ID
///
/// # Returns
///
/// Returns a redirect response to the device detail page after hiding.
#[get("{id}/hide")]
pub async fn hide_device(
    request: HttpRequest,
    identity: Option<Identity>,
    device_repo: web::Data<PgDeviceRepository>,
    path: web::Path<(Id,)>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let user_id = parse_user_id(&i)?;
    let device_id = path.0;
    device_repo
        .toggle_publicity(&device_id, &user_id, false)
        .await?;
    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, format!("/device/{}", device_id)))
        .finish())
}

/// Creates a new device in the database.
///
/// Creates a device record associated with a probe, identified by MAC address and IP address.
/// The user must have permission to create devices for the specified probe.
///
/// # Arguments
///
/// * `request` - HTTP request
/// * `identity` - Optional user identity (required for access)
/// * `device_repo` - Device repository for database operations
/// * `form` - Form data containing device information (probe ID, MAC, IP, name, etc.)
///
/// # Returns
///
/// Returns a redirect response to the newly created device's detail page.
#[post("create")]
pub async fn create_device(
    request: HttpRequest,
    identity: Option<Identity>,
    device_repo: web::Data<PgDeviceRepository>,
    form: web::Form<CreateDeviceForm>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let params = CreateDevice::from(form.into_inner());
    let device = device_repo
        .create_auth(&params, &parse_user_id(&i)?)
        .await?;
    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, format!("/device/{}", device.id)))
        .finish())
}

/// Displays the device creation form.
///
/// Shows a form for creating a new device associated with a specific probe.
///
/// # Arguments
///
/// * `request` - HTTP request for template name detection
/// * `identity` - Optional user identity (required for access)
/// * `user_repo` - User repository for user information
/// * `state` - Application state containing template engine
/// * `path` - Path parameter containing probe ID
///
/// # Returns
///
/// Returns an HTML response with the device creation form.
#[get("create/{id}")]
pub async fn create_device_form(
    request: HttpRequest,
    identity: Option<Identity>,
    user_repo: web::Data<PgUserRepository>,
    state: web::Data<AppState>,
    path: web::Path<(Uuid,)>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let user_id = parse_user_id(&i)?;
    let user = user_repo.read_one(&user_id).await?;
    let template_name = get_template_name(&request, "device/create");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let body = template.render(DeviceCreateTemplate {
        probe_id: path.0,
        user,
    })?;
    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}
