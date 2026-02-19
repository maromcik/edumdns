//! Packet management handlers.
//!
//! This module provides HTTP handlers for viewing and managing captured mDNS packets:
//! - Packet listing with filtering and pagination
//! - Packet detail viewing with metadata
//! - Packet creation (manual packet entry)
//! - Packet updates
//! - Packet deletion
//! - Packet reassignment to different devices
//!
//! These handlers allow administrators to view captured packets, create custom packets
//! for testing, and manage packet associations with devices.

use crate::authorized;
use crate::error::WebError;
use crate::forms::packet::{
    CreatePacketForm, PacketDeviceDataForm, PacketQuery, ReassignPacketForm, UpdatePacketForm,
    UpdatePacketPayloadForm,
};
use crate::handlers::utilities::{get_template_name, parse_user_id, validate_has_groups};
use crate::header::LOCATION;
use crate::templates::PageInfo;
use crate::templates::packet::{
    PacketCreateTemplate, PacketDetailTemplate, PacketTemplate, PacketUpdatePayloadTemplate,
};
use crate::utils::AppState;
use actix_identity::Identity;
use actix_web::{HttpRequest, HttpResponse, delete, get, post, web};
use edumdns_core::app_packet::Id;
use edumdns_core::bincode_types::MacAddr;
use edumdns_db::repositories::common::{
    DbCreate, DbDelete, DbReadOne, PAGINATION_ELEMENTS_PER_PAGE,
};
use edumdns_db::repositories::device::models::SelectSingleDevice;
use edumdns_db::repositories::device::repository::PgDeviceRepository;
use edumdns_db::repositories::packet::models::{PacketDisplay, SelectManyPackets};
use edumdns_db::repositories::packet::repository::PgPacketRepository;
use edumdns_db::repositories::user::repository::PgUserRepository;
use hickory_proto::op::Message;
use hickory_proto::serialize::binary::BinDecodable;
use std::collections::HashMap;
use log::{error, warn};

/// Lists all packets with filtering and pagination.
///
/// Retrieves packets accessible to the authenticated user, applies filters from query parameters,
/// and renders them in a paginated list view.
///
/// # Arguments
///
/// * `request` - HTTP request for template name detection
/// * `identity` - Optional user identity (required for access)
/// * `packet_repo` - Packet repository for database operations
/// * `user_repo` - User repository for user information
/// * `state` - Application state containing template engine
/// * `query` - Query parameters for filtering and pagination
///
/// # Returns
///
/// Returns an HTML response with the packet list page, or redirects to login if not authenticated.
#[get("")]
pub async fn get_packets(
    request: HttpRequest,
    identity: Option<Identity>,
    packet_repo: web::Data<PgPacketRepository>,
    user_repo: web::Data<PgUserRepository>,
    state: web::Data<AppState>,
    query: web::Query<PacketQuery>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let user_id = parse_user_id(&i)?;
    let user = user_repo.read_one(&user_id).await?;
    validate_has_groups(&user)?;
    let page = query.page.unwrap_or(1);
    let query = query.into_inner();
    let params = SelectManyPackets::from(query.clone());
    let packets = packet_repo.read_many_auth(&params, &user_id).await?;
    let packet_count = packet_repo.get_packet_count(params, &user_id).await?;
    let total_pages = (packet_count as f64 / PAGINATION_ELEMENTS_PER_PAGE as f64).ceil() as i64;
    let packets_parsed = packets
        .into_iter()
        .map(PacketDisplay::from)
        .filter_map(Result::ok)
        .collect();

    let template_name = get_template_name(&request, "packet");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let query_string = request.uri().query().unwrap_or("").to_string();
    let body = template.render(PacketTemplate {
        user,
        packets: &packets_parsed,
        page_info: PageInfo::new(page, total_pages),
        filters: query,
        query_string,
    })?;

    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}

/// Displays detailed information about a specific packet.
///
/// Shows packet metadata, payload, and associated device information. The user must have
/// permission to view the packet.
///
/// # Arguments
///
/// * `request` - HTTP request for template name detection
/// * `identity` - Optional user identity (required for access)
/// * `packet_repo` - Packet repository for database operations
/// * `device_repo` - Device repository for finding associated device
/// * `user_repo` - User repository for user information
/// * `state` - Application state containing template engine
/// * `path` - Path parameter containing packet ID
///
/// # Returns
///
/// Returns an HTML response with the packet detail page, or an error if the packet is not found
/// or the user lacks permission.
#[get("{id}")]
pub async fn get_packet(
    request: HttpRequest,
    identity: Option<Identity>,
    packet_repo: web::Data<PgPacketRepository>,
    device_repo: web::Data<PgDeviceRepository>,
    user_repo: web::Data<PgUserRepository>,
    state: web::Data<AppState>,
    path: web::Path<(Id,)>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let user_id = parse_user_id(&i)?;
    let packet = packet_repo.read_one_auth(&path.0, &user_id).await?;
    let user = user_repo.read_one(&user_id).await?;
    let params = SelectSingleDevice::new(
        packet.data.probe_id,
        packet.data.src_mac,
        packet.data.src_addr,
    );

    let device_id = device_repo.read_one(&params).await.ok().map(|d| d.id);

    let template_name = get_template_name(&request, "packet/detail");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let body = template.render(PacketDetailTemplate {
        user,
        permissions: packet.permissions,
        packet: &PacketDisplay::from(packet.data)?,
        device_id,
    })?;

    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}

/// Deletes a packet from the database.
///
/// Removes a packet record. The user must have permission to delete the packet.
///
/// # Arguments
///
/// * `request` - HTTP request
/// * `identity` - Optional user identity (required for access)
/// * `packet_repo` - Packet repository for database operations
/// * `path` - Path parameter containing packet ID
/// * `query` - Query parameters containing optional return URL
///
/// # Returns
///
/// Returns a redirect response to the return URL (or packet list) after deletion.
#[delete("{id}/delete")]
pub async fn delete_packet(
    request: HttpRequest,
    identity: Option<Identity>,
    packet_repo: web::Data<PgPacketRepository>,
    path: web::Path<(Id,)>,
    query: web::Query<HashMap<String, String>>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let user_id = parse_user_id(&i)?;

    let return_url = query
        .get("return_url")
        .map(String::as_str)
        .unwrap_or("/packet");

    packet_repo.delete_auth(&path.0, &user_id).await?;
    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, return_url))
        .finish())
}

/// Creates a new packet in the database.
///
/// Creates a packet record manually. This is useful for testing or adding custom packets
/// that weren't captured by probes.
///
/// # Arguments
///
/// * `request` - HTTP request
/// * `identity` - Optional user identity (required for access)
/// * `packet_repo` - Packet repository for database operations
/// * `form` - JSON form data containing packet information
///
/// # Returns
///
/// Returns a redirect response to the newly created packet's detail page.
#[post("create")]
pub async fn create_packet(
    request: HttpRequest,
    identity: Option<Identity>,
    packet_repo: web::Data<PgPacketRepository>,
    form: web::Json<CreatePacketForm>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let params = form.into_inner().to_db_params()?;
    let packet = packet_repo
        .create_auth(&params, &parse_user_id(&i)?)
        .await?;
    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, format!("/packet/{}", packet.id)))
        .finish())
}

/// Updates packet metadata.
///
/// Modifies packet properties such as source/destination ports and addresses.
/// The user must have permission to update the packet.
///
/// # Arguments
///
/// * `request` - HTTP request
/// * `identity` - Optional user identity (required for access)
/// * `packet_repo` - Packet repository for database operations
/// * `form` - Form data containing updated packet information
///
/// # Returns
///
/// Returns a redirect response to the packet detail page after updating.
#[post("update")]
pub async fn update_packet(
    request: HttpRequest,
    identity: Option<Identity>,
    packet_repo: web::Data<PgPacketRepository>,
    form: web::Form<UpdatePacketForm>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let params = form.into_inner().to_db_params();
    packet_repo
        .update_auth(&params, &parse_user_id(&i)?)
        .await?;

    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, format!("/packet/{}", params.id)))
        .finish())
}

/// Reassigns a packet to a different device.
///
/// Changes the probe, MAC address, and IP address association of a packet to match
/// a different device. This is useful when packets were incorrectly associated.
///
/// # Arguments
///
/// * `request` - HTTP request
/// * `identity` - Optional user identity (required for access)
/// * `packet_repo` - Packet repository for database operations
/// * `device_repo` - Device repository for retrieving device information
/// * `form` - Form data containing packet ID and target device ID
///
/// # Returns
///
/// Returns a redirect response to the packet detail page after reassignment.
#[post("reassign")]
pub async fn reassign_packet(
    request: HttpRequest,
    identity: Option<Identity>,
    packet_repo: web::Data<PgPacketRepository>,
    device_repo: web::Data<PgDeviceRepository>,
    form: web::Form<ReassignPacketForm>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);

    let device = device_repo.read_one(&form.device_id).await?;

    let params = form
        .into_inner()
        .to_db_params(device.probe_id, device.mac, device.ip);
    packet_repo
        .update_auth(&params, &parse_user_id(&i)?)
        .await?;

    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, format!("/packet/{}", params.id)))
        .finish())
}

/// Displays the packet creation form.
///
/// Shows a form for creating a new packet, optionally pre-filled with device information
/// from query parameters.
///
/// # Arguments
///
/// * `request` - HTTP request for template name detection
/// * `identity` - Optional user identity (required for access)
/// * `state` - Application state containing template engine
/// * `user_repo` - User repository for user information
/// * `query` - Query parameters containing optional device information (probe ID, IP, MAC, port)
///
/// # Returns
///
/// Returns an HTML response with the packet creation form.
#[get("create")]
pub async fn create_packet_form(
    request: HttpRequest,
    identity: Option<Identity>,
    state: web::Data<AppState>,
    user_repo: web::Data<PgUserRepository>,
    query: web::Query<PacketDeviceDataForm>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let user_id = parse_user_id(&i)?;
    let user = user_repo.read_one(&user_id).await?;
    validate_has_groups(&user)?;
    let template_name = get_template_name(&request, "packet/create");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let body = template.render(PacketCreateTemplate {
        user,
        probe_id: query.probe_id,
        ip: query.ip,
        mac: query.mac,
        port: query.port,
    })?;
    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}

/// Updates the DNS payload of a packet.
///
/// Modifies the DNS message content of a packet. The payload must be a valid DNS message.
/// The user must have permission to update the packet.
///
/// # Arguments
///
/// * `request` - HTTP request
/// * `identity` - Optional user identity (required for access)
/// * `packet_repo` - Packet repository for database operations
/// * `form` - JSON form data containing packet ID and new DNS payload
///
/// # Returns
///
/// Returns a redirect response to the packet detail page after updating the payload.
#[post("update-payload")]
pub async fn update_packet_payload(
    request: HttpRequest,
    identity: Option<Identity>,
    packet_repo: web::Data<PgPacketRepository>,
    form: String,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let form = serde_json::from_str::<UpdatePacketPayloadForm>(&form)?;
    let params = form.to_db_params()?;
    packet_repo
        .update_auth(&params, &parse_user_id(&i)?)
        .await?;

    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, format!("/packet/{}", params.id)))
        .finish())
}

/// Displays the packet payload editing form.
///
/// Shows a form for editing the DNS payload of a packet. The current payload is parsed
/// and displayed as JSON for editing.
///
/// # Arguments
///
/// * `request` - HTTP request for template name detection
/// * `identity` - Optional user identity (required for access)
/// * `state` - Application state containing template engine
/// * `packet_repo` - Packet repository for database operations
/// * `user_repo` - User repository for user information
/// * `path` - Path parameter containing packet ID
///
/// # Returns
///
/// Returns an HTML response with the payload editing form, or an error if the packet is not
/// a valid DNS packet.
#[get("{id}/update-payload")]
pub async fn update_packet_payload_form(
    request: HttpRequest,
    identity: Option<Identity>,
    state: web::Data<AppState>,
    packet_repo: web::Data<PgPacketRepository>,
    user_repo: web::Data<PgUserRepository>,
    path: web::Path<(Id,)>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let user_id = parse_user_id(&i)?;
    let user = user_repo.read_one(&user_id).await?;
    let packet = packet_repo.read_one_auth(&path.0, &user_id).await?;

    let message = Message::from_bytes(&packet.data.payload)
        .map_err(|_| WebError::BadRequest("Not a DNS packet payload".to_string()))?;

    let template_name = get_template_name(&request, "packet/edit");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let msg = serde_json::to_string(&message)?;
    let body = template.render(PacketUpdatePayloadTemplate {
        user,
        id: packet.data.id,
        probe_id: packet.data.probe_id,
        ip: packet.data.src_addr,
        mac: MacAddr::from_octets(packet.data.src_mac),
        port: packet.data.dst_port as u16,
        message: msg,
    })?;
    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}
