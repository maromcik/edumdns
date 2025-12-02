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
use crate::forms::packet::{CreatePacketForm, PacketDeviceDataForm, PacketQuery, ReassignPacketForm, UpdatePacketForm, UpdatePacketPayloadForm};
use crate::handlers::utilities::{get_template_name, parse_user_id, validate_has_groups};
use crate::header::LOCATION;
use crate::templates::PageInfo;
use crate::templates::packet::{PacketCreateTemplate, PacketDetailTemplate, PacketTemplate, PacketUpdatePayloadTemplate};
use crate::utils::AppState;
use actix_identity::Identity;
use actix_web::{HttpRequest, HttpResponse, delete, get, post, web};
use edumdns_core::app_packet::Id;
use edumdns_db::repositories::common::{
    DbCreate, DbDelete, DbReadOne, PAGINATION_ELEMENTS_PER_PAGE,
};
use edumdns_db::repositories::device::models::SelectSingleDevice;
use edumdns_db::repositories::device::repository::PgDeviceRepository;
use edumdns_db::repositories::packet::models::{PacketDisplay, SelectManyPackets};
use edumdns_db::repositories::packet::repository::PgPacketRepository;
use edumdns_db::repositories::user::repository::PgUserRepository;
use std::collections::HashMap;
use hickory_proto::op::Message;
use hickory_proto::serialize::binary::BinDecodable;
use edumdns_core::bincode_types::MacAddr;

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

#[post("update-payload")]
pub async fn update_packet_payload(
    request: HttpRequest,
    identity: Option<Identity>,
    packet_repo: web::Data<PgPacketRepository>,
    form: web::Form<UpdatePacketPayloadForm>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let params = form.into_inner().to_db_params()?;
    packet_repo
        .update_auth(&params, &parse_user_id(&i)?)
        .await?;

    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, format!("/packet/{}", params.id)))
        .finish())
}


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

    let message = Message::from_bytes(&packet.data.payload)?;

    let template_name = get_template_name(&request, "packet/edit");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let body = template.render(PacketUpdatePayloadTemplate {
        user,
        probe_id: packet.data.probe_id,
        ip: packet.data.src_addr,
        mac: MacAddr::from_octets(packet.data.src_mac),
        port: packet.data.dst_port as u16,
        message
    })?;
    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}

