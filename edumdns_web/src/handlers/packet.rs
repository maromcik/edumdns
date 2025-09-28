use crate::authorized;
use crate::error::WebError;
use crate::forms::packet::{CreatePacketForm, PacketDeviceDataForm, PacketQuery};
use crate::handlers::utilities::{get_template_name, parse_user_id};
use crate::header::LOCATION;
use crate::templates::PageInfo;
use crate::templates::packet::{PacketCreateTemplate, PacketDetailTemplate, PacketTemplate};
use crate::utils::AppState;
use actix_identity::Identity;
use actix_web::{HttpRequest, HttpResponse, delete, get, post, web, put};
use edumdns_db::error::{BackendError, BackendErrorKind, DbError, DbErrorKind};
use edumdns_db::repositories::common::{DbCreate, DbDelete, DbReadMany, DbReadOne, Id, PAGINATION_ELEMENTS_PER_PAGE};
use edumdns_db::repositories::device::models::{CreateDevice, SelectSingleDevice};
use edumdns_db::repositories::device::repository::PgDeviceRepository;
use edumdns_db::repositories::packet::models::{CreatePacket, PacketDisplay, SelectManyPackets};
use edumdns_db::repositories::packet::repository::PgPacketRepository;
use edumdns_db::repositories::user::repository::PgUserRepository;
use hickory_proto::op::{Header, Message};
use std::collections::HashMap;
use uuid::Uuid;
use crate::forms::device::CreateDeviceForm;
use crate::templates::device::DeviceCreateTemplate;

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
    let has_groups = !user_repo.get_groups(&user_id).await?.is_empty();
    let is_admin = user_repo.read_one(&user_id).await?.admin;
    if !has_groups && !is_admin {
        return Err(DbError::new(
            DbErrorKind::BackendError(BackendError::new(
                BackendErrorKind::PermissionDenied,
                "User is not assigned to any group",
            )),
            "",
        ))?;
    }
    let page = query.page.unwrap_or(1);
    let query = query.into_inner();
    let params = SelectManyPackets::from(query.clone());
    let packets = packet_repo.read_many_auth(&params, &user_id).await?;
    let packet_count = packet_repo.get_packet_count(params).await?;
    let total_pages = (packet_count as f64 / PAGINATION_ELEMENTS_PER_PAGE as f64).ceil() as i64;
    let packets_parsed = packets
        .data
        .into_iter()
        .map(PacketDisplay::from)
        .filter_map(Result::ok)
        .collect::<Vec<PacketDisplay>>();

    let template_name = get_template_name(&request, "packet");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let query_string = request.uri().query().unwrap_or("").to_string();
    let body = template.render(PacketTemplate {
        logged_in: true,
        permissions: packets.permissions,
        packets: &packets_parsed,
        is_admin,
        has_groups,
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

    let params = SelectSingleDevice::new(
        packet.data.probe_id,
        packet.data.src_mac,
        packet.data.src_addr,
    );
    let device = device_repo.read_one_auth(&params, &user_id).await?;
    let template_name = get_template_name(&request, "packet/detail");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let body = template.render(PacketDetailTemplate {
        logged_in: true,
        permissions: packet.permissions,
        packet: &PacketDisplay::from(packet.data)?,
        device_id: device.data.id,
        is_admin: user_repo.read_one(&user_id).await?.admin,
        has_groups: !user_repo.get_groups(&user_id).await?.is_empty(),
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
    form: web::Form<CreatePacketForm>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let params = CreatePacket::from(form.into_inner());
    let packet = packet_repo
        .create_auth(&params, &parse_user_id(&i)?)
        .await?;
    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, format!("/packet/{}", packet.id)))
        .finish())
}

#[put("create")]
pub async fn create_packet_form(
    request: HttpRequest,
    identity: Option<Identity>,
    state: web::Data<AppState>,
    form: web::Form<PacketDeviceDataForm>,
) -> Result<HttpResponse, WebError> {
    let _ = authorized!(identity, request);
    let template_name = get_template_name(&request, "packet/create");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let body = template.render(PacketCreateTemplate {
        probe_id: form.probe_id,
        ip: form.ip,
        mac: form.mac,
    })?;
    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}
