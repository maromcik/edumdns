use crate::authorized;
use crate::error::WebError;
use crate::forms::packet::PacketQuery;
use crate::handlers::helpers::{get_template_name, parse_user_id};
use crate::header::LOCATION;
use crate::templates::packet::{PacketDetailTemplate, PacketTemplate};
use crate::utils::AppState;
use actix_identity::Identity;
use actix_session::Session;
use actix_web::{HttpRequest, HttpResponse, get, web};
use edumdns_db::repositories::common::{DbReadMany, DbReadOne, Id, Pagination};
use edumdns_db::repositories::device::models::SelectSingleDevice;
use edumdns_db::repositories::device::repository::PgDeviceRepository;
use edumdns_db::repositories::packet::models::{PacketDisplay, SelectManyPackets};
use edumdns_db::repositories::packet::repository::PgPacketRepository;

#[get("")]
pub async fn get_packets(
    request: HttpRequest,
    identity: Option<Identity>,
    packet_repo: web::Data<PgPacketRepository>,
    state: web::Data<AppState>,
    query: web::Query<PacketQuery>,
    session: Session,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request.path());
    let packets = packet_repo
        .read_many_auth(
            &SelectManyPackets::from(query.into_inner()),
            &parse_user_id(&i)?,
        )
        .await?;
    let packets_parsed = packets
        .data
        .into_iter()
        .map(PacketDisplay::from)
        .filter_map(Result::ok)
        .collect::<Vec<PacketDisplay>>();

    let template_name = get_template_name(&request, "packet");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let body = template.render(PacketTemplate {
        logged_in: true,
        permissions: packets.permissions,
        packets: &packets_parsed,
        is_admin: session.get::<bool>("is_admin")?.unwrap_or(false),
    })?;

    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}

#[get("{id}")]
pub async fn get_packet(
    request: HttpRequest,
    identity: Option<Identity>,
    packet_repo: web::Data<PgPacketRepository>,
    device_repo: web::Data<PgDeviceRepository>,
    state: web::Data<AppState>,
    path: web::Path<(Id,)>,
    session: Session,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request.path());
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
        is_admin: session.get::<bool>("is_admin")?.unwrap_or(false),
    })?;

    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}
