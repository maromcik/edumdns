use crate::authorized;
use crate::error::WebError;
use crate::forms::packet::PacketQuery;
use crate::handlers::helpers::{get_template_name, parse_user_id};
use crate::header::LOCATION;
use crate::templates::packet::{PacketDetailTemplate, PacketTemplate};
use crate::utils::AppState;
use actix_identity::Identity;
use actix_web::{get, web, HttpRequest, HttpResponse};
use edumdns_db::repositories::common::{DbReadMany, DbReadOne, Id, Pagination, SelectSingleById};
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
) -> Result<HttpResponse, WebError> {
    let packets = packet_repo
        .read_many(&SelectManyPackets::new(
            query.probe_id,
            query.src_mac.map(|addr| addr.to_octets()),
            query.dst_mac.map(|addr| addr.to_octets()),
            query.src_addr,
            query.dst_addr,
            query.src_port,
            query.dst_port,
            Some(Pagination::default_pagination(query.page))))
        .await?
        .into_iter()
        .map(PacketDisplay::from)
        .filter_map(Result::ok)
        .collect::<Vec<PacketDisplay>>();

    let template_name = get_template_name(&request, "packet");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let body = template.render(PacketTemplate {
        logged_in: identity.is_some(),
        packets: &packets,
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
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request.path());
    let user_id = parse_user_id(&i)?;
    let params = SelectSingleById::new(user_id, path.0);
    let packet = packet_repo.read_one(&params).await?;

    let params = SelectSingleDevice::new_with_user_id(user_id, packet.probe_id, packet.src_mac, packet.src_addr);
    let device = device_repo.read_one(&params).await?;
    let template_name = get_template_name(&request, "packet/detail");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let body = template.render(PacketDetailTemplate {
        logged_in: true,
        packet: &PacketDisplay::from(packet)?,
    })?;

    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}
