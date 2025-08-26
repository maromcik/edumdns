use crate::error::WebError;
use crate::forms::packet::PacketQuery;
use crate::handlers::helpers::get_template_name;
use crate::templates::packet::{PacketDetailTemplate, PacketTemplate};
use crate::utils::AppState;
use actix_identity::Identity;
use actix_web::{HttpRequest, HttpResponse, get, web};
use edumdns_db::repositories::common::{DbReadMany, DbReadOne, Id, Pagination};
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
    println!("{:?}", query);
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
    state: web::Data<AppState>,
    path: web::Path<(Id,)>,
) -> Result<HttpResponse, WebError> {
    let packet = packet_repo.read_one(&path.into_inner().0).await?;

    let template_name = get_template_name(&request, "packet/detail");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let body = template.render(PacketDetailTemplate {
        logged_in: identity.is_some(),
        packet: &PacketDisplay::from(packet)?,
    })?;

    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}
