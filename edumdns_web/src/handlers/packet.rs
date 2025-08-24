use crate::error::WebError;
use crate::handlers::helpers::get_template_name;
use crate::models::display::PacketDisplay;
use crate::templates::packet::{PacketDetailTemplate, PacketTemplate};
use crate::utils::AppState;
use actix_identity::Identity;
use actix_web::{get, web, HttpRequest, HttpResponse};
use edumdns_db::repositories::common::{DbReadMany, DbReadOne, Id};
use edumdns_db::repositories::packet::models::SelectManyFilter;
use edumdns_db::repositories::packet::repository::PgPacketRepository;

#[get("")]
pub async fn get_packets(
    request: HttpRequest,
    identity: Option<Identity>,
    packet_repo: web::Data<PgPacketRepository>,
    state: web::Data<AppState>,
) -> Result<HttpResponse, WebError> {
    let packets = packet_repo
        .read_many(&SelectManyFilter::new(None, None, None, None, None, None, None, None))
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
    let packet = packet_repo
        .read_one(&path.0)
        .await?;

    let template_name = get_template_name(&request, "packet/detail");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let body = template.render(PacketDetailTemplate {
        logged_in: identity.is_some(),
        packet: &PacketDisplay::from(packet)?
    })?;

    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}