use actix_identity::Identity;
use actix_web::{get, web, HttpRequest, HttpResponse};
use diesel_async::RunQueryDsl;
use edumdns_db::models::Probe;
use edumdns_db::repositories::common::DbReadMany;
use edumdns_db::repositories::probe::models::SelectManyFilter;
use edumdns_db::repositories::probe::repository::PgProbeRepository;
use crate::error::WebError;
use crate::handlers::helpers::get_template_name;
use crate::models::display::ProbeDisplay;
use crate::templates::probe::ProbeTemplate;
use crate::utils::AppState;

#[get("")]
pub async fn get_probes(
    request: HttpRequest,
    identity: Option<Identity>,
    probe_repo: web::Data<PgProbeRepository>,
    state: web::Data<AppState>,
) -> Result<HttpResponse, WebError> {
    let probes = probe_repo
        .read_many(&SelectManyFilter::new(None,None,None,None,None,None))
        .await?
        .into_iter()
        .map(|(l, u, p)| (l, u, ProbeDisplay::from(p)))
        .collect();

    let template_name = get_template_name(&request, "probe");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let body = template.render(ProbeTemplate {
        logged_in: identity.is_some(),
        probes
    })?;

    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}