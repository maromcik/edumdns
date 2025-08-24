use crate::error::WebError;
use crate::handlers::helpers::get_template_name;
use crate::templates::device::DeviceTemplate;
use crate::utils::AppState;
use actix_identity::Identity;
use actix_web::{get, web, HttpRequest, HttpResponse};
use edumdns_db::repositories::common::DbReadMany;
use edumdns_db::repositories::device::models::SelectManyFilter;
use edumdns_db::repositories::device::repository::PgDeviceRepository;
use crate::models::display::DeviceDisplay;

#[get("")]
pub async fn get_devices(
    request: HttpRequest,
    identity: Option<Identity>,
    device_repo: web::Data<PgDeviceRepository>,
    state: web::Data<AppState>,
) -> Result<HttpResponse, WebError> {
    let devices = device_repo
        .read_many(&SelectManyFilter::new(None, None, None, None, None))
        .await?
        .into_iter()
        .map(|(p,d)| (p, DeviceDisplay::from(d)))
        .collect();

    let template_name = get_template_name(&request, "device");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let body = template.render(DeviceTemplate {
        logged_in: identity.is_some(),
        devices
    })?;

    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}