use crate::AppState;
use crate::error::WebError;
use crate::handlers::helpers::get_template_name;
use crate::templates::index::IndexTemplate;
use actix_identity::Identity;
use actix_web::{HttpRequest, HttpResponse, get, web};

#[get("/")]
pub async fn index(
    request: HttpRequest,
    identity: Option<Identity>,
    state: web::Data<AppState>,
) -> Result<HttpResponse, WebError> {
    let template_name = get_template_name(&request, "index");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;

    let body = template.render(IndexTemplate {
        logged_in: identity.is_some(),
    })?;

    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}
