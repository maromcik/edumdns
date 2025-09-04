use crate::error::WebError;
use crate::handlers::helpers::get_template_name;
use crate::templates::index::IndexTemplate;
use crate::{AppState, authorized};
use actix_identity::Identity;
use actix_session::Session;
use actix_web::http::header::LOCATION;
use actix_web::{HttpRequest, HttpResponse, get, web};

#[get("/")]
pub async fn index(
    request: HttpRequest,
    identity: Option<Identity>,
    session: Session,
    state: web::Data<AppState>,
) -> Result<HttpResponse, WebError> {
    let _ = authorized!(identity, request.path());

    let template_name = get_template_name(&request, "index");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;

    let body = template.render(IndexTemplate {
        logged_in: true,
        is_admin: session.get::<bool>("is_admin")?.unwrap_or(false),
    })?;

    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}
