use crate::authorized;
use crate::error::WebError;
use crate::utils::AppState;
use actix_identity::Identity;
use actix_session::Session;
use actix_web::http::header::LOCATION;
use actix_web::{HttpRequest, HttpResponse, web};

// pub async fn get_locations(
//     request: HttpRequest,
//     identity: Option<Identity>,
//     session: Session,
//     state: web::Data<AppState>,
// ) -> Result<HttpResponse, WebError> {
//     let i = authorized!(identity, request.path());
//     let template_name = "location/index.html";
//     let env = state.jinja.acquire_env()?;
//     let template = env.get_template(&template_name)?;
//
//
// }
