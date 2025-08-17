use actix_identity::Identity;
use actix_web::{web, HttpRequest, HttpResponse};
use edumdns_db::repositories::common::Id;
use crate::error::WebError;
use crate::handlers::utilities::is_htmx;

pub fn get_template_name(request: &HttpRequest, path: &str) -> String {
    if is_htmx(request) {
        format!("{path}/content.html")
    } else {
        format!("{path}/page.html")
    }
}

pub fn parse_user_id(identity: &Identity) -> Result<Id, WebError> {
    Ok(identity.id()?.parse::<i64>()?)
}

