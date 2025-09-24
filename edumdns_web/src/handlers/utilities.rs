use crate::MIN_PASS_LEN;
use crate::error::WebError;
use crate::utils::DeviceAclApDatabase;
use actix_identity::Identity;
use actix_session::Session;
use actix_web::HttpRequest;
use edumdns_db::repositories::common::Id;
use edumdns_db::repositories::user::models::UserCreate;
use log::error;
use regex::Regex;
use serde_json::Value;
use std::collections::HashMap;
use tokio_postgres::NoTls;

#[macro_export]
macro_rules! authorized {
    ($identity:expr, $req:expr ) => {{
        match $identity {
            None => {
                let path = format!("/login?ret={}", $req.path());
                log::debug!("Redirecting to {}", path);
                return Ok(actix_web::HttpResponse::SeeOther()
                    .insert_header((actix_web::http::header::LOCATION, path))
                    .finish());
            }
            Some(v) => v,
        }
    }};
}


pub fn validate_password(password: &str) -> bool {
    let (lower, upper, numeric, special) =
        password
            .chars()
            .fold((false, false, false, false), |(l, u, n, s), c| {
                (
                    { if c.is_lowercase() { true } else { l } },
                    { if c.is_uppercase() { true } else { u } },
                    { if c.is_numeric() { true } else { n } },
                    { if !c.is_alphanumeric() { true } else { s } },
                )
            });
    lower && upper && numeric && special && password.len() >= MIN_PASS_LEN
}

pub fn is_htmx(request: &HttpRequest) -> bool {
    request
        .headers()
        .get("HX-Request")
        .map_or(false, |v| v == "true")
}

pub async fn verify_transmit_request_client_ap(
    database_config: &DeviceAclApDatabase,
    ap_hostname_regex: &str,
    client_ip: &str,
) -> Result<bool, WebError> {
    let regex = Regex::new(ap_hostname_regex)?;
    let (client, connection) =
        tokio_postgres::connect(database_config.connection_string.as_str(), NoTls).await?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            error!("AP database connection error: {}", e);
        }
    });
    for row in client
        .query(database_config.query.as_str(), &[&client_ip])
        .await?
    {
        let ap: String = row.get(0);
        if regex.is_match(&ap) {
            return Ok(true);
        }
    }
    Ok(false)
}

pub fn parse_user_from_oidc(request: &HttpRequest) -> Option<UserCreate> {
    let cookie = request.cookie("user_info")?.value().to_string();
    let parsed_cookie: HashMap<String, Value> = serde_json::from_str(cookie.as_str()).ok()?;
    let id = parsed_cookie.get("preferred_username")?.as_str()?;
    let email = parsed_cookie.get("email")?.as_str()?;
    let name = parsed_cookie.get("given_name")?.as_str()?;
    let surname = parsed_cookie.get("family_name")?.as_str()?;
    Some(UserCreate::new_from_oidc(
        id.parse::<Id>().ok()?,
        email,
        name,
        surname,
        None,
        None,
        false,
    ))
}

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

pub fn destroy_session(session: Session, identity: Option<Identity>) {
    if let Some(u) = identity {
        u.logout();
    }
    session.purge();
}
