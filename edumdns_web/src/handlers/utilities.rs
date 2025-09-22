use crate::MIN_PASS_LEN;
use crate::error::WebError;
use crate::utils::DeviceAclApDatabase;
use actix_web::HttpRequest;
use log::error;
use tokio_postgres::{NoTls};
use regex::Regex;

#[macro_export]
macro_rules! authorized {
    ($e:expr, $p:expr) => {{
        match $e {
            None => {
                let path = format!("/user/login?ret={}", $p);
                return Ok(HttpResponse::SeeOther()
                    .insert_header((LOCATION, path))
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
    let (client, connection) = tokio_postgres::connect(
        database_config.connection_string.as_str(),
        NoTls,
    ).await?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            error!("AP database connection error: {}", e);
        }
    });
    for row in client.query(database_config.query.as_str(), &[&client_ip]).await? {
        let ap: String = row.get(0);
        if regex.is_match(&ap) {
            return Ok(true);
        }
    }
    Ok(false)
}
