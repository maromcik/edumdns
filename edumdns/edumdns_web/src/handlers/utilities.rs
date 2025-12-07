//! General utility functions for request handlers.
//!
//! This module provides various utility functions used throughout the web interface:
//! - User authentication and session management helpers
//! - Template name resolution based on HTMX requests
//! - OIDC user information parsing
//! - Access point (AP) hostname verification via external database
//! - Request header parsing and validation
//!
//! These utilities abstract common operations and provide consistent behavior
//! across all handlers.

use crate::config::ExternalAuthDatabase;
use crate::error::WebError;
use actix_identity::Identity;
use actix_session::Session;
use actix_web::HttpRequest;
use edumdns_core::app_packet::Id;
use edumdns_db::error::{BackendError, DbError};
use edumdns_db::repositories::user::models::{UserCreate, UserDisplay};
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
                return Ok(actix_web::HttpResponse::SeeOther()
                    .insert_header((actix_web::http::header::LOCATION, path))
                    .finish());
            }
            Some(v) => v,
        }
    }};
}

#[macro_export]
macro_rules! has_groups {
    ($user:expr ) => {{
        match $identity {
            None => {
                let path = format!("/login?ret={}", $req.path());
                return Ok(actix_web::HttpResponse::SeeOther()
                    .insert_header((actix_web::http::header::LOCATION, path))
                    .finish());
            }
            Some(v) => v,
        }
    }};
}

pub fn is_htmx(request: &HttpRequest) -> bool {
    request
        .headers()
        .get("HX-Request")
        .map_or(false, |v| v == "true")
}

/// Verifies that a client's access point hostname matches the required regex pattern.
///
/// This function queries an external database (typically a RADIUS database) to retrieve
/// the access point hostname associated with a client IP address. It then checks if
/// the hostname matches the configured regex pattern.
///
/// # Arguments
///
/// * `database_config` - Configuration containing database connection string and query
/// * `ap_hostname_regex` - Regular expression pattern that the AP hostname must match
/// * `client_ip` - IP address of the client requesting packet transmission
///
/// # Returns
///
/// Returns `Ok(true)` if the AP hostname matches the regex, `Ok(false)` if it doesn't
/// match or no AP is found, or a `WebError` if:
/// - Database connection fails
/// - Query execution fails
/// - Regex compilation fails
///
/// # Note
///
/// The database query should use parameterized queries with `$$1` as a placeholder
/// for the client IP address. The query should return at least one column containing
/// the AP hostname.
pub async fn verify_transmit_request_client_ap(
    database_config: &Option<ExternalAuthDatabase>,
    ap_hostname_regex: &str,
    client_ip: &str,
) -> Result<bool, WebError> {
    let Some(db_config) = database_config else {
        return Err(WebError::ApDatabaseError(
            "External AP Hostname database is not configured".to_string(),
        ));
    };
    let regex = Regex::new(ap_hostname_regex)?;
    let (client, connection) =
        tokio_postgres::connect(db_config.connection_string.as_str(), NoTls).await?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            error!("AP database connection error: {}", e);
        }
    });
    for row in client
        .query(db_config.auth_query.as_str(), &[&client_ip])
        .await?
    {
        let ap: String = row.get(0);
        if regex.is_match(&ap) {
            return Ok(true);
        }
    }
    Ok(false)
}

pub fn parse_user_from_oidc(request: &HttpRequest, admin: bool) -> Option<UserCreate> {
    let cookie = request.cookie("user_info")?.value().to_string();
    let parsed_cookie: HashMap<String, Value> = serde_json::from_str(cookie.as_str()).ok()?;
    // let id = parsed_cookie.get("preferred_username")?.as_str()?;
    let email = parsed_cookie.get("sub")?.as_str()?;
    let name = parsed_cookie.get("given_name")?.as_str()?;
    let surname = parsed_cookie.get("family_name")?.as_str()?;
    Some(UserCreate::new_from_oidc(email, name, surname, admin))
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

pub fn extract_referrer(request: &HttpRequest) -> String {
    request
        .headers()
        .get(actix_web::http::header::REFERER)
        .map_or("/".to_string(), |header_value| {
            header_value.to_str().unwrap_or("/").to_string()
        })
}

pub fn validate_has_groups(user: &UserDisplay) -> Result<(), WebError> {
    if user.has_groups || user.user.admin {
        return Ok(());
    }
    Err(DbError::from(BackendError::PermissionDenied(
        "User is not assigned to any group".to_string(),
    ))
    .into())
}
