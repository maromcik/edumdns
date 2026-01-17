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

/// Checks if the request is from HTMX (Hypermedia Transfer).
///
/// HTMX requests include a special `HX-Request` header. This function checks for
/// the presence of this header to determine if the request is from HTMX, which
/// is used to determine which template to render (content fragment vs full page).
///
/// # Arguments
///
/// * `request` - HTTP request to check
///
/// # Returns
///
/// Returns `true` if the request includes the `HX-Request: true` header, `false` otherwise.
pub fn is_htmx(request: &HttpRequest) -> bool {
    request
        .headers()
        .get("HX-Request")
        .is_some_and(|v| v == "true")
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

/// Parses user information from OIDC authentication cookies.
///
/// Extracts user information (email, name, surname) from the OIDC `user_info` cookie
/// and creates a `UserCreate` structure. The email is taken from the `sub` claim,
/// which is the OIDC subject identifier.
///
/// # Arguments
///
/// * `request` - HTTP request containing OIDC cookies
/// * `admin` - Whether the new user should have administrator privileges
///
/// # Returns
///
/// Returns `Some(UserCreate)` if the OIDC cookie is present and contains valid user
/// information, or `None` if:
/// - The `user_info` cookie is missing
/// - The cookie cannot be parsed as JSON
/// - Required fields (`sub`, `given_name`, `family_name`) are missing
///
/// # Note
///
/// This function is used during OIDC authentication flow to create or update user
/// accounts based on information from the identity provider.
pub fn parse_user_from_oidc(request: &HttpRequest, admin: bool) -> Option<UserCreate> {
    let cookie = request.cookie("user_info")?.value().to_string();
    let parsed_cookie: HashMap<String, Value> = serde_json::from_str(cookie.as_str()).ok()?;
    // let id = parsed_cookie.get("preferred_username")?.as_str()?;
    let email = parsed_cookie.get("sub")?.as_str()?;
    let name = parsed_cookie.get("given_name")?.as_str()?;
    let surname = parsed_cookie.get("family_name")?.as_str()?;
    Some(UserCreate::new_from_oidc(email, name, surname, admin))
}

/// Determines the template name based on request type and base path.
///
/// Returns different template paths depending on whether the request is from HTMX:
/// - HTMX requests: `{path}/content.html` (fragment for partial page updates)
/// - Regular requests: `{path}/page.html` (full page with layout)
///
/// This allows the same handler to serve both full pages and HTMX fragments.
///
/// # Arguments
///
/// * `request` - HTTP request to check for HTMX header
/// * `path` - Base template path (e.g., "device", "probe/detail")
///
/// # Returns
///
/// Returns a template path string:
/// - `"{path}/content.html"` for HTMX requests
/// - `"{path}/page.html"` for regular requests
///
/// # Example
///
/// ```
/// get_template_name(request, "device") // Returns "device/content.html" or "device/page.html"
/// ```
pub fn get_template_name(request: &HttpRequest, path: &str) -> String {
    if is_htmx(request) {
        format!("{path}/content.html")
    } else {
        format!("{path}/page.html")
    }
}

/// Extracts the user ID from an identity object.
///
/// Parses the user ID from the identity's ID string, which is stored as a string
/// but needs to be converted to an integer ID for database operations.
///
/// # Arguments
///
/// * `identity` - User identity object from Actix Identity middleware
///
/// # Returns
///
/// Returns `Ok(Id)` with the parsed user ID, or a `WebError` if:
/// - The identity ID is missing
/// - The ID string cannot be parsed as an integer
///
/// # Note
///
/// The identity ID is set during login and stored in the session. This function
/// is used throughout handlers to get the current user's ID for authorization checks.
pub fn parse_user_id(identity: &Identity) -> Result<Id, WebError> {
    Ok(identity.id()?.parse::<i64>()?)
}

/// Destroys a user session and logs out the identity.
///
/// This function performs complete session cleanup:
/// - Logs out the identity (if present)
/// - Purges all session data
///
/// Used during logout to ensure all authentication state is cleared.
///
/// # Arguments
///
/// * `session` - Session to destroy
/// * `identity` - Optional user identity to log out
///
/// # Note
///
/// This function does not return errors. It attempts to clean up as much as possible
/// even if some operations fail.
pub fn destroy_session(session: Session, identity: Option<Identity>) {
    if let Some(u) = identity {
        u.logout();
    }
    session.purge();
}

/// Extracts the referrer URL from the request headers.
///
/// Retrieves the `Referer` header from the request, which indicates the page
/// the user came from. This is used for redirects after login or other operations.
///
/// # Arguments
///
/// * `request` - HTTP request containing headers
///
/// # Returns
///
/// Returns the referrer URL as a string, or `"/"` if:
/// - The `Referer` header is missing
/// - The header value cannot be converted to a string
///
/// # Example
///
/// If a user clicks a link from `https://example.com/page1` to `https://example.com/page2`,
/// the referrer would be `https://example.com/page1`.
pub fn extract_referrer(request: &HttpRequest) -> String {
    request
        .headers()
        .get(actix_web::http::header::REFERER)
        .map_or("/".to_string(), |header_value| {
            header_value.to_str().unwrap_or("/").to_string()
        })
}

/// Validates that a user is assigned to at least one group or is an administrator.
///
/// This function ensures that users have the necessary permissions to access
/// certain features. Administrators bypass this check, but regular users must
/// be assigned to at least one group.
///
/// # Arguments
///
/// * `user` - User display information containing group membership status
///
/// # Returns
///
/// Returns `Ok(())` if the user is an administrator or has at least one group,
/// or a `WebError::PermissionDenied` if the user has no group assignments.
///
/// # Use Case
///
/// This validation is typically used before allowing users to:
/// - Create probes
/// - View device lists
/// - Perform other group-restricted operations
pub fn validate_has_groups(user: &UserDisplay) -> Result<(), WebError> {
    if user.has_groups || user.user.admin {
        return Ok(());
    }
    Err(DbError::from(BackendError::PermissionDenied(
        "User is not assigned to any group".to_string(),
    ))
    .into())
}
