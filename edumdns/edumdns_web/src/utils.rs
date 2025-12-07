//! Utility functions and types for the web interface.
//!
//! This module provides:
//! - Application state management (`AppState`, `DeviceAclApDatabase`)
//! - Template reloader creation with custom filters
//! - OpenID Connect (OIDC) configuration and initialization
//! - Middleware configuration (CORS, session, identity)
//! - Request parsing configuration (JSON, query, path)
//! - Hostname and port parsing from environment variables
//!
//! These utilities are used throughout the web interface to configure the server,
//! handle authentication, and provide shared state to request handlers.

use crate::config::{OidcConfig, WebConfig};
use crate::error::WebError;
use actix_cors::Cors;
use actix_identity::IdentityMiddleware;
use actix_session::SessionMiddleware;
use actix_session::config::PersistentSession;
use actix_session::storage::CookieSessionStore;
use actix_web::ResponseError;
use actix_web::dev::ServiceRequest;
use actix_web::http::header;
use actix_web::web::{FormConfig, JsonConfig, PathConfig, QueryConfig};
use actix_web_openidconnect::ActixWebOpenId;
use edumdns_db::models::GroupProbePermission;
use edumdns_db::repositories::common::Permission;
use edumdns_server::app_packet::AppPacket;
use minijinja::{Environment, Value, path_loader};
use minijinja_autoreload::AutoReloader;
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::mpsc::Sender;

#[derive(Clone)]
pub struct AppState {
    pub jinja: Arc<AutoReloader>,
    pub command_channel: Sender<AppPacket>,
    pub web_config: WebConfig,
}

impl AppState {
    pub fn new(
        jinja: Arc<AutoReloader>,
        command_channel: Sender<AppPacket>,
        web_config: WebConfig,
    ) -> Self {
        AppState {
            jinja,
            command_channel,
            web_config,
        }
    }
}

/// Creates a Minijinja template reloader with auto-reload support.
///
/// This function sets up a template environment that watches for file changes and
/// automatically reloads templates during development. It also adds a custom `has_perm`
/// filter for checking user permissions in templates.
///
/// # Arguments
///
/// * `template_path` - Directory path containing Minijinja template files
///
/// # Returns
///
/// Returns an `AutoReloader` instance that can be used to acquire template environments.
/// The reloader watches the template directory for changes and reloads templates automatically.
pub fn create_reloader(template_path: String) -> AutoReloader {
    AutoReloader::new(move |notifier| {
        let mut env = Environment::new();
        env.set_loader(path_loader(&template_path));
        env.add_filter("has_perm", has_perm);
        notifier.set_fast_reload(true);
        notifier.watch_path(&template_path, true);
        Ok(env)
    })
}

fn has_perm(perms_values: Vec<Value>, query: Value) -> Result<bool, minijinja::Error> {
    let query_perm = Permission::deserialize(query)?;
    for perm in perms_values {
        let perm = GroupProbePermission::deserialize(perm)?;
        if perm.permission == query_perm || perm.permission == Permission::Full {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Initializes and configures OpenID Connect (OIDC) authentication.
///
/// This function reads OIDC configuration from environment variables and creates an
/// `ActixWebOpenId` instance. It configures the OIDC client with the necessary scopes
/// (openid, profile, email) and sets up authentication requirements.
///
/// # Returns
///
/// Returns `Ok(ActixWebOpenId)` if all required environment variables are present and
/// OIDC initialization succeeds, or a `WebError` if configuration is missing or invalid.
///
/// # Environment Variables
///
/// This function requires the following environment variables:
/// - `EDUMDNS_OIDC_CLIENT_ID` - OIDC client ID from the identity provider
/// - `EDUMDNS_OIDC_CLIENT_SECRET` - OIDC client secret from the identity provider
/// - `EDUMDNS_OIDC_CALLBACK_URL` - Callback URL for OIDC authentication flow
/// - `EDUMDNS_OIDC_ISSUER` - Base URL of the OIDC identity provider
///
/// # Authentication Logic
///
/// The function configures a `should_auth` callback that determines which requests require
/// OIDC authentication:
/// - Static files, login, and logout paths are excluded
/// - Requests with `auth=local` cookie use local authentication
/// - Requests with `auth=oidc` cookie require OIDC authentication
/// - All other requests require OIDC authentication
///
/// # Note
///
/// If this function returns an error, the web server will start without OIDC support
/// and use local authentication only.
pub async fn create_oidc(oidc_config: &Option<OidcConfig>) -> Result<ActixWebOpenId, WebError> {
    let oidc_config = oidc_config
        .clone()
        .ok_or_else(|| WebError::OidcError("required OIDC parameters are missing".to_string()))?;
    let should_auth = |req: &ServiceRequest| {
        let path = req.path();
        if path.starts_with("/static") {
            return false;
        }
        if path.starts_with("/login") {
            return false;
        }
        if path.starts_with("/logout") {
            return false;
        }

        if let Some(cookie) = req.request().cookie("auth") {
            if cookie.value() == "local" {
                return false;
            }
            if cookie.value() == "oidc" {
                return true;
            }
        }
        true
    };

    ActixWebOpenId::builder(
        oidc_config.client_id,
        oidc_config.callback_url,
        oidc_config.issuer,
    )
    .client_secret(oidc_config.client_secret)
    .logout_path("/logout/oidc")
    .should_auth(should_auth)
    .scopes(vec![
        "openid".to_string(),
        "profile".to_string(),
        "email".to_string(),
    ])
    .build_and_init()
    .await
    .map_err(|e| WebError::OidcError(e.to_string()))
}

/// Creates CORS middleware configured for the application.
///
/// This function sets up Cross-Origin Resource Sharing (CORS) to allow requests from
/// the configured site URL. It permits common HTTP methods and headers needed for the
/// web interface.
///
/// # Arguments
///
/// * `host` - The hostname or base URL of the application (from `EDUMDNS_SITE_URL`)
///
/// # Returns
///
/// Returns a configured `Cors` middleware instance that:
/// - Allows requests from `http://{host}`
/// - Permits GET, POST, PUT, DELETE, and PATCH methods
/// - Allows Authorization, Accept, and Content-Type headers
/// - Supports credentials (cookies, authorization headers)
/// - Sets a max age of 3600 seconds for preflight requests
pub fn get_cors_middleware(host: &str) -> Cors {
    Cors::default()
        .allowed_origin(format!("http://{}", host).as_str())
        .allowed_methods(vec!["GET", "POST", "PUT", "DELETE", "PATCH"])
        .allowed_headers(vec![header::AUTHORIZATION, header::ACCEPT])
        .allowed_header(header::CONTENT_TYPE)
        .supports_credentials()
        .max_age(3600)
}

/// Creates session middleware for cookie-based session management.
///
/// This function configures session middleware that stores session data in encrypted
/// cookies. Sessions persist across requests and can be configured with secure flags
/// and expiry times.
///
/// # Arguments
///
/// * `key` - Secret key for encrypting and signing session cookies
/// * `use_secure_cookie` - If true, cookies are only sent over HTTPS connections
/// * `session_expiry` - Session time-to-live in seconds
///
/// # Returns
///
/// Returns a configured `SessionMiddleware` that:
/// - Uses `CookieSessionStore` for client-side session storage
/// - Encrypts session data with the provided key
/// - Sets secure flag based on `use_secure_cookie`
/// - Expires sessions after `session_expiry` seconds
pub fn get_session_middleware(
    key: String,
    use_secure_cookie: bool,
    session_expiry: u64,
) -> SessionMiddleware<CookieSessionStore> {
    let key = actix_web::cookie::Key::from(&*key.bytes().collect::<Vec<u8>>());
    SessionMiddleware::builder(CookieSessionStore::default(), key.clone())
        .cookie_secure(use_secure_cookie)
        .session_lifecycle(
            PersistentSession::default()
                .session_ttl(time::Duration::seconds(session_expiry as i64)),
        )
        .build()
}

/// Creates identity middleware for user authentication tracking.
///
/// This function configures middleware that tracks user identity across requests.
/// It manages login deadlines and visit deadlines to automatically expire inactive sessions.
///
/// # Arguments
///
/// * `session_expiry` - Maximum session lifetime in seconds from login time
/// * `last_visit` - Maximum time in seconds a session can remain inactive
///
/// # Returns
///
/// Returns a configured `IdentityMiddleware` that:
/// - Tracks user identity using the `actix_identity.user_id` session key
/// - Records last visit timestamp in `actix_identity.last_visited_at`
/// - Expires sessions after `session_expiry` seconds from login
/// - Expires sessions after `last_visit` seconds of inactivity
/// - Purges session data on logout
pub fn get_identity_middleware(session_expiry: u64, last_visit: u64) -> IdentityMiddleware {
    let login_deadline = core::time::Duration::from_secs(session_expiry);
    let visit_deadline = core::time::Duration::from_secs(last_visit);
    IdentityMiddleware::builder()
        .logout_behavior(actix_identity::config::LogoutBehavior::PurgeSession)
        .id_key("actix_identity.user_id")
        .login_unix_timestamp_key("actix_identity.last_visited_at")
        .last_visit_unix_timestamp_key("actix_identity.last_visited_at")
        .login_deadline(Some(login_deadline))
        .visit_deadline(Some(visit_deadline))
        .build()
}

pub fn json_config() -> JsonConfig {
    JsonConfig::default().error_handler(|err, _req| {
        let web_error = WebError::ParseError(err.to_string());
        actix_web::error::InternalError::from_response(err, web_error.error_response()).into()
    })
}

pub fn query_config() -> QueryConfig {
    QueryConfig::default().error_handler(|err, _req| {
        let web_error = WebError::ParseError(err.to_string());
        actix_web::error::InternalError::from_response(err, web_error.error_response()).into()
    })
}

pub fn form_config() -> FormConfig {
    FormConfig::default().error_handler(|err, _req| {
        let web_error = WebError::ParseError(err.to_string());
        actix_web::error::InternalError::from_response(err, web_error.error_response()).into()
    })
}

pub fn path_config() -> PathConfig {
    PathConfig::default().error_handler(|err, _req| {
        let web_error = WebError::ParseError(err.to_string());
        actix_web::error::InternalError::from_response(err, web_error.error_response()).into()
    })
}
