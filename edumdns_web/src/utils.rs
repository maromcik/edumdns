use crate::error::{WebError, WebErrorKind};
use crate::{DEFAULT_HOSTNAME, DEFAULT_PORT, SECS_IN_MONTH, SECS_IN_WEEK};
use actix_cors::Cors;
use actix_identity::IdentityMiddleware;
use actix_session::SessionMiddleware;
use actix_session::config::PersistentSession;
use actix_session::storage::CookieSessionStore;
use actix_web::dev::ServiceRequest;
use actix_web::http::header;
use actix_web_openidconnect::ActixWebOpenId;
use edumdns_core::app_packet::AppPacket;
use edumdns_db::models::GroupProbePermission;
use edumdns_db::repositories::common::Permission;
use log::info;
use minijinja::{Environment, Value, path_loader};
use minijinja_autoreload::AutoReloader;
use serde::Deserialize;
use std::env;
use std::sync::Arc;
use tokio::sync::mpsc::Sender;

#[derive(Clone)]
pub struct DeviceAclApDatabase {
    pub connection_string: String,
    pub query: String,
}

#[derive(Clone)]
pub struct AppState {
    pub jinja: Arc<AutoReloader>,
    pub command_channel: Sender<AppPacket>,
    pub device_acl_ap_database: DeviceAclApDatabase,
}

impl AppState {
    pub fn new(
        jinja: Arc<AutoReloader>,
        command_channel: Sender<AppPacket>,
        device_acl_ap_database: DeviceAclApDatabase,
    ) -> Self {
        AppState {
            jinja,
            command_channel,
            device_acl_ap_database,
        }
    }
}

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

pub async fn create_oidc() -> Result<ActixWebOpenId, WebError> {
    let client_id = env::var("EDUMDNS_OIDC_CLIENT_ID").map_err(|_| {
        WebError::new(
            WebErrorKind::EnvVarError,
            "Environment variable `EDUMDNS_OIDC_CLIENT_ID` could not be loaded",
        )
    })?;
    let client_secret = env::var("EDUMDNS_OIDC_CLIENT_SECRET").map_err(|_| {
        WebError::new(
            WebErrorKind::EnvVarError,
            "Environment variable `EDUMDNS_OIDC_CLIENT_SECRET` could not be loaded",
        )
    })?;
    let callback = env::var("EDUMDNS_OIDC_CALLBACK_URL").map_err(|_| {
        WebError::new(
            WebErrorKind::EnvVarError,
            "Environment variable `EDUMDNS_OIDC_CALLBACK_URL` could not be loaded",
        )
    })?;
    let issuer = env::var("EDUMDNS_OIDC_ISSUER").map_err(|_| {
        WebError::new(
            WebErrorKind::EnvVarError,
            "Environment variable `EDUMDNS_OIDC_ISSUER` could not be loaded",
        )
    })?;

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

    ActixWebOpenId::builder(client_id, callback, issuer)
        .client_secret(client_secret)
        .logout_path("/logout/oidc")
        .should_auth(should_auth)
        .scopes(vec![
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
        ])
        .build_and_init()
        .await
        .map_err(|e| WebError::new(WebErrorKind::OidcError, e.to_string().as_str()))
}

pub fn get_cors_middleware(host: &str) -> Cors {
    Cors::default()
        .allowed_origin(format!("http://{}", host).as_str())
        .allowed_methods(vec!["GET", "POST", "PUT", "DELETE", "PATCH"])
        .allowed_headers(vec![header::AUTHORIZATION, header::ACCEPT])
        .allowed_header(header::CONTENT_TYPE)
        .supports_credentials()
        .max_age(3600)
}

pub fn get_session_middleware(
    key: actix_web::cookie::Key,
    use_secure_cookie: bool,
) -> SessionMiddleware<CookieSessionStore> {
    SessionMiddleware::builder(CookieSessionStore::default(), key.clone())
        .cookie_secure(use_secure_cookie)
        .session_lifecycle(PersistentSession::default().session_ttl(time::Duration::days(30)))
        .build()
}

pub fn get_identity_middleware() -> IdentityMiddleware {
    let login_deadline = core::time::Duration::from_secs(SECS_IN_MONTH as u64);
    let visit_deadline = core::time::Duration::from_secs(SECS_IN_WEEK);
    IdentityMiddleware::builder()
        .logout_behavior(actix_identity::config::LogoutBehavior::PurgeSession)
        .id_key("actix_identity.user_id")
        .login_unix_timestamp_key("actix_identity.last_visited_at")
        .last_visit_unix_timestamp_key("actix_identity.last_visited_at")
        .login_deadline(Some(login_deadline))
        .visit_deadline(Some(visit_deadline))
        .build()
}

pub fn parse_host() -> String {
    let hostname = env::var("EDUMDNS_WEB_HOSTNAME").unwrap_or(DEFAULT_HOSTNAME.to_string());
    let port = env::var("EDUMDNS_WEB_PORT").unwrap_or(DEFAULT_PORT.to_string());
    format!("{hostname}:{port}")
}
