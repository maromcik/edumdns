use crate::error::WebError;
use crate::init::{configure_webapp, run_web};
use crate::utils::{
    AppState, DeviceAclApDatabase, create_oidc, create_reloader, get_cors_middleware,
    get_identity_middleware, get_session_middleware, json_config, path_config,
    query_config,
};
use actix_multipart::form::MultipartFormConfig;
use actix_web::http::header;
use actix_web::middleware::{Logger, NormalizePath, TrailingSlash};
use actix_web::web::{FormConfig, PayloadConfig};
use actix_web::{App, HttpServer, cookie::Key};
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::deadpool::Pool;
use edumdns_server::app_packet::AppPacket;
use log::{info, warn};
use std::env;
use std::sync::Arc;
use tokio::sync::mpsc::Sender;
use edumdns_core::utils::parse_host;

pub mod error;

mod forms;
mod handlers;
mod init;
mod middleware;
mod templates;
mod utils;

const DEFAULT_HOSTNAME: &str = "localhost";
const DEFAULT_PORT: &str = "8000";
pub const SESSION_EXPIRY: i64 = 30; // days
const SECS_IN_MONTH: i64 = 60 * 60 * 24 * 30;
const SECS_IN_WEEK: u64 = 60 * 60 * 24 * 7;
const PAYLOAD_LIMIT: usize = 16 * 1024 * 1024 * 1024; // 16GiB

const FORM_LIMIT: usize = 16 * 1024 * 1024; // 16MiB

const PING_INTERVAL: u64 = 1;

pub async fn web_init(
    pool: Pool<AsyncPgConnection>,
    command_channel: Sender<AppPacket>,
) -> Result<(), WebError> {
    if let Err(e) = dotenvy::dotenv() {
        warn!("failed loading .env file: {e}");
    };

    let hostnames = parse_host(
        "EDUMDNS_WEB_HOSTNAME",
        "EDUMDNS_WEB_PORT",
        DEFAULT_HOSTNAME,
        DEFAULT_PORT,
    ).await?;


    let site_url = env::var("EDUMDNS_SITE_URL").unwrap_or(DEFAULT_HOSTNAME.to_string());
    let files_dir = env::var("EDUMDNS_FILES_DIR").unwrap_or("edumdns_web".to_string());
    let key = Key::from(
        &env::var("EDUMDNS_COOKIE_SESSION_KEY")
            .unwrap_or_default()
            .bytes()
            .collect::<Vec<u8>>(),
    );
    let use_secure_cookie = env::var("EDUMDNS_USE_SECURE_COOKIE")
        .unwrap_or("false".to_string())
        .parse::<bool>()?;

    let oidc_users_admin = env::var("EDUMDNS_OIDC_NEW_USERS_ADMIN")
        .unwrap_or("false".to_string())
        .parse::<bool>()?;

    info!("EDUMDNS_USE_SECURE_COOKIE: {}", use_secure_cookie);

    let jinja = Arc::new(create_reloader(format!("{files_dir}/templates")));
    let device_acl_ap_database = DeviceAclApDatabase {
        connection_string: env::var("EDUMDNS_ACL_AP_DATABASE_CONNECTION_STRING")
            .unwrap_or_default(),
        query: env::var("EDUMDNS_ACL_AP_DATABASE_QUERY").unwrap_or_default(),
    };
    let app_state = AppState::new(
        jinja.clone(),
        command_channel.clone(),
        device_acl_ap_database,
        use_secure_cookie,
        oidc_users_admin,
    );

    run_web(pool, hostnames, app_state, files_dir, key, site_url, use_secure_cookie).await?;

    Ok(())
}
