use crate::error::WebError;
use crate::init::configure_webapp;
use crate::utils::{
    AppState, DeviceAclApDatabase, create_oidc, create_reloader, get_cors_middleware,
    get_identity_middleware, get_session_middleware, json_config, parse_host, path_config,
    query_config,
};
use actix_cors::Cors;
use actix_identity::IdentityMiddleware;
use actix_multipart::form::MultipartFormConfig;
use actix_session::config::PersistentSession;
use actix_session::{SessionMiddleware, storage::CookieSessionStore};
use actix_web::dev::{ResourcePath, ServiceRequest};
use actix_web::http::header;
use actix_web::middleware::{Condition, Logger, NormalizePath, TrailingSlash};
use actix_web::web::{FormConfig, PayloadConfig};
use actix_web::{App, HttpServer, cookie::Key};
use actix_web_openidconnect::ActixWebOpenId;
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::deadpool::Pool;
use edumdns_core::app_packet::AppPacket;
use log::{error, info, warn};
use std::env;
use std::sync::Arc;
use tokio::sync::mpsc::Sender;

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

    let host = parse_host();
    let host2 = host.clone();
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
    );

    match create_oidc().await {
        Err(e) => {
            info!("starting server on {host} without OIDC support. Reason: {e}");
            HttpServer::new(move || {
                App::new()
                    .app_data(
                        MultipartFormConfig::default()
                            .total_limit(PAYLOAD_LIMIT)
                            .memory_limit(PAYLOAD_LIMIT),
                    )
                    .app_data(FormConfig::default().limit(FORM_LIMIT))
                    .app_data(PayloadConfig::new(PAYLOAD_LIMIT))
                    .app_data(json_config())
                    .app_data(query_config()) // <-- attach custom handler// <- important
                    .app_data(path_config()) // <-- attach custom handler// <- important
                    .wrap(NormalizePath::new(TrailingSlash::Trim))
                    .wrap(get_identity_middleware())
                    .wrap(get_session_middleware(key.clone(), use_secure_cookie))
                    .wrap(get_cors_middleware(host.as_str()))
                    // .wrap(o.get_middleware())
                    .wrap(middleware::RedirectToLogin)
                    .wrap(Logger::default())
                    // .configure(openid.configure_open_id())
                    .configure(configure_webapp(
                        &pool,
                        app_state.clone(),
                        files_dir.clone(),
                    ))
            })
            .bind(host2)?
            .run()
            .await?;
        }
        Ok(oidc) => {
            info!("starting server on {host} with OIDC support");
            HttpServer::new(move || {
                App::new()
                    .app_data(
                        MultipartFormConfig::default()
                            .total_limit(PAYLOAD_LIMIT)
                            .memory_limit(PAYLOAD_LIMIT),
                    )
                    .app_data(FormConfig::default().limit(FORM_LIMIT))
                    .app_data(PayloadConfig::new(PAYLOAD_LIMIT))
                    .app_data(json_config())
                    .app_data(query_config()) // <-- attach custom handler// <- important
                    .app_data(path_config())
                    .wrap(NormalizePath::new(TrailingSlash::Trim))
                    .wrap(get_identity_middleware())
                    .wrap(get_session_middleware(key.clone(), use_secure_cookie))
                    .wrap(get_cors_middleware(host.as_str()))
                    .wrap(oidc.get_middleware())
                    .wrap(middleware::RedirectToLogin)
                    .wrap(Logger::default())
                    .configure(oidc.configure_open_id())
                    .configure(configure_webapp(
                        &pool,
                        app_state.clone(),
                        files_dir.clone(),
                    ))
            })
            .bind(host2)?
            .run()
            .await?;
        }
    }
    Ok(())
}
