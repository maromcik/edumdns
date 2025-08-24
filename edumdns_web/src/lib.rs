use crate::error::WebError;
use crate::init::configure_webapp;
use crate::utils::{AppState, create_reloader};
use actix_cors::Cors;
use actix_identity::IdentityMiddleware;
use actix_multipart::form::MultipartFormConfig;
use actix_session::config::PersistentSession;
use actix_session::{SessionMiddleware, storage::CookieSessionStore};
use actix_web::http::header;
use actix_web::middleware::Logger;
use actix_web::web::{FormConfig, PayloadConfig};
use actix_web::{App, HttpServer, cookie::Key};
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::deadpool::Pool;
use log::{info, warn};
use std::env;
use std::sync::Arc;
use actix_web::dev::ServerHandle;

pub mod error;

mod init;
mod templates;
mod utils;
mod handlers;
mod models;

const DEFAULT_HOSTNAME: &str = "localhost";
const DEFAULT_PORT: &str = "8000";
const SECS_IN_MONTH: i64 = 60 * 60 * 24 * 30;
const PAYLOAD_LIMIT: usize = 16 * 1024 * 1024 * 1024; // 16GiB

const FORM_LIMIT: usize = 16 * 1024 * 1024; // 16MiB
const MIN_PASS_LEN: usize = 6;

pub async fn web_init(pool: Pool<AsyncPgConnection>) ->  Result<(), WebError> {
    let _dir = env::temp_dir();

    let host = parse_host();
    let host2 = host.clone();

    let jinja = Arc::new(create_reloader("edumdns_web/templates".to_owned()));

    let app_state = AppState::new(jinja.clone());

    let key = Key::from(
        &env::var("COOKIE_SESSION_KEY")
            .unwrap_or_default()
            .bytes()
            .collect::<Vec<u8>>(),
    );

    // TODO remove unwrap
    let use_secure_cookie = env::var("USE_SECURE_COOKIE")
        .unwrap_or("false".to_string())
        .parse::<bool>()?;
    info!("USE_SECURE_COOKIE: {}", use_secure_cookie);

    if let Err(e) = dotenvy::dotenv() {
        warn!("failed loading .env file: {e}");
    };
    info!("starting server on {host}");

    let server = HttpServer::new(move || {
        App::new()
            .app_data(
                MultipartFormConfig::default()
                    .total_limit(PAYLOAD_LIMIT)
                    .memory_limit(PAYLOAD_LIMIT),
            )
            .app_data(FormConfig::default().limit(FORM_LIMIT))
            .app_data(PayloadConfig::new(PAYLOAD_LIMIT))
            .wrap(IdentityMiddleware::default())
            .wrap(
                SessionMiddleware::builder(CookieSessionStore::default(), key.clone())
                    .cookie_secure(use_secure_cookie)
                    .session_lifecycle(
                        PersistentSession::default()
                            .session_ttl(actix_web::cookie::time::Duration::seconds(SECS_IN_MONTH)),
                    )
                    .build(),
            )
            .wrap(
                Cors::default()
                    .allowed_origin(format!("http://{}", host).as_str())
                    .allowed_methods(vec!["GET", "POST", "PUT", "DELETE", "PATCH"])
                    .allowed_headers(vec![header::AUTHORIZATION, header::ACCEPT])
                    .allowed_header(header::CONTENT_TYPE)
                    .supports_credentials()
                    .max_age(3600),
            )
            .wrap(Logger::default())
            .configure(configure_webapp(&pool, app_state.clone()))
    })
        .bind(host2)?
        .run()
        .await;
    Ok(())
}

fn parse_host() -> String {
    let hostname = env::var("HOSTNAME").unwrap_or(DEFAULT_HOSTNAME.to_string());
    let port = env::var("PORT").unwrap_or(DEFAULT_PORT.to_string());
    format!("{hostname}:{port}")
}
