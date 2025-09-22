use crate::error::WebError;
use crate::init::configure_webapp;
use crate::utils::{AppState, create_reloader};
use actix_cors::Cors;
use actix_identity::IdentityMiddleware;
use actix_multipart::form::MultipartFormConfig;
use actix_session::config::PersistentSession;
use actix_session::{SessionMiddleware, storage::CookieSessionStore};
use actix_web::dev::ServiceRequest;
use actix_web::http::header;
use actix_web::middleware::Logger;
use actix_web::web::{FormConfig, PayloadConfig};
use actix_web::{App, HttpServer, cookie::Key};
use actix_web_openidconnect::ActixWebOpenId;
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::deadpool::Pool;
use edumdns_core::app_packet::AppPacket;
use log::{info, warn};
use std::env;
use std::sync::Arc;
use tokio::sync::mpsc::Sender;

pub mod error;

mod forms;
mod handlers;
mod init;
mod templates;
mod utils;

const DEFAULT_HOSTNAME: &str = "localhost";
const DEFAULT_PORT: &str = "8000";
const SECS_IN_MONTH: i64 = 60 * 60 * 24 * 30;
const PAYLOAD_LIMIT: usize = 16 * 1024 * 1024 * 1024; // 16GiB

const FORM_LIMIT: usize = 16 * 1024 * 1024; // 16MiB
const MIN_PASS_LEN: usize = 6;

const PING_INTERVAL: u64 = 1;

pub async fn web_init(
    pool: Pool<AsyncPgConnection>,
    command_channel: Sender<AppPacket>,
) -> Result<(), WebError> {
    let _dir = env::temp_dir();

    let host = parse_host();
    let host2 = host.clone();

    let files_dir = env::var("EDUMDNS_FILES_DIR").unwrap_or("edumdns_web".to_string());

    let jinja = Arc::new(create_reloader(format!("{files_dir}/templates")));

    let app_state = AppState::new(jinja.clone(), command_channel.clone());

    let key = Key::from(
        &env::var("EDUMDNS_COOKIE_SESSION_KEY")
            .unwrap_or_default()
            .bytes()
            .collect::<Vec<u8>>(),
    );

    // let client_id = env::var("EDUMDNS_OIDC_CLIENT_ID")?;
    // let client_secret = env::var("EDUMDNS_OIDC_CLIENT_SECRET")?;
    // let callback = env::var("EDUMDNS_OIDC_CALLBACK_URL")?;
    // let issuer = env::var("EDUMDNS_OIDC_ISSUER")?;
    //
    // let should_auth = |req: &ServiceRequest| {
    //     !req.path().starts_with("/no_auth") && req.method() != actix_web::http::Method::OPTIONS
    // };
    //
    // let openid = ActixWebOpenId::builder(client_id, callback, issuer)
    //     .client_secret(client_secret)
    //     .should_auth(|_| true)
    //     .scopes(vec!["openid".to_string()])
    //     .build_and_init()
    //     .await
    //     .unwrap();

    let use_secure_cookie = env::var("EDUMDNS_USE_SECURE_COOKIE")
        .unwrap_or("false".to_string())
        .parse::<bool>()?;
    info!("EDUMDNS_USE_SECURE_COOKIE: {}", use_secure_cookie);

    if let Err(e) = dotenvy::dotenv() {
        warn!("failed loading .env file: {e}");
    };
    info!("starting server on {host}");

    let _ = HttpServer::new(move || {
        App::new()
            .app_data(
                MultipartFormConfig::default()
                    .total_limit(PAYLOAD_LIMIT)
                    .memory_limit(PAYLOAD_LIMIT),
            )
            .app_data(FormConfig::default().limit(FORM_LIMIT))
            .app_data(PayloadConfig::new(PAYLOAD_LIMIT))
            // .wrap(openid.get_middleware())
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
            // .configure(openid.configure_open_id())
            .configure(configure_webapp(
                &pool,
                app_state.clone(),
                files_dir.clone(),
            ))
    })
    .bind(host2)?
    .run()
    .await;
    Ok(())
}

fn parse_host() -> String {
    let hostname = env::var("EDUMDNS_WEB_HOSTNAME").unwrap_or(DEFAULT_HOSTNAME.to_string());
    let port = env::var("EDUMDNS_WEB_PORT").unwrap_or(DEFAULT_PORT.to_string());
    format!("{hostname}:{port}")
}
