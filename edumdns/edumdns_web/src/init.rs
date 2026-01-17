//! Web server initialization and configuration.
//!
//! This module handles the setup and configuration of the Actix Web server, including:
//! - Creating and configuring the `WebSpawner` with database connections and application state
//! - Setting up route handlers for all endpoints (users, probes, devices, packets, groups)
//! - Configuring middleware (CORS, session, identity, OIDC)
//! - Starting the HTTP server with or without OIDC support
//!
//! The `WebSpawner` struct encapsulates all the configuration needed to run the web server,
//! including session keys, file directories, and middleware settings.

use crate::config::WebConfig;
use crate::error::WebError;
use crate::handlers::device::{
    create_device, create_device_form, delete_device, delete_request_packet_transmit,
    extend_custom_request_packet_transmit, extend_request_packet_transmit, get_device,
    get_device_for_transmit, get_devices, hide_device, publish_device,
    request_custom_packet_transmit, request_packet_transmit, update_device,
};
use crate::handlers::group::{
    add_group_users, create_group, delete_group, delete_group_user, get_group, get_groups,
    search_group_users, update_group,
};
use crate::handlers::index::{
    index, login, login_base, login_oidc, login_oidc_redirect, logout_cleanup,
};
use crate::handlers::packet::{
    create_packet, create_packet_form, delete_packet, get_packet, get_packets, reassign_packet,
    update_packet, update_packet_payload, update_packet_payload_form,
};
use crate::handlers::probe::{
    adopt, change_probe_permission, create_config, create_probe, delete_config, delete_probe,
    forget, get_probe, get_probe_ws, get_probes, reconnect, save_config, update_probe,
    update_probe_owner,
};
use crate::handlers::user::{
    add_user_groups, create_user, delete_user, get_user, get_users, search_user_groups,
    update_user, update_user_password, user_manage, user_manage_form_page, user_manage_password,
    user_manage_password_form,
};
use crate::middleware;
use crate::utils::{
    AppState, create_oidc, create_reloader, form_config, get_cors_middleware,
    get_identity_middleware, get_session_middleware, json_config, path_config, query_config,
};
use actix_files::Files;
use actix_multipart::form::MultipartFormConfig;
use actix_web::middleware::{Logger, NormalizePath, TrailingSlash};
use actix_web::web::{FormConfig, PayloadConfig, ServiceConfig};
use actix_web::{App, HttpServer, web};
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::deadpool::Pool;
use edumdns_core::utils::parse_tls_config;
use edumdns_db::repositories::device::repository::PgDeviceRepository;
use edumdns_db::repositories::group::repository::PgGroupRepository;
use edumdns_db::repositories::packet::repository::PgPacketRepository;
use edumdns_db::repositories::probe::repository::PgProbeRepository;
use edumdns_db::repositories::user::repository::PgUserRepository;
use edumdns_server::app_packet::AppPacket;
use log::info;
use std::sync::Arc;
use actix_csrf::CsrfMiddleware;
use actix_web::http::Method;
use rand::prelude::StdRng;
use tokio::sync::mpsc::Sender;

pub struct WebSpawner {
    pool: Pool<AsyncPgConnection>,
    app_state: AppState,
    web_config: WebConfig,
}

impl WebSpawner {
    /// Creates a new `WebSpawner` instance with configuration from `WebConfig`.
    ///
    /// This function initializes all the components needed to run the web server:
    /// - Creates the template reloader for Minijinja using the configured static files directory
    /// - Sets up the application state with command channel and web configuration
    /// - Configures session and identity middleware settings from the configuration
    ///
    /// # Arguments
    ///
    /// * `pool` - Database connection pool for repository access
    /// * `command_channel` - Channel sender for sending commands to the server component
    /// * `web_config` - Global web configuration containing all web component settings
    ///
    /// # Returns
    ///
    /// Returns a `WebSpawner` instance ready to start the web server.
    pub async fn new(
        pool: Pool<AsyncPgConnection>,
        command_channel: Sender<AppPacket>,
        web_config: WebConfig,
    ) -> Self {
        let jinja = Arc::new(create_reloader(format!(
            "{}/templates",
            web_config.static_files_dir
        )));

        let app_state = AppState::new(jinja.clone(), command_channel.clone(), web_config.clone());
        Self {
            pool,
            app_state,
            web_config,
        }
    }

    /// Configures all route handlers and scopes for the web application.
    ///
    /// This function sets up all the HTTP endpoints organized by resource type:
    /// - User management endpoints (CRUD operations, password management, group assignments)
    /// - Probe management endpoints (adoption, configuration, monitoring, reconnection)
    /// - Device management endpoints (discovery, publishing, packet transmission)
    /// - Packet management endpoints (viewing, creation, reassignment)
    /// - Group management endpoints (CRUD operations, user assignments)
    /// - Static file serving
    ///
    /// # Arguments
    ///
    /// * `pool` - Database connection pool for creating repository instances
    /// * `app_state` - Shared application state (templates, command channel, ACL config)
    /// * `files_dir` - Directory path for static files
    ///
    /// # Returns
    ///
    /// Returns a boxed closure that configures the `ServiceConfig` with all routes and handlers.
    /// The closure is called by Actix Web during application initialization.
    fn configure_webapp(
        pool: Pool<AsyncPgConnection>,
        app_state: AppState,
        files_dir: String,
    ) -> Box<dyn FnOnce(&mut ServiceConfig)> {
        let group_repo = PgGroupRepository::new(pool.clone());
        let user_repo = PgUserRepository::new(pool.clone());
        let probe_repo = PgProbeRepository::new(pool.clone());
        let device_repo = PgDeviceRepository::new(pool.clone());
        let packet_repo = PgPacketRepository::new(pool.clone());

        let group_scope = web::scope("group")
            .app_data(web::Data::new(group_repo.clone()))
            .service(get_groups)
            .service(get_group)
            .service(create_group)
            .service(delete_group)
            .service(add_group_users)
            .service(search_group_users)
            .service(delete_group_user)
            .service(update_group);

        let user_scope = web::scope("user")
            .app_data(web::Data::new(user_repo.clone()))
            .service(user_manage_form_page)
            .service(user_manage_password_form)
            .service(user_manage)
            .service(user_manage_password)
            .service(get_users)
            .service(create_user)
            .service(delete_user)
            .service(get_user)
            .service(update_user)
            .service(add_user_groups)
            .service(search_user_groups)
            .service(update_user_password);

        let probe_scope = web::scope("probe")
            .app_data(web::Data::new(probe_repo.clone()))
            .app_data(web::Data::new(group_repo.clone()))
            .app_data(web::Data::new(device_repo.clone()))
            .service(get_probes)
            .service(get_probe)
            .service(forget)
            .service(adopt)
            .service(reconnect)
            .service(save_config)
            .service(delete_config)
            .service(create_config)
            .service(change_probe_permission)
            .service(update_probe)
            .service(delete_probe)
            .service(get_probe_ws)
            .service(create_probe)
            .service(update_probe_owner);

        let device_scope = web::scope("device")
            .app_data(web::Data::new(device_repo.clone()))
            .app_data(web::Data::new(packet_repo.clone()))
            .service(get_devices)
            .service(get_device)
            .service(request_custom_packet_transmit)
            .service(delete_request_packet_transmit)
            .service(update_device)
            .service(delete_device)
            .service(request_packet_transmit)
            .service(get_device_for_transmit)
            .service(publish_device)
            .service(hide_device)
            .service(create_device)
            .service(create_device_form)
            .service(extend_request_packet_transmit)
            .service(extend_custom_request_packet_transmit);

        let packet_scope = web::scope("packet")
            .app_data(web::Data::new(packet_repo))
            .app_data(web::Data::new(device_repo.clone()))
            .service(create_packet_form)
            .service(get_packets)
            .service(get_packet)
            .service(delete_packet)
            .service(create_packet)
            .service(update_packet)
            .service(reassign_packet)
            .service(update_packet_payload)
            .service(update_packet_payload_form);

        Box::new(move |cfg: &mut ServiceConfig| {
            cfg.app_data(web::Data::new(app_state))
                .app_data(web::Data::new(user_repo.clone()))
                .service(index)
                .service(login_oidc)
                .service(login)
                .service(login_base)
                .service(login_oidc_redirect)
                .service(logout_cleanup)
                .service(user_scope)
                .service(probe_scope)
                .service(device_scope)
                .service(packet_scope)
                .service(group_scope)
                .service(Files::new("/static", format!("{files_dir}/static",)).prefer_utf8(true));
        })
    }

    /// Starts the HTTP server and begins serving requests.
    ///
    /// This function creates and configures the Actix Web `HttpServer` with all middleware
    /// and routes. It attempts to initialize OIDC support from `web_config.oidc`; if OIDC
    /// configuration is incomplete, it falls back to local authentication only.
    ///
    /// The server is configured with:
    /// - Multipart form limits from `web_config.limits.payload_limit`
    /// - Form limits from `web_config.limits.form_limit`
    /// - JSON, query, path, and form parameter parsing with custom error handlers
    /// - Path normalization (trailing slash trimming)
    /// - Identity middleware (user session tracking with expiry from config)
    /// - Session middleware (cookie-based sessions with secure flag from config)
    /// - CORS middleware (configured for the site URL from config)
    /// - OIDC middleware (if OIDC is configured)
    /// - Login redirect middleware (for unauthenticated requests)
    /// - Request logging
    /// - TLS support (if `web_config.tls` is configured)
    ///
    /// The server binds to all addresses specified in `web_config.hostnames` and supports
    /// both plain HTTP and HTTPS (when TLS is configured).
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the server runs successfully, or a `WebError` if:
    /// - The server fails to bind to any configured address
    /// - TLS configuration is invalid
    /// - The server encounters a fatal error during operation
    ///
    /// # Note
    ///
    /// This function blocks until the server is shut down. The server will run indefinitely
    /// unless interrupted by a signal or error.
    pub(crate) async fn run_web(&self) -> Result<(), WebError> {
        let app_state_local = self.app_state.clone();
        let pool_local = self.pool.clone();
        let config = self.web_config.clone();
        match create_oidc(&self.web_config.oidc).await {
            Err(e) => {
                info!("Starting the web server without OIDC support: {e}");
                let mut server = HttpServer::new(move || {
                    App::new()
                        .app_data(
                            MultipartFormConfig::default()
                                .total_limit(config.limits.payload_limit)
                                .memory_limit(config.limits.payload_limit),
                        )
                        .app_data(FormConfig::default().limit(config.limits.form_limit))
                        .app_data(PayloadConfig::new(config.limits.payload_limit))
                        .app_data(json_config())
                        .app_data(query_config())
                        .app_data(path_config())
                        .app_data(form_config())
                        .wrap(NormalizePath::new(TrailingSlash::Trim))
                        .wrap(get_identity_middleware(
                            config.session.session_expiration,
                            config.session.last_visit_deadline,
                        ))
                        .wrap(get_session_middleware(
                            config.session_cookie.clone(),
                            config.session.use_secure_cookie,
                            config.session.session_expiration,
                        ))
                        .wrap(CsrfMiddleware::<StdRng>::new().set_cookie(Method::GET, "/login"))
                        .wrap(get_cors_middleware(config.site_url.as_str()))
                        .wrap(middleware::RedirectToLogin)
                        .wrap(Logger::default())
                        .configure(Self::configure_webapp(
                            pool_local.clone(),
                            app_state_local.clone(),
                            config.static_files_dir.clone(),
                        ))
                });

                match parse_tls_config(&config.tls).await? {
                    None => {
                        for addr in config.hostnames {
                            server = server.bind(addr)?;
                        }
                    }
                    Some(tls_config) => {
                        for addr in config.hostnames {
                            server = server.bind_rustls_0_23(addr, tls_config.clone())?;
                        }
                    }
                }
                server.run().await?;
            }
            Ok(oidc) => {
                info!("Starting the web server with OIDC support");
                let mut server = HttpServer::new(move || {
                    App::new()
                        .app_data(
                            MultipartFormConfig::default()
                                .total_limit(config.limits.payload_limit)
                                .memory_limit(config.limits.payload_limit),
                        )
                        .app_data(FormConfig::default().limit(config.limits.form_limit))
                        .app_data(PayloadConfig::new(config.limits.payload_limit))
                        .app_data(json_config())
                        .app_data(query_config())
                        .app_data(path_config())
                        .app_data(form_config())
                        .wrap(NormalizePath::new(TrailingSlash::Trim))
                        .wrap(get_identity_middleware(
                            config.session.session_expiration,
                            config.session.last_visit_deadline,
                        ))
                        .wrap(get_session_middleware(
                            config.session_cookie.clone(),
                            config.session.use_secure_cookie,
                            config.session.session_expiration,
                        ))
                        .wrap(CsrfMiddleware::<StdRng>::new().set_cookie(Method::GET, "/login"))
                        .wrap(get_cors_middleware(config.site_url.as_str()))
                        .wrap(oidc.get_middleware())
                        .wrap(middleware::RedirectToLogin)
                        .wrap(Logger::default())
                        .configure(oidc.configure_open_id())
                        .configure(Self::configure_webapp(
                            pool_local.clone(),
                            app_state_local.clone(),
                            config.static_files_dir.clone(),
                        ))
                });
                match parse_tls_config(&config.tls).await? {
                    None => {
                        for addr in config.hostnames {
                            server = server.bind(addr)?;
                        }
                    }
                    Some(tls_config) => {
                        for addr in config.hostnames {
                            server = server.bind_rustls_0_23(addr, tls_config.clone())?;
                        }
                    }
                }
                server.run().await?;
            }
        }
        Ok(())
    }
}
