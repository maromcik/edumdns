use std::net::SocketAddr;
use crate::handlers::device::{
    create_device, create_device_form, delete_device, delete_request_packet_transmit, get_device,
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
    update_packet,
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
use crate::utils::{create_oidc, get_cors_middleware, get_identity_middleware, get_session_middleware, json_config, path_config, query_config, AppState};
use actix_files::Files;
use actix_multipart::form::MultipartFormConfig;
use actix_web::{web, App, HttpServer};
use actix_web::middleware::{Logger, NormalizePath, TrailingSlash};
use actix_web::web::{FormConfig, PayloadConfig, ServiceConfig};
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::deadpool::Pool;
use log::info;
use edumdns_db::repositories::device::repository::PgDeviceRepository;
use edumdns_db::repositories::group::repository::PgGroupRepository;
use edumdns_db::repositories::location::repository::PgLocationRepository;
use edumdns_db::repositories::packet::repository::PgPacketRepository;
use edumdns_db::repositories::probe::repository::PgProbeRepository;
use edumdns_db::repositories::user::repository::PgUserRepository;
use crate::error::WebError;
use crate::{middleware, FORM_LIMIT, PAYLOAD_LIMIT};

pub fn configure_webapp(
    pool: &Pool<AsyncPgConnection>,
    app_state: AppState,
    files_dir: String,
) -> Box<dyn FnOnce(&mut ServiceConfig)> {
    let _ = PgLocationRepository::new(pool.clone());
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
        .service(create_device_form);

    let packet_scope = web::scope("packet")
        .app_data(web::Data::new(packet_repo))
        .app_data(web::Data::new(device_repo.clone()))
        .service(create_packet_form)
        .service(get_packets)
        .service(get_packet)
        .service(delete_packet)
        .service(create_packet)
        .service(update_packet)
        .service(reassign_packet);

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
            .service(Files::new("/static", format!("{files_dir}/static")).prefer_utf8(true));
    })
}


pub(crate) async fn run_web(
    pool: Pool<AsyncPgConnection>,
    hostnames: Vec<SocketAddr>,
    app_state: AppState,
    files_dir: String,
    key: actix_web::cookie::Key,
    site_url: String,
    use_secure_cookie: bool
) -> Result<(), WebError> {
    for addr in hostnames {
        let app_state_local = app_state.clone();
        let files_dir_local = files_dir.clone();
        let key_local = key.clone();
        let site_url_local = site_url.clone();
        let pool = pool.clone();

        match create_oidc().await {
            Err(e) => {
                info!("Starting the web server without OIDC support. Reason: {e}");
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
                        .wrap(get_session_middleware(key_local.clone(), use_secure_cookie))
                        .wrap(get_cors_middleware(site_url_local.as_str()))
                        .wrap(middleware::RedirectToLogin)
                        .wrap(Logger::default())
                        .configure(configure_webapp(
                            &pool,
                            app_state_local.clone(),
                            files_dir_local.clone(),
                        ))
                })
                    .bind(addr)?
                    .run()
                    .await?;
            }
            Ok(oidc) => {
                info!("Starting the web server with OIDC support");
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
                        .wrap(get_session_middleware(key_local.clone(), use_secure_cookie))
                        .wrap(get_cors_middleware(site_url_local.as_str()))
                        .wrap(oidc.get_middleware())
                        .wrap(middleware::RedirectToLogin)
                        .wrap(Logger::default())
                        .configure(oidc.configure_open_id())
                        .configure(configure_webapp(
                            &pool,
                            app_state_local.clone(),
                            files_dir_local.clone(),
                        ))
                })
                    .bind(addr)?
                    .run()
                    .await?;
            }
        }
    }
    Ok(())
}