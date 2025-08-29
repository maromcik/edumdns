use actix_files::Files;
use crate::utils::AppState;
use crate::handlers::index::{index};
use actix_web::web;
use actix_web::web::ServiceConfig;
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::deadpool::Pool;
use edumdns_db::repositories::device::repository::PgDeviceRepository;
use edumdns_db::repositories::group::repository::PgGroupRepository;
use edumdns_db::repositories::location::repository::PgLocationRepository;
use edumdns_db::repositories::packet::repository::PgPacketRepository;
use edumdns_db::repositories::probe::repository::PgProbeRepository;
use edumdns_db::repositories::user::repository::PgUserRepository;
use crate::handlers::device::{get_devices, get_device, device_request_packet_transmit};
use crate::handlers::group::{get_groups, get_group};
use crate::handlers::packet::{get_packet, get_packets};
use crate::handlers::probe::{adopt, forget, get_probe, get_probes, restart};
use crate::handlers::user::{login, login_user, logout_user};

pub fn configure_webapp(
    pool: &Pool<AsyncPgConnection>,
    app_state: AppState,
) -> Box<dyn FnOnce(&mut ServiceConfig)> {
    let location_repo = PgLocationRepository::new(pool.clone());
    let group_repo = PgGroupRepository::new(pool.clone());
    let user_repo = PgUserRepository::new(pool.clone());
    let probe_repo = PgProbeRepository::new(pool.clone());
    let device_repo = PgDeviceRepository::new(pool.clone());
    let packet_repo = PgPacketRepository::new(pool.clone());

    let group_scope = web::scope("group")
        .app_data(web::Data::new(group_repo))
        .service(get_groups)
        .service(get_group);


    let user_scope = web::scope("user")
        .app_data(web::Data::new(user_repo))
        .service(login)
        .service(login_user)
        .service(logout_user);

    let probe_scope = web::scope("probe")
        .app_data(web::Data::new(probe_repo))
        .service(get_probes)
        .service(get_probe)
        .service(forget)
        .service(adopt)
        .service(restart);

    let device_scope = web::scope("device")
        .app_data(web::Data::new(device_repo))
        .app_data(web::Data::new(packet_repo.clone()))
        .service(get_devices)
        .service(get_device)
        .service(device_request_packet_transmit);

    let packet_scope = web::scope("packet")
        .app_data(web::Data::new(packet_repo))
        .service(get_packets)
        .service(get_packet);

    Box::new(move |cfg: &mut ServiceConfig| {
        cfg.app_data(web::Data::new(app_state))
            .service(index)
            .service(user_scope)
            .service(probe_scope)
            .service(device_scope)
            .service(packet_scope)
            .service(group_scope)
            .service(Files::new("/static", "./edumdns_web/static").prefer_utf8(true))
            .service(Files::new("/", "./edumdns_web/webroot").prefer_utf8(true));
    })
}
