use actix_files::Files;
use crate::utils::AppState;
use crate::handlers::index::{index};
use actix_web::web;
use actix_web::web::ServiceConfig;
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::deadpool::Pool;
use edumdns_db::repositories::device::repository::PgDeviceRepository;
use edumdns_db::repositories::location::repository::PgLocationRepository;
use edumdns_db::repositories::packet::repository::PgPacketRepository;
use edumdns_db::repositories::probe::repository::PgProbeRepository;
use crate::handlers::device::get_devices;
use crate::handlers::packet::{get_packet, get_packets};
use crate::handlers::probe::get_probes;

pub fn configure_webapp(
    pool: &Pool<AsyncPgConnection>,
    app_state: AppState,
) -> Box<dyn FnOnce(&mut ServiceConfig)> {
    let location_repo = PgLocationRepository::new(pool.clone());
    let probe_repo = PgProbeRepository::new(pool.clone());
    let device_repo = PgDeviceRepository::new(pool.clone());
    let packet_repo = PgPacketRepository::new(pool.clone());
    
    
    let user_scope = web::scope("user");
    let probe_scope = web::scope("probe")
        .app_data(web::Data::new(probe_repo))
        .service(get_probes);

    let device_scope = web::scope("device")
        .app_data(web::Data::new(device_repo))
        .service(get_devices);

    let packet_scope = web::scope("packet")
        .app_data(web::Data::new(packet_repo))
        .service(get_packets)
        .service(get_packet);

    Box::new(move |cfg: &mut ServiceConfig| {
        cfg.app_data(web::Data::new(app_state))
            .service(index)
            .service(probe_scope)
            .service(device_scope)
            .service(packet_scope)
            .service(Files::new("/static", "./edumdns_web/static").prefer_utf8(true))
            .service(Files::new("/", "./edumdns_web/webroot").prefer_utf8(true));
    })
}
