use crate::utils::AppState;
use actix_files::Files as ActixFiles;
use actix_web::web;
use actix_web::web::ServiceConfig;
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::deadpool::Pool;

pub fn configure_webapp(pool: &Pool<AsyncPgConnection>, app_state: AppState) -> Box<dyn FnOnce(&mut ServiceConfig)> {


    let user_scope = web::scope("user");



    Box::new(move |cfg: &mut ServiceConfig| {
        cfg
            .app_data(web::Data::new(app_state))
            .service(ActixFiles::new("/media", "./media").prefer_utf8(true))
            .service(ActixFiles::new("/static", "./static").prefer_utf8(true))
            .service(ActixFiles::new("/", "./webroot").prefer_utf8(true));
    })
}
