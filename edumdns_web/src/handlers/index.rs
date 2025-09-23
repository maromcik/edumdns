use crate::error::{WebError, WebErrorKind};
use crate::forms::user::{UserLoginForm, UserLoginReturnURL};
use crate::handlers::utilities::{destroy_session, get_template_name, parse_user_from_oidc};
use crate::templates::index::IndexTemplate;
use crate::templates::user::LoginTemplate;
use crate::{authorized, AppState};
use actix_identity::Identity;
use actix_session::Session;
use actix_web::http::header::LOCATION;
use actix_web::http::StatusCode;
use actix_web::web::Redirect;
use actix_web::{get, post, web, HttpMessage, HttpRequest, HttpResponse, Responder};
use log::error;
use edumdns_db::repositories::common::DbCreate;
use edumdns_db::repositories::user::models::UserLogin;
use edumdns_db::repositories::user::repository::PgUserRepository;


#[get("/")]
pub async fn index(
    request: HttpRequest,
    identity: Option<Identity>,
    session: Session,
    state: web::Data<AppState>,
) -> Result<HttpResponse, WebError> {
    let _ = authorized!(identity, request.path());
    let template_name = get_template_name(&request, "index");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;

    let body = template.render(IndexTemplate {
        logged_in: true,
        is_admin: session.get::<bool>("is_admin")?.unwrap_or(false),
    })?;

    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}

#[get("/login/oidc")]
pub async fn login_oidc(
    request: HttpRequest,
    identity: Option<Identity>,
    user_repo: web::Data<PgUserRepository>,
    query: web::Query<UserLoginReturnURL>,
) -> Result<HttpResponse, WebError> {
    let referer = request
        .headers()
        .get(actix_web::http::header::REFERER)
        .map_or("/".to_string(), |header_value| header_value.to_str().unwrap_or("/").to_string());

    let return_url = query.ret.clone().unwrap_or(referer);
    if identity.is_some() {
        return Ok(HttpResponse::SeeOther()
            .insert_header((LOCATION, return_url))
            .finish());
    }

    let mut resp = HttpResponse::SeeOther();
    let c = actix_web::cookie::Cookie::build("auth", "oidc")
        .path("/")
        .finish();
    resp.cookie(c);
    println!("Cookie set to oidc");

    let user_create = parse_user_from_oidc(&request).ok_or(WebError::new(
        WebErrorKind::CookieError,
        "Cookie or some of its fields were not found or invalid",
    ))?;
    Identity::login(&request.extensions(), user_create.id.to_string())?;
    user_repo.create(&user_create).await?;
    Ok(resp
        .insert_header((LOCATION, return_url))
        .finish())
}

#[get("/login")]
pub async fn login(
    request: HttpRequest,
    identity: Option<Identity>,
    query: web::Query<UserLoginReturnURL>,
    state: web::Data<AppState>,
) -> Result<HttpResponse, WebError> {
    let referer = request
        .headers()
        .get(actix_web::http::header::REFERER)
        .map_or("/".to_string(), |header_value| header_value.to_str().unwrap_or("/").to_string());

    let return_url = query.ret.clone().unwrap_or(referer.to_string());
    if identity.is_some() {
        return Ok(HttpResponse::SeeOther()
            .insert_header((LOCATION, return_url))
            .finish());
    }

    let template_name = "index/login.html";
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(template_name)?;
    let body = template.render(LoginTemplate {
        message: String::new(),
        return_url,
    })?;
    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}

#[post("/login")]
pub async fn login_base(
    request: HttpRequest,
    user_repo: web::Data<PgUserRepository>,
    form: web::Form<UserLoginForm>,
    session: Session,
    state: web::Data<AppState>,
) -> Result<impl Responder, WebError> {
    match user_repo
        .login(&UserLogin::new(&form.email, &form.password))
        .await
    {
        Ok(user) => {
            Identity::login(&request.extensions(), user.id.to_string())?;
            session.insert("is_admin", user.admin)?;
            let mut resp = HttpResponse::SeeOther();
            let c = actix_web::cookie::Cookie::build("auth", "local")
                .path("/")
                .finish();
            resp.cookie(c);
            println!("Cookie set to local");
            Ok(resp.insert_header((LOCATION, form.return_url.clone())).finish())
        }
        Err(db_error) => {
            if let edumdns_db::error::DbErrorKind::BackendError(err) = db_error.error_kind {
                let template_name = "index/login.html";
                let env = state.jinja.acquire_env()?;
                let template = env.get_template(template_name)?;
                let body = template.render(LoginTemplate {
                    message: err.to_string(),
                    return_url: form.return_url.clone(),
                })?;

                return Ok(HttpResponse::Ok().content_type("text/html").body(body));
            }

            Err(WebError::from(db_error))
        }
    }
}

#[get("/oidc/logout")]
pub async fn logout_oidc(session: Session, identity: Option<Identity>) -> Result<impl Responder, WebError> {
    destroy_session(session, identity);
    Ok(Redirect::to("/logout").using_status_code(StatusCode::FOUND))

}

#[get("/logout/local")]
pub async fn logout_base(session: Session, identity: Option<Identity>) -> Result<impl Responder, WebError> {
    destroy_session(session, identity);
    Ok(Redirect::to("/login").using_status_code(StatusCode::FOUND))
}

#[get("/logout/cleanup")]
pub async fn logout_oidc_cleanup(session: Session, identity: Option<Identity>) -> Result<impl Responder, WebError> {
    destroy_session(session, identity);
    let mut resp = HttpResponse::Found();
    resp.insert_header((LOCATION, "/login"));

    for name in &["pkce_verifier", "access_token", "id_token", "user_info", "nonce", "auth"] {
        let c = actix_web::cookie::Cookie::build(name.to_string(), "")
            .path("/")
            .max_age(time::Duration::seconds(0))
            .finish();
        resp.cookie(c);
    }

    Ok(resp.finish())
}