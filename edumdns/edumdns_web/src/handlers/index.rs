use actix_csrf::extractor::{Csrf, CsrfToken};
use crate::error::WebError;
use crate::forms::user::{UserLoginForm, UserLoginReturnURL};
use crate::handlers::utilities::{
    destroy_session, extract_referrer, get_template_name, parse_user_from_oidc, parse_user_id,
};
use crate::templates::index::IndexTemplate;
use crate::templates::user::LoginTemplate;
use crate::{AppState, SESSION_EXPIRY, authorized};
use actix_identity::Identity;
use actix_session::Session;
use actix_web::http::StatusCode;
use actix_web::http::header::LOCATION;
use actix_web::web::Redirect;
use actix_web::{HttpMessage, HttpRequest, HttpResponse, Responder, get, post, web};
use edumdns_db::error::DbError;
use edumdns_db::repositories::common::{DbCreate, DbReadOne};
use edumdns_db::repositories::user::models::UserLogin;
use edumdns_db::repositories::user::repository::PgUserRepository;
use time::{Duration, OffsetDateTime};

#[get("/")]
pub async fn index(
    request: HttpRequest,
    identity: Option<Identity>,
    user_repo: web::Data<PgUserRepository>,
    state: web::Data<AppState>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let user_id = parse_user_id(&i)?;
    let user = user_repo.read_one(&user_id).await?;
    let template_name = get_template_name(&request, "index");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let body = template.render(IndexTemplate { user })?;

    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}

#[get("/login")]
pub async fn login(
    request: HttpRequest,
    identity: Option<Identity>,
    query: web::Query<UserLoginReturnURL>,
    token: CsrfToken,
    state: web::Data<AppState>,
) -> Result<HttpResponse, WebError> {
    let return_url = query.ret.clone().unwrap_or(extract_referrer(&request));
    if identity.is_some() {
        return Ok(HttpResponse::SeeOther()
            .insert_header((LOCATION, return_url))
            .finish());
    }

    let template_name = "index/login.html";
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(template_name)?;
    let body = template.render(LoginTemplate {
        token: token.get().to_string(),
        message: String::new(),
        return_url,
    })?;
    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}

#[post("/login")]
pub async fn login_base(
    request: HttpRequest,
    user_repo: web::Data<PgUserRepository>,
    form: Csrf<web::Form<UserLoginForm>>,
    state: web::Data<AppState>,
) -> Result<impl Responder, WebError> {
    let secure_cookie = state.secure_cookie;
    match user_repo
        .login(&UserLogin::new(&form.email, &form.password))
        .await
    {
        Ok(user) => {
            Identity::login(&request.extensions(), user.id.to_string())?;
            let mut resp = HttpResponse::SeeOther();
            let c = actix_web::cookie::Cookie::build("auth", "local")
                .path("/")
                .secure(secure_cookie)
                .expires(OffsetDateTime::now_utc() + Duration::days(SESSION_EXPIRY))
                .finish();
            resp.cookie(c);
            Ok(resp
                .insert_header((LOCATION, form.return_url.clone()))
                .finish())
        }
        Err(db_error) => {
            if let DbError::BackendError(err) = db_error {
                let template_name = "index/login.html";
                let env = state.jinja.acquire_env()?;
                let template = env.get_template(template_name)?;
                let body = template.render(LoginTemplate {
                    token: form.csrf_token.get().to_string(),
                    message: err.to_string(),
                    return_url: form.return_url.clone(),
                })?;

                return Ok(HttpResponse::Ok().content_type("text/html").body(body));
            }

            Err(WebError::from(db_error))
        }
    }
}

#[get("/login/oidc")]
pub async fn login_oidc(
    request: HttpRequest,
    identity: Option<Identity>,
    user_repo: web::Data<PgUserRepository>,
    query: web::Query<UserLoginReturnURL>,
    state: web::Data<AppState>,
) -> Result<HttpResponse, WebError> {
    let return_url = query.ret.clone().unwrap_or(extract_referrer(&request));
    if identity.is_some() {
        return Ok(HttpResponse::SeeOther()
            .insert_header((LOCATION, return_url))
            .finish());
    }

    let secure_cookie = state.secure_cookie;
    let mut resp = HttpResponse::SeeOther();
    let c = actix_web::cookie::Cookie::build("auth", "oidc")
        .secure(secure_cookie)
        .expires(OffsetDateTime::now_utc() + Duration::days(SESSION_EXPIRY))
        .path("/")
        .finish();
    resp.cookie(c);

    let user_create = parse_user_from_oidc(&request).ok_or(WebError::CookieError(
        "Cookie or some of its fields were not found or invalid".to_string(),
    ))?;
    let user = user_repo.create(&user_create).await?;
    Identity::login(&request.extensions(), user.id.to_string())?;
    Ok(resp.insert_header((LOCATION, return_url)).finish())
}

#[get("/oidc/redirect")]
pub async fn login_oidc_redirect(
    query: web::Query<UserLoginReturnURL>,
) -> Result<HttpResponse, WebError> {
    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, format!("/login/oidc?{}", query.0)))
        .finish())
}

#[get("/logout")]
pub async fn logout(
    request: HttpRequest,
    session: Session,
    identity: Option<Identity>,
) -> Result<impl Responder, WebError> {
    destroy_session(session, identity);
    let path = if let Some(cookie) = request.cookie("auth") {
        if cookie.value() == "oidc" {
            "/logout/oidc"
        } else {
            "/login"
        }
    } else {
        "/login"
    };
    Ok(Redirect::to(path).using_status_code(StatusCode::FOUND))
}

#[get("/logout/cleanup")]
pub async fn logout_cleanup(
    session: Session,
    identity: Option<Identity>,
) -> Result<impl Responder, WebError> {
    destroy_session(session, identity);
    let mut resp = HttpResponse::Found();
    resp.insert_header((LOCATION, "/login"));

    for name in &[
        "pkce_verifier",
        "access_token",
        "id_token",
        "user_info",
        "nonce",
        "auth",
    ] {
        let c = actix_web::cookie::Cookie::build(name.to_string(), "")
            .path("/")
            .max_age(time::Duration::seconds(0))
            .finish();
        resp.cookie(c);
    }

    Ok(resp.finish())
}
