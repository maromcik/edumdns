use crate::error::{WebError, WebErrorKind};
use crate::forms::user::{UserLoginForm, UserLoginReturnURL};
use crate::handlers::utilities::{destroy_session, extract_referrer, get_template_name, parse_user_from_oidc, parse_user_id};
use crate::templates::index::IndexTemplate;
use crate::templates::user::LoginTemplate;
use crate::{AppState, authorized};
use actix_identity::Identity;
use actix_session::Session;
use actix_web::http::StatusCode;
use actix_web::http::header::LOCATION;
use actix_web::web::Redirect;
use actix_web::{HttpMessage, HttpRequest, HttpResponse, Responder, get, post, web};
use edumdns_db::repositories::common::{DbCreate, DbReadOne};
use edumdns_db::repositories::user::models::UserLogin;
use edumdns_db::repositories::user::repository::PgUserRepository;

#[get("/")]
pub async fn index(
    request: HttpRequest,
    identity: Option<Identity>,
    user_repo: web::Data<PgUserRepository>,
    state: web::Data<AppState>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let user_id = parse_user_id(&i)?;
    let template_name = get_template_name(&request, "index");
    let env = state.jinja.acquire_env()?;
    let template = env.get_template(&template_name)?;
    let body = template.render(IndexTemplate {
        logged_in: true,
        is_admin: user_repo.read_one(&user_id).await?.admin,
        has_groups: !user_repo.get_groups(&user_id).await?.is_empty(),
    })?;

    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}

#[get("/login")]
pub async fn login(
    request: HttpRequest,
    identity: Option<Identity>,
    query: web::Query<UserLoginReturnURL>,
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
    state: web::Data<AppState>,
) -> Result<impl Responder, WebError> {
    match user_repo
        .login(&UserLogin::new(&form.email, &form.password))
        .await
    {
        Ok(user) => {
            Identity::login(&request.extensions(), user.id.to_string())?;
            let mut resp = HttpResponse::SeeOther();
            let c = actix_web::cookie::Cookie::build("auth", "local")
                .path("/")
                .finish();
            resp.cookie(c);
            Ok(resp
                .insert_header((LOCATION, form.return_url.clone()))
                .finish())
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

#[get("/login/oidc")]
pub async fn login_oidc(
    request: HttpRequest,
    identity: Option<Identity>,
    user_repo: web::Data<PgUserRepository>,
    query: web::Query<UserLoginReturnURL>,
) -> Result<HttpResponse, WebError> {
    let return_url = query.ret.clone().unwrap_or(extract_referrer(&request));
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

    let user_create = parse_user_from_oidc(&request).ok_or(WebError::new(
        WebErrorKind::CookieError,
        "Cookie or some of its fields were not found or invalid",
    ))?;
    Identity::login(&request.extensions(), user_create.id.to_string())?;
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
