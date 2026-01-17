//! Index and authentication handlers.
//!
//! This module provides HTTP handlers for:
//! - Main index page (dashboard)
//! - User login (local authentication)
//! - OpenID Connect (OIDC) authentication flow
//! - User logout and session cleanup
//!
//! These handlers manage user sessions, set authentication cookies, and handle
//! redirects after successful authentication.

use actix_csrf::extractor::CsrfToken;
use actix_csrf::extractor::Csrf;
use crate::authorized;
use crate::error::WebError;
use crate::forms::user::{UserLoginForm, UserLoginReturnURL};
use crate::handlers::utilities::{
    destroy_session, extract_referrer, get_template_name, parse_user_from_oidc, parse_user_id,
};
use crate::templates::index::{IndexTemplate, LoginTemplate};
use crate::utils::AppState;
use actix_identity::Identity;
use actix_session::Session;
use actix_web::http::header::LOCATION;
use actix_web::{HttpMessage, HttpRequest, HttpResponse, Responder, get, post, web};
use edumdns_db::error::DbError;
use edumdns_db::repositories::common::{DbCreate, DbReadOne};
use edumdns_db::repositories::user::models::UserLogin;
use edumdns_db::repositories::user::repository::PgUserRepository;
use time::{Duration, OffsetDateTime};

/// Displays the main dashboard page.
///
/// Shows the user's dashboard with an overview of the system. The user must be authenticated.
///
/// # Arguments
///
/// * `request` - HTTP request for template name detection
/// * `identity` - Optional user identity (required for access)
/// * `user_repo` - User repository for user information
/// * `state` - Application state containing template engine
///
/// # Returns
///
/// Returns an HTML response with the dashboard page, or redirects to login if not authenticated.
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

/// Displays the login page.
///
/// Shows the login form. If the user is already authenticated, redirects to the return URL
/// or the referrer. Supports both local and OIDC authentication.
///
/// # Arguments
///
/// * `request` - HTTP request for extracting referrer
/// * `identity` - Optional user identity (if already logged in)
/// * `query` - Query parameters containing optional return URL
/// * `state` - Application state containing template engine
///
/// # Returns
///
/// Returns an HTML response with the login page, or redirects if already authenticated.
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

    let env = state.jinja.acquire_env()?;
    let template = env.get_template("index/login.html")?;
    let body = template.render(LoginTemplate {
        token: token.get().to_string(),
        message: String::new(),
        return_url,
    })?;

    Ok(HttpResponse::Ok().content_type("text/html").body(body))
}

/// Handles POST requests for local user authentication.
///
/// This function processes login form submissions, validates user credentials against
/// the database, and creates a user session if authentication succeeds. It sets an
/// authentication cookie and redirects to the return URL.
///
/// # Arguments
///
/// * `request` - HTTP request containing session information
/// * `user_repo` - User repository for database operations
/// * `form` - Login form data (email, password, return URL)
/// * `state` - Application state containing session configuration
///
/// # Returns
///
/// Returns a redirect response to the return URL on success, or renders the login
/// page with an error message if authentication fails.
///
/// # Errors
///
/// Returns a `WebError` if:
/// - Database operations fail
/// - Session creation fails
/// - Template rendering fails
#[post("/login")]
pub async fn login_base(
    request: HttpRequest,
    user_repo: web::Data<PgUserRepository>,
    form: Csrf<web::Form<UserLoginForm>>,
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
                .secure(state.web_config.session.use_secure_cookie)
                .expires(
                    OffsetDateTime::now_utc()
                        + Duration::seconds(state.web_config.session.session_expiration as i64),
                )
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

/// Handles OIDC authentication callback and user creation.
///
/// This function processes OIDC authentication by extracting user information from
/// OIDC cookies, creating or retrieving a user account, and establishing a session.
/// It sets an OIDC authentication cookie and redirects to the return URL.
///
/// # Arguments
///
/// * `request` - HTTP request containing OIDC cookies and session information
/// * `identity` - Optional user identity (if already logged in)
/// * `user_repo` - User repository for database operations
/// * `query` - Query parameters containing return URL
/// * `state` - Application state containing OIDC configuration
///
/// # Returns
///
/// Returns a redirect response to the return URL on success, or a `WebError` if:
/// - User is already authenticated (redirects to return URL)
/// - OIDC cookies are missing or invalid
/// - User creation fails
/// - Session creation fails
#[get("/login/oidc")]
pub async fn login_oidc(
    request: HttpRequest,
    identity: Option<Identity>,
    user_repo: web::Data<PgUserRepository>,
    query: web::Query<UserLoginReturnURL>,
    state: web::Data<AppState>,
) -> Result<HttpResponse, WebError> {
    let Some(oidc_config) = &state.web_config.oidc else {
        return Err(WebError::OidcError(
            "OIDC is not enabled for this server".to_string(),
        ));
    };

    let return_url = query.ret.clone().unwrap_or(extract_referrer(&request));
    if identity.is_some() {
        return Ok(HttpResponse::SeeOther()
            .insert_header((LOCATION, return_url))
            .finish());
    }

    let mut resp = HttpResponse::SeeOther();
    let c = actix_web::cookie::Cookie::build("auth", "oidc")
        .secure(state.web_config.session.use_secure_cookie)
        .expires(
            OffsetDateTime::now_utc()
                + Duration::seconds(state.web_config.session.session_expiration as i64),
        )
        .path("/")
        .finish();
    resp.cookie(c);

    let user_create = parse_user_from_oidc(&request, oidc_config.new_users_admin).ok_or(
        WebError::CookieError("Cookie or some of its fields were not found or invalid".to_string()),
    )?;
    let user = user_repo.create(&user_create).await?;
    Identity::login(&request.extensions(), user.id.to_string())?;
    Ok(resp.insert_header((LOCATION, return_url)).finish())
}

/// Redirects to the OIDC login endpoint.
///
/// Intermediate redirect handler that preserves query parameters when redirecting to OIDC
/// authentication. Used as part of the OIDC authentication flow.
///
/// # Arguments
///
/// * `query` - Query parameters containing return URL
///
/// # Returns
///
/// Returns a redirect response to the OIDC login endpoint with preserved query parameters.
#[get("/oidc/redirect")]
pub async fn login_oidc_redirect(
    query: web::Query<UserLoginReturnURL>,
) -> Result<HttpResponse, WebError> {
    Ok(HttpResponse::SeeOther()
        .insert_header((LOCATION, format!("/login/oidc?{}", query.0)))
        .finish())
}

// #[get("/logout")]
// pub async fn logout(
//     request: HttpRequest,
//     session: Session,
//     identity: Option<Identity>,
// ) -> Result<impl Responder, WebError> {
//     destroy_session(session, identity);
//     let path = if let Some(cookie) = request.cookie("auth") {
//         if cookie.value() == "oidc" {
//             "/logout/oidc"
//         } else {
//             "/login"
//         }
//     } else {
//         "/login"
//     };
//     Ok(Redirect::to(path).using_status_code(StatusCode::FOUND))
// }

/// Handles user logout and session cleanup.
///
/// This function destroys the user session, logs out the identity, and clears all
/// authentication-related cookies (including OIDC cookies). It then redirects to
/// the login page.
///
/// # Arguments
///
/// * `session` - Active session to destroy
/// * `identity` - Optional user identity to log out
///
/// # Returns
///
/// Returns a redirect response to the login page after clearing all cookies.
#[get("/logout")]
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
