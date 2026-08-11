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

use crate::authorized;
use crate::error::WebError;
use crate::forms::user::{UserLoginForm, UserLoginReturnURL};
use crate::handlers::utilities::{
    destroy_session, extract_referrer, parse_user_from_oidc, parse_user_id,
};
use crate::templates::index::IndexTemplate;
use crate::utils::AppState;
use actix_identity::Identity;
use actix_session::Session;
use actix_web::http::header::LOCATION;
use actix_web::{HttpMessage, HttpRequest, HttpResponse, Responder, get, post, web};
use edumdns_db::repositories::common::{DbCreate, DbReadOne};
use edumdns_db::repositories::user::models::UserLogin;
use edumdns_db::repositories::user::repository::PgUserRepository;
use time::{Duration, OffsetDateTime};

/// Returns the current user's information for the dashboard.
///
/// The user must be authenticated.
///
/// # Arguments
///
/// * `request` - HTTP request
/// * `identity` - Optional user identity (required for access)
/// * `user_repo` - User repository for user information
///
/// # Returns
/// Returns a JSON response with the current user, or a 401 error if not authenticated.
#[get("")]
pub async fn index(
    request: HttpRequest,
    identity: Option<Identity>,
    user_repo: web::Data<PgUserRepository>,
) -> Result<HttpResponse, WebError> {
    let i = authorized!(identity, request);
    let user_id = parse_user_id(&i)?;
    let user = user_repo.read_one(&user_id).await?;

    Ok(HttpResponse::Ok().json(IndexTemplate { user }))
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
/// Returns a JSON response with the return URL on success, or a JSON error
/// with an authentication message if authentication fails.
///
/// # Errors
///
/// Returns a `WebError` if:
/// - Database operations fail
/// - Session creation fails
/// - Credentials are invalid
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
            let mut resp = HttpResponse::Ok();
            let c = actix_web::cookie::Cookie::build("auth", "local")
                .path("/")
                .secure(state.web_config.session.use_secure_cookie)
                .expires(
                    OffsetDateTime::now_utc()
                        + Duration::seconds(state.web_config.session.session_expiration as i64),
                )
                .finish();
            resp.cookie(c);
            Ok(resp.json(serde_json::json!({"return_url": form.return_url})))
        }
        Err(db_error) => Err(WebError::from(db_error)),
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
#[get("/oidc/handle")]
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

    let user_create = parse_user_from_oidc(&request, oidc_config.oidc_admin_flag.as_str()).ok_or(
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
        .insert_header((LOCATION, format!("/oidc/handle?{}", query.0)))
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
