//! Custom middleware for request handling and authentication.
//!
//! This module provides the `RedirectToLogin` middleware that intercepts unauthenticated
//! requests and redirects them to the login page. It allows certain paths (static files,
//! login/logout endpoints) to be accessed without authentication, and checks for
//! authentication cookies to determine if a user is logged in.

use actix_web::body::BoxBody;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready};
use actix_web::{Error, HttpResponse};
use futures_util::FutureExt;
use futures_util::future::LocalBoxFuture;
use std::future::{Ready, ready};

pub struct RedirectToLogin;

impl<S, B> Transform<S, ServiceRequest> for RedirectToLogin
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static + actix_web::body::MessageBody,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type InitError = ();
    type Transform = RedirectToLoginMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RedirectToLoginMiddleware { service }))
    }
}

pub struct RedirectToLoginMiddleware<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for RedirectToLoginMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static + actix_web::body::MessageBody,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    /// Processes a request and redirects to login if authentication is required.
    ///
    /// This function checks if the request path should be allowed without authentication
    /// (static files, login/logout paths) or if the request has authentication cookies.
    /// If neither condition is met, it redirects to the login page with a return URL.
    ///
    /// # Arguments
    ///
    /// * `req` - The incoming service request
    ///
    /// # Returns
    ///
    /// Returns a future that resolves to:
    /// - The original response if the path is public or the user is authenticated
    /// - A redirect response to `/login?ret={encoded_path}` if authentication is required
    ///
    /// # Authentication Checks
    ///
    /// The following paths are allowed without authentication:
    /// - `/static/*` - Static file serving
    /// - `/login*` - Login endpoints
    /// - `/auth_callback` - OAuth callback
    /// - `/logout*` - Logout endpoints
    /// - `/oidc*` - OIDC-related endpoints
    ///
    /// The following cookies indicate authentication:
    /// - `auth` - Authentication method cookie (local or oidc)
    /// - `id` - User identity cookie
    /// - `id_token` - OIDC identity token cookie
    fn call(&self, req: ServiceRequest) -> Self::Future {
        let path = req.path().to_string();
        if path.starts_with("/static")
            || path.starts_with("/login")
            || path.starts_with("/auth_callback")
            || path.starts_with("/logout")
            || path.starts_with("/oidc")
        {
            let fut = self.service.call(req);
            return fut
                .map(|res| res.map(|r| r.map_into_boxed_body()))
                .boxed_local();
        }

        let has_auth_cookie = req.cookie("auth").is_some();
        let has_id_cookie = req.cookie("id").is_some();
        let has_id_token = req.cookie("id_token").is_some();

        if has_auth_cookie || has_id_token || has_id_cookie {
            let fut = self.service.call(req);
            return fut
                .map(|res| res.map(|r| r.map_into_boxed_body()))
                .boxed_local();
        }

        let ret = urlencoding::encode(&path);
        let redirect = HttpResponse::SeeOther()
            .insert_header((
                actix_web::http::header::LOCATION,
                format!("/login?ret={}", ret),
            ))
            .finish();

        let srv_res = req.into_response(redirect.map_into_boxed_body());
        async { Ok(srv_res) }.boxed_local()
    }
}
