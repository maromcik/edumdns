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
