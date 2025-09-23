use actix_identity::error::GetIdentityError;
use actix_identity::{Identity, IdentityExt};
use actix_web::FromRequest;
use actix_web::body::BoxBody;
use actix_web::http::header::LOCATION;
use actix_web::{
    Error, HttpMessage, HttpResponse,
    dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready},
};
use futures_util::future::LocalBoxFuture;
use log::{error, info};
use std::future::{Ready, ready};
use std::ops::Deref;
use std::rc::Rc;

pub struct RedirectToSelector;

impl<S, B> Transform<S, ServiceRequest> for RedirectToSelector
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static + actix_web::body::MessageBody,
{
    type Response = ServiceResponse<BoxBody>; // use BoxBody here
    type Error = Error;
    type InitError = ();
    type Transform = RedirectToSelectorMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RedirectToSelectorMiddleware { service }))
    }
}

pub struct RedirectToSelectorMiddleware<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for RedirectToSelectorMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static + actix_web::body::MessageBody,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let cookie = req.cookie("id");
        match &cookie {
            Some(i) => {
                info!("identity: {:?}", i.value());
            }
            None => {
                error!("identity error");
            }
        }

        let path = req.path();
        println!("PATH: {}", path);
        if (path.starts_with("/login")
            || path.starts_with("/logout")
            || path.starts_with("/oidc")
            || path.starts_with("/static"))
            || cookie.is_some()
        {
            let fut = self.service.call(req);
            Box::pin(async move {
                let res = fut.await?;
                Ok(res.map_into_boxed_body())
            })
        } else {
            Box::pin(async move {
                let res = HttpResponse::SeeOther()
                    .insert_header((LOCATION, format!("/login/oidc?ret={}", req.path())))
                    .finish();
                let srv_res: ServiceResponse<BoxBody> = req.into_response(res);

                Ok(srv_res)
            })
        }
    }
}
