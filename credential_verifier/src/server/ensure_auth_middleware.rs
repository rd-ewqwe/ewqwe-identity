use crate::AuthenticatedUser;
use actix_service::{Service, Transform};
use actix_web::body::{BoxBody, EitherBody};
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::{Error, HttpMessage, HttpResponse};
use futures::{
    Future,
    future::{Ready, ok},
};
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

#[derive(Clone)]
pub struct EnsureAuth {
    disable_authentication: bool,
    disabled_authentication_user: String,
}

impl EnsureAuth {
    pub fn new(
        disable_authentication: bool,
        disabled_authentication_user: impl Into<String>,
    ) -> Self {
        EnsureAuth {
            disable_authentication,
            disabled_authentication_user: disabled_authentication_user.into(),
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for EnsureAuth
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
{
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Error = Error;
    type Transform = EnsureAuthMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(EnsureAuthMiddleware {
            service: Rc::new(service),
            disable_authentication: self.disable_authentication,
            disabled_authentication_user: self.disabled_authentication_user.clone(),
        })
    }
}

pub struct EnsureAuthMiddleware<S> {
    service: Rc<S>,
    disable_authentication: bool,
    disabled_authentication_user: String,
}

impl<S, B> Service<ServiceRequest> for EnsureAuthMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
{
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&self, ctx: &mut Context) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(ctx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = self.service.clone();
        let disable_authentication = self.disable_authentication;
        let disabled_user = self.disabled_authentication_user.clone();

        Box::pin(async move {
            let req = req;
            if disable_authentication {
                if req.extensions().get::<AuthenticatedUser>().is_none() {
                    req.extensions_mut().insert(AuthenticatedUser {
                        username: disabled_user,
                    });
                }
            } else if req.extensions().get::<AuthenticatedUser>().is_none() {
                let response =
                    req.into_response(HttpResponse::Unauthorized().body("Authentication required"));
                return Ok(response.map_into_right_body());
            }

            let res = service.call(req).await?;
            Ok(res.map_into_left_body())
        })
    }
}
