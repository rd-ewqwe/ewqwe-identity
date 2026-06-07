pub mod services;

mod start;
pub use start::start_server;

pub(crate) mod dc_api_endpoint;
mod ensure_auth_middleware;
pub(crate) mod journal_endpoints;
pub(crate) mod openid4vp_endpoints;
pub(crate) mod qr_verifier;
pub(crate) mod request_tracing_middleware;
pub(crate) mod verify_endpoint;
use crate::AttError;

pub use ensure_auth_middleware::EnsureAuth;
use serde::{Deserialize, Serialize};

impl actix_web::ResponseError for AttError {
    fn error_response(&self) -> actix_web::HttpResponse {
        match self {
            Self::BadRequest(_) => actix_web::HttpResponse::BadRequest().json(format!("{self}")),
            Self::Authentication(_) => {
                actix_web::HttpResponse::Unauthorized().json(format!("{self}"))
            }
            _ => actix_web::HttpResponse::InternalServerError().json(format!("{self}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Version {
    pub version: String,
}
