mod start;
pub use start::start_server;

pub(crate) mod openid4vp_endpoints;
pub(crate) mod verify_endpoint;

mod params;
pub use params::ServerParams;

use crate::AttError;
use serde::{Deserialize, Serialize};

impl actix_web::ResponseError for AttError {
    fn error_response(&self) -> actix_web::HttpResponse {
        match self {
            Self::BadRequest(_) => actix_web::HttpResponse::BadRequest().json(format!("{self}")),
            _ => actix_web::HttpResponse::InternalServerError().json(format!("{self}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Version {
    pub version: String,
}
