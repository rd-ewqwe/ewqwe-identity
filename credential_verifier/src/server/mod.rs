mod att_server;
pub use att_server::start_att_server;

pub(crate) mod endpoints;
pub(crate) mod openid4vp_endpoints;

mod params;
pub use params::AttServerParams;

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
