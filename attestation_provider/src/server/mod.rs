mod params;
pub use params::AttServerParams;
use serde::{Deserialize, Serialize};

use crate::AuthError;
mod endpoints;
mod server;
pub use server::start_att_server;

impl actix_web::ResponseError for AuthError {
    fn error_response(&self) -> actix_web::HttpResponse {
        match self {
            Self::AuthServer(_) => actix_web::HttpResponse::BadRequest().json(format!("{self}")),
            _ => actix_web::HttpResponse::InternalServerError().json(format!("{self}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Version {
    pub version: String,
}
