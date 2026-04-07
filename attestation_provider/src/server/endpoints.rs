use crate::{AuthError, server::Version};
use actix_web::{HttpRequest, HttpResponse};

pub(crate) async fn version_endpoint(_req: HttpRequest) -> Result<HttpResponse, AuthError> {
    let version = env!("CARGO_PKG_VERSION");
    let version = Version {
        version: version.to_string(),
    };
    Ok(HttpResponse::Ok().json(version))
}
