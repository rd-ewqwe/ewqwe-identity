use crate::{AttError, server::Version};
use actix_session::Session;
use actix_web::{HttpRequest, HttpResponse};

pub(crate) async fn version_endpoint(
    _req: HttpRequest,
    session: Session,
) -> Result<HttpResponse, AttError> {
    let _user_id: String = session
        .get("user_id")
        .map_err(|e| AttError::Session(e.to_string()))?
        .ok_or_else(|| AttError::Session("Invalid session".to_owned()))?;
    let version = env!("CARGO_PKG_VERSION");
    let version = Version {
        version: version.to_string(),
    };
    Ok(HttpResponse::Ok().json(version))
}
