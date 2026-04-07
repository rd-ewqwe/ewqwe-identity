use actix_session::Session;
use actix_web::{HttpRequest, HttpResponse};
use tracing::debug;

use crate::AttError;

pub async fn mock_authenticate_endpoint(
    _req: HttpRequest,
    session: Session,
) -> Result<HttpResponse, AttError> {
    session
        .insert("user_id", "test_user")
        .map_err(|e| AttError::Test(e.to_string()))?;
    debug!("Mock user authenticated: test_user");
    Ok(HttpResponse::Ok().json(serde_json::json!({"status": "authenticated"})))
}
