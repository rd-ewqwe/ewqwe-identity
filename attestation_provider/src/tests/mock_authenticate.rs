use actix_session::Session;
use actix_web::{HttpRequest, HttpResponse};

use crate::AuthError;

pub(crate) async fn mock_authenticate_endpoint(
    _req: HttpRequest,
    session: Session,
) -> Result<HttpResponse, AuthError> {
    session
        .insert("user_id", "test_user")
        .map_err(|e| AuthError::Test(e.to_string()))?;
    Ok(HttpResponse::Ok().json(serde_json::json!({"status": "authenticated"})))
}
