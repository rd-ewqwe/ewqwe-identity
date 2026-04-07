use crate::{
    AttResult,
    tests::{start_default_test_server, test_client::TestClient},
};
use serde_json::json;

#[actix_web::test]
async fn test_verify_endpoint_requires_client_certificate() -> AttResult<()> {
    let ctx = start_default_test_server().await?;

    let client = TestClient::new(&ctx.base_url())?;
    let response = client
        .post_raw("/api/verify", &json!({ "vp_token": "{}" }))
        .await?;

    assert_eq!(
        response.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "Expected /api/verify to reject requests without client certificate"
    );

    ctx.stop_server().await?;
    Ok(())
}

#[actix_web::test]
async fn test_verify_endpoint_accepts_valid_client_certificate() -> AttResult<()> {
    let ctx = start_default_test_server().await?;

    let client = TestClient::new_with_user1_cert(&ctx.base_url())?;
    let response = client
        .post_raw("/api/verify", &json!({ "vp_token": "{}" }))
        .await?;

    assert_ne!(
        response.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "Expected /api/verify to pass mTLS middleware when a valid client certificate is provided"
    );

    assert_eq!(
        response.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "Expected bad request because vp_token is intentionally invalid once auth passes"
    );

    ctx.stop_server().await?;
    Ok(())
}
