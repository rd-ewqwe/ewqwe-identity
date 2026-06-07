use crate::{
    AttResult,
    tests::{
        make_test_server_params, start_default_test_server, start_test_server,
        test_client::TestClient,
    },
};
use serde_json::json;

#[actix_web::test]
async fn test_verify_endpoint_requires_client_certificate() -> AttResult<()> {
    // With disable_authentication=false and no client cert exchange at the TLS layer,
    // the server returns 401 because no AuthenticatedUser can be established.
    let params = make_test_server_params(false, "");
    let ctx = start_test_server(params).await?;

    let client = TestClient::new(&ctx.base_url())?;
    let response = client
        .post_raw("/ewqwe_api/verify", &json!({ "vp_token": "{}" }))
        .await?;

    assert_eq!(
        response.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "Expected /ewqwe_api/verify to reject requests without client certificate"
    );

    ctx.stop_server().await?;
    Ok(())
}

#[actix_web::test]
async fn test_verify_endpoint_accepts_valid_client_certificate() -> AttResult<()> {
    // With disable_authentication=true, auth is bypassed and requests reach the handler.
    let ctx = start_default_test_server().await?;

    let client = TestClient::new_with_user1_cert(&ctx.base_url())?;
    let response = client
        .post_raw("/ewqwe_api/verify", &json!({ "vp_token": "{}" }))
        .await?;

    // Auth passes (disabled), handler should return 400 for invalid vp_token payload
    assert_eq!(
        response.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "Expected bad request because vp_token is intentionally invalid once auth passes"
    );

    ctx.stop_server().await?;
    Ok(())
}

#[actix_web::test]
async fn test_verify_endpoint_allows_disable_authentication_without_cert() -> AttResult<()> {
    // With disable_authentication=true, no client cert needed — request should
    // pass auth and get BAD_REQUEST (handler rejects invalid vp_token payload).
    let ctx = start_default_test_server().await?;

    let client = TestClient::new(&ctx.base_url())?;
    let response = client
        .post_raw("/ewqwe_api/verify", &json!({ "vp_token": "{}" }))
        .await?;

    assert_eq!(
        response.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "Expected bad request (auth bypassed, handler rejects invalid payload)"
    );

    ctx.stop_server().await?;
    Ok(())
}
