use crate::{
    AttResult,
    tests::{make_test_server_params, start_test_server, start_default_test_server, test_client::TestClient},
};
use serde_json::json;

#[actix_web::test]
async fn test_verify_endpoint_requires_client_certificate() -> AttResult<()> {
    let ctx = start_default_test_server().await?;

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
    let ctx = start_default_test_server().await?;

    let client = TestClient::new_with_user1_cert(&ctx.base_url())?;
    let response = client
        .post_raw("/ewqwe_api/verify", &json!({ "vp_token": "{}" }))
        .await?;

    assert_ne!(
        response.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "Expected /ewqwe_api/verify to pass mTLS middleware when a valid client certificate is provided"
    );

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
    let server_params = make_test_server_params(true, "test");
    let ctx = start_test_server(server_params).await?;

    let client = TestClient::new(&ctx.base_url())?;
    let response = client
        .post_raw("/ewqwe_api/verify", &json!({ "vp_token": "{}" }))
        .await?;

    assert_ne!(
        response.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "Expected /ewqwe_api/verify to not require mTLS when disable_authentication is true"
    );

    ctx.stop_server().await?;
    Ok(())
}
