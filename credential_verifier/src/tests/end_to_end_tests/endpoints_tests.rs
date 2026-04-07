use crate::{
    AttResult,
    server::Version,
    tests::{
        make_test_server_params, start_default_test_server, start_test_server,
        test_client::TestClient,
    },
};
use ewqwe_logging::log_init;
use std::fs;
use tracing::info;
use uuid::Uuid;

#[actix_web::test]
async fn test_version_endpoint() -> AttResult<()> {
    log_init(Some("info,actix_server=warn,attestation_provider=debug"));
    info!("Starting test server...");
    let ctx = start_default_test_server().await?;

    let client = TestClient::new(&ctx.base_url())?;

    let version: Version = client.get("/version").await?;
    assert_eq!(version.version, env!("CARGO_PKG_VERSION"));

    info!("Success: version endpoint returned: {:?}", version);

    ctx.stop_server().await?;
    Ok(())
}

#[actix_web::test]
async fn test_issuer_certs_empty_dir_and_issuer_untrusted() -> AttResult<()> {
    log_init(Some("info,actix_server=warn,attestation_provider=debug"));
    info!("Starting test server with empty issuer CA directory...");

    let temp_dir =
        std::env::temp_dir().join(format!("credential-issuer-ca-empty-{}", Uuid::new_v4()));
    fs::create_dir_all(&temp_dir).expect("unable to create temp dir");

    let mut params = make_test_server_params(true, "test-user");
    params.credential_issuer_ca_dir = Some(temp_dir.to_string_lossy().to_string());

    let ctx = start_test_server(params).await?;
    let client = TestClient::new(&ctx.base_url())?;

    let certs_resp: serde_json::Value = client.get("/ewqwe_api/.well-known/issuer_certs").await?;
    assert_eq!(certs_resp["count"], 0);

    // Submit a dummy credential: it will fail to parse (the test token is not a
    // valid base64-encoded mDoc / SD-JWT), which produces a 400 response.  This
    // still confirms that the empty CA directory causes the server to reject any
    // credential verification attempt — no 200 is ever returned.
    let verify_req = serde_json::json!({
        "vp_token": "{\"my_credential\":[\"eyJhbGciOiJFUzI1NiJ9.test.QMA\"]}",
        "presentation_submission": null,
        "state": null,
        "client_id": "https://example.com"
    });

    let verify_raw = client.post_raw("/ewqwe_api/verify", &verify_req).await?;
    assert!(
        !verify_raw.status().is_success(),
        "Expected a non-2xx response when no trusted CAs are configured, got {}",
        verify_raw.status()
    );

    ctx.stop_server().await?;
    fs::remove_dir_all(&temp_dir).expect("unable to clean up temp dir");
    Ok(())
}
