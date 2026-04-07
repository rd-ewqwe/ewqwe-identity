use crate::{
    AttResult,
    server::Version,
    tests::{log_test, start_default_test_server, test_client::TestClient},
};
use tracing::info;

#[actix_web::test]
async fn test_version_endpoint() -> AttResult<()> {
    log_test(Some("info,actix_server=warn,attestation_provider=debug"));
    info!("Starting test server...");
    let ctx = start_default_test_server().await?;

    let client = TestClient::new(&ctx.base_url())?;
    client.authenticate().await?;

    let version: Version = client.get("/version").await?;
    assert_eq!(version.version, env!("CARGO_PKG_VERSION"));

    ctx.stop_server().await?;
    info!("Test server stopped.");

    Ok(())
}
