use tokio::time::sleep;
use tracing::info;

use crate::{
    AuthError,
    tests::{log_test, start_default_test_server},
};

#[tokio::test]
async fn test_start_server() -> Result<(), AuthError> {
    log_test(Some("info,attestation_provider=debug"));
    info!("Starting test server...");
    let ctx = start_default_test_server().await?;
    info!("Test server started successfully. Sleeping for 3 seconds...");
    sleep(std::time::Duration::from_secs(3)).await;
    info!("Stopping test server...");
    ctx.stop_server().await?;
    info!("Test server stopped.");
    Ok(())
}
