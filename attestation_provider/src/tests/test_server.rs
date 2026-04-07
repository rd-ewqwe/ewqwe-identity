use std::{
    path::PathBuf,
    sync::{Arc, mpsc},
    thread,
};

use actix_web::{HttpRequest, HttpResponse, dev::ServerHandle, web::Data};
use tracing::error;

use crate::{
    AuthError, AuthResult, AuthServerParams, IdpParams, JwtParams, TlsParams,
    server::start_auth_server, tests::TestsContext,
};

/// Starts the test server in a separate thread and returns a `TestsContext` containing
/// the server handle and thread handle.
pub async fn start_test_server(server_params: AuthServerParams) -> AuthResult<TestsContext> {
    let (tx, rx) = mpsc::channel::<ServerHandle>();

    let params = Arc::new(server_params.clone());
    let thread_handle = thread::spawn(move || {
        // allow others `spawn` to happen within the  Server in the future
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| {
                error!("Error building tokio runtime: {e:?}");
                AuthError::AuthServer(e.to_string())
            })?;

        runtime
            .block_on(start_auth_server(params, Some(tx)))
            .map_err(|e| {
                error!("Error starting the  server: {e:?}");
                AuthError::AuthServer(e.to_string())
            })
    });

    let server_handle = rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .map_err(|e| AuthError::Unexpected(format!("Error getting test server handle: {e}")))?;

    Ok(TestsContext {
        server_params,
        server_handle,
        thread_handle,
    })
}

/// Starts a default test server with predefined parameters.
/// Returns a `TestsContext` containing the server handle and thread handle.
pub async fn start_default_test_server() -> AuthResult<TestsContext> {
    let cargo_manifest_dir = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR")
            .map_err(|_e| AuthError::AuthServer("Failed to find cargo manifest dir".to_owned()))?,
    );
    let certificates_dir = cargo_manifest_dir.join("src/tests/certificates/ec");

    let server_params = AuthServerParams {
        host_name: "localhost".to_string(),
        host_port: 49998,
        tls_params: TlsParams {
            server_certificate: certificates_dir
                .join("velo.server.cert.pem")
                .to_string_lossy()
                .to_string(),
            server_private_key: certificates_dir
                .join("velo.server.key.pem")
                .to_string_lossy()
                .to_string(),
            server_ca_chain: certificates_dir
                .join("velo.chain.pem")
                .to_string_lossy()
                .to_string(),
            client_ca_cert_chain: Some(
                certificates_dir
                    .join("velo.chain.pem")
                    .to_string_lossy()
                    .to_string(),
            ),
            #[cfg(feature = "openssl")]
            tls_cipher_suites: None,
            // tls_cipher_suites: Some(
            //     tls::openssl_config::TLS13_CIPHER_SUITES
            //         .iter()
            //         .map(|s| s.to_string())
            //         .collect(),
            // ),
            #[cfg(feature = "rustls")]
            tls_cipher_suites: None,
        },
        default_username: Some("default_user".to_string()),
    };

    start_test_server(server_params).await
}

mod tests {

    use tokio::time::sleep;
    use tracing::info;

    use crate::{
        AuthError,
        tests::{log_test, test_server::start_default_test_server},
    };

    #[tokio::test]
    async fn test_start_server() -> Result<(), AuthError> {
        log_test(Some("info"));
        info!("Starting test server...");
        let ctx = start_default_test_server().await?;
        info!("Test server started successfully. Sleeping for 3 seconds...");
        sleep(std::time::Duration::from_secs(3)).await;
        info!("Stopping test server...");
        ctx.stop_server().await?;
        info!("Test server stopped.");
        Ok(())
    }
}
