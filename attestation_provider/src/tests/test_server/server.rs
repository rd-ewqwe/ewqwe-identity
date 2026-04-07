use crate::{
    AttError, AttResult, AttServerParams, TlsParams, server::start_att_server, tests::TestsContext,
};
use actix_web::dev::ServerHandle;
use std::{
    path::PathBuf,
    sync::{Arc, mpsc},
    thread,
};
use tracing::error;

/// Starts the test server in a separate thread and returns a `TestsContext` containing
/// the server handle and thread handle.
pub async fn start_test_server(server_params: AttServerParams) -> AttResult<TestsContext> {
    let (tx, rx) = mpsc::channel::<ServerHandle>();

    let params = Arc::new(server_params.clone());
    let thread_handle = thread::spawn(move || {
        // allow others `spawn` to happen within the  Server in the future
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| {
                error!("Error building tokio runtime: {e:?}");
                AttError::Test(e.to_string())
            })?;

        runtime
            .block_on(start_att_server(params, Some(tx)))
            .map_err(|e| {
                error!("Error starting the attestation provider server: {e:?}");
                AttError::Test(e.to_string())
            })
    });

    let server_handle = rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .map_err(|e| {
            AttError::Unexpected(format!(
                "Error getting the attestation provider server handle: {e}"
            ))
        })?;

    Ok(TestsContext {
        server_params,
        server_handle,
        thread_handle,
    })
}

/// Starts a default test server with predefined parameters.
/// Returns a `TestsContext` containing the server handle and thread handle.
pub async fn start_default_test_server() -> AttResult<TestsContext> {
    let cargo_manifest_dir = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR")
            .map_err(|_e| AttError::Test("Failed to find cargo manifest dir".to_owned()))?,
    );
    let certificates_dir = cargo_manifest_dir.join("src/tests/certificates/ec");

    let server_params = AttServerParams {
        host_name: "localhost".to_string(),
        host_port: 59900,
        tls_params: TlsParams {
            server_certificate: certificates_dir
                .join("ewqwe.server.cert.pem")
                .to_string_lossy()
                .to_string(),
            server_private_key: certificates_dir
                .join("ewqwe.server.key.pem")
                .to_string_lossy()
                .to_string(),
            server_ca_chain: certificates_dir
                .join("ewqwe.chain.pem")
                .to_string_lossy()
                .to_string(),
            client_ca_cert_chain: Some(
                certificates_dir
                    .join("ewqwe.chain.pem")
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
