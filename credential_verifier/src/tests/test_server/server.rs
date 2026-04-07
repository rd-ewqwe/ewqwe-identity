use crate::{
    AttError, AttResult, ServerParams, TlsParams, server::start_server, tests::TestsContext,
};
use actix_web::dev::ServerHandle;
use ewqwe_openid4vp::{HaipConfig, OpenID4VPServiceConfig};
use std::{
    path::PathBuf,
    sync::{Arc, atomic::AtomicU16, mpsc},
    thread,
};
use tracing::error;

/// An atomic monotonically increasing counter for generating unique server ports.
static SERVER_PORT_COUNTER: AtomicU16 = AtomicU16::new(59900);

/// Starts the test server in a separate thread and returns a `TestsContext` containing
/// the server handle and thread handle.
pub async fn start_test_server(server_params: ServerParams) -> AttResult<TestsContext> {
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
            .block_on(start_server(params, Some(tx)))
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

    let server_params = ServerParams {
        // Bind to 127.0.0.1 explicitly — on macOS "localhost" resolves to ::1 (IPv6)
        // but the test client connects to 127.0.0.1 (IPv4), causing the connection to fail.
        // The server certificate has IP:127.0.0.1 as a SAN so TLS verification still works.
        host_name: "127.0.0.1".to_string(),
        host_port: SERVER_PORT_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
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
        openid4vp_config: OpenID4VPServiceConfig {
            transaction_ttl_secs: Some(60), // 1 minute for tests
            transaction_store: Default::default(),
            haip_config: Some(HaipConfig {
                // Use the pre-built fullchain PEM (leaf + CA) for x5c
                x509_cert_path: certificates_dir
                    .join("ewqwe.server.fullchain.pem")
                    .to_string_lossy()
                    .to_string(),
                x509_key_path: certificates_dir
                    .join("ewqwe.server.key.pem")
                    .to_string_lossy()
                    .to_string(),
            }),
        },
        trusted_issuer_certs_dir: Some(
            cargo_manifest_dir
                .join("src/tests/certificates/trusted_issuers")
                .to_string_lossy()
                .to_string(),
        ),
        attestation_issuer_certificate: None,
        attestation_issuer_key: None,
    };

    start_test_server(server_params).await
}
