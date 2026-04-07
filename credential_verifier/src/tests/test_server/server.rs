use crate::{
    AttError, AttResult, ServerParams, TlsParams, server::start_server, tests::TestsContext,
};
use actix_web::dev::ServerHandle;
use ewqwe_logging::TracingConfig;
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
        rust_log: None,
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
            tls_cipher_suites: None,
            // tls_cipher_suites: Some(
            //     tls::openssl_config::TLS13_CIPHER_SUITES
            //         .iter()
            //         .map(|s| s.to_string())
            //         .collect(),
            // ),
        },
        default_username: Some("default_user".to_string()),
        openid4vp_config: OpenID4VPServiceConfig {
            transaction_ttl_secs: Some(60), // 1 minute for tests
            transaction_store: Default::default(),
            haip_config: Some(HaipConfig {
                // Use the pre-built full chain PEM (leaf + CA) for x5c
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
        journal_config: Default::default(),
        disable_authentication: false,
        disabled_authentication_user: None,
        tracing_config: TracingConfig::default(),
    };

    start_test_server(server_params).await
}

pub fn make_test_server_params(
    disable_authentication: bool,
    disabled_authentication_user: impl Into<String>,
) -> ServerParams {
    let cargo_manifest_dir = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").expect("Failed to find cargo manifest dir"),
    );
    let certificates_dir = cargo_manifest_dir.join("src/tests/certificates/ec");

    ServerParams {
        host_name: "127.0.0.1".to_string(),
        host_port: SERVER_PORT_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
        rust_log: None,
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
            tls_cipher_suites: None,
        },
        default_username: Some("default_user".to_string()),
        openid4vp_config: OpenID4VPServiceConfig {
            transaction_ttl_secs: Some(60), // 1 minute for tests
            transaction_store: Default::default(),
            haip_config: Some(HaipConfig {
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
        journal_config: Default::default(),
        disable_authentication,
        disabled_authentication_user: Some(disabled_authentication_user.into()),
        tracing_config: TracingConfig::default(),
    }
}

/// Starts a test server with the verification journal enabled (SQLite in-memory backend).
///
/// Use this helper in tests that exercise the `/api/journal/…` endpoints.
pub async fn start_journal_test_server() -> AttResult<TestsContext> {
    use crate::journal::{JournalBackend, JournalConfig};

    let cargo_manifest_dir = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR")
            .map_err(|_e| AttError::Test("Failed to find cargo manifest dir".to_owned()))?,
    );
    let certificates_dir = cargo_manifest_dir.join("src/tests/certificates/ec");

    let server_params = crate::ServerParams {
        rust_log: None,
        host_name: "127.0.0.1".to_string(),
        host_port: SERVER_PORT_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
        tls_params: crate::TlsParams {
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
            tls_cipher_suites: None,
        },
        default_username: Some("default_user".to_string()),
        openid4vp_config: ewqwe_openid4vp::OpenID4VPServiceConfig {
            transaction_ttl_secs: Some(60),
            transaction_store: Default::default(),
            haip_config: Some(ewqwe_openid4vp::HaipConfig {
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
        journal_config: JournalConfig {
            enabled: true,
            backend: JournalBackend::SqliteMemory,
        },
        disable_authentication: false,
        disabled_authentication_user: None,
        tracing_config: TracingConfig::default(),
    };

    start_test_server(server_params).await
}
