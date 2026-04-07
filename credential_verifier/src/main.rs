//! EU Age Verification - Credential Verifier Server
//!
//! This is the main entry point for the Credential Verifier server.
//! It verifies VP tokens from wallets and returns signed attestations to Relying Parties.
//!
//! # Usage
//!
//! ```bash
//! # With default settings (uses test certificates)
//! cargo run --features openssl
//!
//! # With environment variables
//! RUST_LOG=debug HOST=0.0.0.0 PORT=9443 cargo run --features openssl
//! ```

use credential_verifier::{AttServerParams, TlsParams, start_att_server};
use ewqwe_logging::{TracingConfig, tracing_init};
use std::sync::Arc;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize logging
    let config = TracingConfig::default();
    let _guard = tracing_init(&config);

    tracing::info!("Starting EU Age Verification Credential Verifier");

    // Load configuration from environment or use defaults
    let host = std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(9443);

    // For development, use test certificates
    // In production, these would be loaded from secure configuration
    let cert_dir =
        std::env::var("CERT_DIR").unwrap_or_else(|_| "src/tests/certificates/ec".to_string());

    let tls_params = TlsParams {
        server_private_key: format!("{}/ewqwe.server.key.pem", cert_dir),
        server_certificate: format!("{}/ewqwe.server.cert.pem", cert_dir),
        server_ca_chain: format!("{}/ewqwe.chain.pem", cert_dir),
        client_ca_cert_chain: None,
        tls_cipher_suites: None,
    };

    let server_params = Arc::new(AttServerParams {
        host_name: host.clone(),
        host_port: port,
        tls_params,
        default_username: Some("demo-user".to_string()),
    });

    tracing::info!("Server will listen on https://{}:{}", host, port);
    tracing::info!("Certificate directory: {}", cert_dir);

    // Start the server
    match start_att_server(server_params, None).await {
        Ok(()) => {
            tracing::info!("Server shut down gracefully");
            Ok(())
        }
        Err(e) => {
            tracing::error!("Server error: {}", e);
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))
        }
    }
}
