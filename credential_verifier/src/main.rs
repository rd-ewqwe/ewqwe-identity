//! EU Age Verification - Credential Verifier Server
//!
//! This is the main entry point for the Credential Verifier server.
//! It verifies VP tokens from wallets and returns signed attestations to Relying Parties.
//!
//! # Usage
//!
//! ```bash
//! # With an explicit config file path
//! cargo run --features openssl -- /path/to/credential-server.toml
//!
//! # From a TOML configuration file in the current directory or the platform config directory
//! cargo run --features openssl
//! ```

use credential_verifier::{ServerParams, start_server};
use ewqwe_logging::{TracingConfig, tracing_init};
use std::{path::PathBuf, sync::Arc};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize logging
    let config = TracingConfig::default();
    let _guard = tracing_init(&config);

    tracing::info!("Starting ewQwe Credential Verifier");

    let (server_params, config_path) = if let Some(config_path) = std::env::args_os().nth(1) {
        let config_path = PathBuf::from(config_path);
        let server_params = ServerParams::load_from_file(&config_path)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;
        (server_params, config_path)
    } else {
        ServerParams::load_from_default_locations()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?
    };

    tracing::info!("Loaded configuration from {}", config_path.display());
    tracing::info!(
        "Server will listen on https://{}:{}",
        server_params.host_name,
        server_params.host_port
    );

    let server_params = Arc::new(server_params);

    // Start the server
    match start_server(server_params, None).await {
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
