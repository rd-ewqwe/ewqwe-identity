//! Test HTTP Client for Integration Testing
//!
//! This module provides an HTTPS client for testing purposes that uses a custom
//! CA certificate for TLS verification and manages cookies through a shared cookie store.
//!
//! The client is configured to:
//! - Use a custom CA certificate for server verification
//! - Store and send cookies automatically
//! - Make authenticated requests using session cookies
//!
//! # Example
//! ```no_run
//! use attestation_provider::tests::test_client::TestClient;
//!
//! # async fn example() -> Result<(), attestation_provider::AuthError> {
//! // Create a client
//! let client = TestClient::new("https://localhost:8443")?;
//!
//! // Make a GET request
//! let response: serde_json::Value = client.get("/api/health").await?;
//!
//! // Make a POST request
//! let body = serde_json::json!({"key": "value"});
//! let response: serde_json::Value = client.post("/api/submit", &body).await?;
//!
//! // Get a raw response
//! let response = client.get_raw("/api/endpoint").await?;
//!
//! // Access cookies
//! let cookie = client.get_cookie("https://localhost:8443")?;
//! # Ok(())
//! # }
//! ```

use std::sync::Arc;

use crate::{AttError, AttResult, tests::test_client::TestCookieStore};
use reqwest::{Certificate, Client, Identity, Response};
use serde::{Serialize, de::DeserializeOwned};
use tracing::{debug, error, trace};

const EC_CERTIFICATES_PATH: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/src/tests/certificates/ec");

const USER1_P12_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/tests/certificates/ec/ewqwe.user1.p12"
);
const USER_P12_PASSWORD: &str = "secret";

/// Test HTTP client with configurable authentication
pub struct TestClient {
    /// The underlying reqwest client
    client: Client,
    /// Base URL for requests
    base_url: String,
    /// Authentication configuration
    cookie_store: Arc<TestCookieStore>,
}

impl TestClient {
    /// Create a new test client with the specified authentication mode
    ///
    /// # Arguments
    /// * `base_url` - The base URL for all requests (e.g., "https://localhost:8443")
    /// * `auth` - The authentication configuration
    ///
    /// # Returns
    /// A configured `TestClient` ready to make requests
    pub fn new(base_url: &str) -> AttResult<Self> {
        let cookie_store = Arc::new(TestCookieStore::new());
        let client = Self::build_client(cookie_store.clone(), None)?;

        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            cookie_store,
        })
    }

    /// Create a test client that authenticates with the bundled user1 client certificate.
    pub fn new_with_user1_cert(base_url: &str) -> AttResult<Self> {
        Self::new_with_pkcs12_identity(base_url, USER1_P12_PATH, USER_P12_PASSWORD)
    }

    /// Create a test client that authenticates with a specific client certificate/key pair.
    pub fn new_with_client_certificate(
        base_url: &str,
        cert_path: &str,
        key_path: &str,
    ) -> AttResult<Self> {
        let cookie_store = Arc::new(TestCookieStore::new());
        let cert_pem = std::fs::read(cert_path).map_err(|e| {
            AttError::Config(format!("Failed to read client certificate file: {e}"))
        })?;
        let key_pem = std::fs::read(key_path).map_err(|e| {
            AttError::Config(format!("Failed to read client private key file: {e}"))
        })?;
        let identity = Identity::from_pkcs8_pem(&cert_pem, &key_pem).map_err(|e| {
            AttError::Config(format!("Failed to parse client cert/key identity: {e}"))
        })?;

        let client = Self::build_client(cookie_store.clone(), Some(identity))?;

        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            cookie_store,
        })
    }

    /// Create a test client from a PKCS#12 identity bundle.
    pub fn new_with_pkcs12_identity(
        base_url: &str,
        p12_path: &str,
        password: &str,
    ) -> AttResult<Self> {
        let cookie_store = Arc::new(TestCookieStore::new());

        let p12_der = std::fs::read(p12_path)
            .map_err(|e| AttError::Config(format!("Failed to read PKCS#12 file: {e}")))?;
        let identity = Identity::from_pkcs12_der(&p12_der, password)
            .map_err(|e| AttError::Config(format!("Failed to parse PKCS#12 identity: {e}")))?;

        let client = Self::build_client(cookie_store.clone(), Some(identity))?;

        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            cookie_store,
        })
    }

    /// Build the reqwest client based on authentication configuration
    fn build_client(
        cookie_store: Arc<TestCookieStore>,
        identity: Option<Identity>,
    ) -> AttResult<Client> {
        // Load the CA certificate for TLS verification
        let ca_cert_path = format!("{}/ewqwe.chain.pem", EC_CERTIFICATES_PATH);
        let ca_cert_pem = std::fs::read(&ca_cert_path)
            .map_err(|e| AttError::Config(format!("Failed to read CA certificate: {}", e)))?;
        let ca_cert = Certificate::from_pem(&ca_cert_pem)
            .map_err(|e| AttError::Config(format!("Failed to parse CA certificate: {}", e)))?;
        debug!("Loaded CA certificate from {}", ca_cert_path);

        let mut builder = Client::builder()
            .cookie_provider(cookie_store)
            .add_root_certificate(ca_cert);

        if let Some(identity) = identity {
            builder = builder.identity(identity);
            debug!("Configured client certificate authentication");
        }

        #[cfg(target_os = "macos")]
        // macOS's Security framework (used by native-tls) won't trust a
        // programmatically-added root cert that isn't in the system keychain.
        // This is a test-only client against local test certificates, so
        // skipping hostname/cert verification is acceptable here.
        let builder = builder.danger_accept_invalid_certs(true);

        debug!(
            "Configured client with custom server CA certificate (TLS cert validation disabled for tests)"
        );

        let client = builder
            .build()
            .map_err(|e| AttError::Config(format!("Failed to build HTTP client: {}", e)))?;

        Ok(client)
    }

    /// Perform an HTTPS GET request and deserialize the JSON response
    ///
    /// # Arguments
    /// * `path` - The path to request (e.g., "/api/health")
    ///
    /// # Returns
    /// The deserialized response body
    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> AttResult<T> {
        let url = format!("{}{}", self.base_url, path);
        let request = self.client.get(&url);

        let response = request.send().await.map_err(|e| {
            error!("GET request failed: {}", e);
            AttError::Config(format!("GET request failed: {}", e))
        })?;

        Self::handle_response(response).await
    }

    /// Perform an HTTPS GET request and return the raw response
    ///
    /// # Arguments
    /// * `path` - The path to request (e.g., "/api/health")
    ///
    /// # Returns
    /// The raw response
    pub async fn get_raw(&self, path: &str) -> AttResult<Response> {
        let url = format!("{}{}", self.base_url, path);
        let request = self.client.get(&url);

        request
            .send()
            .await
            .map_err(|e| AttError::Config(format!("GET request failed: {}", e)))
    }

    /// Perform an HTTPS POST request with a JSON body and deserialize the JSON response
    ///
    /// # Arguments
    /// * `path` - The path to request (e.g., "/api/submit")
    /// * `body` - The request body (will be serialized to JSON)
    ///
    /// # Returns
    /// The deserialized response body
    pub async fn post<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> AttResult<T> {
        let url = format!("{}{}", self.base_url, path);
        let request = self.client.post(&url).json(body);

        let response = request
            .send()
            .await
            .map_err(|e| AttError::Config(format!("POST request failed: {}", e)))?;

        Self::handle_response(response).await
    }

    /// Perform an HTTPS POST request and return the raw response
    ///
    /// # Arguments
    /// * `path` - The path to request (e.g., "/api/submit")
    /// * `body` - The request body (will be serialized to JSON)
    ///
    /// # Returns
    /// The raw response
    pub async fn post_raw<B: Serialize>(&self, path: &str, body: &B) -> AttResult<Response> {
        let url = format!("{}{}", self.base_url, path);
        let request = self.client.post(&url).json(body);

        request
            .send()
            .await
            .map_err(|e| AttError::Config(format!("POST request failed: {}", e)))
    }

    /// Handle the HTTP response, checking for errors and deserializing JSON
    async fn handle_response<T: DeserializeOwned>(response: Response) -> AttResult<T> {
        let status = response.status();

        if !status.is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(AttError::Config(format!(
                "Request failed with status {}: {}",
                status, error_text
            )));
        }

        trace!(
            "Handling response with status: {}, body: {:?}",
            status, response
        );

        response
            .json()
            .await
            .map_err(|e| AttError::Config(format!("Failed to deserialize response: {}", e)))
    }

    /// Get the base URL
    pub fn base_url(&self) -> &str {
        &self.base_url
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        // log_init(Some("info"));
        let client = TestClient::new("https://localhost:8443");
        assert!(client.is_ok());
        let client = client.unwrap();
        assert_eq!(client.base_url(), "https://localhost:8443");
    }
}
