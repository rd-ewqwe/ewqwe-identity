//! # `ewqwe_digital_identity`
//!
//! Rust client library for the **ewQwe EU Age Verification** system.
//!
//! Mirrors the `@ewqwe/digital-identity` JavaScript library and covers:
//! - All `ewqwe_api/openid4vp/` REST endpoints (transaction lifecycle)
//! - The `ewqwe_api/verify` credential verification endpoint
//! - Typed request / response models for OpenID4VP 1.0 and DCQL
//!
//! ## Design
//!
//! The HTTP transport is abstracted behind the [`HttpClient`] trait.  
//! The default implementation uses [`reqwest`](https://docs.rs/reqwest), but you
//! can supply any `Send + Sync` implementation — useful for testing or embedding in
//! frameworks that already manage an HTTP stack.
//!
//! ```rust,no_run
//! use ewqwe_digital_identity::{EwqweApiClient, ClientOptions};
//!
//! # async fn example() -> ewqwe_digital_identity::Result<()> {
//! let client = EwqweApiClient::new(ClientOptions::new("https://localhost:9443")?)?;
//! # Ok(())
//! # }
//! ```
//!
//! See [`EwqweApiClient`] for the full method listing and the crate README for a
//! quick-start guide.

pub mod error;
pub mod http;
pub mod models;

#[cfg(test)]
mod tests;

pub use error::{ApiError, Result};
pub use http::{DefaultHttpClient, HttpClient};
pub use models::*;

use std::sync::Arc;
use url::Url;

// ============================================================================
// Client Options
// ============================================================================

/// Configuration for [`EwqweApiClient`].
#[derive(Debug, Clone)]
pub struct ClientOptions {
    /// Base URL of the credential-verifier server (e.g. `https://localhost:9443`).
    pub base_url: Url,
    /// Optional PEM-encoded CA certificate bundle for server TLS verification.
    /// Required when the server uses a self-signed or private CA certificate.
    pub ca_cert_pem: Option<String>,
    /// Optional PEM-encoded client certificate and private key used for mutual TLS
    /// authentication (`ewqwe_api/verify` requires a client certificate by default).
    pub client_cert_pem: Option<String>,
    pub client_key_pem: Option<String>,
}

impl ClientOptions {
    /// Create options with only a base URL (no custom TLS).
    pub fn new(base_url: &str) -> Result<Self> {
        let base_url =
            Url::parse(base_url).map_err(|e| ApiError::Config(format!("invalid base URL: {e}")))?;
        Ok(Self {
            base_url,
            ca_cert_pem: None,
            client_cert_pem: None,
            client_key_pem: None,
        })
    }

    /// Attach a PEM CA certificate bundle for server TLS verification.
    pub fn with_ca_cert(mut self, pem: impl Into<String>) -> Self {
        self.ca_cert_pem = Some(pem.into());
        self
    }

    /// Attach a PEM client certificate and private key for mTLS.
    pub fn with_client_cert(
        mut self,
        cert_pem: impl Into<String>,
        key_pem: impl Into<String>,
    ) -> Self {
        self.client_cert_pem = Some(cert_pem.into());
        self.client_key_pem = Some(key_pem.into());
        self
    }
}

// ============================================================================
// API Client
// ============================================================================

/// Client for the ewQwe credential-verifier REST API.
///
/// # Transport injection
///
/// The client is generic over the HTTP transport via the [`HttpClient`] trait.
/// Use [`EwqweApiClient::new`] for the default [`reqwest`]-based transport or
/// [`EwqweApiClient::with_http_client`] to supply your own.
///
/// # Thread safety
///
/// `EwqweApiClient` is `Clone + Send + Sync` when the underlying `HttpClient`
/// implementation is.  The default [`DefaultHttpClient`] satisfies both.
pub struct EwqweApiClient<C: HttpClient = DefaultHttpClient> {
    base_url: Url,
    http: Arc<C>,
}

impl EwqweApiClient<DefaultHttpClient> {
    /// Construct a client backed by the default [`reqwest`] transport.
    pub fn new(options: ClientOptions) -> Result<Self> {
        let http = DefaultHttpClient::build(options.clone())?;
        Ok(Self {
            base_url: options.base_url,
            http: Arc::new(http),
        })
    }
}

impl<C: HttpClient> EwqweApiClient<C> {
    /// Construct a client using a custom [`HttpClient`] implementation.
    ///
    /// The `base_url` is used to resolve all endpoint paths.
    pub fn with_http_client(base_url: Url, http: C) -> Self {
        Self {
            base_url,
            http: Arc::new(http),
        }
    }

    fn url(&self, path: &str) -> Result<Url> {
        self.base_url
            .join(path)
            .map_err(|e| ApiError::Config(format!("failed to build URL for {path}: {e}")))
    }

    // ── OpenID4VP transaction endpoints ─────────────────────────────────────

    /// Initialize a new OpenID4VP transaction.
    ///
    /// `POST /ewqwe_api/openid4vp/init`
    ///
    /// Builds a DCQL authorization request, persists the transaction in the
    /// credential-verifier session store and returns the QR-code data URL
    /// (cross-device) or deep-link URI (same-device).
    pub async fn init_openid4vp_transaction(
        &self,
        request: InitTransactionRequest,
    ) -> Result<InitTransactionResponse> {
        let url = self.url("/ewqwe_api/openid4vp/init")?;
        self.http.post_json(url, &request).await
    }

    /// Poll the status of an existing transaction.
    ///
    /// `GET /ewqwe_api/openid4vp/status/{transaction_id}`
    ///
    /// Returns [`TransactionStatusResult`] whose `status` field cycles through
    /// `"pending"` → `"received"` (or `"expired"` / `"error"`).
    pub async fn get_openid4vp_transaction_status(
        &self,
        transaction_id: &str,
    ) -> Result<TransactionStatusResult> {
        let path = format!("/ewqwe_api/openid4vp/status/{}", urlenc(transaction_id));
        let url = self.url(&path)?;
        self.http.get_json(url).await
    }

    /// Fetch the signed JAR (HAIP profile) or plain JSON authorization request
    /// (Annex-A profile) that the wallet retrieves via `request_uri`.
    ///
    /// `GET /ewqwe_api/openid4vp/request/{transaction_id}`
    pub async fn get_openid4vp_authorization_request(
        &self,
        transaction_id: &str,
    ) -> Result<serde_json::Value> {
        let path = format!("/ewqwe_api/openid4vp/request/{}", urlenc(transaction_id));
        let url = self.url(&path)?;
        self.http.get_json(url).await
    }

    /// Post an authorization response to the wallet-facing request endpoint.
    ///
    /// `POST /ewqwe_api/openid4vp/request/{transaction_id}`
    pub async fn post_openid4vp_authorization_request(
        &self,
        transaction_id: &str,
        response: &OpenID4VPResponse,
    ) -> Result<()> {
        let path = format!("/ewqwe_api/openid4vp/request/{}", urlenc(transaction_id));
        let url = self.url(&path)?;
        let _: serde_json::Value = self.http.post_json(url, response).await?;
        Ok(())
    }

    /// Direct-post endpoint: wallet POSTs the VP Token after scanning the QR code.
    ///
    /// `POST /ewqwe_api/openid4vp/direct_post`
    pub async fn post_openid4vp_direct_post(&self, response: &OpenID4VPResponse) -> Result<()> {
        let url = self.url("/ewqwe_api/openid4vp/direct_post")?;
        let _: serde_json::Value = self.http.post_json(url, response).await?;
        Ok(())
    }

    /// Fetch the verifier's public JWK Set.
    ///
    /// `GET /ewqwe_api/openid4vp/.well-known/jwks.json`
    ///
    /// Used by the relying party to verify JWT attestations returned by
    /// [`verify_presentation`](Self::verify_presentation).
    pub async fn get_openid4vp_jwks(&self) -> Result<JwkSet> {
        let url = self.url("/ewqwe_api/openid4vp/.well-known/jwks.json")?;
        self.http.get_json(url).await
    }

    // ── Verification endpoint ────────────────────────────────────────────────

    /// Submit a VP Token to the credential-verifier for signature and policy
    /// validation.  Returns a signed [`VerifyResponse`] containing a JWT
    /// attestation on success.
    ///
    /// `POST /ewqwe_api/verify`
    ///
    /// # Mutual TLS
    ///
    /// The `/ewqwe_api/verify` endpoint requires a valid client certificate
    /// unless `disable_authentication = true` is set in the server config.
    /// Provide `client_cert_pem` / `client_key_pem` in [`ClientOptions`].
    pub async fn verify_presentation(&self, request: VerifyRequest) -> Result<VerifyResponse> {
        let url = self.url("/ewqwe_api/verify")?;
        self.http.post_json(url, &request).await
    }

    // ── Server info endpoints ────────────────────────────────────────────────

    /// Fetch the server's software version.
    ///
    /// `GET /version`
    pub async fn get_version(&self) -> Result<VersionResponse> {
        let url = self.url("/version")?;
        self.http.get_json(url).await
    }
}

/// URL-encode a path segment component (no `/` pass-through).
#[inline]
fn urlenc(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}
