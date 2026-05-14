/*!
HTTP transport abstraction — trait + default reqwest implementation.

Any type that implements [`HttpClient`] can be injected into [`EwqweApiClient`].
The only requirement is `Send + Sync + 'static` so the client can be safely
shared across async task boundaries (e.g. `Arc<dyn HttpClient>`).
*/

use async_trait::async_trait;
use serde::{Serialize, de::DeserializeOwned};
use url::Url;

use crate::{ClientOptions, error::{ApiError, Result}};

// ============================================================================
// HttpClient trait
// ============================================================================

/// Minimal HTTP client interface used by [`EwqweApiClient`].
///
/// Implement this trait to swap out the default [`reqwest`]-based transport with
/// a custom implementation (e.g., a mock for unit testing or an integration
/// with another HTTP framework).
#[async_trait]
pub trait HttpClient: Send + Sync + 'static {
    /// Perform a `GET` request and deserialize the JSON response body.
    async fn get_json<R: DeserializeOwned>(&self, url: Url) -> Result<R>;

    /// Perform a `POST` request, serialize `body` as JSON, and deserialize the
    /// JSON response body.
    async fn post_json<B: Serialize + Send + Sync, R: DeserializeOwned>(
        &self,
        url: Url,
        body: &B,
    ) -> Result<R>;
}

// ============================================================================
// Default reqwest implementation
// ============================================================================

/// Default HTTP transport backed by [`reqwest`].
///
/// Built from [`ClientOptions`]; supports:
/// - Custom CA certificate bundle (self-signed / private CA)
/// - Optional mTLS client certificate
/// - TLS backend selection via Cargo features (`default-tls` / `rustls-tls`)
pub struct DefaultHttpClient {
    inner: reqwest::Client,
}

impl std::fmt::Debug for DefaultHttpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DefaultHttpClient").finish_non_exhaustive()
    }
}

impl DefaultHttpClient {
    /// Build a [`DefaultHttpClient`] from [`ClientOptions`].
    pub fn build(options: ClientOptions) -> Result<Self> {
        let mut builder = reqwest::Client::builder();

        // Custom CA certificate
        if let Some(pem) = options.ca_cert_pem {
            let cert = reqwest::Certificate::from_pem(pem.as_bytes())
                .map_err(|e| ApiError::Config(format!("invalid CA certificate PEM: {e}")))?;
            builder = builder.add_root_certificate(cert);
        }

        // mTLS client certificate
        if let (Some(cert_pem), Some(key_pem)) =
            (options.client_cert_pem, options.client_key_pem)
        {
            let identity =
                reqwest::Identity::from_pkcs8_pem(cert_pem.as_bytes(), key_pem.as_bytes())
                    .map_err(|e| {
                        ApiError::Config(format!("invalid client cert/key PEM: {e}"))
                    })?;
            builder = builder.identity(identity);
        }

        let inner = builder
            .build()
            .map_err(|e| ApiError::Config(format!("failed to build HTTP client: {e}")))?;

        Ok(Self { inner })
    }
}

#[async_trait]
impl HttpClient for DefaultHttpClient {
    async fn get_json<R: DeserializeOwned>(&self, url: Url) -> Result<R> {
        let response = self
            .inner
            .get(url.clone())
            .header("Accept", "application/json")
            .send()
            .await?;

        parse_response(response).await
    }

    async fn post_json<B: Serialize + Send + Sync, R: DeserializeOwned>(
        &self,
        url: Url,
        body: &B,
    ) -> Result<R> {
        let response = self
            .inner
            .post(url.clone())
            .header("Accept", "application/json")
            .json(body)
            .send()
            .await?;

        parse_response(response).await
    }
}

    /// Convert a `reqwest::Response` into `Result<R>`, mapping non-2xx to
/// [`ApiError::Server`] and JSON parse failures to [`ApiError::Decode`].
async fn parse_response<R: DeserializeOwned>(response: reqwest::Response) -> Result<R> {
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(ApiError::Server {
            status: status.as_u16(),
            body,
        });
    }
    let bytes = response.bytes().await?;
    serde_json::from_slice(&bytes).map_err(ApiError::Decode)
}

// ============================================================================
// Blanket impl for Arc<C>
// ============================================================================

/// Forward all [`HttpClient`] calls through an [`Arc`] wrapper.
///
/// This enables `EwqweApiClient::with_http_client` to accept an
/// `Arc<MyClient>` directly, which is useful in tests where the same
/// client stub needs to be shared between the `EwqweApiClient` and the
/// assertion code.
///
/// ```rust,no_run
/// # use std::sync::Arc;
/// # use ewqwe_digital_identity::{EwqweApiClient, HttpClient};
/// # use url::Url;
/// // Share the stub between the client and the test assertions:
/// // let stub = Arc::new(MyStub::new());
/// // let client = EwqweApiClient::with_http_client(base_url, Arc::clone(&stub));
/// ```
#[async_trait]
impl<C: HttpClient> HttpClient for std::sync::Arc<C> {
    async fn get_json<R: DeserializeOwned>(&self, url: Url) -> Result<R> {
        (**self).get_json(url).await
    }

    async fn post_json<B: Serialize + Send + Sync, R: DeserializeOwned>(
        &self,
        url: Url,
        body: &B,
    ) -> Result<R> {
        (**self).post_json(url, body).await
    }
}
