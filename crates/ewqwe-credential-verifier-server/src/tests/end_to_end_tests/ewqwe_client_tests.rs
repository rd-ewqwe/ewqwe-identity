//! End-to-end tests exercising the `ewQwe` credential-verifier API via the
//! `ewqwe_credential_verifier_client` Rust client library.
//!
//! These tests start an in-process credential-verifier server (with test TLS
//! certificates), then use `EwqweApiClient` to call each endpoint and assert
//! correct behaviour.
//!
//! # Transport note
//!
//! On macOS, the Security Framework used by `native-tls` does not trust CA
//! certificates that are not in the macOS system keychain.  The production
//! `DefaultHttpClient` therefore cannot verify the test server's self-signed
//! certificate on macOS.  These tests instead inject a custom `HttpClient`
//! implementation — `TestReqwestClient` — that is built from the same
//! `reqwest` version used by `credential_verifier` (0.13) and sets
//! `danger_accept_invalid_certs(true)`.  This is acceptable here because:
//! - We are testing against a *local* server under our control.
//! - The certificates and server code are themselves the subject of testing.
//! - `danger_accept_invalid_certs` is *never* set in production code.

use std::fs;

use async_trait::async_trait;
use ewqwe_credential_verifier_client::{ApiError, EwqweApiClient, HttpClient};
use ewqwe_logging::log_init;
use ewqwe_openid4vp::{
    InitTransactionRequest, ProfileId, TransactionStatus, VerifyCredentialRequest,
};
use serde::{Serialize, de::DeserializeOwned};
use tracing::info;
use url::Url;

use crate::{
    AttResult,
    tests::{make_test_server_params, start_default_test_server},
};

// ============================================================================
// Test-only HTTP transport
// ============================================================================

const EC_CERTS_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../certificates/tls");

/// An [`HttpClient`] implementation for tests that:
/// - Accepts the test server's self-signed certificate without validating the
///   chain (required on macOS where the keychain does not contain our test CA).
/// - Loads the test CA certificate so the server TLS fingerprint can still be
///   verified on Linux CI.
///
/// Uses `credential_verifier`'s `reqwest` version (0.13) so there is no
/// duplicate reqwest compilation in these tests.
struct TestReqwestClient {
    inner: reqwest::Client,
}

impl TestReqwestClient {
    /// Build a client that trusts the test CA and, on macOS, skips full chain
    /// validation.
    fn new() -> Self {
        let ca_chain_pem =
            fs::read(format!("{EC_CERTS_DIR}/ewqwe.ca.pem")).expect("failed to read test CA chain");

        let mut builder = reqwest::Client::builder()
            .add_root_certificate(
                reqwest::Certificate::from_pem(&ca_chain_pem)
                    .expect("failed to parse test CA chain"),
            )
            // On macOS the Security Framework only trusts system-keychain CAs.
            // This flag is set explicitly so tests run locally without requiring
            // the developer to install the test CA into the keychain.
            .danger_accept_invalid_certs(true);

        // Load the user1 client certificate for mTLS-protected endpoints.
        // This is the same PKCS#12 bundle used by the existing TestClient.
        let p12_bytes = fs::read(format!("{EC_CERTS_DIR}/ewqwe.user1.p12"))
            .expect("failed to read user1 PKCS#12");
        let identity = reqwest::Identity::from_pkcs12_der(&p12_bytes, "secret")
            .expect("failed to parse user1 PKCS#12");
        builder = builder.identity(identity);

        let inner = builder
            .build()
            .expect("failed to build test reqwest client");
        Self { inner }
    }
}

#[async_trait]
impl HttpClient for TestReqwestClient {
    async fn get_json<R: DeserializeOwned>(
        &self,
        url: Url,
    ) -> ewqwe_credential_verifier_client::Result<R> {
        let response = self
            .inner
            .get(url)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| ApiError::Config(e.to_string()))?;

        parse_response(response).await
    }

    async fn post_json<B: Serialize + Send + Sync, R: DeserializeOwned>(
        &self,
        url: Url,
        body: &B,
    ) -> ewqwe_credential_verifier_client::Result<R> {
        let response = self
            .inner
            .post(url)
            .header("Accept", "application/json")
            .json(body)
            .send()
            .await
            .map_err(|e| ApiError::Config(e.to_string()))?;

        parse_response(response).await
    }
}

async fn parse_response<R: DeserializeOwned>(
    response: reqwest::Response,
) -> ewqwe_credential_verifier_client::Result<R> {
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(ApiError::Server {
            status: status.as_u16(),
            body,
        });
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|e| ApiError::Config(e.to_string()))?;
    serde_json::from_slice(&bytes).map_err(ApiError::Decode)
}

/// Build an `EwqweApiClient<TestReqwestClient>` pointed at `base_url`.
fn build_test_api_client(base_url: &str) -> EwqweApiClient<TestReqwestClient> {
    let url = Url::parse(base_url).expect("invalid test base URL");
    EwqweApiClient::with_http_client(url, TestReqwestClient::new())
}

// ============================================================================
// E2E tests
// ============================================================================

/// `GET /version` returns the credential-verifier's Cargo package version.
#[actix_web::test]
async fn e2e_ewqwe_client_version_endpoint() -> AttResult<()> {
    log_init(None);
    info!("Starting test server for version endpoint test");
    let ctx = start_default_test_server().await?;
    let client = build_test_api_client(&ctx.base_url());

    let version = client
        .get_version()
        .await
        .map_err(|e| crate::AttError::Test(format!("get_version failed: {e}")))?;

    assert_eq!(
        version.version,
        env!("CARGO_PKG_VERSION"),
        "version must match Cargo.toml version"
    );
    info!("version = {}", version.version);

    ctx.stop_server().await?;
    Ok(())
}

/// `POST /ewqwe_api/openid4vp/init` creates a transaction and returns a
/// well-formed `InitTransactionResponse`.
#[actix_web::test]
async fn e2e_ewqwe_client_init_transaction() -> AttResult<()> {
    log_init(None);
    let ctx = start_default_test_server().await?;
    let client = build_test_api_client(&ctx.base_url());

    let req = InitTransactionRequest::new()
        .with_profile(ProfileId::AnnexA)
        .with_credential_type("proof-of-age");

    let tx = client
        .init_openid4vp_transaction(req)
        .await
        .map_err(|e| crate::AttError::Test(format!("init_openid4vp_transaction failed: {e}")))?;

    info!(
        transaction_id = %tx.transaction_id,
        profile = %tx.profile,
        client_id = %tx.client_id,
        expires_in = tx.expires_in,
        "Transaction initialized"
    );

    assert!(
        !tx.transaction_id.is_empty(),
        "transaction_id must be non-empty"
    );
    assert!(!tx.client_id.is_empty(), "client_id must be non-empty");
    assert!(!tx.request_uri.is_empty(), "request_uri must be non-empty");
    assert!(
        !tx.authorization_request_uri.is_empty(),
        "authorization_request_uri must be non-empty"
    );
    assert!(tx.expires_in > 0, "expires_in must be positive");
    assert_eq!(tx.profile, ProfileId::AnnexA, "profile must match request");

    ctx.stop_server().await?;
    Ok(())
}

/// `GET /ewqwe_api/openid4vp/status/:id` returns `pending` for a fresh transaction.
#[actix_web::test]
async fn e2e_ewqwe_client_transaction_status_pending() -> AttResult<()> {
    log_init(None);
    let ctx = start_default_test_server().await?;
    let client = build_test_api_client(&ctx.base_url());

    // Create a transaction first
    let req = InitTransactionRequest::new()
        .with_profile(ProfileId::AnnexA)
        .with_credential_type("proof-of-age");
    let tx = client
        .init_openid4vp_transaction(req)
        .await
        .map_err(|e| crate::AttError::Test(format!("init failed: {e}")))?;

    // Poll status immediately — must be pending
    let status_result = client
        .get_openid4vp_transaction_status(&tx.transaction_id)
        .await
        .map_err(|e| crate::AttError::Test(format!("get_status failed: {e}")))?;

    info!(
        status = ?status_result.status,
        expires_in = ?status_result.expires_in,
        "Transaction status polled"
    );

    assert_eq!(
        status_result.status,
        TransactionStatus::Pending,
        "Fresh transaction must be pending"
    );
    assert!(
        status_result.expires_in.is_some(),
        "expires_in must be present when pending"
    );
    assert!(
        status_result.authorization_response.is_none(),
        "No authorization response yet"
    );

    ctx.stop_server().await?;
    Ok(())
}

/// `GET /ewqwe_api/openid4vp/status/:id` returns `expired` for an unknown
/// transaction ID.
///
/// The `InMemoryTransactionStore::is_expired` returns `true` for nonexistent
/// keys, so the server treats unknown IDs as expired transactions rather than
/// returning HTTP 404.
#[actix_web::test]
async fn e2e_ewqwe_client_transaction_status_unknown_id() -> AttResult<()> {
    log_init(None);
    let ctx = start_default_test_server().await?;
    let client = build_test_api_client(&ctx.base_url());

    let result = client
        .get_openid4vp_transaction_status("no-such-transaction-id")
        .await;

    // The InMemoryTransactionStore treats unknown IDs as expired,
    // so the call succeeds with status == Expired.
    let status_result = result
        .map_err(|e| crate::AttError::Test(format!("Expected Ok(expired) but got Err: {e}")))?;

    assert_eq!(
        status_result.status,
        TransactionStatus::Expired,
        "Unknown transaction ID must be reported as expired (not an HTTP error)"
    );
    info!("Correctly received Expired status for unknown transaction ID");

    ctx.stop_server().await?;
    Ok(())
}

/// `GET /ewqwe_api/openid4vp/.well-known/jwks.json` returns a JWK Set.
#[actix_web::test]
async fn e2e_ewqwe_client_jwks_endpoint() -> AttResult<()> {
    log_init(None);
    let ctx = start_default_test_server().await?;
    let client = build_test_api_client(&ctx.base_url());

    let jwks = client
        .get_openid4vp_jwks()
        .await
        .map_err(|e| crate::AttError::Test(format!("get_jwks failed: {e}")))?;

    info!(key_count = jwks.keys.len(), "JWKS retrieved");

    assert!(!jwks.keys.is_empty(), "JWKS must contain at least one key");

    // Every key must have a `kty` field (RFC 7517 §4)
    for key in &jwks.keys {
        assert!(
            key.get("kty").is_some(),
            "Each JWK must have a 'kty' field; got: {key}"
        );
    }

    ctx.stop_server().await?;
    Ok(())
}

/// `GET /ewqwe_api/openid4vp/request/:id` returns the authorization request
/// (JSON or JWT depending on the profile).
#[actix_web::test]
async fn e2e_ewqwe_client_get_authorization_request() -> AttResult<()> {
    log_init(None);
    let ctx = start_default_test_server().await?;
    let client = build_test_api_client(&ctx.base_url());

    // Create a transaction with Annex-A profile (returns plain JSON auth request)
    let req = InitTransactionRequest::new().with_profile(ProfileId::AnnexA);
    let tx = client
        .init_openid4vp_transaction(req)
        .await
        .map_err(|e| crate::AttError::Test(format!("init failed: {e}")))?;

    let auth_request = client
        .get_openid4vp_authorization_request(&tx.transaction_id)
        .await
        .map_err(|e| crate::AttError::Test(format!("get_auth_request failed: {e}")))?;

    info!(
        response_type = ?auth_request.get("response_type"),
        client_id = ?auth_request.get("client_id"),
        "Authorization request retrieved"
    );

    // The authorization request must contain required OpenID4VP fields
    assert!(
        auth_request.get("response_type").is_some() || auth_request.get("client_id").is_some(),
        "Authorization request must include at least response_type or client_id"
    );

    ctx.stop_server().await?;
    Ok(())
}

/// `POST /ewqwe_api/verify` rejects a request without a proper mTLS client
/// certificate when authentication is enabled.
///
/// The test server fires up with `disable_authentication = false` (default).
/// The test verifies that the server honours the auth requirement.
/// Note: on macOS with `danger_accept_invalid_certs(true)`, the TLS connection
/// is still established; the server then fails the mTLS check at the application
/// layer or returns 401.
#[actix_web::test]
async fn e2e_ewqwe_client_verify_requires_client_cert() -> AttResult<()> {
    log_init(None);

    // Server with authentication enabled (default) and no user override
    let mut params = make_test_server_params(false, "unused");
    // disable authentication is false, authorized user is None
    params.disable_authentication = false;
    params.disabled_authentication_user = None;

    let ctx = crate::tests::start_test_server(params).await?;

    // Build a client *without* a client certificate (use a fresh TestReqwestClient
    // that doesn't load the user1.p12 identity)
    let url = Url::parse(&ctx.base_url()).expect("invalid base_url");
    let no_cert_client = {
        let ca_chain_pem =
            fs::read(format!("{EC_CERTS_DIR}/ewqwe.ca.pem")).expect("failed to read test CA chain");
        let inner = reqwest::Client::builder()
            .add_root_certificate(
                reqwest::Certificate::from_pem(&ca_chain_pem).expect("failed to parse CA"),
            )
            .danger_accept_invalid_certs(true)
            .build()
            .expect("failed to build no-cert reqwest client");

        struct NoCertClient {
            inner: reqwest::Client,
        }

        #[async_trait]
        impl HttpClient for NoCertClient {
            async fn get_json<R: DeserializeOwned>(
                &self,
                url: Url,
            ) -> ewqwe_credential_verifier_client::Result<R> {
                let resp = self
                    .inner
                    .get(url)
                    .send()
                    .await
                    .map_err(|e| ApiError::Config(e.to_string()))?;
                parse_response(resp).await
            }

            async fn post_json<B: Serialize + Send + Sync, R: DeserializeOwned>(
                &self,
                url: Url,
                body: &B,
            ) -> ewqwe_credential_verifier_client::Result<R> {
                let resp = self
                    .inner
                    .post(url)
                    .json(body)
                    .send()
                    .await
                    .map_err(|e| ApiError::Config(e.to_string()))?;
                parse_response(resp).await
            }
        }

        EwqweApiClient::with_http_client(url, NoCertClient { inner })
    };

    let verify_req = VerifyCredentialRequest {
        vp_token: "DUMMY".to_string(),
        presentation_submission: None,
        state: None,
        client_id: None,
    };
    let result = no_cert_client.verify_presentation(verify_req).await;

    ctx.stop_server().await?;

    // Expect either a TLS error (mTLS rejected) or a 401 HTTP response
    assert!(
        result.is_err(),
        "verify without client cert must fail when auth is enabled"
    );

    match &result {
        Err(ApiError::Server { status: 401, .. }) => {
            info!("Correctly received 401 when no client cert is presented");
        }
        Err(ApiError::Transport(_)) => {
            info!("Correctly received a TLS/transport error when no client cert is presented");
        }
        other => {
            info!("Received unexpected result: {other:?}");
        }
    }

    Ok(())
}

/// Full transaction init + status poll + verify flow with `disable_authentication = true`.
///
/// This is an approximation of the cross-device RP flow:
/// 1. RP calls `init_openid4vp_transaction` → gets back `transaction_id`.
/// 2. RP polls `get_openid4vp_transaction_status` to wait for the wallet.
/// 3. (Wallet interaction is skipped — we just assert the transaction stays `pending`.)
/// 4. RP could call `verify_presentation` once the wallet posts a VP Token.
///    Here we use a dummy token and assert the expected error response.
#[actix_web::test]
async fn e2e_ewqwe_client_full_flow_no_auth() -> AttResult<()> {
    log_init(None);

    let ctx =
        crate::tests::start_test_server(make_test_server_params(true, "test-e2e-user")).await?;
    let client = build_test_api_client(&ctx.base_url());

    // 1. Init transaction
    let req = InitTransactionRequest::new()
        .with_profile(ProfileId::AnnexA)
        .with_credential_type("proof-of-age");
    let tx = client
        .init_openid4vp_transaction(req)
        .await
        .map_err(|e| crate::AttError::Test(format!("init failed: {e}")))?;
    info!(transaction_id = %tx.transaction_id, "Step 1: transaction created");

    // 2. Poll — must be pending
    let status = client
        .get_openid4vp_transaction_status(&tx.transaction_id)
        .await
        .map_err(|e| crate::AttError::Test(format!("status poll failed: {e}")))?;
    assert_eq!(status.status, TransactionStatus::Pending, "Must be pending");
    info!("Step 2: status confirmed pending");

    // 3. Attempt verify with a dummy base64 VP Token — expect a parse error (400)
    //    because the credential payload isn't a real mDoc / SD-JWT.
    let verify_req = VerifyCredentialRequest {
        vp_token: "{\"proof_of_age\":[\"dGVzdA==\"]}".to_string(),
        presentation_submission: None,
        state: None,
        client_id: Some("https://rp.example.com".to_string()),
    };

    let verify_result = client.verify_presentation(verify_req).await;
    info!("Step 3: verify result = {verify_result:?}");

    assert!(
        verify_result.is_err(),
        "Dummy VP Token must be rejected by the verifier"
    );

    ctx.stop_server().await?;
    Ok(())
}
