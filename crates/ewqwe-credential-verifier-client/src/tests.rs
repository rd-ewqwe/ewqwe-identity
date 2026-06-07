/*!
Unit tests for `ewqwe_digital_identity`.

Tests are organized in per-module sub-modules mirroring the library layout:

- `models` — field serialization / deserialization round-trips
- `client` — transport injection and endpoint mapping using a `mockito` HTTP server
- `errors` — error variant construction and display

These tests do **not** start the real credential-verifier server.
End-to-end tests that exercise the live server live in
`credential_verifier/src/tests/end_to_end_tests/`.
*/

use crate::{
    ApiError, ClientOptions, DefaultHttpClient, EwqweApiClient, InitTransactionRequest,
    InitTransactionResponse, JwkSet, TransactionStatusResult, VerifyCredentialRequest,
    VerifyCredentialResponse, VersionResponse,
};
use url::Url;

/// Minimal `HttpClient` stub that always returns the JSON supplied at construction.
///
/// Used to test that [`EwqweApiClient`] calls the correct endpoint paths / methods
/// without going to a real HTTP server.
mod stub {
    use crate::{ApiError, HttpClient, Result};
    use async_trait::async_trait;
    use serde::{Serialize, de::DeserializeOwned};
    use serde_json::Value;
    use url::Url;

    /// Records every call made to it so the test can assert on URLs.
    pub struct StubHttpClient {
        pub response: Value,
        pub calls: std::sync::Mutex<Vec<(String, String)>>, // (method, url)
    }

    impl StubHttpClient {
        pub fn new(response: Value) -> Self {
            Self {
                response,
                calls: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn record(&self, method: &str, url: &Url) {
            self.calls
                .lock()
                .unwrap()
                .push((method.to_string(), url.to_string()));
        }
    }

    #[async_trait]
    impl HttpClient for StubHttpClient {
        async fn get_json<R: DeserializeOwned>(&self, url: Url) -> Result<R> {
            self.record("GET", &url);
            serde_json::from_value(self.response.clone()).map_err(ApiError::Decode)
        }

        async fn post_json<B: Serialize + Send + Sync, R: DeserializeOwned>(
            &self,
            url: Url,
            _body: &B,
        ) -> Result<R> {
            self.record("POST", &url);
            serde_json::from_value(self.response.clone()).map_err(ApiError::Decode)
        }
    }
}

use stub::StubHttpClient;

// ============================================================================
// Model serialization / deserialization
// ============================================================================

mod models {
    use super::*;
    use ewqwe_openid4vp::{
        ClaimsPathComponent, ClientIdScheme, DCQLClaimsQuery, DCQLCredentialMeta,
        DCQLCredentialQuery, DCQLQuery, ProfileId, TransactionStatus,
    };
    use serde_json::json;

    #[test]
    fn init_request_minimal_serializes() {
        let req = InitTransactionRequest::new();
        let json = serde_json::to_value(&req).unwrap();

        // Optional fields should be absent
        assert!(json.get("dcql_query").is_none());
        assert!(json.get("nonce").is_none());
        assert!(json.get("profile").is_none());
        assert!(json.get("credential_type").is_none());
    }

    #[test]
    fn init_request_builder_methods() {
        let req = InitTransactionRequest::new()
            .with_credential_type("mdl")
            .with_profile(ProfileId::Haip);

        assert_eq!(req.credential_type.as_deref(), Some("mdl"));
        assert_eq!(req.profile, Some(ProfileId::Haip));
    }

    #[test]
    fn init_request_with_dcql_query() {
        let query = DCQLQuery {
            credentials: vec![DCQLCredentialQuery {
                id: "age_proof".to_string(),
                format: "mso_mdoc".to_string(),
                meta: DCQLCredentialMeta {
                    doctype_value: Some("org.iso.18013.5.1.mDL".to_string()),
                    ..Default::default()
                },
                claims: Some(vec![DCQLClaimsQuery {
                    id: None,
                    path: vec![
                        ClaimsPathComponent::Key("org.iso.18013.5.1".into()),
                        ClaimsPathComponent::Key("age_over_18".into()),
                    ],
                    values: None,
                    intent_to_retain: None,
                }]),
                claim_sets: None,
                multiple: None,
                trusted_authorities: None,
                require_cryptographic_holder_binding: None,
            }],
            credential_sets: None,
        };

        let req = InitTransactionRequest::new().with_dcql_query(query);
        let json = serde_json::to_value(&req).unwrap();

        assert_eq!(json["dcql_query"]["credentials"][0]["id"], "age_proof");
        assert_eq!(
            json["dcql_query"]["credentials"][0]["meta"]["doctype_value"],
            "org.iso.18013.5.1.mDL"
        );
        assert_eq!(
            json["dcql_query"]["credentials"][0]["claims"][0]["path"][0],
            "org.iso.18013.5.1"
        );
    }

    #[test]
    fn init_response_deserializes() {
        let json = json!({
            "transaction_id": "txn-abc123",
            "client_id": "x509_san_dns:demo.ewqwe.local",
            "client_id_scheme": "x509_san_dns",
            "request_uri": "https://rp.example.com/ewqwe_api/openid4vp/request/txn-abc123",
            "authorization_request_uri": "eudi-openid4vp://?request_uri=...",
            "expires_in": 60,
            "profile": "haip",
            "qr_code_data_url": "data:image/svg+xml;base64,PHN2Zy8+"
        });

        let resp: InitTransactionResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.transaction_id, "txn-abc123");
        assert_eq!(resp.client_id_scheme, ClientIdScheme::X509SanDns);
        assert_eq!(resp.expires_in, 60);
        assert_eq!(resp.profile, ProfileId::Haip);
        assert!(resp.qr_code_data_url.is_some());
    }

    #[test]
    fn init_response_without_qr_code() {
        let json = json!({
            "transaction_id": "txn-xyz",
            "client_id": "redirect_uri:https://rp.example.com",
            "client_id_scheme": "redirect_uri",
            "request_uri": "https://rp.example.com/request/txn-xyz",
            "authorization_request_uri": "openid4vp://?request_uri=https://rp.example.com/request/txn-xyz",
            "expires_in": 300,
            "profile": "annex-a"
        });

        let resp: InitTransactionResponse = serde_json::from_value(json).unwrap();
        assert!(resp.qr_code_data_url.is_none());
    }

    #[test]
    fn transaction_status_pending_deserializes() {
        let json = json!({ "status": "pending", "expires_in": 55 });
        let result: TransactionStatusResult = serde_json::from_value(json).unwrap();

        assert_eq!(result.status, TransactionStatus::Pending);
        assert_eq!(result.expires_in, Some(55));
        assert!(result.authorization_response.is_none());
    }

    #[test]
    fn transaction_status_error_with_wallet_error() {
        let json = json!({
            "status": "error",
            "wallet_error": {
                "error": "access_denied",
                "error_description": "User denied consent",
                "state": "my-oauth-state"
            }
        });

        let result: TransactionStatusResult = serde_json::from_value(json).unwrap();
        assert_eq!(result.status, TransactionStatus::Error);
        let we = result.wallet_error.unwrap();
        assert_eq!(we.error, "access_denied");
        assert_eq!(we.error_description.as_deref(), Some("User denied consent"));
        assert_eq!(we.state.as_deref(), Some("my-oauth-state"));
    }

    #[test]
    fn transaction_status_verified_serializes() {
        let status = TransactionStatus::Verified;
        let json = serde_json::to_value(status).unwrap();
        assert_eq!(json, "verified");
    }

    #[test]
    fn transaction_status_expired_round_trips() {
        let json = json!({ "status": "expired" });
        let result: TransactionStatusResult = serde_json::from_value(json).unwrap();
        assert_eq!(result.status, TransactionStatus::Expired);
    }

    #[test]
    fn verify_request_builder() {
        let req = VerifyCredentialRequest {
            vp_token: "eyJhbGci...truncated".to_string(),
            presentation_submission: None,
            state: Some("my-state".to_string()),
            client_id: Some("x509_san_dns:demo.ewqwe.local".to_string()),
        };

        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["vp_token"], "eyJhbGci...truncated");
        assert_eq!(json["state"], "my-state");
        assert_eq!(json["client_id"], "x509_san_dns:demo.ewqwe.local");
        assert!(json.get("presentation_submission").is_none());
    }

    #[test]
    fn verify_response_deserializes() {
        let json = json!({
            "success": true,
            "message": "Age verification successful",
            "attestation": "eyJhbGciOiJFUzI1NiJ9.stub.sig",
            "verification_details": {
                "signature_valid": true,
                "not_expired": true,
                "issuer_trusted": true
            }
        });

        let resp: VerifyCredentialResponse = serde_json::from_value(json).unwrap();
        assert!(resp.success);
        assert_eq!(resp.attestation, "eyJhbGciOiJFUzI1NiJ9.stub.sig");
        let vd = resp.verification_details.unwrap();
        assert!(vd.signature_valid && vd.not_expired && vd.issuer_trusted);
    }

    #[test]
    fn verify_response_failed_with_errors() {
        let json = json!({
            "success": false,
            "message": "Credential expired",
            "attestation": "",
            "errors": ["not_expired check failed"]
        });

        let resp: VerifyCredentialResponse = serde_json::from_value(json).unwrap();
        assert!(!resp.success);
        assert_eq!(resp.errors.unwrap(), vec!["not_expired check failed"]);
    }

    #[test]
    fn jwk_set_deserializes() {
        let json = json!({
            "keys": [
                { "kty": "EC", "crv": "P-256", "x": "abc", "y": "def", "kid": "key1" }
            ]
        });

        let jwks: JwkSet = serde_json::from_value(json).unwrap();
        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(jwks.keys[0]["kty"], "EC");
    }

    #[test]
    fn version_response_deserializes() {
        let json = json!({ "version": "0.1.0" });
        let v: VersionResponse = serde_json::from_value(json).unwrap();
        assert_eq!(v.version, "0.1.0");
    }
}

// ============================================================================
// Client endpoint routing (transport-injected StubHttpClient)
// ============================================================================

mod client {
    use super::*;
    use ewqwe_openid4vp::TransactionStatus;
    use serde_json::json;
    use std::sync::Arc;

    fn make_client(response: serde_json::Value) -> EwqweApiClient<Arc<StubHttpClient>> {
        let base_url = Url::parse("https://verifier.example.com").unwrap();
        let stub = Arc::new(StubHttpClient::new(response));
        EwqweApiClient::with_http_client(base_url, stub)
    }

    #[tokio::test]
    async fn init_transaction_posts_to_correct_url() {
        let stub_resp = json!({
            "transaction_id": "txn-1",
            "client_id": "x509_san_dns:demo.ewqwe.local",
            "client_id_scheme": "x509_san_dns",
            "request_uri": "https://rp.example.com/request/txn-1",
            "authorization_request_uri": "eudi-openid4vp://?request_uri=...",
            "expires_in": 60,
            "profile": "haip"
        });

        let base = Url::parse("https://verifier.example.com").unwrap();
        let stub = Arc::new(StubHttpClient::new(stub_resp));
        let client = EwqweApiClient::with_http_client(base, Arc::clone(&stub));

        let req = InitTransactionRequest::new();
        let resp = client.init_openid4vp_transaction(req).await.unwrap();

        assert_eq!(resp.transaction_id, "txn-1");

        let calls = stub.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "POST");
        assert!(calls[0].1.ends_with("/ewqwe_api/openid4vp/init"));
    }

    #[tokio::test]
    async fn get_status_uses_correct_path() {
        let stub_resp = json!({ "status": "pending", "expires_in": 45 });
        let base = Url::parse("https://verifier.example.com").unwrap();
        let stub = Arc::new(StubHttpClient::new(stub_resp));
        let client = EwqweApiClient::with_http_client(base, Arc::clone(&stub));

        let result = client
            .get_openid4vp_transaction_status("my-txn-id")
            .await
            .unwrap();

        assert_eq!(result.status, TransactionStatus::Pending);

        let calls = stub.calls.lock().unwrap();
        assert!(calls[0].1.contains("/ewqwe_api/openid4vp/status/my-txn-id"));
    }

    #[tokio::test]
    async fn get_status_url_encodes_slashes_in_id() {
        let stub_resp = json!({ "status": "pending" });
        let base = Url::parse("https://verifier.example.com").unwrap();
        let stub = Arc::new(StubHttpClient::new(stub_resp));
        let client = EwqweApiClient::with_http_client(base, Arc::clone(&stub));

        client
            .get_openid4vp_transaction_status("id/with/slashes")
            .await
            .unwrap();

        let calls = stub.calls.lock().unwrap();
        // "/" must not appear unescaped in the path segment
        assert!(!calls[0].1.contains("/id/with/slashes"));
        assert!(calls[0].1.contains("id%2Fwith%2Fslashes"));
    }

    #[tokio::test]
    async fn get_authorization_request_uses_get() {
        let stub_resp = json!({ "client_id": "x509_san_dns:demo.ewqwe.local" });
        let base = Url::parse("https://verifier.example.com").unwrap();
        let stub = Arc::new(StubHttpClient::new(stub_resp));
        let client = EwqweApiClient::with_http_client(base, Arc::clone(&stub));

        client
            .get_openid4vp_authorization_request("txn-42")
            .await
            .unwrap();

        let calls = stub.calls.lock().unwrap();
        assert_eq!(calls[0].0, "GET");
        assert!(calls[0].1.contains("/ewqwe_api/openid4vp/request/txn-42"));
    }

    #[tokio::test]
    async fn get_jwks_uses_correct_path() {
        let stub_resp = json!({ "keys": [] });
        let client = make_client(stub_resp);

        let jwks = client.get_openid4vp_jwks().await.unwrap();
        assert_eq!(jwks.keys.len(), 0);
    }

    #[tokio::test]
    async fn verify_presentation_posts_to_verify() {
        let stub_resp = json!({
            "success": true,
            "message": "OK",
            "attestation": "eyJ.stub.sig"
        });
        let base = Url::parse("https://verifier.example.com").unwrap();
        let stub = Arc::new(StubHttpClient::new(stub_resp));
        let client = EwqweApiClient::with_http_client(base, Arc::clone(&stub));

        let req = VerifyCredentialRequest {
            vp_token: "{\"age_proof\":[\"base64...\"]}".to_string(),
            presentation_submission: None,
            state: None,
            client_id: None,
        };
        let resp = client.verify_presentation(req).await.unwrap();

        assert!(resp.success);

        let calls = stub.calls.lock().unwrap();
        assert_eq!(calls[0].0, "POST");
        assert!(calls[0].1.ends_with("/ewqwe_api/verify"));
    }

    #[tokio::test]
    async fn get_version_uses_get() {
        let stub_resp = json!({ "version": "1.2.3" });
        let base = Url::parse("https://verifier.example.com").unwrap();
        let stub = Arc::new(StubHttpClient::new(stub_resp));
        let client = EwqweApiClient::with_http_client(base, Arc::clone(&stub));

        let v = client.get_version().await.unwrap();
        assert_eq!(v.version, "1.2.3");

        let calls = stub.calls.lock().unwrap();
        assert_eq!(calls[0].0, "GET");
        assert!(calls[0].1.ends_with("/version"));
    }
}

// ============================================================================
// ClientOptions
// ============================================================================

mod options {
    use super::*;

    #[test]
    fn new_parses_valid_url() {
        let opts = ClientOptions::new("https://localhost:9443").unwrap();
        assert_eq!(opts.base_url.port(), Some(9443));
        assert!(opts.ca_cert_pem.is_none());
        assert!(opts.client_cert_pem.is_none());
    }

    #[test]
    fn new_rejects_invalid_url() {
        let err = ClientOptions::new("not a url at all").unwrap_err();
        assert!(matches!(err, ApiError::Config(_)));
    }

    #[test]
    fn with_ca_cert_sets_field() {
        let opts = ClientOptions::new("https://localhost:9443")
            .unwrap()
            .with_ca_cert("-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----\n");
        assert!(opts.ca_cert_pem.is_some());
    }

    #[test]
    fn with_client_cert_sets_both_fields() {
        let opts = ClientOptions::new("https://localhost:9443")
            .unwrap()
            .with_client_cert("CERT_PEM", "KEY_PEM");
        assert_eq!(opts.client_cert_pem.as_deref(), Some("CERT_PEM"));
        assert_eq!(opts.client_key_pem.as_deref(), Some("KEY_PEM"));
    }
}

// ============================================================================
// Error types
// ============================================================================

mod errors {
    use super::*;

    #[test]
    fn api_error_server_display() {
        let err = ApiError::Server {
            status: 404,
            body: "not found".to_string(),
        };
        let display = format!("{err}");
        assert!(display.contains("404"));
        assert!(display.contains("not found"));
    }

    #[test]
    fn api_error_config_display() {
        let err = ApiError::Config("bad option".to_string());
        let display = format!("{err}");
        assert!(display.contains("bad option"));
    }

    #[test]
    fn api_error_decode_from_bad_json() {
        let json = serde_json::json!({ "unexpected_field": 1 });
        // Deserializing this as VersionResponse should fail: `version` is missing
        let result: std::result::Result<VersionResponse, _> =
            serde_json::from_value(json).map_err(ApiError::Decode);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ApiError::Decode(_)));
    }
}

// ============================================================================
// DefaultHttpClient — build errors (no live server required)
// ============================================================================

mod default_client {
    use super::*;

    #[test]
    fn build_succeeds_with_no_tls_options() {
        let opts = ClientOptions::new("https://localhost:9443").unwrap();
        assert!(DefaultHttpClient::build(opts).is_ok());
    }
}
