//! OpenID4VP Service — Transaction Lifecycle Orchestrator.
//!
//! Manages the full OpenID4VP authorization flow:
//! 1. **Initialize transactions** — build DCQL, generate IDs, construct auth request URIs
//! 2. **Serve authorization requests** — signed JAR (HAIP) or plain JSON (Annex A)
//! 3. **Receive wallet responses** — JWE decryption (HAIP) or plain (Annex A)
//! 4. **Poll transaction status** — returns VP token when available
//! 5. **Provide public JWKS** — for wallet signature verification
//!
//! This service is transport-agnostic — it accepts and returns plain data objects,
//! never HTTP Request/Response. The server layer maps HTTP ↔ service calls.
//!
//! # References
//!
//! - [OpenID4VP 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
//! - [RFC 9101 — JAR](https://www.rfc-editor.org/rfc/rfc9101)
//! - [RFC 7516 — JWE](https://www.rfc-editor.org/rfc/rfc7516)

use crate::{
    crypto::{
        DecryptedWalletResponse, JarKeyMaterial, JarPayload, JweKeyMaterial, build_public_jwk_set,
        decrypt_jwe_response, initialize_jar_key, initialize_jwe_key, sign_jar,
    },
    dcql::get_default_age_verification_dcql,
    error::{OpenID4VPError, OpenID4VPResult},
    transaction::TransactionStore,
    types::{
        AuthorizationRequestResult, ClientIdScheme, ClientMetadata, DCQLQuery,
        InitTransactionRequest, InitTransactionResponse, OpenID4VPTransaction, ProfileId,
        ResponseMode, TransactionStatus, TransactionStatusResult, WalletDirectPostData,
    },
};

use crate::config::determine_profile;

const DEFAULT_TRANSACTION_TTL_MS: i64 = 5 * 60 * 1000; // 5 minutes
const JAR_KEY_ID: &str = "ewqwe-jar-key-1";
const JWE_KEY_ID: &str = "ewqwe-enc-key-1";

// ============================================================================
// Configuration
// ============================================================================

/// Configuration required to initialize the OpenID4VP service.
#[derive(Debug, Clone)]
pub struct OpenID4VPServiceConfig {
    /// Path to X.509 certificate chain PEM (for JAR signing).
    pub x509_cert_path: String,
    /// Path to private key PEM (for JAR signing).
    pub x509_key_path: String,
    /// Transaction TTL in milliseconds (default: 5 minutes).
    pub transaction_ttl_ms: Option<i64>,
}

// ============================================================================
// Service
// ============================================================================

/// OpenID4VP Relying Party service.
///
/// Orchestrates the full OpenID4VP transaction lifecycle. Create with
/// [`OpenID4VPService::create`], which loads keys and starts background cleanup.
///
/// # Thread Safety
///
/// The service is `Send + Sync` and can be shared across actix-web handlers
/// via `web::Data<OpenID4VPService>`.
pub struct OpenID4VPService {
    jar_key: JarKeyMaterial,
    jwe_key: JweKeyMaterial,
    transactions: TransactionStore,
    ttl_ms: i64,
}

impl OpenID4VPService {
    /// Create and initialize an OpenID4VP service instance.
    ///
    /// Loads JAR signing key + certificate chain from PEM files, generates
    /// an ECDH encryption key pair for JWE, and starts background transaction
    /// cleanup.
    pub fn create(config: OpenID4VPServiceConfig) -> OpenID4VPResult<Self> {
        let cert_pem = std::fs::read_to_string(&config.x509_cert_path).map_err(|e| {
            OpenID4VPError::Config(format!(
                "Failed to read certificate from {}: {e}",
                config.x509_cert_path
            ))
        })?;
        let key_pem = std::fs::read_to_string(&config.x509_key_path).map_err(|e| {
            OpenID4VPError::Config(format!(
                "Failed to read private key from {}: {e}",
                config.x509_key_path
            ))
        })?;

        let jar_key = initialize_jar_key(&cert_pem, &key_pem, JAR_KEY_ID)?;
        let jwe_key = initialize_jwe_key(JWE_KEY_ID)?;
        let ttl_ms = config
            .transaction_ttl_ms
            .unwrap_or(DEFAULT_TRANSACTION_TTL_MS);

        let transactions = TransactionStore::new();
        transactions.start_cleanup(ttl_ms as u64);

        tracing::info!(
            san = %jar_key.san_dns_name,
            ttl_secs = ttl_ms / 1000,
            "OpenID4VP service initialized"
        );

        Ok(Self {
            jar_key,
            jwe_key,
            transactions,
            ttl_ms,
        })
    }

    /// Shut down the service (stop background cleanup).
    pub fn shutdown(&self) {
        self.transactions.stop_cleanup();
        tracing::info!("OpenID4VP service shut down");
    }

    // ========================================================================
    // Transaction Lifecycle
    // ========================================================================

    /// Initialize a new OpenID4VP transaction.
    ///
    /// Builds the DCQL query, authorization request URI, and returns data for
    /// the QR code (cross-device) or deep link (same-device).
    ///
    /// The `public_url` in the request tells the service which URL the wallet
    /// should use for `response_uri` and `request_uri` (since the RP proxies
    /// wallet traffic to this service).
    pub fn init_transaction(
        &self,
        request: InitTransactionRequest,
    ) -> OpenID4VPResult<InitTransactionResponse> {
        let profile = determine_profile(request.credential_type.as_deref(), request.profile);

        let transaction_id = uuid::Uuid::new_v4().to_string();
        let state = uuid::Uuid::new_v4().to_string();
        let nonce = request
            .nonce
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let now = chrono::Utc::now().timestamp_millis();
        let expires_at = now + self.ttl_ms;

        let public_url = request.public_url.trim_end_matches('/');
        let response_uri = format!("{public_url}/api/openid4vp/direct_post");
        let request_uri = format!("{public_url}/api/openid4vp/request/{transaction_id}");

        // Determine client_id, scheme, response_mode, and URL scheme per profile
        let (client_id, client_id_scheme, response_mode, url_scheme) = match profile {
            ProfileId::Haip => (
                format!("x509_san_dns:{}", self.jar_key.san_dns_name),
                ClientIdScheme::X509SanDns,
                ResponseMode::DirectPostJwt,
                "eudi-openid4vp://",
            ),
            ProfileId::AnnexA => (
                format!("redirect_uri:{response_uri}"),
                ClientIdScheme::RedirectUri,
                ResponseMode::DirectPost,
                "av://",
            ),
        };

        // Resolve DCQL query
        let dcql_query = if let Some(q) = request.dcql_query {
            q
        } else {
            get_default_age_verification_dcql()
        };

        // Validate the DCQL query structure (§6 + §6.4.1)
        dcql_query
            .is_valid()
            .map_err(|msg| OpenID4VPError::BadRequest(format!("Invalid dcql_query: {msg}")))?;

        // Client metadata (use request-provided or defaults)
        let client_metadata = request.client_metadata.unwrap_or_else(|| {
            let mut meta = ClientMetadata::default();
            meta.logo_uri = Some(format!("{public_url}/logo.png"));
            meta
        });

        // Store the transaction
        let transaction = OpenID4VPTransaction {
            id: transaction_id.clone(),
            state: state.clone(),
            nonce: nonce.clone(),
            created_at: now,
            expires_at,
            status: TransactionStatus::Pending,
            dcql_query: dcql_query.clone(),
            client_id: client_id.clone(),
            client_id_scheme,
            response_uri: response_uri.clone(),
            response_mode,
            profile,
            wallet_response: None,
            verification_result: None,
            error_message: None,
            client_metadata: Some(client_metadata),
        };
        self.transactions.set(transaction);

        // Build authorization request URI
        let authorization_request_uri = self.build_authorization_request_uri(
            profile,
            url_scheme,
            &client_id,
            &request_uri,
            response_mode,
            &response_uri,
            &nonce,
            &state,
            &dcql_query,
            public_url,
        );

        tracing::info!(
            tx = %transaction_id[..8.min(transaction_id.len())],
            profile = %profile,
            client_id = %client_id,
            "Transaction created"
        );

        // Generate QR code SVG as a data URL so the frontend can display it
        // directly in an <img src> without any external API dependency.
        let qr_code_data_url = qrcode::QrCode::new(authorization_request_uri.as_bytes())
            .ok()
            .map(|code| {
                use base64::Engine as _;
                use qrcode::render::svg;
                let svg_str = code
                    .render::<svg::Color<'_>>()
                    .min_dimensions(256, 256)
                    .build();
                format!(
                    "data:image/svg+xml;base64,{}",
                    base64::engine::general_purpose::STANDARD.encode(svg_str.as_bytes())
                )
            });

        Ok(InitTransactionResponse {
            transaction_id,
            client_id,
            client_id_scheme,
            request_uri,
            authorization_request_uri,
            expires_in: self.ttl_ms / 1000,
            profile,
            qr_code_data_url,
        })
    }

    /// Build the authorization request that the wallet fetches via `request_uri`.
    ///
    /// Returns a signed JAR (HAIP) or plain JSON (Annex A).
    pub fn get_authorization_request(
        &self,
        transaction_id: &str,
    ) -> OpenID4VPResult<AuthorizationRequestResult> {
        let transaction = self
            .transactions
            .get(transaction_id)
            .ok_or_else(|| OpenID4VPError::NotFound("Transaction not found".into()))?;

        if self.transactions.is_expired(transaction_id) {
            return Err(OpenID4VPError::Expired("Transaction expired".into()));
        }

        // Build client_metadata with VP format capabilities.
        // `vp_formats` is typed as `VpFormats`; serialize to JSON for embedding in the request.
        let base_formats = transaction
            .client_metadata
            .as_ref()
            .and_then(|m| {
                m.vp_formats
                    .as_ref()
                    .map(|f| serde_json::to_value(f).unwrap_or_default())
            })
            .unwrap_or_else(|| {
                serde_json::json!({
                    "mso_mdoc": {
                        "issuerauth_alg_values": [-7, -35, -36],
                        "deviceauth_alg_values": [-7, -35, -36]
                    }
                })
            });

        let mut metadata = serde_json::json!({
            "client_name": transaction
                .client_metadata
                .as_ref()
                .and_then(|m| m.client_name.as_deref())
                .unwrap_or("ewQwe Client"),
            "logo_uri": transaction
                .client_metadata
                .as_ref()
                .and_then(|m| m.logo_uri.as_deref())
                .unwrap_or(""),
            "vp_formats_supported": base_formats,
        });

        // Add JWE encryption parameters for HAIP profile
        if transaction.profile == ProfileId::Haip {
            metadata["jwks"] = serde_json::json!({ "keys": [self.jwe_key.public_jwk.clone()] });
            metadata["authorization_encrypted_response_alg"] = "ECDH-ES".into();
            metadata["authorization_encrypted_response_enc"] = "A256GCM".into();
        }

        if transaction.profile == ProfileId::Haip {
            // HAIP: Signed JAR (RFC 9101)
            let jar_payload = JarPayload {
                client_id: transaction.client_id.clone(),
                client_id_scheme: transaction.client_id_scheme.to_string(),
                response_mode: transaction.response_mode.to_string(),
                response_uri: transaction.response_uri.clone(),
                state: transaction.state.clone(),
                nonce: transaction.nonce.clone(),
                dcql_query: serde_json::to_value(&transaction.dcql_query).unwrap_or_default(),
                client_metadata: metadata,
                expires_at_secs: transaction.expires_at / 1000,
            };

            let jwt = sign_jar(&jar_payload, &self.jar_key)?;
            Ok(AuthorizationRequestResult {
                body: jwt,
                content_type: "application/oauth-authz-req+jwt".to_string(),
            })
        } else {
            // Annex A: Plain JSON authorization request
            let auth_request = serde_json::json!({
                "client_id": transaction.client_id,
                "client_id_scheme": transaction.client_id_scheme.to_string(),
                "response_type": "vp_token",
                "response_mode": transaction.response_mode.to_string(),
                "response_uri": transaction.response_uri,
                "state": transaction.state,
                "nonce": transaction.nonce,
                "dcql_query": transaction.dcql_query,
                "client_metadata": metadata,
            });
            Ok(AuthorizationRequestResult {
                body: serde_json::to_string(&auth_request)
                    .map_err(|e| OpenID4VPError::Internal(format!("JSON serialization: {e}")))?,
                content_type: "application/json".to_string(),
            })
        }
    }

    /// Process a wallet `direct_post` response.
    ///
    /// For HAIP (`direct_post.jwt`), decrypts the JWE. For Annex A (`direct_post`),
    /// uses the plain data directly. Stores the response in the transaction.
    ///
    /// # Arguments
    ///
    /// * `data` — Pre-parsed wallet data (plain `direct_post` mode)
    /// * `jwe_response` — JWE compact serialization (`direct_post.jwt` mode)
    /// * `fallback_state` — State value from outside the JWE (some wallets duplicate it)
    pub fn handle_wallet_response(
        &self,
        data: Option<WalletDirectPostData>,
        jwe_response: Option<&str>,
        fallback_state: Option<&str>,
    ) -> OpenID4VPResult<()> {
        let wallet_data: WalletDirectPostData = if let Some(jwe) = jwe_response {
            // HAIP: Decrypt JWE
            let decrypted: DecryptedWalletResponse = decrypt_jwe_response(jwe, &self.jwe_key)?;
            let state = if decrypted.state.is_empty() {
                fallback_state.unwrap_or("").to_string()
            } else {
                decrypted.state
            };
            WalletDirectPostData {
                vp_token: decrypted.vp_token,
                presentation_submission: decrypted.presentation_submission,
                state,
            }
        } else if let Some(d) = data {
            d
        } else {
            return Err(OpenID4VPError::BadRequest(
                "No wallet response data provided".into(),
            ));
        };

        // Find transaction by state and update it
        let found = self.transactions.update_by_state(&wallet_data.state, |tx| {
            tx.wallet_response = Some(wallet_data.clone());
            tx.status = TransactionStatus::Received;
        });

        if found.is_none() {
            return Err(OpenID4VPError::BadRequest(format!(
                "No transaction found for state: {}",
                wallet_data.state
            )));
        }

        tracing::info!(state = %wallet_data.state, "Transaction status → received");
        Ok(())
    }

    /// Get the current status of a transaction.
    ///
    /// If the wallet has responded, includes the VP token for the frontend to verify.
    pub fn get_transaction_status(
        &self,
        transaction_id: &str,
    ) -> OpenID4VPResult<TransactionStatusResult> {
        let transaction = self
            .transactions
            .get(transaction_id)
            .ok_or_else(|| OpenID4VPError::NotFound("Transaction not found".into()))?;

        if self.transactions.is_expired(transaction_id) {
            return Ok(TransactionStatusResult {
                status: TransactionStatus::Expired,
                expires_in: None,
                vp_token: None,
                presentation_submission: None,
                nonce: None,
                state: None,
                error_message: None,
            });
        }

        if transaction.status == TransactionStatus::Received {
            if let Some(ref wr) = transaction.wallet_response {
                return Ok(TransactionStatusResult {
                    status: TransactionStatus::Received,
                    expires_in: None,
                    vp_token: Some(wr.vp_token.clone()),
                    presentation_submission: wr.presentation_submission.clone(),
                    nonce: Some(transaction.nonce.clone()),
                    state: Some(transaction.state.clone()),
                    error_message: None,
                });
            }
        }

        let now = chrono::Utc::now().timestamp_millis();
        Ok(TransactionStatusResult {
            status: transaction.status,
            expires_in: Some((transaction.expires_at - now) / 1000),
            vp_token: None,
            presentation_submission: None,
            nonce: None,
            state: None,
            error_message: transaction.error_message.clone(),
        })
    }

    // ========================================================================
    // Public JWKS
    // ========================================================================

    /// Returns the public JWK Set for JAR signature verification.
    ///
    /// Serves at `.well-known/jwks.json` so wallets can verify the
    /// JWT Authorization Request signature.
    pub fn get_public_jwk_set(&self) -> serde_json::Value {
        build_public_jwk_set(&self.jar_key)
    }

    // ========================================================================
    // Private Helpers
    // ========================================================================

    #[allow(clippy::too_many_arguments)]
    fn build_authorization_request_uri(
        &self,
        profile: ProfileId,
        url_scheme: &str,
        client_id: &str,
        request_uri: &str,
        response_mode: ResponseMode,
        response_uri: &str,
        nonce: &str,
        state: &str,
        dcql_query: &DCQLQuery,
        public_url: &str,
    ) -> String {
        if profile == ProfileId::Haip {
            // HAIP: wallet fetches signed JAR from request_uri
            format!(
                "{}?client_id={}&request_uri={}",
                url_scheme,
                urlencoding::encode(client_id),
                urlencoding::encode(request_uri),
            )
        } else {
            // Annex A: all parameters inline
            let client_metadata = serde_json::json!({
                "client_name": "ewQwe Age Verification Demo",
                "logo_uri": format!("{public_url}/logo.png"),
                "vp_formats_supported": {
                    "mso_mdoc": {
                        "issuerauth_alg_values": [-7, -35, -36],
                        "deviceauth_alg_values": [-7, -35, -36]
                    }
                }
            });

            let mut params = url::form_urlencoded::Serializer::new(String::new());
            params.append_pair("client_id", client_id);
            params.append_pair("response_type", "vp_token");
            params.append_pair("response_mode", &response_mode.to_string());
            params.append_pair("response_uri", response_uri);
            params.append_pair("nonce", nonce);
            params.append_pair("state", state);
            params.append_pair(
                "dcql_query",
                &serde_json::to_string(dcql_query).unwrap_or_default(),
            );
            params.append_pair(
                "client_metadata",
                &serde_json::to_string(&client_metadata).unwrap_or_default(),
            );
            format!("{}?{}", url_scheme, params.finish())
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> OpenID4VPServiceConfig {
        let base = env!("CARGO_MANIFEST_DIR");
        let cert_dir = format!("{base}/../../credential_verifier/src/tests/certificates/ec");
        // Use the pre-built fullchain PEM (leaf + CA) for x5c
        let cert_path = format!("{cert_dir}/ewqwe.server.fullchain.pem");

        OpenID4VPServiceConfig {
            x509_cert_path: cert_path,
            x509_key_path: format!("{cert_dir}/ewqwe.server.key.pem"),
            transaction_ttl_ms: Some(60_000), // 1 minute for tests
        }
    }

    #[tokio::test]
    async fn test_service_create() {
        let config = test_config();
        let service = OpenID4VPService::create(config).unwrap();
        service.shutdown();
    }

    #[tokio::test]
    async fn test_init_transaction_annex_a() {
        let config = test_config();
        let service = OpenID4VPService::create(config).unwrap();

        let request = InitTransactionRequest {
            public_url: "https://rp.example.com".to_string(),
            dcql_query: None,
            nonce: Some("test-nonce-123".to_string()),
            client_metadata: None,
            profile: Some(ProfileId::AnnexA),
            credential_type: None,
        };

        let response = service.init_transaction(request).unwrap();

        assert!(!response.transaction_id.is_empty());
        assert!(response.client_id.starts_with("redirect_uri:"));
        assert_eq!(response.client_id_scheme, ClientIdScheme::RedirectUri);
        assert_eq!(response.profile, ProfileId::AnnexA);
        assert!(
            response
                .request_uri
                .starts_with("https://rp.example.com/api/openid4vp/request/")
        );
        assert!(response.authorization_request_uri.starts_with("av://"));
        assert!(response.expires_in > 0);

        service.shutdown();
    }

    #[tokio::test]
    async fn test_init_transaction_haip() {
        let config = test_config();
        let service = OpenID4VPService::create(config).unwrap();

        let request = InitTransactionRequest {
            public_url: "https://rp.example.com".to_string(),
            dcql_query: None,
            nonce: None,
            client_metadata: None,
            profile: Some(ProfileId::Haip),
            credential_type: None,
        };

        let response = service.init_transaction(request).unwrap();

        assert!(response.client_id.starts_with("x509_san_dns:"));
        assert_eq!(response.client_id_scheme, ClientIdScheme::X509SanDns);
        assert_eq!(response.profile, ProfileId::Haip);
        assert!(
            response
                .authorization_request_uri
                .starts_with("eudi-openid4vp://")
        );

        service.shutdown();
    }

    #[tokio::test]
    async fn test_get_authorization_request_annex_a() {
        let config = test_config();
        let service = OpenID4VPService::create(config).unwrap();

        let request = InitTransactionRequest {
            public_url: "https://rp.example.com".to_string(),
            dcql_query: None,
            nonce: None,
            client_metadata: None,
            profile: Some(ProfileId::AnnexA),
            credential_type: None,
        };

        let init_resp = service.init_transaction(request).unwrap();
        let auth_req = service
            .get_authorization_request(&init_resp.transaction_id)
            .unwrap();

        assert_eq!(auth_req.content_type, "application/json");
        let parsed: serde_json::Value = serde_json::from_str(&auth_req.body).unwrap();
        assert_eq!(parsed["response_type"], "vp_token");
        assert_eq!(parsed["response_mode"], "direct_post");
        assert!(parsed["dcql_query"].is_object());

        service.shutdown();
    }

    #[tokio::test]
    async fn test_get_authorization_request_haip() {
        let config = test_config();
        let service = OpenID4VPService::create(config).unwrap();

        let request = InitTransactionRequest {
            public_url: "https://rp.example.com".to_string(),
            dcql_query: None,
            nonce: None,
            client_metadata: None,
            profile: Some(ProfileId::Haip),
            credential_type: None,
        };

        let init_resp = service.init_transaction(request).unwrap();
        let auth_req = service
            .get_authorization_request(&init_resp.transaction_id)
            .unwrap();

        assert_eq!(auth_req.content_type, "application/oauth-authz-req+jwt");
        // JWT: 3 base64url parts separated by dots
        assert_eq!(auth_req.body.matches('.').count(), 2);

        service.shutdown();
    }

    #[tokio::test]
    async fn test_transaction_status_pending() {
        let config = test_config();
        let service = OpenID4VPService::create(config).unwrap();

        let request = InitTransactionRequest {
            public_url: "https://rp.example.com".to_string(),
            dcql_query: None,
            nonce: None,
            client_metadata: None,
            profile: Some(ProfileId::AnnexA),
            credential_type: None,
        };

        let init_resp = service.init_transaction(request).unwrap();
        let status = service
            .get_transaction_status(&init_resp.transaction_id)
            .unwrap();

        assert_eq!(status.status, TransactionStatus::Pending);
        assert!(status.expires_in.unwrap() > 0);
        assert!(status.vp_token.is_none());

        service.shutdown();
    }

    #[tokio::test]
    async fn test_handle_wallet_response_plain() {
        let config = test_config();
        let service = OpenID4VPService::create(config).unwrap();

        let request = InitTransactionRequest {
            public_url: "https://rp.example.com".to_string(),
            dcql_query: None,
            nonce: Some("test-nonce".to_string()),
            client_metadata: None,
            profile: Some(ProfileId::AnnexA),
            credential_type: None,
        };

        let init_resp = service.init_transaction(request).unwrap();

        // Extract the state from the authorization request
        let auth_req = service
            .get_authorization_request(&init_resp.transaction_id)
            .unwrap();
        let auth_json: serde_json::Value = serde_json::from_str(&auth_req.body).unwrap();
        let state = auth_json["state"].as_str().unwrap().to_string();

        // Simulate wallet direct_post response
        let wallet_data = WalletDirectPostData {
            vp_token: "test-vp-token-content".to_string(),
            presentation_submission: Some("test-submission".to_string()),
            state,
        };

        service
            .handle_wallet_response(Some(wallet_data), None, None)
            .unwrap();

        // Check status is now "received"
        let status = service
            .get_transaction_status(&init_resp.transaction_id)
            .unwrap();
        assert_eq!(status.status, TransactionStatus::Received);
        assert_eq!(status.vp_token.as_deref(), Some("test-vp-token-content"));
        assert_eq!(status.nonce.as_deref(), Some("test-nonce"));

        service.shutdown();
    }

    #[tokio::test]
    async fn test_handle_wallet_response_unknown_state() {
        let config = test_config();
        let service = OpenID4VPService::create(config).unwrap();

        let wallet_data = WalletDirectPostData {
            vp_token: "token".to_string(),
            presentation_submission: None,
            state: "unknown-state".to_string(),
        };

        let result = service.handle_wallet_response(Some(wallet_data), None, None);
        assert!(result.is_err());

        service.shutdown();
    }

    #[tokio::test]
    async fn test_get_transaction_status_not_found() {
        let config = test_config();
        let service = OpenID4VPService::create(config).unwrap();

        let result = service.get_transaction_status("nonexistent-id");
        assert!(result.is_err());

        service.shutdown();
    }

    #[tokio::test]
    async fn test_get_public_jwk_set() {
        let config = test_config();
        let service = OpenID4VPService::create(config).unwrap();

        let jwks = service.get_public_jwk_set();
        assert!(jwks["keys"].is_array());
        let keys = jwks["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["kty"], "EC");
        assert_eq!(keys[0]["alg"], "ES256");

        service.shutdown();
    }
}
