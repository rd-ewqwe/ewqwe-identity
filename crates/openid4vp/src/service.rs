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
    transaction::{DynTransactionStore, TransactionStore, TransactionStoreParams},
    types::{
        AuthorizationRequestResult, ClientIdScheme, ClientMetadata, DCQLQuery,
        InitTransactionRequest, InitTransactionResponse, OpenID4VPResponse, OpenID4VPTransaction,
        ProfileId, ResponseMode, TransactionStatus, TransactionStatusResult,
        WalletAuthorizationError,
    },
};

use crate::config::determine_profile;
use serde::{Deserialize, Serialize};

fn compute_jwk_thumbprint_bytes(jwk: &serde_json::Value) -> Option<Vec<u8>> {
    let obj = jwk.as_object()?;
    let canonical = match obj.get("kty")?.as_str()? {
        "EC" => serde_json::json!({
            "crv": obj.get("crv")?.as_str()?,
            "kty": "EC",
            "x": obj.get("x")?.as_str()?,
            "y": obj.get("y")?.as_str()?,
        }),
        "RSA" => serde_json::json!({
            "e": obj.get("e")?.as_str()?,
            "kty": "RSA",
            "n": obj.get("n")?.as_str()?,
        }),
        "OKP" => serde_json::json!({
            "crv": obj.get("crv")?.as_str()?,
            "kty": "OKP",
            "x": obj.get("x")?.as_str()?,
        }),
        _ => return None,
    };

    let canonical_json = serde_json::to_string(&canonical).ok()?;
    Some(openssl::sha::sha256(canonical_json.as_bytes()).to_vec())
}

const DEFAULT_TRANSACTION_TTL_SEC: i64 = 5 * 60; // 5 minutes
const JAR_KEY_ID: &str = "ewqwe-jar-key-1";
const JWE_KEY_ID: &str = "ewqwe-enc-key-1";

// ============================================================================
// Configuration
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HaipConfig {
    /// Path to X.509 certificate chain PEM (for JAR signing).
    pub x509_cert_path: String,

    /// Path to private key PEM (for JAR signing).
    pub x509_key_path: String,
}

/// Configuration required to initialize the OpenID4VP service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenID4VPServiceConfig {
    /// Time-to-live for transactions in seconds.
    /// Used for cleanup and expiration logic.
    /// Defaults to 5 minutes if not set.
    pub transaction_ttl_secs: Option<i64>,

    /// HAIP profile requires a certificate for JAR signing.
    pub haip_config: Option<HaipConfig>,

    /// Transaction store backend configuration.
    /// Defaults to SQLite in-memory when omitted.
    #[serde(default)]
    pub transaction_store: TransactionStoreParams,
}

// ============================================================================
// Service
// ============================================================================

/// OpenID4VP Relying Party service.
///
/// Orchestrates the full OpenID4VP transaction lifecycle. Create with
/// [`OpenID4VPService::create`], which loads keys and initialises the
/// configured transaction store.
///
/// # Thread Safety
///
/// The service is `Send + Sync` and can be shared across actix-web handlers
/// via `web::Data<OpenID4VPService>`.
pub struct OpenID4VPService {
    /// Key material for signing JARs (HAIP profile). If `None`,
    /// JAR signing is disabled and the service operates in Annex A mode.
    jar_key: Option<JarKeyMaterial>,

    /// Key material for JWE encryption (HAIP profile). If `None`, JWE encryption is disabled.
    jwe_key: Option<JweKeyMaterial>,

    /// Pluggable transaction store (SQLite / Postgres / Redis / in-memory).
    transactions: DynTransactionStore,

    /// Time-to-live for transactions in seconds. Used for cleanup and expiration logic.
    ttl_secs: i64,
}

impl OpenID4VPService {
    /// Create and initialize an OpenID4VP service instance.
    ///
    /// Loads JAR signing key + certificate chain from PEM files, generates
    /// an ECDH encryption key pair for JWE, and connects to (or initialises)
    /// the configured transaction store.
    pub async fn create(config: OpenID4VPServiceConfig) -> OpenID4VPResult<Self> {
        let (jar_key, jwe_key) = if let Some(haip_config) = &config.haip_config {
            tracing::info!("HAIP profile enabled — JAR signing configured");
            let cert_pem = std::fs::read_to_string(&haip_config.x509_cert_path).map_err(|e| {
                OpenID4VPError::Config(format!(
                    "Failed to read certificate from {}: {e}",
                    haip_config.x509_cert_path
                ))
            })?;
            let key_pem = std::fs::read_to_string(&haip_config.x509_key_path).map_err(|e| {
                OpenID4VPError::Config(format!(
                    "Failed to read private key from {}: {e}",
                    haip_config.x509_key_path
                ))
            })?;

            let jar_key = initialize_jar_key(&cert_pem, &key_pem, JAR_KEY_ID)?;
            let jwe_key = initialize_jwe_key(JWE_KEY_ID)?;
            (Some(jar_key), Some(jwe_key))
        } else {
            tracing::info!("No HAIP config provided — running in Annex A mode only");
            (None, None)
        };

        let ttl_secs = config
            .transaction_ttl_secs
            .unwrap_or(DEFAULT_TRANSACTION_TTL_SEC);

        let transactions = DynTransactionStore::new(&config.transaction_store, ttl_secs)
            .await
            .map_err(|e| {
                OpenID4VPError::Config(format!("Failed to initialise transaction store: {e}"))
            })?;

        tracing::info!(
            san = %jar_key.as_ref().map(|k| &k.san_dns_name).unwrap_or(&"N/A".to_string()),
            ttl_secs = ttl_secs,
            "OpenID4VP service initialized"
        );

        Ok(Self {
            jar_key,
            jwe_key,
            transactions,
            ttl_secs,
        })
    }

    /// Shut down the service.
    pub fn shutdown(&self) {
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
    pub async fn init_transaction(
        &self,
        request: InitTransactionRequest,
    ) -> OpenID4VPResult<InitTransactionResponse> {
        let profile = determine_profile(request.credential_type.as_deref(), request.profile);

        let transaction_id = uuid::Uuid::new_v4().to_string();
        let state = request
            .state
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let nonce = request
            .nonce
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let now = chrono::Utc::now().timestamp_millis();
        let expires_at = now + (self.ttl_secs * 1000);

        let public_url = request.public_url.trim_end_matches('/');
        let response_uri = format!("{public_url}/api/openid4vp/direct_post");
        let request_uri = format!("{public_url}/api/openid4vp/request/{transaction_id}");

        // Determine client_id, scheme, response_mode, and URL scheme per profile
        let (client_id, client_id_scheme, response_mode, url_scheme) = match profile {
            ProfileId::Haip => {
                let san_dns_name =
                    self.jar_key
                        .as_ref()
                        .map(|k| &k.san_dns_name)
                        .ok_or_else(|| {
                            OpenID4VPError::Config(
                                "Unable to initialize transaction: HAIP is not configured; the JAR keys are not configured".into(),
                            )
                        })?;
                (
                    format!("x509_san_dns:{}", san_dns_name),
                    ClientIdScheme::X509SanDns,
                    ResponseMode::DirectPostJwt,
                    "eudi-openid4vp://",
                )
            }
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
            wallet_error: None,
            verification_result: None,
            error_message: None,
            client_metadata: Some(client_metadata),
            transaction_data: request.transaction_data.clone(),
        };
        self.transactions.set(transaction).await?;

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
            expires_in: self.ttl_secs,
            profile,
            qr_code_data_url,
        })
    }

    /// Build the authorization request that the wallet fetches via `request_uri`.
    ///
    /// Returns a signed JAR (HAIP) or plain JSON (Annex A).
    pub async fn get_authorization_request(
        &self,
        transaction_id: &str,
    ) -> OpenID4VPResult<AuthorizationRequestResult> {
        if self.transactions.is_expired(transaction_id).await? {
            return Err(OpenID4VPError::Expired("Transaction expired".into()));
        }

        let transaction = self
            .transactions
            .get(transaction_id)
            .await?
            .ok_or_else(|| OpenID4VPError::NotFound("Transaction not found".into()))?;

        let jar_key = self.jar_key.as_ref().ok_or_else(|| {
            OpenID4VPError::Config(
                "Unable to build authorization request: HAIP is not configured; the JAR signing key is not configured".into(),
            )
        })?;

        let jwe_key = self.jwe_key.as_ref().ok_or_else(|| {
            OpenID4VPError::Config(
                "Unable to build authorization request: HAIP is not configured; the JWE encryption key is not configured".into(),
            )
        })?;

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
            metadata["jwks"] = serde_json::json!({ "keys": [jwe_key.public_jwk.clone()] });
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
                transaction_data: transaction.transaction_data.clone(),
            };

            let jwt = sign_jar(&jar_payload, jar_key)?;
            Ok(AuthorizationRequestResult {
                body: jwt,
                content_type: "application/oauth-authz-req+jwt".to_string(),
            })
        } else {
            // Annex A: Plain JSON authorization request
            let mut auth_request = serde_json::json!({
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
            // §8.4: include transaction_data when present
            if let Some(ref td) = transaction.transaction_data {
                if let Some(obj) = auth_request.as_object_mut() {
                    obj.insert(
                        "transaction_data".to_string(),
                        serde_json::Value::Array(
                            td.iter()
                                .map(|s| serde_json::Value::String(s.clone()))
                                .collect(),
                        ),
                    );
                }
            }
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
    pub async fn handle_wallet_response(
        &self,
        data: Option<OpenID4VPResponse>,
        jwe_response: Option<&str>,
        fallback_state: Option<&str>,
    ) -> OpenID4VPResult<()> {
        let wallet_data: OpenID4VPResponse = if let Some(jwe) = jwe_response {
            let jwe_key = self.jwe_key.as_ref().ok_or_else(|| {
                OpenID4VPError::Config(
                    "Unable to handle wallet response: HAIP is not configured; the JWE encryption key is not configured".into(),
                )
            })?;
            // HAIP: Decrypt JWE
            let decrypted: DecryptedWalletResponse = decrypt_jwe_response(jwe, &jwe_key)?;
            let state = if decrypted.state.is_empty() {
                fallback_state.unwrap_or("").to_string()
            } else {
                decrypted.state
            };
            OpenID4VPResponse {
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
        let found = self
            .transactions
            .update_by_state(&wallet_data.state, |tx| {
                tx.wallet_response = Some(wallet_data.clone());
                tx.status = TransactionStatus::Received;
            })
            .await?;

        if found.is_none() {
            return Err(OpenID4VPError::BadRequest(format!(
                "No transaction found for state: {}",
                wallet_data.state
            )));
        }

        tracing::info!(state = %wallet_data.state, "Transaction status → received");
        Ok(())
    }

    /// Handle a wallet error response sent to `direct_post` (§8.5).
    ///
    /// When the wallet cannot or will not fulfil the Authorization Request it sends
    /// `error=<code>&error_description=<text>&state=<state>` instead of a VP Token.
    /// The transaction is updated to `Error` status and the error details are stored
    /// so the frontend can retrieve them via the status endpoint.
    pub async fn handle_wallet_error(
        &self,
        error: WalletAuthorizationError,
    ) -> OpenID4VPResult<()> {
        let state = error.state.clone().unwrap_or_default();

        let found = self
            .transactions
            .update_by_state(&state, |tx| {
                tx.wallet_error = Some(error.clone());
                tx.status = TransactionStatus::Error;
            })
            .await?;

        if found.is_none() {
            return Err(OpenID4VPError::BadRequest(format!(
                "No transaction found for state: {state}"
            )));
        }

        tracing::warn!(
            state = %state,
            error_code = %error.error,
            "Transaction status → error (wallet error response §8.5)"
        );
        Ok(())
    }

    /// Get the current status of a transaction.
    ///
    /// If the wallet has responded, includes the VP token for the frontend to verify.
    pub async fn get_transaction_status(
        &self,
        transaction_id: &str,
    ) -> OpenID4VPResult<TransactionStatusResult> {
        if self.transactions.is_expired(transaction_id).await? {
            return Ok(TransactionStatusResult {
                status: TransactionStatus::Expired,
                expires_in: None,
                authorization_response: None,
                nonce: None,
                wallet_error: None,
                error_message: None,
                transaction_data: None,
            });
        }

        let transaction = self
            .transactions
            .get(transaction_id)
            .await?
            .ok_or_else(|| OpenID4VPError::NotFound("Transaction not found".into()))?;

        if transaction.status == TransactionStatus::Received {
            if let Some(ref wr) = transaction.wallet_response {
                return Ok(TransactionStatusResult {
                    status: TransactionStatus::Received,
                    expires_in: None,
                    authorization_response: Some(wr.clone()),
                    nonce: Some(transaction.nonce.clone()),
                    wallet_error: None,
                    error_message: None,
                    transaction_data: transaction.transaction_data.clone(),
                });
            }
        }

        if transaction.status == TransactionStatus::Error {
            return Ok(TransactionStatusResult {
                status: TransactionStatus::Error,
                expires_in: None,
                authorization_response: None,
                nonce: None,
                wallet_error: transaction.wallet_error.clone(),
                error_message: transaction.error_message.clone(),
                transaction_data: None,
            });
        }

        let now = chrono::Utc::now().timestamp_millis();
        Ok(TransactionStatusResult {
            status: transaction.status,
            expires_in: Some((transaction.expires_at - now) / 1000),
            authorization_response: None,
            nonce: None,
            wallet_error: None,
            error_message: transaction.error_message.clone(),
            transaction_data: None,
        })
    }

    /// Look up the server-stored nonce for a transaction identified by its
    /// OpenID4VP `state` parameter.
    ///
    /// Returns `Ok(Some(nonce))` when a matching transaction exists,
    /// `Ok(None)` when no transaction is found for the given state.
    pub async fn get_nonce_by_state(&self, state: &str) -> OpenID4VPResult<Option<String>> {
        Ok(self
            .transactions
            .find_by_state(state)
            .await?
            .map(|tx| tx.nonce))
    }

    /// Look up the full stored transaction identified by its OpenID4VP `state`.
    pub async fn get_transaction_by_state(
        &self,
        state: &str,
    ) -> OpenID4VPResult<Option<OpenID4VPTransaction>> {
        self.transactions.find_by_state(state).await
    }

    /// Delete the stored transaction identified by its OpenID4VP `state`.
    ///
    /// Returns `Ok(true)` when a transaction existed and was removed.
    pub async fn consume_transaction_by_state(&self, state: &str) -> OpenID4VPResult<bool> {
        let Some(transaction) = self.transactions.find_by_state(state).await? else {
            return Ok(false);
        };

        self.transactions.delete(&transaction.id).await
    }

    /// Returns the RFC 7638 SHA-256 JWK thumbprint bytes for the response
    /// encryption key used by `direct_post.jwt` / `dc_api.jwt` flows.
    pub fn get_response_jwk_thumbprint(&self) -> Option<Vec<u8>> {
        self.jwe_key
            .as_ref()
            .and_then(|key| compute_jwk_thumbprint_bytes(&key.public_jwk))
    }

    // ========================================================================
    // Public JWKS
    // ========================================================================

    /// Returns the public JWK Set for JAR signature verification.
    ///
    /// Serves at `.well-known/jwks.json` so wallets can verify the
    /// JWT Authorization Request signature.
    pub fn get_public_jwk_set(&self) -> OpenID4VPResult<serde_json::Value> {
        let jar_key = self.jar_key.as_ref().ok_or_else(|| {
            OpenID4VPError::Config(
                "Unable to get public JWK Set: HAIP is not configured; the JAR signing key is not configured".into(),
            )
        })?;
        Ok(build_public_jwk_set(jar_key))
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

        OpenID4VPServiceConfig {
            transaction_ttl_secs: Some(60), // 1 minute for tests
            haip_config: Some(HaipConfig {
                // Use the pre-built fullchain PEM (leaf + CA) for x5c
                x509_cert_path: format!("{cert_dir}/ewqwe.server.fullchain.pem"),
                x509_key_path: format!("{cert_dir}/ewqwe.server.key.pem"),
            }),
            transaction_store: Default::default(), // SQLite in-memory
        }
    }

    #[tokio::test]
    async fn test_service_create() {
        let config = test_config();
        let service = OpenID4VPService::create(config).await.unwrap();
        service.shutdown();
    }

    #[tokio::test]
    async fn test_init_transaction_annex_a() {
        let config = test_config();
        let service = OpenID4VPService::create(config).await.unwrap();

        let request = InitTransactionRequest {
            public_url: "https://rp.example.com".to_string(),
            dcql_query: None,
            nonce: Some("test-nonce-123".to_string()),
            state: None,
            client_metadata: None,
            profile: Some(ProfileId::AnnexA),
            credential_type: None,
            transaction_data: None,
        };

        let response = service.init_transaction(request).await.unwrap();

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
        let service = OpenID4VPService::create(config).await.unwrap();

        let request = InitTransactionRequest {
            public_url: "https://rp.example.com".to_string(),
            dcql_query: None,
            nonce: None,
            state: None,
            client_metadata: None,
            profile: Some(ProfileId::Haip),
            credential_type: None,
            transaction_data: None,
        };

        let response = service.init_transaction(request).await.unwrap();

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
        let service = OpenID4VPService::create(config).await.unwrap();

        let request = InitTransactionRequest {
            public_url: "https://rp.example.com".to_string(),
            dcql_query: None,
            nonce: None,
            state: None,
            client_metadata: None,
            profile: Some(ProfileId::AnnexA),
            credential_type: None,
            transaction_data: None,
        };

        let init_resp = service.init_transaction(request).await.unwrap();
        let auth_req = service
            .get_authorization_request(&init_resp.transaction_id)
            .await
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
        let service = OpenID4VPService::create(config).await.unwrap();

        let request = InitTransactionRequest {
            public_url: "https://rp.example.com".to_string(),
            dcql_query: None,
            nonce: None,
            state: None,
            client_metadata: None,
            profile: Some(ProfileId::Haip),
            credential_type: None,
            transaction_data: None,
        };

        let init_resp = service.init_transaction(request).await.unwrap();
        let auth_req = service
            .get_authorization_request(&init_resp.transaction_id)
            .await
            .unwrap();

        assert_eq!(auth_req.content_type, "application/oauth-authz-req+jwt");
        // JWT: 3 base64url parts separated by dots
        assert_eq!(auth_req.body.matches('.').count(), 2);

        service.shutdown();
    }

    #[tokio::test]
    async fn test_transaction_status_pending() {
        let config = test_config();
        let service = OpenID4VPService::create(config).await.unwrap();

        let request = InitTransactionRequest {
            public_url: "https://rp.example.com".to_string(),
            dcql_query: None,
            nonce: None,
            state: None,
            client_metadata: None,
            profile: Some(ProfileId::AnnexA),
            credential_type: None,
            transaction_data: None,
        };

        let init_resp = service.init_transaction(request).await.unwrap();
        let status = service
            .get_transaction_status(&init_resp.transaction_id)
            .await
            .unwrap();

        assert_eq!(status.status, TransactionStatus::Pending);
        assert!(status.expires_in.unwrap() > 0);
        assert!(status.authorization_response.is_none());

        service.shutdown();
    }

    #[tokio::test]
    async fn test_handle_wallet_response_plain() {
        let config = test_config();
        let service = OpenID4VPService::create(config).await.unwrap();

        let request = InitTransactionRequest {
            public_url: "https://rp.example.com".to_string(),
            dcql_query: None,
            nonce: Some("test-nonce".to_string()),
            state: None,
            client_metadata: None,
            profile: Some(ProfileId::AnnexA),
            credential_type: None,
            transaction_data: None,
        };

        let init_resp = service.init_transaction(request).await.unwrap();

        // Extract the state from the authorization request
        let auth_req = service
            .get_authorization_request(&init_resp.transaction_id)
            .await
            .unwrap();
        let auth_json: serde_json::Value = serde_json::from_str(&auth_req.body).unwrap();
        let state = auth_json["state"].as_str().unwrap().to_string();

        // Simulate wallet direct_post response
        let wallet_data = OpenID4VPResponse {
            vp_token: "test-vp-token-content".to_string(),
            presentation_submission: Some("test-submission".to_string()),
            state,
        };

        service
            .handle_wallet_response(Some(wallet_data), None, None)
            .await
            .unwrap();

        // Check status is now "received"
        let status = service
            .get_transaction_status(&init_resp.transaction_id)
            .await
            .unwrap();
        assert_eq!(status.status, TransactionStatus::Received);
        assert_eq!(
            status
                .authorization_response
                .as_ref()
                .map(|r| r.vp_token.as_str()),
            Some("test-vp-token-content")
        );
        assert_eq!(status.nonce.as_deref(), Some("test-nonce"));

        service.shutdown();
    }

    #[tokio::test]
    async fn test_handle_wallet_response_unknown_state() {
        let config = test_config();
        let service = OpenID4VPService::create(config).await.unwrap();

        let wallet_data = OpenID4VPResponse {
            vp_token: "token".to_string(),
            presentation_submission: None,
            state: "unknown-state".to_string(),
        };

        let result = service
            .handle_wallet_response(Some(wallet_data), None, None)
            .await;
        assert!(result.is_err());

        service.shutdown();
    }

    #[tokio::test]
    async fn test_get_transaction_status_not_found() {
        let config = test_config();
        let service = OpenID4VPService::create(config).await.unwrap();

        // A nonexistent transaction ID is treated as expired (not an error).
        let result = service.get_transaction_status("nonexistent-id").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().status, TransactionStatus::Expired);

        service.shutdown();
    }

    #[tokio::test]
    async fn test_get_public_jwk_set() {
        let config = test_config();
        let service = OpenID4VPService::create(config).await.unwrap();

        let jwks = service.get_public_jwk_set().expect("a JWKS should exist");
        assert!(jwks["keys"].is_array());
        let keys = jwks["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["kty"], "EC");
        assert_eq!(keys[0]["alg"], "ES256");

        service.shutdown();
    }

    // ========================================================================
    // §8.2 — Authorization Response via direct_post (success path)
    // ========================================================================

    /// §8.2 example: Wallet POSTs `vp_token=...&state=...` to the response_uri.
    /// The service must store the response and transition to `Received`.
    /// (Mirrors `test_handle_wallet_response_plain` — kept as spec-anchored reference.)
    #[tokio::test]
    async fn test_section_8_2_success_direct_post() {
        let config = test_config();
        let service = OpenID4VPService::create(config).await.unwrap();

        let request = InitTransactionRequest {
            public_url: "https://rp.example.com".to_string(),
            dcql_query: None,
            nonce: Some("test-nonce-8-2".to_string()),
            state: None,
            client_metadata: None,
            profile: Some(ProfileId::AnnexA),
            credential_type: None,
            transaction_data: None,
        };

        let init_resp = service.init_transaction(request).await.unwrap();
        let auth_req = service
            .get_authorization_request(&init_resp.transaction_id)
            .await
            .unwrap();
        let auth_json: serde_json::Value = serde_json::from_str(&auth_req.body).unwrap();
        let state = auth_json["state"].as_str().unwrap().to_string();

        // §8.2 example: form-encoded `vp_token=<JWT>&state=<state>`
        let wallet_data = OpenID4VPResponse {
            vp_token: "{\"my_credential\":[\"eyJhbGciOiJFUzI1NiJ9.test.QMA\"]}".to_string(),
            presentation_submission: None,
            state: state.clone(),
        };
        service
            .handle_wallet_response(Some(wallet_data), None, None)
            .await
            .unwrap();

        let status = service
            .get_transaction_status(&init_resp.transaction_id)
            .await
            .unwrap();
        assert_eq!(status.status, TransactionStatus::Received);
        assert!(status.authorization_response.is_some());
        assert!(status.wallet_error.is_none());
        assert_eq!(status.nonce.as_deref(), Some("test-nonce-8-2"));

        service.shutdown();
    }

    // ========================================================================
    // §8.5 — Authorization Error Response from Wallet
    // ========================================================================

    /// §8.5 example: `error=access_denied&state=<state>`.
    /// Wallet denied consent — transaction must transition to `Error`.
    #[tokio::test]
    async fn test_section_8_5_access_denied() {
        let config = test_config();
        let service = OpenID4VPService::create(config).await.unwrap();

        let request = InitTransactionRequest {
            public_url: "https://rp.example.com".to_string(),
            dcql_query: None,
            nonce: None,
            state: None,
            client_metadata: None,
            profile: Some(ProfileId::AnnexA),
            credential_type: None,
            transaction_data: None,
        };

        let init_resp = service.init_transaction(request).await.unwrap();
        let auth_req = service
            .get_authorization_request(&init_resp.transaction_id)
            .await
            .unwrap();
        let auth_json: serde_json::Value = serde_json::from_str(&auth_req.body).unwrap();
        let state = auth_json["state"].as_str().unwrap().to_string();

        let wallet_error = WalletAuthorizationError {
            error: "access_denied".to_string(),
            error_description: None,
            state: Some(state),
        };
        service
            .handle_wallet_error(wallet_error.clone())
            .await
            .unwrap();

        let status = service
            .get_transaction_status(&init_resp.transaction_id)
            .await
            .unwrap();
        assert_eq!(status.status, TransactionStatus::Error);
        assert!(status.authorization_response.is_none());
        let we = status.wallet_error.unwrap();
        assert_eq!(we.error, "access_denied");
        assert!(we.error_description.is_none());

        service.shutdown();
    }

    /// §8.5 example: `error=invalid_request&error_description=unsupported%20client_id_prefix&state=<state>`.
    /// Wallet rejected the request — transaction must transition to `Error` with description.
    #[tokio::test]
    async fn test_section_8_5_invalid_request_with_description() {
        let config = test_config();
        let service = OpenID4VPService::create(config).await.unwrap();

        let request = InitTransactionRequest {
            public_url: "https://rp.example.com".to_string(),
            dcql_query: None,
            nonce: None,
            state: None,
            client_metadata: None,
            profile: Some(ProfileId::AnnexA),
            credential_type: None,
            transaction_data: None,
        };

        let init_resp = service.init_transaction(request).await.unwrap();
        let auth_req = service
            .get_authorization_request(&init_resp.transaction_id)
            .await
            .unwrap();
        let auth_json: serde_json::Value = serde_json::from_str(&auth_req.body).unwrap();
        let state = auth_json["state"].as_str().unwrap().to_string();

        let wallet_error = WalletAuthorizationError {
            error: "invalid_request".to_string(),
            error_description: Some("unsupported client_id_prefix".to_string()),
            state: Some(state),
        };
        service.handle_wallet_error(wallet_error).await.unwrap();

        let status = service
            .get_transaction_status(&init_resp.transaction_id)
            .await
            .unwrap();
        assert_eq!(status.status, TransactionStatus::Error);
        let we = status.wallet_error.unwrap();
        assert_eq!(we.error, "invalid_request");
        assert_eq!(
            we.error_description.as_deref(),
            Some("unsupported client_id_prefix")
        );

        service.shutdown();
    }

    /// §8.5: All six error codes must be accepted and stored correctly.
    #[tokio::test]
    async fn test_section_8_5_all_error_codes() {
        let error_codes = [
            "invalid_request",
            "access_denied",
            "vp_formats_not_supported",
            "invalid_request_uri_method",
            "invalid_transaction_data",
            "wallet_unavailable",
        ];

        for error_code in &error_codes {
            let config = test_config();
            let service = OpenID4VPService::create(config).await.unwrap();

            let request = InitTransactionRequest {
                public_url: "https://rp.example.com".to_string(),
                dcql_query: None,
                nonce: None,
                state: None,
                client_metadata: None,
                profile: Some(ProfileId::AnnexA),
                credential_type: None,
                transaction_data: None,
            };

            let init_resp = service.init_transaction(request).await.unwrap();
            let auth_req = service
                .get_authorization_request(&init_resp.transaction_id)
                .await
                .unwrap();
            let auth_json: serde_json::Value = serde_json::from_str(&auth_req.body).unwrap();
            let state = auth_json["state"].as_str().unwrap().to_string();

            let wallet_error = WalletAuthorizationError {
                error: error_code.to_string(),
                error_description: Some(format!("test: {error_code}")),
                state: Some(state),
            };
            service
                .handle_wallet_error(wallet_error.clone())
                .await
                .unwrap();

            let status = service
                .get_transaction_status(&init_resp.transaction_id)
                .await
                .unwrap();
            assert_eq!(
                status.status,
                TransactionStatus::Error,
                "error_code={error_code}"
            );
            assert_eq!(
                status.wallet_error.unwrap().error,
                *error_code,
                "error_code={error_code}"
            );

            service.shutdown();
        }
    }

    /// §8.5: `handle_wallet_error` with an unknown / expired state must return an error.
    #[tokio::test]
    async fn test_section_8_5_unknown_state() {
        let config = test_config();
        let service = OpenID4VPService::create(config).await.unwrap();

        let wallet_error = WalletAuthorizationError {
            error: "access_denied".to_string(),
            error_description: None,
            state: Some("unknown-state-xyz".to_string()),
        };

        let result = service.handle_wallet_error(wallet_error).await;
        assert!(result.is_err());

        service.shutdown();
    }

    // ========================================================================
    // §8.4 — Transaction Data
    // ========================================================================

    /// Base64url-encode a JSON transaction data entry (simulates the RP encoding).
    fn encode_transaction_data_entry(entry: &serde_json::Value) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_string(entry).unwrap().as_bytes())
    }

    /// §8.4: `transaction_data` supplied in `InitTransactionRequest` is stored in the
    /// transaction and later echoed back via the status endpoint.
    #[tokio::test]
    async fn test_section_8_4_status_returns_transaction_data() {
        let config = test_config();
        let service = OpenID4VPService::create(config).await.unwrap();

        let entry = serde_json::json!({
            "type": "payment",
            "credential_ids": ["my_credential"],
            "amount": "100.00",
            "currency": "EUR"
        });
        let encoded = encode_transaction_data_entry(&entry);
        let transaction_data = vec![encoded.clone()];

        let request = InitTransactionRequest {
            public_url: "https://rp.example.com".to_string(),
            dcql_query: None,
            nonce: Some("nonce-8-4".to_string()),
            state: None,
            client_metadata: None,
            profile: Some(ProfileId::AnnexA),
            credential_type: None,
            transaction_data: Some(transaction_data.clone()),
        };

        let init_resp = service.init_transaction(request).await.unwrap();

        // Retrieve state from auth request for wallet simulation
        let auth_req = service
            .get_authorization_request(&init_resp.transaction_id)
            .await
            .unwrap();
        let auth_json: serde_json::Value = serde_json::from_str(&auth_req.body).unwrap();
        let state = auth_json["state"].as_str().unwrap().to_string();

        // Simulate wallet response
        let wallet_data = OpenID4VPResponse {
            vp_token: "vp-token-with-td-hash".to_string(),
            presentation_submission: None,
            state,
        };
        service
            .handle_wallet_response(Some(wallet_data), None, None)
            .await
            .unwrap();

        // Status must echo back transaction_data
        let status = service
            .get_transaction_status(&init_resp.transaction_id)
            .await
            .unwrap();
        assert_eq!(status.status, TransactionStatus::Received);
        assert!(
            status.transaction_data.is_some(),
            "transaction_data should be present in status"
        );
        let td = status.transaction_data.unwrap();
        assert_eq!(td.len(), 1);
        assert_eq!(td[0], encoded);

        service.shutdown();
    }

    /// §8.4: Annex A plain JSON authorization request contains `transaction_data` array.
    #[tokio::test]
    async fn test_section_8_4_annex_a_auth_request_contains_transaction_data() {
        let config = test_config();
        let service = OpenID4VPService::create(config).await.unwrap();

        let entry = serde_json::json!({
            "type": "age_verification",
            "credential_ids": ["age_cred"],
            "minimum_age": 18
        });
        let encoded = encode_transaction_data_entry(&entry);

        let request = InitTransactionRequest {
            public_url: "https://rp.example.com".to_string(),
            dcql_query: None,
            nonce: None,
            state: None,
            client_metadata: None,
            profile: Some(ProfileId::AnnexA),
            credential_type: None,
            transaction_data: Some(vec![encoded.clone()]),
        };

        let init_resp = service.init_transaction(request).await.unwrap();
        let auth_req = service
            .get_authorization_request(&init_resp.transaction_id)
            .await
            .unwrap();

        assert_eq!(auth_req.content_type, "application/json");
        let parsed: serde_json::Value = serde_json::from_str(&auth_req.body).unwrap();
        assert!(
            parsed["transaction_data"].is_array(),
            "transaction_data must be an array in the auth request"
        );
        let td_arr = parsed["transaction_data"].as_array().unwrap();
        assert_eq!(td_arr.len(), 1);
        assert_eq!(td_arr[0].as_str().unwrap(), encoded);

        service.shutdown();
    }

    /// §8.4: HAIP JAR JWT payload contains `transaction_data` array.
    #[tokio::test]
    async fn test_section_8_4_haip_jar_contains_transaction_data() {
        let config = test_config();
        let service = OpenID4VPService::create(config).await.unwrap();

        let entry = serde_json::json!({
            "type": "consent",
            "credential_ids": ["consent_cred"],
            "document_ref": "terms-v2"
        });
        let encoded = encode_transaction_data_entry(&entry);

        let request = InitTransactionRequest {
            public_url: "https://rp.example.com".to_string(),
            dcql_query: None,
            nonce: None,
            state: None,
            client_metadata: None,
            profile: Some(ProfileId::Haip),
            credential_type: None,
            transaction_data: Some(vec![encoded.clone()]),
        };

        let init_resp = service.init_transaction(request).await.unwrap();
        let auth_req = service
            .get_authorization_request(&init_resp.transaction_id)
            .await
            .unwrap();

        assert_eq!(auth_req.content_type, "application/oauth-authz-req+jwt");
        // Decode the JAR JWT payload (middle part)
        let parts: Vec<&str> = auth_req.body.splitn(3, '.').collect();
        assert_eq!(parts.len(), 3, "JAR must have 3 JWT parts");
        use base64::Engine as _;
        let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();

        assert!(
            payload["transaction_data"].is_array(),
            "transaction_data must be in the JAR payload"
        );
        let td_arr = payload["transaction_data"].as_array().unwrap();
        assert_eq!(td_arr.len(), 1);
        assert_eq!(td_arr[0].as_str().unwrap(), encoded);

        service.shutdown();
    }

    /// §8.4: When `transaction_data` is `None`, the auth request must NOT include the field.
    #[tokio::test]
    async fn test_section_8_4_absent_when_not_provided() {
        let config = test_config();
        let service = OpenID4VPService::create(config).await.unwrap();

        let request = InitTransactionRequest {
            public_url: "https://rp.example.com".to_string(),
            dcql_query: None,
            nonce: None,
            state: None,
            client_metadata: None,
            profile: Some(ProfileId::AnnexA),
            credential_type: None,
            transaction_data: None,
        };

        let init_resp = service.init_transaction(request).await.unwrap();
        let auth_req = service
            .get_authorization_request(&init_resp.transaction_id)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&auth_req.body).unwrap();
        assert!(
            parsed.get("transaction_data").is_none(),
            "transaction_data must be absent when not provided"
        );

        let status = service
            .get_transaction_status(&init_resp.transaction_id)
            .await
            .unwrap();
        assert!(status.transaction_data.is_none());

        service.shutdown();
    }

    #[tokio::test]
    async fn test_init_transaction_preserves_client_supplied_state() {
        let config = test_config();
        let service = OpenID4VPService::create(config).await.unwrap();

        let request = InitTransactionRequest {
            public_url: "https://rp.example.com".to_string(),
            dcql_query: None,
            nonce: Some("nonce-from-client".to_string()),
            state: Some("client-state-123".to_string()),
            client_metadata: None,
            profile: Some(ProfileId::AnnexA),
            credential_type: None,
            transaction_data: None,
        };

        let init_resp = service.init_transaction(request).await.unwrap();
        let auth_req = service
            .get_authorization_request(&init_resp.transaction_id)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&auth_req.body).unwrap();

        assert_eq!(parsed["state"], "client-state-123");
        assert_eq!(
            service
                .get_nonce_by_state("client-state-123")
                .await
                .unwrap(),
            Some("nonce-from-client".to_string())
        );

        service.shutdown();
    }

    #[tokio::test]
    async fn test_consume_transaction_by_state_removes_transaction() {
        let config = test_config();
        let service = OpenID4VPService::create(config).await.unwrap();

        let request = InitTransactionRequest {
            public_url: "https://rp.example.com".to_string(),
            dcql_query: None,
            nonce: None,
            state: Some("consume-me-state".to_string()),
            client_metadata: None,
            profile: Some(ProfileId::AnnexA),
            credential_type: None,
            transaction_data: None,
        };

        let init_resp = service.init_transaction(request).await.unwrap();

        assert!(
            service
                .consume_transaction_by_state("consume-me-state")
                .await
                .unwrap()
        );
        assert!(
            service
                .get_transaction_by_state("consume-me-state")
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            service
                .get_transaction_status(&init_resp.transaction_id)
                .await
                .unwrap()
                .status,
            TransactionStatus::Expired
        );

        service.shutdown();
    }
}
