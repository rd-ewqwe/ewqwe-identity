//! OpenID4VP endpoints for the credential verifier server.
//!
//! These endpoints implement the server-side OpenID4VP protocol, proxied by the
//! RP webapp (`server.ts`). The RP's `public_url` is passed in the init request
//! so that authorization request URIs point back to the RP (which then proxies
//! wallet traffic here).
//!
//! # Endpoints
//!
//! | Method | Path                                     | Description                              |
//! |--------|------------------------------------------|------------------------------------------|
//! | POST   | `/ewqwe_api/openid4vp/init`                    | Initialize a new transaction             |
//! | GET    | `/ewqwe_api/openid4vp/status/{id}`             | Poll transaction status                  |
//! | POST   | `/ewqwe_api/openid4vp/direct_post`             | Wallet posts VP token                    |
//! | GET    | `/ewqwe_api/openid4vp/request/{id}`            | Wallet fetches authorization request     |
//! | POST   | `/ewqwe_api/openid4vp/request/{id}`            | Wallet fetches authorization request     |
//! | GET    | `/ewqwe_api/openid4vp/.well-known/jwks.json`   | Public JWK Set for JAR verification      |

use actix_web::{HttpRequest, HttpResponse, web};
use ewqwe_openid4vp::{
    InitTransactionRequest, OpenID4VPError, OpenID4VPResponse, OpenID4VPService,
    WalletAuthorizationError,
};
use serde::Deserialize;
use std::sync::Arc;
use tracing::{error, info, warn};

use crate::parameters::ServerParams;

/// Initialize a new OpenID4VP transaction.
///
/// # Request Body
///
/// ```json
/// {
///     "profile": "annex-a",
///     "credential_type": "proof-of-age",
///     "nonce": "optional-nonce"
/// }
/// ```
pub async fn init_transaction(
    req: HttpRequest,
    service: web::Data<Arc<OpenID4VPService>>,
    params: web::Data<ServerParams>,
    body: web::Json<InitTransactionRequest>,
) -> HttpResponse {
    info!("POST /ewqwe_api/openid4vp/init");
    let request = body.into_inner();

    // Construct the public URL for the transaction.
    // If `public_root_url` is not set, use the request's scheme and host.
    let public_url = params.public_root_url.clone().unwrap_or_else(|| {
        let conn = req.connection_info();
        format!("{}://{}", conn.scheme(), conn.host())
    });

    match service.init_transaction(request, &public_url).await {
        Ok(response) => {
            info!(
                transaction_id = %response.transaction_id,
                profile = %response.profile,
                "Transaction created"
            );
            HttpResponse::Ok().json(response)
        }
        Err(e) => openid4vp_error_response(e),
    }
}

/// Poll the status of an OpenID4VP transaction.
///
/// Returns the current status. When `status == "received"`, the response includes
/// `vp_token`, `presentation_submission`, `nonce`, and `state` for the RP to
/// forward to `/ewqwe_api/verify`.
pub async fn get_transaction_status(
    service: web::Data<Arc<OpenID4VPService>>,
    path: web::Path<String>,
) -> HttpResponse {
    let transaction_id = path.into_inner();

    match service.get_transaction_status(&transaction_id).await {
        Ok(status) => HttpResponse::Ok().json(status),
        Err(e) => openid4vp_error_response(e),
    }
}

/// Receive a wallet's direct_post response.
///
/// Supports two content types:
/// - `application/x-www-form-urlencoded`: Form data with `vp_token`, `state`,
///   and optionally `presentation_submission` or `response` (JWE for HAIP).
/// - `application/json`: JSON body with the same fields.
pub async fn handle_direct_post(
    service: web::Data<Arc<OpenID4VPService>>,
    req: HttpRequest,
    body: web::Bytes,
) -> HttpResponse {
    info!("POST /ewqwe_api/openid4vp/direct_post");

    let content_type = req
        .headers()
        .get("content-type")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    let result = if content_type.contains("application/x-www-form-urlencoded") {
        handle_form_direct_post(&service, &body).await
    } else {
        handle_json_direct_post(&service, &body).await
    };

    match result {
        Ok(()) => {
            info!("Wallet response stored successfully");
            // §8.2: Verifier MUST respond HTTP 200 + Content-Type: application/json + `{}`
            // (or {"redirect_uri":"..."} for same-device redirects — not used here).
            HttpResponse::Ok().json(serde_json::json!({}))
        }
        Err(e) => openid4vp_error_response(e),
    }
}

/// Parse and handle form-encoded direct_post data.
async fn handle_form_direct_post(
    service: &OpenID4VPService,
    body: &[u8],
) -> Result<(), OpenID4VPError> {
    let params: Vec<(String, String)> = url::form_urlencoded::parse(body).into_owned().collect();

    let get_param = |name: &str| -> Option<String> {
        params
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    };

    // Check for JWE response (HAIP profile: direct_post.jwt)
    if let Some(jwe_response) = get_param("response") {
        info!(jwe_len = jwe_response.len(), "JWE response received");
        let fallback_state = get_param("state");
        service
            .handle_wallet_response(None, Some(&jwe_response), fallback_state.as_deref())
            .await
    } else if let Some(error_code) = get_param("error") {
        // §8.5: Wallet sent an error response instead of a VP Token
        let error_description = get_param("error_description");
        let state = get_param("state");
        warn!(
            error_code = %error_code,
            error_description = ?error_description,
            state = ?state,
            "Wallet error response (§8.5)"
        );
        let wallet_error = WalletAuthorizationError {
            error: error_code,
            error_description,
            state,
        };
        service.handle_wallet_error(wallet_error).await
    } else {
        // Plain form data (Annex A profile: direct_post)
        let vp_token = get_param("vp_token").unwrap_or_default();
        let presentation_submission = get_param("presentation_submission");
        let state = get_param("state").unwrap_or_default();
        info!(
            state_prefix = &state[..state.len().min(8)],
            "Plain direct_post received"
        );

        let wallet_data = OpenID4VPResponse {
            vp_token,
            presentation_submission,
            state,
        };
        service
            .handle_wallet_response(Some(wallet_data), None, None)
            .await
    }
}

/// Parse and handle JSON direct_post data.
async fn handle_json_direct_post(
    service: &OpenID4VPService,
    body: &[u8],
) -> Result<(), OpenID4VPError> {
    #[derive(Deserialize)]
    struct JsonDirectPost {
        vp_token: Option<String>,
        presentation_submission: Option<String>,
        state: Option<String>,
        // §8.5: Wallet error response fields
        error: Option<String>,
        error_description: Option<String>,
    }

    let parsed: JsonDirectPost = serde_json::from_slice(body).map_err(|e| {
        OpenID4VPError::BadRequest(format!("Invalid JSON in direct_post body: {e}"))
    })?;

    // §8.5: Wallet error response takes priority over vp_token
    if let Some(error_code) = parsed.error {
        let state = parsed.state;
        warn!(
            error_code = %error_code,
            error_description = ?parsed.error_description,
            state = ?state,
            "Wallet error response §8.5 (JSON)"
        );
        let wallet_error = WalletAuthorizationError {
            error: error_code,
            error_description: parsed.error_description,
            state,
        };
        return service.handle_wallet_error(wallet_error).await;
    }

    let state = parsed.state.unwrap_or_default();
    info!(
        state_prefix = &state[..state.len().min(8)],
        "JSON direct_post received"
    );

    let wallet_data = OpenID4VPResponse {
        vp_token: parsed.vp_token.unwrap_or_default(),
        presentation_submission: parsed.presentation_submission,
        state,
    };
    service
        .handle_wallet_response(Some(wallet_data), None, None)
        .await
}

/// Serve the authorization request for a transaction.
///
/// For HAIP: returns a signed JAR (`application/oauth-authz-req+jwt`).
/// For Annex A: returns plain JSON (`application/json`).
///
/// Wallets fetch this via the `request_uri` from the authorization request URI.
pub async fn get_authorization_request(
    service: web::Data<Arc<OpenID4VPService>>,
    path: web::Path<String>,
) -> HttpResponse {
    let transaction_id = path.into_inner();
    info!(
        transaction_id_prefix = &transaction_id[..transaction_id.len().min(8)],
        "GET /ewqwe_api/openid4vp/request"
    );

    match service.get_authorization_request(&transaction_id).await {
        Ok(result) => {
            info!(content_type = %result.content_type, "Returning authorization request");
            HttpResponse::Ok()
                .content_type(result.content_type)
                .body(result.body)
        }
        Err(e) => openid4vp_error_response(e),
    }
}

/// Return the public JWK Set.
///
/// The JWKS contains two logical groups:
/// 1. **JAR signing key** (present only in HAIP mode): used by the wallet to verify
///    signed Authorization Requests (RFC 9101 JARs).
/// 2. **Attestation verification key**: used by the Relying Party to verify the
///    signed attestation JWT returned by `POST /ewqwe_api/verify`.  The key is extracted
///    from `ServerParams::attestation_issuer_certificate` (or the TLS server
///    certificate when not configured).  The corresponding `kid` value is also
///    embedded in every attestation JWT header so the RP can look it up by ID.
pub async fn get_jwks(
    service: web::Data<Arc<OpenID4VPService>>,
    server_params: web::Data<Arc<ServerParams>>,
) -> HttpResponse {
    let mut keys: Vec<serde_json::Value> = Vec::new();

    // JAR signing key — present in HAIP mode only
    if let Ok(jar_jwks) = service.get_public_jwk_set() {
        keys.extend(jar_jwks.keys.iter().cloned());
    }

    // Attestation verification key (from the issuer certificate)
    if let Some(att_jwk) = build_attestation_jwk(&server_params) {
        keys.push(att_jwk);
    }

    HttpResponse::Ok()
        .content_type("application/jwk-set+json")
        .json(serde_json::json!({ "keys": keys }))
}

/// Build a JWK for the attestation signing certificate.
///
/// Returns `None` if the certificate cannot be loaded or parsed (non-fatal: the
/// JWKS will simply not include the attestation key).
fn build_attestation_jwk(server_params: &ServerParams) -> Option<serde_json::Value> {
    use base64::Engine as _;
    use openssl::bn::BigNumContext;
    use openssl::x509::X509;

    let cert_path = server_params.attestation_issuer_certificate_path();
    let cert_pem = std::fs::read(cert_path)
        .map_err(|e| warn!(cert_path, %e, "Failed to read attestation issuer certificate for JWKS"))
        .ok()?;
    let cert = X509::from_pem(&cert_pem)
        .map_err(
            |e| warn!(cert_path, %e, "Failed to parse attestation issuer certificate for JWKS"),
        )
        .ok()?;
    let cert_der = cert
        .to_der()
        .map_err(|e| warn!(%e, "Failed to DER-encode attestation issuer certificate for JWKS"))
        .ok()?;

    // SHA-256 fingerprint of the DER cert → stable, unique kid
    let fingerprint = openssl::sha::sha256(&cert_der);
    let kid = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(fingerprint);

    // Extract EC P-256 public key coordinates
    let pub_key = cert
        .public_key()
        .map_err(|e| warn!(%e, "Failed to extract attestation public key"))
        .ok()?;
    let ec_key = pub_key
        .ec_key()
        .map_err(|e| warn!(%e, "Attestation certificate public key is not EC"))
        .ok()?;

    let group = ec_key.group();
    let point = ec_key.public_key();
    let mut bn_ctx = BigNumContext::new()
        .map_err(|e| warn!(%e, "BigNumContext creation failed"))
        .ok()?;
    let mut x = openssl::bn::BigNum::new().ok()?;
    let mut y = openssl::bn::BigNum::new().ok()?;
    point
        .affine_coordinates_gfp(group, &mut x, &mut y, &mut bn_ctx)
        .map_err(|e| warn!(%e, "Failed to extract EC coordinates"))
        .ok()?;

    let x_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(x.to_vec());
    let y_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(y.to_vec());

    // x5c: standard base64 (not URL-safe) of the raw DER certificate (RFC 7517 §4.7)
    let x5c = base64::engine::general_purpose::STANDARD.encode(&cert_der);

    Some(serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "use": "sig",
        "alg": "ES256",
        "kid": kid,
        "x": x_b64,
        "y": y_b64,
        "x5c": [x5c]
    }))
}

/// Map OpenID4VP errors to appropriate HTTP responses.
fn openid4vp_error_response(e: OpenID4VPError) -> HttpResponse {
    match &e {
        OpenID4VPError::NotFound(msg) => {
            warn!(error = %msg, "Not found");
            HttpResponse::NotFound().json(serde_json::json!({"error": msg}))
        }
        OpenID4VPError::Expired(msg) => {
            warn!(error = %msg, "Expired");
            HttpResponse::Gone().json(serde_json::json!({"error": msg, "status": "expired"}))
        }
        OpenID4VPError::BadRequest(msg) => {
            warn!(error = %msg, "Bad request");
            HttpResponse::BadRequest().json(serde_json::json!({"error": msg}))
        }
        OpenID4VPError::Crypto(msg) => {
            error!(error = %msg, "Crypto error");
            HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "Internal crypto error"}))
        }
        OpenID4VPError::Config(msg) => {
            error!(error = %msg, "Config error");
            HttpResponse::InternalServerError().json(
                serde_json::json!({"error": format!("credential verifier configuration: {msg}")}),
            )
        }
        OpenID4VPError::Internal(msg) => {
            error!(error = %msg, "Internal error");
            HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "Internal server error"}))
        }
    }
}
