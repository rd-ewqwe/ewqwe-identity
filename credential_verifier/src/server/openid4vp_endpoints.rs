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
//! | POST   | `/api/openid4vp/init`                    | Initialize a new transaction             |
//! | GET    | `/api/openid4vp/status/{id}`             | Poll transaction status                  |
//! | POST   | `/api/openid4vp/direct_post`             | Wallet posts VP token                    |
//! | GET    | `/api/openid4vp/request/{id}`            | Wallet fetches authorization request     |
//! | POST   | `/api/openid4vp/request/{id}`            | Wallet fetches authorization request     |
//! | GET    | `/api/openid4vp/.well-known/jwks.json`   | Public JWK Set for JAR verification      |

use actix_web::{HttpRequest, HttpResponse, web};
use ewqwe_openid4vp::{
    InitTransactionRequest, OpenID4VPError, OpenID4VPService, WalletDirectPostData,
};
use serde::Deserialize;
use std::sync::Arc;
use tracing::{error, info, warn};

/// Initialize a new OpenID4VP transaction.
///
/// The RP sends its `public_url` so the verifier can construct authorization
/// request URIs that point back to the RP (which proxies wallet traffic here).
///
/// # Request Body
///
/// ```json
/// {
///     "public_url": "https://rp.example.com",
///     "profile": "annex-a",
///     "credential_type": "proof-of-age",
///     "nonce": "optional-nonce"
/// }
/// ```
pub async fn init_transaction(
    service: web::Data<Arc<OpenID4VPService>>,
    body: web::Json<InitTransactionRequest>,
) -> HttpResponse {
    info!("POST /api/openid4vp/init");
    let request = body.into_inner();

    match service.init_transaction(request) {
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
/// forward to `/api/verify`.
pub async fn get_transaction_status(
    service: web::Data<Arc<OpenID4VPService>>,
    path: web::Path<String>,
) -> HttpResponse {
    let transaction_id = path.into_inner();

    match service.get_transaction_status(&transaction_id) {
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
    info!("POST /api/openid4vp/direct_post");

    let content_type = req
        .headers()
        .get("content-type")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    let result = if content_type.contains("application/x-www-form-urlencoded") {
        handle_form_direct_post(&service, &body)
    } else {
        handle_json_direct_post(&service, &body)
    };

    match result {
        Ok(()) => {
            info!("Wallet response stored successfully");
            HttpResponse::Ok().json(serde_json::json!({"status": "ok"}))
        }
        Err(e) => openid4vp_error_response(e),
    }
}

/// Parse and handle form-encoded direct_post data.
fn handle_form_direct_post(
    service: &OpenID4VPService,
    body: &[u8],
) -> Result<(), OpenID4VPError> {
    let params: Vec<(String, String)> =
        url::form_urlencoded::parse(body).into_owned().collect();

    let get_param = |name: &str| -> Option<String> {
        params
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    };

    // Check for JWE response (HAIP profile: direct_post.jwt)
    if let Some(jwe_response) = get_param("response") {
        info!(
            jwe_len = jwe_response.len(),
            "JWE response received"
        );
        let fallback_state = get_param("state");
        service.handle_wallet_response(None, Some(&jwe_response), fallback_state.as_deref())
    } else {
        // Plain form data (Annex A profile: direct_post)
        let vp_token = get_param("vp_token").unwrap_or_default();
        let presentation_submission = get_param("presentation_submission");
        let state = get_param("state").unwrap_or_default();
        info!(
            state_prefix = &state[..state.len().min(8)],
            "Plain direct_post received"
        );

        let wallet_data = WalletDirectPostData {
            vp_token,
            presentation_submission,
            state,
        };
        service.handle_wallet_response(Some(wallet_data), None, None)
    }
}

/// Parse and handle JSON direct_post data.
fn handle_json_direct_post(
    service: &OpenID4VPService,
    body: &[u8],
) -> Result<(), OpenID4VPError> {
    #[derive(Deserialize)]
    struct JsonDirectPost {
        vp_token: Option<String>,
        presentation_submission: Option<String>,
        state: Option<String>,
    }

    let parsed: JsonDirectPost = serde_json::from_slice(body).map_err(|e| {
        OpenID4VPError::BadRequest(format!("Invalid JSON in direct_post body: {e}"))
    })?;

    let state = parsed.state.unwrap_or_default();
    info!(
        state_prefix = &state[..state.len().min(8)],
        "JSON direct_post received"
    );

    let wallet_data = WalletDirectPostData {
        vp_token: parsed.vp_token.unwrap_or_default(),
        presentation_submission: parsed.presentation_submission,
        state,
    };
    service.handle_wallet_response(Some(wallet_data), None, None)
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
        "GET /api/openid4vp/request"
    );

    match service.get_authorization_request(&transaction_id) {
        Ok(result) => {
            info!(content_type = %result.content_type, "Returning authorization request");
            HttpResponse::Ok()
                .content_type(result.content_type)
                .body(result.body)
        }
        Err(e) => openid4vp_error_response(e),
    }
}

/// Return the public JWK Set for JAR signature verification.
pub async fn get_jwks(service: web::Data<Arc<OpenID4VPService>>) -> HttpResponse {
    let jwks = service.get_public_jwk_set();
    HttpResponse::Ok()
        .content_type("application/jwk-set+json")
        .json(jwks)
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
            HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "Server configuration error"}))
        }
        OpenID4VPError::Internal(msg) => {
            error!(error = %msg, "Internal error");
            HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "Internal server error"}))
        }
    }
}
