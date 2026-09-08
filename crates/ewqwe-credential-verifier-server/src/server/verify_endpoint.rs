//! HTTP endpoint handlers for credential verification.
//!
//! This module wires together the SD-JWT and mDoc sub-modules and exposes two
//! actix-web route handlers:
//!
//! - [`version_endpoint`] — returns the server version
//! - [`verify_credential_endpoint`] — verifies an OpenID4VP credential presentation

use crate::{
    AttError,
    attestation::{Attestation, AttestationMaterial},
    ewqwe_credential_verifier_ui::qr_user_map::QrUserMap,
    journal::{DynJournalStore, append_verification},
    server::Version,
    tls::AuthenticatedUser,
};
use actix_web::{HttpMessage, HttpRequest, HttpResponse, web};
use base64::Engine as _;
use ewqwe_openid4vp::{
    OpenID4VPService, VerificationDetails, VerifyCredentialRequest, VerifyCredentialResponse,
    VpTokenVerificationResult,
};
use openssl::x509::X509;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{debug, error, info, warn};

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct IssuerCertsQuery {
    #[serde(default)]
    cert_pem: bool,
}

#[derive(Debug, Clone, Serialize)]
struct IssuerCertInfo {
    subject: String,
    issuer: String,
    not_before: String,
    not_after: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    cert_pem: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct IssuerCertsResponse {
    loaded: bool,
    count: usize,
    certs: Vec<IssuerCertInfo>,
}

pub(crate) async fn issuer_certs_endpoint(
    trusted_cas: web::Data<Arc<Vec<X509>>>,
    query: web::Query<IssuerCertsQuery>,
) -> Result<HttpResponse, AttError> {
    let include_pem = query.cert_pem;

    let certs: Vec<IssuerCertInfo> = trusted_cas
        .iter()
        .map(|cert| {
            let subject = cert
                .subject_name()
                .entries_by_nid(openssl::nid::Nid::COMMONNAME)
                .next()
                .and_then(|e| e.data().to_string().ok())
                .map(|s| s.to_string())
                .unwrap_or_else(|| "<unknown>".to_string());
            let issuer = cert
                .issuer_name()
                .entries_by_nid(openssl::nid::Nid::COMMONNAME)
                .next()
                .and_then(|e| e.data().to_string().ok())
                .map(|s| s.to_string())
                .unwrap_or_else(|| "<unknown>".to_string());

            let cert_pem = if include_pem {
                let pem_bytes = cert.to_pem().unwrap_or_default();
                Some(String::from_utf8(pem_bytes).unwrap_or_else(|_| "<invalid-pem>".to_string()))
            } else {
                None
            };

            IssuerCertInfo {
                subject,
                issuer,
                not_before: cert.not_before().to_string(),
                not_after: cert.not_after().to_string(),
                cert_pem,
            }
        })
        .collect();

    Ok(HttpResponse::Ok().json(IssuerCertsResponse {
        loaded: true,
        count: certs.len(),
        certs,
    }))
}

// ============================================================================
// Internal helpers
// ============================================================================

// ============================================================================
// Shared utility: credential issuer CA loading
// ============================================================================

/// Load credential issuer CA certificates from all `*.pem` files in a directory.
///
/// Called once on startup (from `start.rs`) and cached for the server lifetime.
pub(crate) fn load_credential_issuer_cas(dir: &str) -> Result<Vec<X509>, AttError> {
    let dir_path = std::path::Path::new(dir);
    if !dir_path.is_dir() {
        return Err(AttError::Config(format!(
            "Credentials issuers CA directory not found: {}",
            dir_path.display()
        )));
    }

    let entries = std::fs::read_dir(dir_path).map_err(|e| {
        AttError::Config(format!(
            "Failed to read credentials issuers CA directory {}: {e}",
            dir_path.display()
        ))
    })?;

    let mut certs = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| {
            AttError::Config(format!(
                "Failed to read credentials issuers CA directory entry {}: {e}",
                dir_path.display()
            ))
        })?;

        let entry_path = entry.path();
        if entry_path.extension().and_then(|e| e.to_str()) != Some("pem") {
            continue;
        }
        let path_str = entry_path.display().to_string();

        let pem = std::fs::read(&entry_path).map_err(|e| {
            AttError::Config(format!(
                "Failed to read credentials issuers CA certificate file {}: {e}",
                path_str
            ))
        })?;

        let parsed = X509::stack_from_pem(&pem).map_err(|e| {
            AttError::Config(format!(
                "Failed to parse credentials issuers CA PEM in {}: {e}",
                path_str
            ))
        })?;

        for cert in parsed {
            tracing::debug!(
                path = %path_str,
                subject = ?cert.subject_name(),
                "loaded credentials issuers CA"
            );
            certs.push(cert);
        }
    }
    Ok(certs)
}

// ============================================================================
// HTTP handlers
// ============================================================================

pub(crate) async fn version_endpoint(_req: HttpRequest) -> Result<HttpResponse, AttError> {
    let version = env!("CARGO_PKG_VERSION");
    let version = Version {
        version: version.to_string(),
    };
    Ok(HttpResponse::Ok().json(version))
}

/// Verify a credential presentation from a wallet and return a signed attestation.
///
/// Delegates VP token parsing, cryptographic verification, and nonce binding
/// to [`OpenID4VPService::verify_presentation`] and then creates a signed
/// attestation JWT and (optionally) writes a verification journal entry.
///
/// The verification logic (mDoc COSE, SD-JWT VC `x5c` + KB-JWT) lives in the
/// `ewqwe_openid4vp` crate, while attestation creation and journal storage
/// remain endpoint-specific concerns handled here.
pub(crate) async fn verify_credential_endpoint(
    req: HttpRequest,
    body: web::Json<VerifyCredentialRequest>,
    service: web::Data<Arc<OpenID4VPService>>,
    attestation_issuer: Option<web::Data<Arc<AttestationMaterial>>>,
    trusted_cas: web::Data<Arc<Vec<X509>>>,
    journal: Option<web::Data<Arc<DynJournalStore>>>,
    qr_map: Option<web::Data<Arc<QrUserMap>>>,
) -> Result<HttpResponse, AttError> {
    let username = req
        .extensions()
        .get::<AuthenticatedUser>()
        .map(|u| u.username.clone())
        .ok_or_else(|| {
            AttError::Authentication(
                "mTLS authentication required: authenticated user not found".to_string(),
            )
        })?;

    // Attestation issuer material pre-loaded at startup (None when not configured).
    let issuer = attestation_issuer
        .as_ref()
        .map(|data| data.as_ref().as_ref());

    info!(
        enduser.id = %username,
        vp_token_len = body.vp_token.len(),
        has_state = body.state.is_some(),
        has_client_id = body.client_id.is_some(),
        "POST /ewqwe_api/verify"
    );

    // Step 1 — verify the VP token via the OpenID4VP service.
    let result: VpTokenVerificationResult = service
        .verify_presentation(
            &body.vp_token,
            body.state.as_deref(),
            body.client_id.as_deref(),
            trusted_cas.as_ref().as_slice(),
        )
        .await
        .map_err(|e| AttError::BadRequest(e.to_string()))?;

    // Step 2 — resolve client_id for the attestation audience.
    // In the DC API (same-device) flow `state` is absent so `transaction` will
    // be `None`; the RP must then supply `client_id` directly in the request body.
    let effective_client_id = body
        .client_id
        .as_deref()
        .or(result.transaction.as_ref().map(|tx| tx.client_id.as_str()))
        .ok_or_else(|| {
            AttError::BadRequest(
                "client_id is required: provide it in the request body when not using \
                 state-based transactions (e.g. same-device DC API flow)"
                    .to_string(),
            )
        })?;

    // Step 3 — bind the attestation `sub` to the server-stored transaction ID
    // when available.  In the DC API flow where `state` is absent a fresh UUID
    // stands in as the attestation event ID.
    let generated_transaction_id;
    let effective_transaction_id = if let Some(tx) = result.transaction.as_ref() {
        tx.id.as_str()
    } else {
        generated_transaction_id = uuid::Uuid::new_v4().to_string();
        generated_transaction_id.as_str()
    };

    // Step 4 — prefer the server-stored nonce (direct_post flow); fall back to
    // the nonce extracted from the presentation itself (DC API flow).
    let attestation_nonce = result
        .server_nonce
        .as_deref()
        .or(result.presentation_nonce.as_deref());

    debug!(
        is_valid = result.is_valid,
        not_expired = result.not_expired,
        issuer_trusted = result.issuer_trusted,
        signature_valid = result.signature_valid,
        "verification result"
    );

    // Step 5 — when verification failed, return a failed attestation.
    if !result.is_valid {
        warn!(
            enduser.id = %username,
            errors = ?result.errors,
            "credential verification failed"
        );
        let attestation = create_attestation(
            effective_client_id,
            attestation_nonce,
            effective_transaction_id,
            &result.claims,
            &result.doc_type,
            &result.namespace,
            issuer,
        )?;
        return Ok(HttpResponse::Ok().json(VerifyCredentialResponse {
            success: false,
            message: "Credential verification failed".to_string(),
            verification_details: Some(VerificationDetails {
                signature_valid: result.signature_valid,
                not_expired: result.not_expired,
                issuer_trusted: result.issuer_trusted,
            }),
            attestation,
            errors: Some(result.errors),
            warnings: Some(result.warnings).filter(|w| !w.is_empty()),
        }));
    }

    // Step 6 — consume the transaction on success.
    if let Some(state) = body.state.as_deref() {
        let consumed = service
            .consume_transaction_by_state(state)
            .await
            .map_err(|e| {
                AttError::Generic(format!("failed to consume verified transaction: {e}"))
            })?;
        if !consumed {
            return Err(AttError::Generic(
                "verified transaction could not be consumed".to_string(),
            ));
        }
    }

    // Step 7 — create the attestation JWT.
    let attestation = create_attestation(
        effective_client_id,
        attestation_nonce,
        effective_transaction_id,
        &result.claims,
        &result.doc_type,
        &result.namespace,
        issuer,
    )?;
    info!(
        enduser.id = %username,
        doc_type = ?result.doc_type,
        has_client_id = body.client_id.is_some(),
        "credential verified"
    );

    // Step 8 — append to the verification journal if enabled.
    let qr_user = body
        .state
        .as_deref()
        .and_then(|txn_id| qr_map.as_ref()?.get(txn_id));

    if let Some(journal_store) = &journal {
        let jti = extract_attestation_jti(&attestation);
        let summary = serde_json::json!({
            "success": true,
            "credential_claims": &result.claims,
        });
        if let Err(e) = append_verification(
            journal_store.as_ref().as_ref(),
            &username,
            &attestation,
            jti.as_deref(),
            Some(effective_client_id),
            Some(&result.doc_type),
            Some(&result.namespace),
            summary,
            qr_user.as_ref().map(|u| u.user_id.as_str()),
            qr_user.as_ref().map(|u| u.user_email.as_str()),
        )
        .await
        {
            error!(error = %e, "failed to append to verification journal");
            return Err(AttError::from(e));
        }
    }

    Ok(HttpResponse::Ok().json(VerifyCredentialResponse {
        success: true,
        message: "Credential verified successfully".to_string(),
        verification_details: Some(VerificationDetails {
            signature_valid: true,
            not_expired: true,
            issuer_trusted: true,
        }),
        attestation,
        errors: None,
        warnings: Some(result.warnings).filter(|w| !w.is_empty()),
    }))
}

/// Create a signed attestation JWT for the verified (or rejected) credential presentation.
///
/// The `sub` claim is set to `transaction_id` so the attestation is cryptographically
/// bound to the specific verification event. When `is_verified` is `true` all verified
/// attribute claims from the credential are embedded via
/// [`Attestation::with_credential_claims`]; when `false` the presented claims are
/// untrusted and not included.
///
/// `doc_type` and `namespace` (credential metadata) are bound into the attestation so
/// the relying party does not need a separate `VerificationDetails` channel.
///
/// The issuer material (certificate + signing key) is pre-loaded once at startup by
/// [`AttestationMaterial::load`] — no file I/O happens on the request path. The issuer
/// (`iss`) claim is the Subject CN of the issuer certificate, and the `kid` JWT header
/// is the SHA-256 fingerprint of the certificate so the verifier can locate the
/// matching public key in the JWKS served at
/// `/ewqwe_api/openid4vp/.well-known/jwks.json`.
pub(crate) fn create_attestation(
    client_id: &str,
    nonce: Option<&str>,
    transaction_id: &str,
    claims: &serde_json::Value,
    doc_type: &str,
    namespace: &str,
    issuer: Option<&AttestationMaterial>,
) -> Result<String, AttError> {
    let credential_claims = claims.as_object().cloned().unwrap_or_default();
    // Convert JPEG2000 portrait to JPEG (e.g. France Identité wallet).
    // Claims may be namespace-nested (mDoc) or flat (SD-JWT).
    let all_nested =
        !credential_claims.is_empty() && credential_claims.values().all(|v| v.is_object());
    let credential_claims = if all_nested {
        let mut converted = serde_json::Map::new();
        for (ns, inner) in credential_claims {
            let inner_map = inner.as_object().cloned().unwrap_or_default();
            let converted_inner = crate::attestation::convert_portrait_to_jpeg(inner_map);
            converted.insert(ns, serde_json::Value::Object(converted_inner));
        }
        converted
    } else {
        crate::attestation::convert_portrait_to_jpeg(credential_claims)
    };

    let material = issuer.ok_or_else(|| {
        AttError::Config(
            "An attestation issuer certificate must be provided if no TLS certificates are set"
                .to_owned(),
        )
    })?;

    let attestation = Attestation::new(material.issuer(), client_id, transaction_id)
        .with_credential_claims(credential_claims)
        .with_doc_type(doc_type)
        .with_namespace(namespace);
    let attestation = match nonce {
        Some(n) => attestation.with_nonce(n),
        None => attestation,
    };

    material
        .signer()
        .sign_to_string(&attestation)
        .map_err(|e| AttError::Generic(format!("Failed to sign attestation: {e}")))
}

/// Extract the `jti` claim from a compact JWT without full signature verification.
///
/// The `jti` is embedded in the JSON payload (second dot-separated segment).
/// Returns `None` on any parse failure — the journal will simply record a null jti.
fn extract_attestation_jti(compact_jwt: &str) -> Option<String> {
    let payload_b64 = compact_jwt.split('.').nth(1)?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .ok()?;
    let json: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    json.get("jti")?.as_str().map(str::to_string)
}

// ============================================================================
// QR Verifier App in-process verification
// ============================================================================

/// Outcome of an in-process VP token verification for the Verifier App QR flow.
pub(crate) struct QrVerificationOutcome {
    pub success: bool,
    pub doc_type: String,
    #[allow(dead_code)]
    pub namespace: String,
    pub errors: Vec<String>,
    /// Value of the `age_over_18` claim from the presented credential, if present.
    pub age_over_18: Option<bool>,
    /// Serialised map of verified claims from the presented credential.
    pub verified_claims: serde_json::Value,
}

/// Verify a VP token presented via the Verifier App QR (`direct_post`) flow.
///
/// Unlike [`verify_credential_endpoint`] this function:
/// - does **not** require mTLS / `AuthenticatedUser` (the Verifier App user is passed as `username`)
/// - does **not** create or return a signed attestation JWT
/// - does **not** consume / delete the transaction (the caller must call
///   `service.mark_transaction_verified(id)` after a successful result)
/// - does append to the verification journal when `journal` is provided
pub(crate) async fn verify_vp_token_for_qr(
    vp_token_str: &str,
    state: &str,
    username: &str,
    service: &OpenID4VPService,
    trusted_cas: &[X509],
    journal: Option<&crate::journal::DynJournalStore>,
) -> Result<QrVerificationOutcome, AttError> {
    let result = service
        .verify_presentation(vp_token_str, Some(state), None, trusted_cas)
        .await
        .map_err(|e| AttError::BadRequest(e.to_string()))?;

    if !result.is_valid {
        return Ok(QrVerificationOutcome {
            success: false,
            doc_type: result.doc_type,
            namespace: result.namespace,
            errors: result.errors,
            age_over_18: None,
            verified_claims: serde_json::Value::Object(Default::default()),
        });
    }

    tracing::info!(
        doc_type = %result.doc_type,
        namespace = %result.namespace,
        username,
        "QR credential verification succeeded"
    );
    let age_over_18 = extract_age_over_18_claim(&result.claims);

    // Convert JPEG2000 portrait to JPEG for the QR response (display only).
    // The raw wallet data is stored as-is in the journal — conversion happens
    // at read time in JournalEntryView.
    let raw_map = result.claims.as_object().cloned().unwrap_or_default();
    let all_nested = !raw_map.is_empty() && raw_map.values().all(|v| v.is_object());
    let display_claims = if all_nested {
        let mut converted = serde_json::Map::new();
        for (ns, inner) in raw_map {
            let inner_map = inner.as_object().cloned().unwrap_or_default();
            let converted_inner = crate::attestation::convert_portrait_to_jpeg(inner_map);
            converted.insert(ns, serde_json::Value::Object(converted_inner));
        }
        serde_json::Value::Object(converted)
    } else {
        serde_json::Value::Object(crate::attestation::convert_portrait_to_jpeg(raw_map))
    };

    if let Some(journal_store) = journal {
        let summary = serde_json::json!({
            "success": true,
            "credential_claims": &result.claims,
        });
        // No attestation JWT in the QR flow — pass empty string; the hash is still recorded.
        let client_id = result.transaction.as_ref().map(|tx| tx.client_id.as_str());
        if let Err(e) = crate::journal::append_verification(
            journal_store,
            username,
            "",
            None,
            client_id,
            Some(result.doc_type.as_str()),
            Some(result.namespace.as_str()),
            summary,
            None,
            Some(username),
        )
        .await
        {
            tracing::error!(error = %e, "failed to append QR verification to journal");
        }
    }

    Ok(QrVerificationOutcome {
        success: true,
        doc_type: result.doc_type,
        namespace: result.namespace,
        errors: Vec::new(),
        age_over_18,
        verified_claims: display_claims,
    })
}

/// Extract the `age_over_18` boolean claim from a credential claims JSON value.
///
/// Handles both flat SD-JWT style (`{"age_over_18": true}`) and namespace-nested
/// mDoc style (`{"eu.europa.ec.av.1": {"age_over_18": true}}`).
fn extract_age_over_18_claim(claims: &serde_json::Value) -> Option<bool> {
    // Try top-level key first (SD-JWT / flat structure)
    if let Some(val) = claims.get("age_over_18") {
        return val.as_bool();
    }
    // Try one level deep inside namespace objects (mDoc structure)
    if let Some(obj) = claims.as_object() {
        for ns_val in obj.values() {
            if let Some(val) = ns_val.get("age_over_18")
                && let Some(b) = val.as_bool()
            {
                return Some(b);
            }
        }
    }
    None
}
