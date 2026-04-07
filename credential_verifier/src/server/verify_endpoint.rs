//! HTTP endpoint handlers for credential verification.
//!
//! This module wires together the SD-JWT and mDoc sub-modules and exposes two
//! actix-web route handlers:
//!
//! - [`version_endpoint`] — returns the server version
//! - [`verify_credential_endpoint`] — verifies an OpenID4VP credential presentation

use crate::{
    AttError,
    attestation::{Attestation, AttestationSigner, JwtSigner, SigningAlgorithm},
    journal::{DynJournalStore, append_verification},
    parameters::ServerParams,
    server::Version,
    tls::AuthenticatedUser,
    verifier_app::qr_user_map::QrUserMap,
};
use actix_web::{HttpMessage, HttpRequest, HttpResponse, web};
use base64::Engine as _;
use ewqwe_digital_credential::{
    SigVerificationResult, decode_mdoc_presentation, decode_sd_jwt_presentation,
    verify_mdoc_presentation, verify_sd_jwt_signatures,
};
use ewqwe_openid4vp::{OpenID4VPService, OpenID4VPTransaction};
use openssl::x509::X509;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

// ============================================================================
// Public request/response types
// ============================================================================

/// Request body for credential verification.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)] // Fields are part of OpenID4VP spec but may not all be actively used
pub struct VerifyCredentialRequest {
    /// The VP token from the wallet (JSON string containing the credential).
    pub vp_token: String,

    /// Presentation submission with descriptor mapping.
    /// Optional because DCQL-based responses (OpenID4VP Section 8.1) don't include
    /// `presentation_submission` — the `vp_token` itself is structured with credential IDs as keys.
    #[serde(default)]
    pub presentation_submission: Option<PresentationSubmission>,

    /// Original state from the request.
    /// Used to look up the server-stored transaction nonce for replay prevention.
    #[serde(default)]
    pub state: Option<String>,

    /// Client ID (relying party identifier).
    #[serde(default)]
    pub client_id: Option<String>,
}

/// Presentation submission structure from OpenID4VP.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)] // Part of OpenID4VP spec, used with presentation_definition (not DCQL)
pub struct PresentationSubmission {
    pub id: String,
    pub definition_id: String,
    pub descriptor_map: Vec<DescriptorMapEntry>,
}

/// Descriptor map entry.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)] // Part of OpenID4VP spec
pub struct DescriptorMapEntry {
    pub id: String,
    pub format: String,
    pub path: String,
}

/// Response from credential verification.
#[derive(Debug, Clone, Serialize)]
pub struct VerifyCredentialResponse {
    /// Whether verification was successful.
    pub success: bool,

    /// Human-readable message.
    pub message: String,

    /// Verification details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_details: Option<VerificationDetails>,

    /// Signed attestation JWT (always present).
    pub attestation: String,

    /// Errors (if failed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
}

/// Details about the verification process.
#[derive(Debug, Clone, Serialize)]
pub struct VerificationDetails {
    pub signature_valid: bool,
    pub not_expired: bool,
    pub issuer_trusted: bool,
}

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
                .and_then(|e| e.data().as_utf8().ok())
                .map(|s| s.to_string())
                .unwrap_or_else(|| "<unknown>".to_string());
            let issuer = cert
                .issuer_name()
                .entries_by_nid(openssl::nid::Nid::COMMONNAME)
                .next()
                .and_then(|e| e.data().as_utf8().ok())
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

/// Parsed VP token — can be direct format or DCQL-wrapped.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)] // Fields are part of credential format spec
struct VpToken {
    doc_type: String,
    namespace: String,
    claims: Option<serde_json::Value>,
    issuer: Option<String>,
    issued_at: Option<String>,
    expires_at: Option<String>,
    /// Nonce bound to this presentation (from KB-JWT for SD-JWT VC).
    #[serde(skip)]
    nonce: Option<String>,
    /// Raw SD-JWT VC compact string preserved for cryptographic verification.
    #[serde(skip)]
    raw_sd_jwt: Option<String>,
    /// Raw base64url-encoded DeviceResponse for mDoc verification.
    #[serde(skip)]
    raw_mdoc: Option<String>,
    issuer_signed: Option<IssuerSigned>,
}

/// DCQL VP token (OpenID4VP §8.1): keys are credential IDs, values are presentation arrays.
type DcqlVpToken = std::collections::HashMap<String, Vec<serde_json::Value>>;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IssuerSigned {
    name_spaces: Option<serde_json::Value>,
}

struct VerificationResult {
    is_valid: bool,
    signature_valid: bool,
    not_expired: bool,
    issuer_trusted: bool,
    errors: Vec<String>,
}

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
            "Credential issuer CA directory not found: {}",
            dir_path.display()
        )));
    }

    let entries = std::fs::read_dir(dir_path).map_err(|e| {
        AttError::Config(format!(
            "Failed to read credential issuer CA directory {}: {e}",
            dir_path.display()
        ))
    })?;

    let mut certs = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| {
            AttError::Config(format!(
                "Failed to read directory entry {}: {e}",
                dir_path.display()
            ))
        })?;

        let entry_path = entry.path();
        if entry_path.extension().and_then(|e| e.to_str()) != Some("pem") {
            continue;
        }
        let path_str = entry_path.display().to_string();

        let pem = std::fs::read(&entry_path).map_err(|e| {
            AttError::Config(format!("Failed to read certificate file {}: {e}", path_str))
        })?;

        let parsed = X509::stack_from_pem(&pem)
            .map_err(|e| AttError::Config(format!("Failed to parse PEM in {}: {e}", path_str)))?;

        for cert in parsed {
            tracing::debug!(
                path = %path_str,
                subject = ?cert.subject_name(),
                "loaded credential issuer CA"
            );
            certs.push(cert);
        }
    }
    Ok(certs)
}

// ============================================================================
// VP token parsing
// ============================================================================

/// Parse a VP token — handles DCQL-wrapped format and direct JSON format.
fn parse_vp_token(vp_token_str: &str) -> Result<(VpToken, Option<String>), AttError> {
    // Try DCQL format first (object with credential IDs as keys)
    if let Ok(dcql_token) = serde_json::from_str::<DcqlVpToken>(vp_token_str) {
        if let Some((credential_id, presentations)) = dcql_token.iter().next() {
            tracing::debug!(
                credential_id,
                presentations_count = presentations.len(),
                "DCQL VP token"
            );

            if let Some(presentation) = presentations.first() {
                if let Some(encoded_str) = presentation.as_str() {
                    // SD-JWT VC: compact format with '~' separators
                    if encoded_str.contains('~') {
                        tracing::debug!(len = encoded_str.len(), "presentation is SD-JWT VC");
                        match decode_sd_jwt_presentation(encoded_str) {
                            Ok(decoded) => {
                                let vp_token = VpToken {
                                    doc_type: decoded.vct.clone(),
                                    namespace: decoded.vct.clone(),
                                    claims: Some(serde_json::Value::Object(decoded.claims)),
                                    issuer: Some(decoded.issuer),
                                    issued_at: decoded.issued_at,
                                    expires_at: decoded.expires_at,
                                    nonce: decoded.nonce,
                                    raw_sd_jwt: Some(encoded_str.to_string()),
                                    raw_mdoc: None,
                                    issuer_signed: None,
                                };
                                return Ok((vp_token, Some(credential_id.clone())));
                            }
                            Err(e) => {
                                tracing::warn!("SD-JWT VC decode failed: {}", e);
                                return Err(AttError::BadRequest(format!(
                                    "SD-JWT VC decode failed: {e}"
                                )));
                            }
                        }
                    }

                    // mDoc: base64-encoded CBOR DeviceResponse
                    tracing::debug!(
                        len = encoded_str.len(),
                        "presentation is base64-encoded mDoc"
                    );
                    match decode_mdoc_presentation(encoded_str) {
                        Ok(decoded) => {
                            tracing::debug!(
                                doc_type = %decoded.doc_type,
                                namespaces = decoded.namespaces.len(),
                                "mDoc decoded"
                            );
                            let first_ns =
                                decoded.namespaces.keys().next().cloned().ok_or_else(|| {
                                    AttError::BadRequest("mDoc contains no namespaces".to_string())
                                })?;
                            let claims = if decoded.namespaces.len() == 1 {
                                let (_, ns_claims) = decoded.namespaces.into_iter().next().unwrap();
                                serde_json::Value::Object(ns_claims.into_iter().collect())
                            } else {
                                let mut obj = serde_json::Map::new();
                                for (ns, ns_claims) in decoded.namespaces {
                                    let ns_obj: serde_json::Map<String, serde_json::Value> =
                                        ns_claims.into_iter().collect();
                                    obj.insert(ns, serde_json::Value::Object(ns_obj));
                                }
                                serde_json::Value::Object(obj)
                            };
                            let vp_token = VpToken {
                                doc_type: decoded.doc_type,
                                namespace: first_ns,
                                claims: Some(claims),
                                issuer: Some("mdoc-issuer".to_string()),
                                issued_at: None,
                                expires_at: None,
                                nonce: None,
                                raw_sd_jwt: None,
                                raw_mdoc: Some(encoded_str.to_string()),
                                issuer_signed: None,
                            };
                            return Ok((vp_token, Some(credential_id.clone())));
                        }
                        Err(e) => {
                            return Err(AttError::BadRequest(format!(
                                "mDoc CBOR decode failed: {e}"
                            )));
                        }
                    }
                } else if presentation.is_object() {
                    tracing::debug!("presentation is JSON object");
                    let vp_token: VpToken =
                        serde_json::from_value(presentation.clone()).map_err(|e| {
                            AttError::BadRequest(format!("Failed to parse DCQL presentation: {e}"))
                        })?;
                    return Ok((vp_token, Some(credential_id.clone())));
                }
            }
        }
        return Err(AttError::BadRequest(
            "DCQL VP token has no presentations".to_string(),
        ));
    }

    // Fallback: direct VpToken JSON format
    tracing::debug!("VP token is direct JSON format");
    let vp_token: VpToken = serde_json::from_str(vp_token_str)
        .map_err(|e| AttError::BadRequest(format!("Invalid VP token format: {e}")))?;
    Ok((vp_token, None))
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
/// Accepts a VP token in DCQL format (mDoc CBOR `DeviceResponse` or SD-JWT VC compact
/// serialisation) or direct JSON. Extracts the credential claims, verifies expiry,
/// nonce binding against the server-stored transaction nonce, and SD-JWT VC / KB-JWT
/// cryptographic signatures, then returns an ES256-signed attestation JWT on success.
///
/// # Nonce replay prevention
///
/// The `state` field locates the server-stored [`OpenID4VPTransaction`]; its
/// server-generated nonce is compared against the nonce in the Key Binding JWT of the
/// SD-JWT VC presentation (or the `DeviceSigned` CBOR of an mDoc).
///
/// # Cryptographic signature verification
///
/// For SD-JWT VC: the issuer JWT `x5c` chain is verified against the trusted CA
/// directory; the holder key from `cnf.jwk` verifies the KB-JWT.
///
/// For mDoc: the full COSE_Sign1 `IssuerAuth` and `DeviceSignature` are verified,
/// including reconstruction of the OpenID4VP `SessionTranscript`.
pub(crate) async fn verify_credential_endpoint(
    req: HttpRequest,
    body: web::Json<VerifyCredentialRequest>,
    service: web::Data<Arc<OpenID4VPService>>,
    server_params: web::Data<Arc<ServerParams>>,
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

    tracing::debug!("Authenticated user: {}", username);

    tracing::debug!(
        vp_token_len = body.vp_token.len(),
        user = %username,
        state = ?body.state,
        client_id = ?body.client_id,
        "verify_credential request received"
    );

    // Look up the server-stored nonce from the transaction (by state).
    let transaction: Option<OpenID4VPTransaction> = if let Some(state) = body.state.as_deref() {
        match service.get_transaction_by_state(state).await {
            Ok(tx) => tx,
            Err(e) => {
                tracing::warn!(state, error = %e, "failed to look up transaction by state");
                None
            }
        }
    } else {
        None
    };
    let server_nonce = transaction.as_ref().map(|tx| tx.nonce.clone());

    if let (Some(tx), Some(client_id)) = (transaction.as_ref(), body.client_id.as_deref())
        && tx.client_id != client_id
    {
        return Err(AttError::BadRequest(
            "client_id does not match the transaction-bound request".to_string(),
        ));
    }

    let (vp_token, credential_id) = parse_vp_token(&body.vp_token)?;
    // Save presentation nonce before vp_token is borrowed by the match below.
    // In the DC API (same-device) flow there is no server-stored transaction so
    // the nonce bound to the presentation is the only one available.
    let presentation_nonce = vp_token.nonce.clone();

    tracing::debug!(
        credential_id = ?credential_id,
        doc_type = ?vp_token.doc_type,
        namespace = ?vp_token.namespace,
        issuer = ?vp_token.issuer,
        "VP token parsed"
    );

    let response_jwk_thumbprint = service.get_response_jwk_thumbprint();

    let (claims, doc_type, namespace, verification_result) = if let Some(raw_mdoc) =
        vp_token.raw_mdoc.as_deref()
    {
        let tx = transaction.as_ref().ok_or_else(|| {
                AttError::BadRequest(
                    "state is required for mDoc verification so the verifier can reconstruct the OpenID4VP handover"
                        .to_string(),
                )
            })?;

        let mdoc_result = verify_mdoc_presentation(
            raw_mdoc,
            &tx.client_id,
            &tx.nonce,
            &tx.response_uri,
            matches!(
                tx.response_mode,
                ewqwe_openid4vp::ResponseMode::DirectPostJwt
                    | ewqwe_openid4vp::ResponseMode::DcApiJwt
            ),
            response_jwk_thumbprint.as_deref(),
            trusted_cas.as_ref().as_slice(),
        )
        .map_err(|e| {
            tracing::error!(error = %e, "mDoc presentation verification failed");
            AttError::BadRequest(e.to_string())
        })?;

        if !mdoc_result.issuer_trusted {
            return Err(AttError::BadRequest(
                "mDoc issuerAuth certificate chain is not trusted: the issuer CA is not in the trusted certificates directory".to_string(),
            ));
        }
        if !mdoc_result.not_expired {
            return Err(AttError::BadRequest(
                "mDoc credential has expired: MSO validUntil is in the past".to_string(),
            ));
        }

        let verification_result = VerificationResult {
            is_valid: true,
            signature_valid: true,
            not_expired: true,
            issuer_trusted: true,
            errors: Vec::new(),
        };

        (
            mdoc_result.claims,
            mdoc_result.doc_type,
            mdoc_result.namespace,
            verification_result,
        )
    } else {
        let sig_result = if let Some(raw) = vp_token.raw_sd_jwt.as_deref() {
            verify_sd_jwt_signatures(raw, trusted_cas.as_ref().as_slice())
        } else {
            SigVerificationResult::skipped("presentation format not recognized")
        };
        let claims = extract_claims(&vp_token);
        let doc_type = vp_token.doc_type.clone();
        let namespace = vp_token.namespace.clone();
        let verification_result = verify_vp_token(&vp_token, server_nonce.as_deref(), &sig_result);
        (claims, doc_type, namespace, verification_result)
    };

    // Resolve client_id for the attestation audience.
    // In the DC API (same-device) flow `state` is absent so `transaction` will be
    // `None`; the RP must then supply `client_id` directly in the request body.
    let effective_client_id = body
        .client_id
        .as_deref()
        .or(transaction.as_ref().map(|tx| tx.client_id.as_str()))
        .ok_or_else(|| {
            AttError::BadRequest(
                "client_id is required: provide it in the request body when not using \
                 state-based transactions (e.g. same-device DC API flow)"
                    .to_string(),
            )
        })?;

    // Bind the attestation `sub` to the server-stored transaction ID when available.
    // In the DC API flow where `state` is absent a fresh UUID stands in as the
    // attestation event ID.
    let generated_transaction_id;
    let effective_transaction_id = if let Some(tx) = transaction.as_ref() {
        tx.id.as_str()
    } else {
        generated_transaction_id = uuid::Uuid::new_v4().to_string();
        generated_transaction_id.as_str()
    };

    // Prefer the server-stored nonce (direct_post flow); fall back to the nonce
    // extracted from the presentation itself (DC API flow).
    let attestation_nonce = server_nonce.as_deref().or(presentation_nonce.as_deref());

    tracing::debug!(
        is_valid = verification_result.is_valid,
        not_expired = verification_result.not_expired,
        issuer_trusted = verification_result.issuer_trusted,
        signature_valid = verification_result.signature_valid,
        "verification result"
    );

    if !verification_result.is_valid {
        tracing::warn!(errors = ?verification_result.errors, "credential verification failed");
        let attestation = create_attestation(
            effective_client_id,
            attestation_nonce,
            effective_transaction_id,
            &claims,
            &doc_type,
            &namespace,
            &server_params,
        )?;
        return Ok(HttpResponse::Ok().json(VerifyCredentialResponse {
            success: false,
            message: "Credential verification failed".to_string(),
            verification_details: Some(VerificationDetails {
                signature_valid: verification_result.signature_valid,
                not_expired: verification_result.not_expired,
                issuer_trusted: verification_result.issuer_trusted,
            }),
            attestation,
            errors: Some(verification_result.errors),
        }));
    }

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

    let attestation = create_attestation(
        effective_client_id,
        attestation_nonce,
        effective_transaction_id,
        &claims,
        &doc_type,
        &namespace,
        &server_params,
    )?;
    tracing::info!(doc_type = ?doc_type, client_id = ?body.client_id, "credential verified");

    // Append to the verification journal if enabled.
    // Look up the QR app user who initiated this transaction (if any).
    let qr_user = body
        .state
        .as_deref()
        .and_then(|txn_id| qr_map.as_ref()?.get(txn_id));

    if let Some(journal_store) = &journal {
        let jti = extract_attestation_jti(&attestation);
        let summary = serde_json::json!({
            "success": true,
            "doc_type": doc_type,
            "namespace": namespace,
            "signature_valid": true,
            "not_expired": true,
            "issuer_trusted": true,
        });
        if let Err(e) = append_verification(
            journal_store.as_ref().as_ref(),
            &username,
            &attestation,
            jti.as_deref(),
            Some(effective_client_id),
            Some(&doc_type),
            Some(&namespace),
            summary,
            qr_user.as_ref().map(|u| u.user_id.as_str()),
            qr_user.as_ref().map(|u| u.user_email.as_str()),
        )
        .await
        {
            tracing::error!(error = %e, "failed to append to verification journal");
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
    }))
}

// ============================================================================
// Internal helpers
// ============================================================================

fn extract_claims(vp_token: &VpToken) -> serde_json::Value {
    if let Some(claims) = &vp_token.claims {
        return claims.clone();
    }
    if let Some(issuer_signed) = &vp_token.issuer_signed
        && let Some(namespaces) = &issuer_signed.name_spaces
    {
        return namespaces.clone();
    }
    serde_json::json!({})
}

/// Verify the VP token: expiry, issuer trust, nonce binding, and signature validity.
fn verify_vp_token(
    vp_token: &VpToken,
    server_nonce: Option<&str>,
    sig: &SigVerificationResult,
) -> VerificationResult {
    let mut errors = Vec::new();

    let not_expired = if let Some(expires_at) = &vp_token.expires_at {
        match chrono::DateTime::parse_from_rfc3339(expires_at) {
            Ok(exp) => {
                if exp < chrono::Utc::now() {
                    errors.push("Credential has expired".to_string());
                    false
                } else {
                    true
                }
            }
            Err(_) => true,
        }
    } else {
        true
    };

    let issuer_trusted = if !sig.skipped {
        if !sig.issuer_trusted {
            errors.push("Issuer certificate does not chain to a trusted CA".to_string());
        }
        sig.issuer_trusted
    } else {
        let has_issuer = vp_token.issuer.is_some();
        if !has_issuer {
            errors.push("No issuer specified in credential".to_string());
        }
        has_issuer
    };

    let nonce_valid = match (server_nonce, vp_token.nonce.as_deref()) {
        (Some(req), Some(token)) => {
            if req == token {
                true
            } else {
                errors.push(
                    "Nonce mismatch: presentation nonce does not match server nonce".to_string(),
                );
                false
            }
        }
        (Some(_), None) => {
            // mDoc: nonce lives in DeviceSigned/SessionTranscript and is not yet extracted.
            // For SD-JWT VC it means the wallet sent no KB-JWT.
            tracing::debug!("nonce binding skipped: presentation carries no bound nonce");
            true
        }
        (None, _) => true,
    };

    let signature_valid = if !sig.skipped {
        let mut ok = true;
        if !sig.issuer_sig_valid {
            errors.push("Issuer JWT signature verification failed".to_string());
            ok = false;
        }
        if !sig.kb_sig_valid {
            errors.push("KB-JWT signature verification failed".to_string());
            ok = false;
        }
        errors.extend(sig.errors.iter().cloned());
        ok
    } else {
        true
    };

    let is_valid = signature_valid && not_expired && issuer_trusted && nonce_valid;

    VerificationResult {
        is_valid,
        signature_valid,
        not_expired,
        issuer_trusted,
        errors,
    }
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
/// The signing key is read from disk per [`ServerParams::attestation_issuer_key_path`].
/// The issuer (`iss`) claim is the Subject CN of [`ServerParams::attestation_issuer_certificate`].
/// The `kid` JWT header is the SHA-256 fingerprint of the certificate so the verifier
/// can locate the matching public key in the JWKS served at
/// `/ewqwe_api/openid4vp/.well-known/jwks.json`.
fn create_attestation(
    client_id: &str,
    nonce: Option<&str>,
    transaction_id: &str,
    claims: &serde_json::Value,
    doc_type: &str,
    namespace: &str,
    server_params: &ServerParams,
) -> Result<String, AttError> {
    let credential_claims = claims.as_object().cloned().unwrap_or_default();

    let iss = server_params.attestation_issuer_iss()?;

    let mut attestation =
        Attestation::new(&iss, client_id, transaction_id).with_credential_claims(credential_claims);

    attestation = attestation
        .with_doc_type(doc_type)
        .with_namespace(namespace);
    if let Some(n) = nonce {
        attestation = attestation.with_nonce(n);
    }

    let key_path = server_params.attestation_issuer_key_path();
    let private_key_pem = std::fs::read(key_path).map_err(|e| {
        AttError::Config(format!(
            "Failed to read attestation issuer key '{key_path}': {e}"
        ))
    })?;

    let mut signer =
        JwtSigner::from_pem(SigningAlgorithm::ES256, &private_key_pem).map_err(|e| {
            AttError::Generic(format!("Failed to create attestation issuer signer: {e}"))
        })?;

    // Include the cert fingerprint as `kid` so the RP can find the right JWKS key.
    if let Some(kid) = server_params.attestation_issuer_kid() {
        signer = signer.with_key_id(&kid);
    }

    let token_bytes = signer
        .sign(&attestation)
        .map_err(|e| AttError::Generic(format!("Failed to sign attestation: {e}")))?;

    String::from_utf8(token_bytes)
        .map_err(|e| AttError::Generic(format!("Failed to encode attestation: {e}")))
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
    let transaction = service
        .get_transaction_by_state(state)
        .await
        .map_err(|e| AttError::BadRequest(format!("failed to look up transaction by state: {e}")))?
        .ok_or_else(|| AttError::BadRequest("no transaction found for state".to_string()))?;

    let response_jwk_thumbprint = service.get_response_jwk_thumbprint();

    let (vp_token, _credential_id) = parse_vp_token(vp_token_str)?;

    let (claims, doc_type, namespace, verification_result) =
        if let Some(raw_mdoc) = vp_token.raw_mdoc.as_deref() {
            let mdoc_result = verify_mdoc_presentation(
                raw_mdoc,
                &transaction.client_id,
                &transaction.nonce,
                &transaction.response_uri,
                matches!(
                    transaction.response_mode,
                    ewqwe_openid4vp::ResponseMode::DirectPostJwt
                        | ewqwe_openid4vp::ResponseMode::DcApiJwt
                ),
                response_jwk_thumbprint.as_deref(),
                trusted_cas,
            )
            .map_err(|e| {
                tracing::error!(error = %e, "QR mDoc presentation verification failed");
                AttError::BadRequest(e.to_string())
            })?;

            if !mdoc_result.issuer_trusted {
                return Err(AttError::BadRequest(
                    "mDoc issuerAuth certificate chain is not trusted: \
                 the issuer CA is not in the trusted certificates directory"
                        .to_string(),
                ));
            }
            if !mdoc_result.not_expired {
                return Err(AttError::BadRequest(
                    "mDoc credential has expired: MSO validUntil is in the past".to_string(),
                ));
            }

            let vr = VerificationResult {
                is_valid: true,
                signature_valid: true,
                not_expired: true,
                issuer_trusted: true,
                errors: Vec::new(),
            };
            (
                mdoc_result.claims,
                mdoc_result.doc_type,
                mdoc_result.namespace,
                vr,
            )
        } else {
            let sig_result = if let Some(raw) = vp_token.raw_sd_jwt.as_deref() {
                verify_sd_jwt_signatures(raw, trusted_cas)
            } else {
                SigVerificationResult::skipped("presentation format not recognized")
            };
            let claims = extract_claims(&vp_token);
            let doc_type = vp_token.doc_type.clone();
            let namespace = vp_token.namespace.clone();
            let vr = verify_vp_token(&vp_token, Some(&transaction.nonce), &sig_result);
            (claims, doc_type, namespace, vr)
        };

    if !verification_result.is_valid {
        return Ok(QrVerificationOutcome {
            success: false,
            doc_type,
            namespace,
            errors: verification_result.errors,
            age_over_18: None,
        });
    }

    tracing::info!(
        doc_type = %doc_type,
        namespace = %namespace,
        username,
        "QR credential verification succeeded"
    );
    let age_over_18 = extract_age_over_18_claim(&claims);

    if let Some(journal_store) = journal {
        let summary = serde_json::json!({
            "success": true,
            "doc_type": doc_type,
            "namespace": namespace,
            "signature_valid": verification_result.signature_valid,
            "not_expired": verification_result.not_expired,
            "issuer_trusted": verification_result.issuer_trusted,
            "source": "qr_verifier_app",
        });
        // No attestation JWT in the QR flow — pass empty string; the hash is still recorded.
        if let Err(e) = crate::journal::append_verification(
            journal_store,
            username,
            "",
            None,
            Some(transaction.client_id.as_str()),
            Some(doc_type.as_str()),
            Some(namespace.as_str()),
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
        doc_type,
        namespace,
        errors: Vec::new(),
        age_over_18,
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
