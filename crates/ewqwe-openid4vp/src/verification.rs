//! VP token parsing and cryptographic verification.
//!
//! This module implements the core verification logic for OpenID4VP presentations:
//!
//! - `parse_vp_token` — decodes DCQL-wrapped or direct JSON VP tokens into
//!   a structured `VpToken`, handling both SD-JWT VC (compact format) and
//!   mDoc (base64-encoded CBOR DeviceResponse) formats.
//! - `verify_vp_token` — validates expiry, nonce binding, and (for SD-JWT VC)
//!   issuer trust and signature validity.
//!
//! Cryptographic verification of mDoc COSE signatures and SD-JWT VC `x5c`
//! chains is delegated to the `ewqwe_digital_credential` crate.

use crate::types::OpenID4VPTransaction;
use ewqwe_digital_credential::{
    SigVerificationResult, decode_mdoc_presentation, decode_sd_jwt_presentation,
    verify_mdoc_presentation, verify_sd_jwt_signatures,
};
use serde::Deserialize;

// ============================================================================
// Internal types for VP token parsing
// ============================================================================

/// Parsed VP token — can be direct format or DCQL-wrapped.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
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

/// Intermediate verification result from the non-cryptographic checks.
pub(crate) struct VerificationResult {
    pub(crate) is_valid: bool,
    pub(crate) signature_valid: bool,
    pub(crate) not_expired: bool,
    pub(crate) issuer_trusted: bool,
    pub(crate) errors: Vec<String>,
    pub(crate) warnings: Vec<String>,
}

// ============================================================================
// VP token parsing
// ============================================================================

/// Parse a VP token — handles DCQL-wrapped format and direct JSON format.
fn parse_vp_token(vp_token_str: &str) -> Result<(VpToken, Option<String>), String> {
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
                                return Err(format!("SD-JWT VC decode failed: {e}"));
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
                            let first_ns = decoded
                                .namespaces
                                .keys()
                                .next()
                                .cloned()
                                .ok_or_else(|| "mDoc contains no namespaces".to_string())?;
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
                            return Err(format!("mDoc CBOR decode failed: {e}"));
                        }
                    }
                } else if presentation.is_object() {
                    tracing::debug!("presentation is JSON object");
                    let vp_token: VpToken = serde_json::from_value(presentation.clone())
                        .map_err(|e| format!("Failed to parse DCQL presentation: {e}"))?;
                    return Ok((vp_token, Some(credential_id.clone())));
                }
            }
        }
        return Err("DCQL VP token has no presentations".to_string());
    }

    // Fallback: direct VpToken JSON format
    tracing::debug!("VP token is direct JSON format");
    let vp_token: VpToken =
        serde_json::from_str(vp_token_str).map_err(|e| format!("Invalid VP token format: {e}"))?;
    Ok((vp_token, None))
}

// ============================================================================
// Verification logic
// ============================================================================

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
        warnings: Vec::new(),
    }
}

/// Extract claims from a VP token.
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

// ============================================================================
// Public API — called from OpenID4VPService::verify_presentation
// ============================================================================

/// Verify a VP token against a server-stored transaction and trusted CAs.
///
/// This is the core verification pipeline invoked by
/// [`OpenID4VPService::verify_presentation`].
///
/// # Arguments
///
/// * `vp_token_str` — The raw VP token string (DCQL-wrapped or direct JSON).
/// * `transaction` — Optional server-stored transaction for nonce/state validation.
/// * `client_id` — Optional client_id to validate against the transaction.
/// * `trusted_cas` — The list of trusted CA certificates.
/// * `response_jwk_thumbprint` — Optional JWK thumbprint for mDoc SessionTranscript reconstruction.
///
/// # Returns
///
/// A tuple of `(claims, doc_type, namespace, verification_result, credential_id)`.
pub(crate) fn verify_vp_token_against_cas(
    vp_token_str: &str,
    transaction: Option<&OpenID4VPTransaction>,
    client_id: Option<&str>,
    trusted_cas: &[openssl::x509::X509],
    response_jwk_thumbprint: Option<&[u8]>,
) -> Result<
    (
        serde_json::Value,
        String,
        String,
        VerificationResult,
        Option<String>,
    ),
    String,
> {
    // Validate client_id against transaction if both are provided.
    if let (Some(tx), Some(cid)) = (transaction, client_id)
        && tx.client_id != cid
    {
        return Err("client_id does not match the transaction-bound request".to_string());
    }

    let server_nonce = transaction.map(|tx| tx.nonce.as_str());
    let (vp_token, credential_id) = parse_vp_token(vp_token_str)?;

    let (claims, doc_type, namespace, verification_result) = if let Some(raw_mdoc) =
        vp_token.raw_mdoc.as_deref()
    {
        let tx = transaction.ok_or_else(|| {
            "state is required for mDoc verification so the verifier can reconstruct \
             the OpenID4VP handover"
                .to_string()
        })?;

        let mdoc_result = verify_mdoc_presentation(
            raw_mdoc,
            &tx.client_id,
            &tx.nonce,
            &tx.response_uri,
            matches!(
                tx.response_mode,
                crate::types::ResponseMode::DirectPostJwt | crate::types::ResponseMode::DcApiJwt
            ),
            response_jwk_thumbprint,
            trusted_cas,
        )
        .map_err(|e| format!("mDoc presentation verification failed: {e}"))?;

        if !mdoc_result.not_expired {
            return Err("credential has expired: MSO validUntil is in the past".to_string());
        }

        let mut warnings = Vec::new();
        if !mdoc_result.issuer_trusted {
            warnings.push("issuerAuth certificate chain is not in the trusted CA list".to_string());
            tracing::error!(
                iss = ?warnings.last(),
                doc_type = %mdoc_result.doc_type,
                "issuerAuth certificate chain is not in the trusted CA list"
            );
            return Err("issuerAuth certificate chain is not in the trusted CA list".to_owned());
        }

        let vr = VerificationResult {
            is_valid: true,
            signature_valid: true,
            not_expired: mdoc_result.not_expired,
            issuer_trusted: mdoc_result.issuer_trusted,
            errors: Vec::new(),
            warnings,
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
        let vr = verify_vp_token(&vp_token, server_nonce, &sig_result);
        (claims, doc_type, namespace, vr)
    };

    Ok((
        claims,
        doc_type,
        namespace,
        verification_result,
        credential_id,
    ))
}
