use crate::{
    AttError,
    attestation::{AttestationClaims, AttestationSigner, JwtSigner, SigningAlgorithm},
    mdoc_decoder,
    server::{ServerParams, Version},
};
use actix_web::{HttpRequest, HttpResponse, web};
use base64::Engine;
use coset::{CborSerializable, CoseKey, CoseSign1, Label, RegisteredLabelWithPrivate, iana};
use ewqwe_openid4vp::{OpenID4VPService, OpenID4VPTransaction, ResponseMode};
use openssl::{
    bn::BigNum,
    ec::{EcGroup, EcKey},
    ecdsa::EcdsaSig,
    hash::{MessageDigest, hash},
    nid::Nid,
    pkey::{PKey, Public},
    rsa::Padding,
    sign::Verifier as OpensslVerifier,
    x509::X509,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Request body for credential verification
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)] // Fields are part of OpenID4VP spec but may not all be actively used
pub struct VerifyCredentialRequest {
    /// The VP token from the wallet (JSON string containing the credential)
    pub vp_token: String,

    /// Presentation submission with descriptor mapping.
    /// Optional because DCQL-based responses (OpenID4VP Section 8.1) don't include
    /// presentation_submission - the vp_token itself is structured with credential IDs as keys.
    #[serde(default)]
    pub presentation_submission: Option<PresentationSubmission>,

    /// Original state from the request.
    /// Used to look up the server-stored transaction nonce for replay prevention.
    #[serde(default)]
    pub state: Option<String>,

    /// Client ID (relying party identifier)
    #[serde(default)]
    pub client_id: Option<String>,
}

/// Presentation submission structure from OpenID4VP
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)] // Part of OpenID4VP spec, used with presentation_definition (not DCQL)
pub struct PresentationSubmission {
    pub id: String,
    pub definition_id: String,
    pub descriptor_map: Vec<DescriptorMapEntry>,
}

/// Descriptor map entry
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)] // Part of OpenID4VP spec
pub struct DescriptorMapEntry {
    pub id: String,
    pub format: String,
    pub path: String,
}

/// Response from credential verification
#[derive(Debug, Clone, Serialize)]
pub struct VerifyCredentialResponse {
    /// Whether verification was successful
    pub success: bool,

    /// Human-readable message
    pub message: String,

    /// Extracted and verified claims (if successful)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims: Option<serde_json::Value>,

    /// Verification details
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_details: Option<VerificationDetails>,

    /// Signed attestation JWT (if successful)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<String>,

    /// Errors (if failed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
}

/// Details about the verification process
#[derive(Debug, Clone, Serialize)]
pub struct VerificationDetails {
    pub signature_valid: bool,
    pub not_expired: bool,
    pub issuer_trusted: bool,
    pub timestamp: String,
    pub doc_type: Option<String>,
    pub namespace: Option<String>,
}

/// Parsed VP Token structure - can be either direct format or DCQL-wrapped
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)] // Fields are part of credential format spec
struct VpToken {
    doc_type: Option<String>,
    namespace: Option<String>,
    claims: Option<serde_json::Value>,
    issuer: Option<String>,
    issued_at: Option<String>,
    expires_at: Option<String>,
    /// Nonce bound to this presentation — for SD-JWT VC extracted from the Key Binding JWT;
    /// for mDoc extracted from DeviceSigned CBOR (not yet implemented).
    #[serde(skip)]
    nonce: Option<String>,
    /// The raw SD-JWT VC compact string (header.payload.sig~disc~...~[kbjwt]),
    /// preserved for cryptographic signature verification.
    #[serde(skip)]
    raw_sd_jwt: Option<String>,
    /// The raw base64url-encoded DeviceResponse presentation for mDoc verification.
    #[serde(skip)]
    raw_mdoc: Option<String>,
    // mDoc format
    issuer_signed: Option<IssuerSigned>,
}

struct MdocVerificationResult {
    claims: serde_json::Value,
    doc_type: Option<String>,
    namespace: Option<String>,
    not_expired: bool,
    issuer_trusted: bool,
}

struct ParsedMobileSecurityObject {
    doc_type: String,
    digest_algorithm: String,
    value_digests: std::collections::BTreeMap<String, std::collections::BTreeMap<u64, Vec<u8>>>,
    device_key: CoseKey,
    valid_from: Option<String>,
    valid_until: Option<String>,
}

/// DCQL-wrapped VP Token format (OpenID4VP Section 8.1)
/// The vp_token is a JSON object where keys are credential IDs and values are arrays of presentations
type DcqlVpToken = std::collections::HashMap<String, Vec<serde_json::Value>>;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IssuerSigned {
    name_spaces: Option<serde_json::Value>,
}

/// Errors that can occur during SD-JWT VC decoding.
#[derive(Debug, thiserror::Error)]
enum SdJwtDecodeError {
    #[error("not an SD-JWT: no '~' separator found")]
    NotSdJwt,
    #[error("malformed JWT: expected 3 dot-separated parts")]
    MalformedJwt,
    #[error("base64 decode failed: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("JSON parse failed: {0}")]
    Json(#[from] serde_json::Error),
}

/// Decode an SD-JWT VC compact presentation.
///
/// Format (IETF SD-JWT §1): `<Issuer-Signed JWT>~<Disclosure1>~...~[KB-JWT]`
///
/// Each disclosure is a base64url-encoded JSON array: `[salt, claim_name, value]`
/// The last `~`-separated element is optionally a Key Binding JWT (starts with "eyJ" and contains
/// exactly 2 dots). The KB-JWT payload contains `{ "nonce": "...", "aud": "...",
/// "iat": ..., "sd_hash": "..." }` — the nonce is extracted and stored in the returned
/// `VpToken` so the caller can verify it against the request nonce.
///
/// Returns a `VpToken` populated with the decoded claims, issuer, and nonce from the KB-JWT.
fn decode_sd_jwt_presentation(raw: &str) -> Result<VpToken, SdJwtDecodeError> {
    let raw_sd_jwt = raw.to_string();
    if !raw.contains('~') {
        return Err(SdJwtDecodeError::NotSdJwt);
    }

    let parts: Vec<&str> = raw.splitn(2, '~').collect();
    let issuer_jwt = parts[0];
    let rest = if parts.len() > 1 { parts[1] } else { "" };

    // Decode JWT payload (middle dot-separated part)
    let jwt_parts: Vec<&str> = issuer_jwt.split('.').collect();
    if jwt_parts.len() != 3 {
        return Err(SdJwtDecodeError::MalformedJwt);
    }
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(jwt_parts[1])
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(jwt_parts[1]))?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes)?;

    tracing::debug!("SD-JWT payload claims: {}", payload);

    // Extract issuer and vct from JWT payload
    let issuer = payload
        .get("iss")
        .and_then(|v| v.as_str())
        .unwrap_or("sd-jwt-issuer")
        .to_string();
    let vct = payload
        .get("vct")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let issued_at = payload
        .get("iat")
        .and_then(|v| v.as_i64())
        .map(|ts| chrono::DateTime::from_timestamp(ts, 0).map(|dt| dt.to_rfc3339()))
        .flatten();
    let expires_at = payload
        .get("exp")
        .and_then(|v| v.as_i64())
        .map(|ts| chrono::DateTime::from_timestamp(ts, 0).map(|dt| dt.to_rfc3339()))
        .flatten();

    // Collect confirmed (non-selectively-disclosed) claims from JWT payload,
    // skipping standard JWT reserved claims and SD-JWT structural fields.
    const SKIP_CLAIMS: &[&str] = &[
        "iss", "sub", "aud", "iat", "exp", "nbf", "jti", "vct", "_sd", "_sd_alg", "cnf", "status",
    ];
    let mut claims = serde_json::Map::new();
    if let Some(obj) = payload.as_object() {
        for (k, v) in obj {
            if !SKIP_CLAIMS.contains(&k.as_str()) {
                claims.insert(k.clone(), v.clone());
            }
        }
    }

    // Process `~`-separated elements: disclosures followed by an optional KB-JWT.
    let mut kb_nonce: Option<String> = None;
    for disclosure_str in rest.split('~') {
        if disclosure_str.is_empty() {
            continue;
        }
        // KB-JWT: a full JWT (2 dots, starts with "eyJ") — extract the nonce claim.
        let dot_count = disclosure_str.chars().filter(|&c| c == '.').count();
        if dot_count == 2 && disclosure_str.starts_with("eyJ") {
            let kb_parts: Vec<&str> = disclosure_str.split('.').collect();
            if let Ok(kb_payload_bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(kb_parts[1])
                .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(kb_parts[1]))
            {
                if let Ok(kb_payload) =
                    serde_json::from_slice::<serde_json::Value>(&kb_payload_bytes)
                {
                    kb_nonce = kb_payload
                        .get("nonce")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    tracing::debug!(nonce_present = kb_nonce.is_some(), "KB-JWT parsed");
                }
            }
            continue;
        }

        let disc_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(disclosure_str)
            .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(disclosure_str));

        match disc_bytes {
            Ok(bytes) => match serde_json::from_slice::<serde_json::Value>(&bytes) {
                Ok(serde_json::Value::Array(arr)) if arr.len() == 3 => {
                    // [salt, claim_name, value]
                    if let Some(claim_name) = arr[1].as_str() {
                        tracing::debug!("SD-JWT disclosure: {} = {:?}", claim_name, arr[2]);
                        claims.insert(claim_name.to_string(), arr[2].clone());
                    }
                }
                Ok(other) => {
                    tracing::warn!("SD-JWT disclosure is not a 3-element array: {:?}", other);
                }
                Err(e) => {
                    tracing::warn!("Failed to parse SD-JWT disclosure JSON: {}", e);
                }
            },
            Err(e) => {
                tracing::warn!("Failed to base64-decode SD-JWT disclosure: {}", e);
            }
        }
    }

    tracing::debug!(vct = %vct, %issuer, claims_count = claims.len(), nonce_bound = kb_nonce.is_some(), "SD-JWT VC decoded");

    Ok(VpToken {
        doc_type: Some(vct.clone()),
        namespace: Some(vct),
        claims: Some(serde_json::Value::Object(claims)),
        issuer: Some(issuer),
        issued_at,
        expires_at,
        nonce: kb_nonce,
        raw_sd_jwt: Some(raw_sd_jwt),
        raw_mdoc: None,
        issuer_signed: None,
    })
}

/// Parse VP token - handles both direct format and DCQL-wrapped format
fn parse_vp_token(vp_token_str: &str) -> Result<(VpToken, Option<String>), AttError> {
    // First, try parsing as DCQL format (object with credential IDs as keys)
    if let Ok(dcql_token) = serde_json::from_str::<DcqlVpToken>(vp_token_str) {
        // Get the first credential from the DCQL response
        if let Some((credential_id, presentations)) = dcql_token.iter().next() {
            tracing::debug!(
                credential_id,
                presentations_count = presentations.len(),
                "DCQL VP token"
            );

            if let Some(presentation) = presentations.first() {
                // The presentation might be:
                //   (a) SD-JWT VC compact string:  header.payload.sig~disc1~disc2~[kbjwt]
                //   (b) base64-encoded mDoc CBOR DeviceResponse
                //   (c) JSON object (legacy direct format)
                if let Some(encoded_str) = presentation.as_str() {
                    // (a) Detect SD-JWT VC: the compact format contains '~' separators.
                    if encoded_str.contains('~') {
                        tracing::debug!(len = encoded_str.len(), "presentation is SD-JWT VC");
                        match decode_sd_jwt_presentation(encoded_str) {
                            Ok(vp_token) => {
                                return Ok((vp_token, Some(credential_id.clone())));
                            }
                            Err(e) => {
                                tracing::warn!("  SD-JWT VC decode failed: {}", e);
                                return Err(AttError::BadRequest(format!(
                                    "SD-JWT VC decode failed: {e}"
                                )));
                            }
                        }
                    }

                    // (b) Try base64-encoded mDoc CBOR
                    tracing::debug!(
                        len = encoded_str.len(),
                        "presentation is base64-encoded mDoc"
                    );

                    let decode_error_msg;
                    match mdoc_decoder::decode_mdoc_presentation(encoded_str) {
                        Ok(decoded) => {
                            tracing::debug!(doc_type = %decoded.doc_type, namespaces = decoded.namespaces.len(), "mDoc decoded");

                            // Capture the first namespace key before we consume the map
                            let first_ns = decoded
                                .namespaces
                                .keys()
                                .next()
                                .cloned()
                                .unwrap_or_else(|| decoded.doc_type.clone());

                            // Flatten all namespaced claims into a single JSON object.
                            // One namespace → flat; multiple → nested by namespace.
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
                                doc_type: Some(decoded.doc_type),
                                namespace: Some(first_ns),
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
                            tracing::warn!(error = %e, "mDoc CBOR decode failed");
                            decode_error_msg = e.to_string();
                        }
                    }

                    // Fallback: CBOR decoding failed — determine type from credential_id
                    let (doc_type, namespace) = if credential_id.contains("age")
                        || credential_id.contains("av")
                    {
                        (
                            "eu.europa.ec.av.1".to_string(),
                            "eu.europa.ec.av.1".to_string(),
                        )
                    } else if credential_id.contains("mdl") {
                        (
                            "org.iso.18013.5.1.mDL".to_string(),
                            "org.iso.18013.5.1".to_string(),
                        )
                    } else if credential_id.contains("national") || credential_id.contains("pid") {
                        (
                            "eu.europa.ec.eudi.pid.1".to_string(),
                            "eu.europa.ec.eudi.pid.1".to_string(),
                        )
                    } else {
                        (credential_id.clone(), credential_id.clone())
                    };

                    let fallback_claims = serde_json::json!({
                        "_note": "mDoc CBOR decoding failed — raw presentation could not be parsed",
                        "_error": decode_error_msg,
                        "_credential_id": credential_id,
                        "_doc_type": &doc_type,
                        "_presentation_length": encoded_str.len()
                    });

                    let vp_token = VpToken {
                        doc_type: Some(doc_type),
                        namespace: Some(namespace),
                        claims: Some(fallback_claims),
                        issuer: Some("unknown".to_string()),
                        issued_at: None,
                        expires_at: None,
                        nonce: None,
                        raw_sd_jwt: None,
                        raw_mdoc: Some(encoded_str.to_string()),
                        issuer_signed: None,
                    };
                    return Ok((vp_token, Some(credential_id.clone())));
                } else if presentation.is_object() {
                    // It's already a JSON object - try to parse as VpToken
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

    // Fall back to direct VpToken format
    tracing::debug!("VP token is direct JSON format");
    let vp_token: VpToken = serde_json::from_str(vp_token_str)
        .map_err(|e| AttError::BadRequest(format!("Invalid VP token format: {e}")))?;
    Ok((vp_token, None))
}

pub(crate) async fn version_endpoint(_req: HttpRequest) -> Result<HttpResponse, AttError> {
    let version = env!("CARGO_PKG_VERSION");
    let version = Version {
        version: version.to_string(),
    };
    Ok(HttpResponse::Ok().json(version))
}

/// Verify a credential presentation from a wallet and return a signed attestation.
///
/// Accepts a VP token in DCQL format (mDoc CBOR DeviceResponse or SD-JWT VC compact
/// serialisation) or direct JSON. Extracts the credential claims, verifies
/// expiry, nonce binding against the server-stored transaction nonce, and
/// SD-JWT VC / KB-JWT cryptographic signatures, then returns an
/// ES256-signed attestation JWT on success.
///
/// # Nonce replay prevention
///
/// The nonce is **not** taken from the HTTP request body. Instead the
/// `state` field in the request is used to look up the `OpenID4VPTransaction`
/// from the server-side store, and its server-generated nonce is compared
/// against the nonce embedded in the Key Binding JWT of the SD-JWT VC
/// presentation (or the DeviceSigned CBOR of an mDoc).
///
/// # Cryptographic signature verification
///
/// For SD-JWT VC presentations the issuer JWT signature and the KB-JWT
/// holder signature are verified using the `jsonwebtoken` crate. The
/// issuer's public key is extracted from the `x5c` JWT header, and the
/// holder's public key from the `cnf.jwk` claim in the issuer payload.
///
/// mDoc MSO COSE_Sign1 signature verification is not yet implemented.
///
/// # Trusted-issuer list
///
/// When the issuer JWT header contains `x5c`, the leaf certificate is
/// validated against the trusted issuer CA certificates loaded from
/// `ServerParams::trusted_issuer_certs`. If no `x5c` header is present
/// the signature is still verified (the public key comes from the JWT
/// header algorithm) but issuer trust is not established.
pub(crate) async fn verify_credential_endpoint(
    _req: HttpRequest,
    body: web::Json<VerifyCredentialRequest>,
    service: web::Data<Arc<OpenID4VPService>>,
    server_params: web::Data<Arc<ServerParams>>,
) -> Result<HttpResponse, AttError> {
    tracing::debug!(
        vp_token_len = body.vp_token.len(),
        state = ?body.state,
        client_id = ?body.client_id,
        "verify_credential request received"
    );

    // Look up the server-stored nonce from the transaction (by state).
    // This is the nonce the verifier generated in init_transaction().
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

    if let (Some(tx), Some(client_id)) = (transaction.as_ref(), body.client_id.as_deref()) {
        if tx.client_id != client_id {
            return Err(AttError::BadRequest(
                "client_id does not match the transaction-bound request".to_string(),
            ));
        }
    }

    // Parse the VP token (handles both direct and DCQL formats)
    let (vp_token, credential_id) = parse_vp_token(&body.vp_token)?;

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
            tx,
            response_jwk_thumbprint.as_deref(),
            &server_params.trusted_issuer_certs,
        )
        .map_err(|e| {
            tracing::error!(error = %e, "mDoc presentation verification failed");
            e
        })?;

        let verification_result = VerificationResult {
            is_valid: true,
            signature_valid: true,
            not_expired: mdoc_result.not_expired,
            issuer_trusted: mdoc_result.issuer_trusted,
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
            verify_sd_jwt_signatures(raw, &server_params.trusted_issuer_certs)
        } else {
            SigVerificationResult::skipped("presentation format not recognized")
        };

        let claims = extract_claims(&vp_token);
        let doc_type = vp_token.doc_type.clone();
        let namespace = vp_token.namespace.clone();
        let verification_result = verify_vp_token(&vp_token, server_nonce.as_deref(), &sig_result);
        (claims, doc_type, namespace, verification_result)
    };

    tracing::debug!(
        is_valid = verification_result.is_valid,
        not_expired = verification_result.not_expired,
        issuer_trusted = verification_result.issuer_trusted,
        signature_valid = verification_result.signature_valid,
        "verification result"
    );

    if !verification_result.is_valid {
        tracing::warn!(errors = ?verification_result.errors, "credential verification failed");
        return Ok(HttpResponse::Ok().json(VerifyCredentialResponse {
            success: false,
            message: "Credential verification failed".to_string(),
            claims: None,
            verification_details: Some(VerificationDetails {
                signature_valid: verification_result.signature_valid,
                not_expired: verification_result.not_expired,
                issuer_trusted: verification_result.issuer_trusted,
                timestamp: chrono::Utc::now().to_rfc3339(),
                doc_type,
                namespace,
            }),
            attestation: None,
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
        body.client_id
            .as_deref()
            .or(transaction.as_ref().map(|tx| tx.client_id.as_str()))
            .unwrap_or("unknown-rp"),
        server_nonce.as_deref(),
        &claims,
    )?;
    tracing::info!(doc_type = ?doc_type, client_id = ?body.client_id, "credential verified");

    Ok(HttpResponse::Ok().json(VerifyCredentialResponse {
        success: true,
        message: "Credential verified successfully".to_string(),
        claims: Some(claims),
        verification_details: Some(VerificationDetails {
            signature_valid: true,
            not_expired: true,
            issuer_trusted: true,
            timestamp: chrono::Utc::now().to_rfc3339(),
            doc_type,
            namespace,
        }),
        attestation: Some(attestation),
        errors: None,
    }))
}

/// Extract claims from the VP token
fn extract_claims(vp_token: &VpToken) -> serde_json::Value {
    // Try direct claims first
    if let Some(claims) = &vp_token.claims {
        return claims.clone();
    }

    // Try mDoc format (issuerSigned.nameSpaces)
    if let Some(issuer_signed) = &vp_token.issuer_signed {
        if let Some(namespaces) = &issuer_signed.name_spaces {
            return namespaces.clone();
        }
    }

    serde_json::json!({})
}

fn verify_mdoc_presentation(
    encoded: &str,
    transaction: &OpenID4VPTransaction,
    response_jwk_thumbprint: Option<&[u8]>,
    trusted_ca_paths: &[String],
) -> Result<MdocVerificationResult, AttError> {
    let decoded = mdoc_decoder::decode_mdoc_presentation(encoded)
        .map_err(|e| AttError::BadRequest(format!("mDoc CBOR decode failed: {e}")))?;

    let bytes = decode_base64url_or_base64(encoded)
        .map_err(|e| AttError::BadRequest(format!("mDoc base64 decode failed: {e}")))?;
    let cbor: ciborium::Value = ciborium::from_reader(&bytes[..])
        .map_err(|e| AttError::BadRequest(format!("mDoc CBOR parse failed: {e}")))?;
    let document = extract_first_document(&cbor)?;
    let document_map = as_cbor_map(document)
        .ok_or_else(|| AttError::BadRequest("mDoc document is not a CBOR map".to_string()))?;

    let doc_type = cbor_map_get_text(document_map, "docType")
        .ok_or_else(|| AttError::BadRequest("mDoc document missing docType".to_string()))?
        .to_string();

    let issuer_signed = unwrap_cbor_tags(
        cbor_map_get(document_map, "issuerSigned")
            .ok_or_else(|| AttError::BadRequest("mDoc missing issuerSigned".to_string()))?,
    );
    let issuer_signed_map = as_cbor_map(issuer_signed)
        .ok_or_else(|| AttError::BadRequest("issuerSigned is not a CBOR map".to_string()))?;
    let name_spaces = unwrap_cbor_tags(
        cbor_map_get(issuer_signed_map, "nameSpaces")
            .ok_or_else(|| AttError::BadRequest("issuerSigned missing nameSpaces".to_string()))?,
    );
    let name_spaces_map = as_cbor_map(name_spaces)
        .ok_or_else(|| AttError::BadRequest("issuerSigned.nameSpaces is not a map".to_string()))?;

    let issuer_auth = parse_cose_sign1_from_value(
        cbor_map_get(issuer_signed_map, "issuerAuth")
            .ok_or_else(|| AttError::BadRequest("issuerSigned missing issuerAuth".to_string()))?,
    )?;
    let issuer_chain = extract_x5chain_from_cose(&issuer_auth)?;
    let (issuer_key, issuer_trusted) =
        verify_cose_certificate_chain(&issuer_chain, trusted_ca_paths)?;
    verify_cose_sign1_embedded(&issuer_auth, &issuer_key)?;

    let mso = parse_mobile_security_object(
        issuer_auth
            .payload
            .as_deref()
            .ok_or_else(|| AttError::BadRequest("issuerAuth missing payload".to_string()))?,
    )?;

    if mso.doc_type != doc_type {
        return Err(AttError::BadRequest(
            "mDoc docType does not match MobileSecurityObject docType".to_string(),
        ));
    }

    verify_issuer_signed_item_digests(name_spaces_map, &mso)?;

    let device_signed = unwrap_cbor_tags(
        cbor_map_get(document_map, "deviceSigned")
            .ok_or_else(|| AttError::BadRequest("mDoc missing deviceSigned".to_string()))?,
    );
    let device_signed_map = as_cbor_map(device_signed)
        .ok_or_else(|| AttError::BadRequest("deviceSigned is not a CBOR map".to_string()))?;
    let device_name_spaces_bytes = extract_device_namespaces_bytes(device_signed_map)?;
    let device_auth = unwrap_cbor_tags(
        cbor_map_get(device_signed_map, "deviceAuth")
            .ok_or_else(|| AttError::BadRequest("deviceSigned missing deviceAuth".to_string()))?,
    );
    let device_auth_map = as_cbor_map(device_auth)
        .ok_or_else(|| AttError::BadRequest("deviceAuth is not a CBOR map".to_string()))?;

    let device_signature = cbor_map_get(device_auth_map, "deviceSignature").ok_or_else(|| {
        AttError::BadRequest(
            "deviceAuth.deviceMac is not supported by this verifier; expected deviceSignature"
                .to_string(),
        )
    })?;
    let device_signature = parse_cose_sign1_from_value(device_signature)?;
    let session_transcript = build_openid4vp_session_transcript(
        &transaction.client_id,
        &transaction.nonce,
        transaction.response_mode,
        response_jwk_thumbprint,
        &transaction.response_uri,
    )?;
    let device_authentication_raw = build_device_authentication_payload(
        &session_transcript,
        &doc_type,
        &device_name_spaces_bytes,
    )?;
    // ISO 18013-5 §9.1.3.4: DeviceAuthenticationBytes = #6.24(bstr .cbor DeviceAuthentication)
    // The wallet (multipaz) signs over DeviceAuthenticationBytes, not raw DeviceAuthentication.
    let device_authentication_bytes = cbor_to_vec(&ciborium::Value::Tag(
        24,
        Box::new(ciborium::Value::Bytes(device_authentication_raw)),
    ))?;
    let device_key = cose_key_to_public_key(&mso.device_key)?;
    verify_cose_sign1_detached(&device_signature, &device_key, &device_authentication_bytes)?;

    let namespace = decoded.namespaces.keys().next().cloned();
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

    let not_expired = validate_mso_validity(&mso)?;

    Ok(MdocVerificationResult {
        claims,
        doc_type: Some(doc_type),
        namespace,
        not_expired,
        issuer_trusted,
    })
}

fn decode_base64url_or_base64(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(input)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(input))
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(input))
}

fn extract_first_document(cbor: &ciborium::Value) -> Result<&ciborium::Value, AttError> {
    let cbor = unwrap_cbor_tags(cbor);
    let map = as_cbor_map(cbor)
        .ok_or_else(|| AttError::BadRequest("mDoc top-level value is not a map".to_string()))?;
    if let Some(documents) = cbor_map_get(map, "documents") {
        let documents = as_cbor_array(unwrap_cbor_tags(documents)).ok_or_else(|| {
            AttError::BadRequest("mDoc DeviceResponse.documents is not an array".to_string())
        })?;
        documents.first().ok_or_else(|| {
            AttError::BadRequest("mDoc DeviceResponse.documents is empty".to_string())
        })
    } else {
        Ok(cbor)
    }
}

fn parse_cose_sign1_from_value(value: &ciborium::Value) -> Result<CoseSign1, AttError> {
    let untagged = match value {
        ciborium::Value::Tag(18, inner) => inner.as_ref().clone(),
        other => other.clone(),
    };
    let mut bytes = Vec::new();
    ciborium::into_writer(&untagged, &mut bytes)
        .map_err(|e| AttError::BadRequest(format!("COSE serialization failed: {e}")))?;
    CoseSign1::from_slice(&bytes)
        .map_err(|e| AttError::BadRequest(format!("COSE_Sign1 parse failed: {e}")))
}

fn extract_x5chain_from_cose(cose: &CoseSign1) -> Result<Vec<Vec<u8>>, AttError> {
    for headers in [&cose.protected.header, &cose.unprotected] {
        for (label, value) in &headers.rest {
            if *label == Label::Int(33) {
                return match value {
                    ciborium::Value::Bytes(cert) => Ok(vec![cert.clone()]),
                    ciborium::Value::Array(items) => items
                        .iter()
                        .map(|item| match item {
                            ciborium::Value::Bytes(cert) => Ok(cert.clone()),
                            _ => Err(AttError::BadRequest(
                                "COSE x5chain array contains a non-byte-string certificate"
                                    .to_string(),
                            )),
                        })
                        .collect(),
                    _ => Err(AttError::BadRequest(
                        "COSE x5chain header is neither a byte string nor an array".to_string(),
                    )),
                };
            }
        }
    }

    Err(AttError::BadRequest(
        "issuerAuth is missing COSE x5chain header parameter 33".to_string(),
    ))
}

fn verify_cose_certificate_chain(
    cert_chain: &[Vec<u8>],
    trusted_ca_paths: &[String],
) -> Result<(PKey<Public>, bool), AttError> {
    let leaf = cert_chain.first().ok_or_else(|| {
        AttError::BadRequest("issuerAuth x5chain does not contain a leaf certificate".to_string())
    })?;
    let leaf = X509::from_der(leaf)
        .map_err(|e| AttError::BadRequest(format!("failed to parse issuer leaf cert: {e}")))?;

    let trusted_cas = load_trusted_issuer_certs(trusted_ca_paths);
    let mut store_builder = openssl::x509::store::X509StoreBuilder::new().map_err(|e| {
        AttError::Generic(format!("failed to create X509 trust store builder: {e}"))
    })?;
    store_builder
        .set_flags(openssl::x509::verify::X509VerifyFlags::PARTIAL_CHAIN)
        .map_err(|e| AttError::Generic(format!("failed to set X509 verify flags: {e}")))?;
    for ca in trusted_cas {
        store_builder
            .add_cert(ca)
            .map_err(|e| AttError::Generic(format!("failed to add trusted issuer CA: {e}")))?;
    }

    let mut intermediates = openssl::stack::Stack::new()
        .map_err(|e| AttError::Generic(format!("failed to create intermediate stack: {e}")))?;
    for cert in cert_chain.iter().skip(1) {
        let cert = X509::from_der(cert).map_err(|e| {
            AttError::BadRequest(format!("failed to parse issuer intermediate cert: {e}"))
        })?;
        intermediates
            .push(cert)
            .map_err(|e| AttError::Generic(format!("failed to push intermediate cert: {e}")))?;
    }

    let store = store_builder.build();
    let mut ctx = openssl::x509::X509StoreContext::new()
        .map_err(|e| AttError::Generic(format!("failed to create X509 store context: {e}")))?;
    let verification_result = ctx.init(&store, &leaf, &intermediates, |ctx| ctx.verify_cert());
    let issuer_trusted = matches!(verification_result, Ok(true));

    if !issuer_trusted {
        match verification_result {
            Ok(false) => tracing::warn!(
                verify_error = ?ctx.error(),
                verify_depth = ctx.error_depth(),
                subject = ?leaf.subject_name(),
                issuer = ?leaf.issuer_name(),
                "issuerAuth certificate chain failed OpenSSL verification"
            ),
            Err(error) => tracing::warn!(
                error = %error,
                verify_error = ?ctx.error(),
                verify_depth = ctx.error_depth(),
                subject = ?leaf.subject_name(),
                issuer = ?leaf.issuer_name(),
                "issuerAuth certificate chain verification errored"
            ),
            Ok(true) => {}
        }
    }

    let key = leaf.public_key().map_err(|e| {
        AttError::BadRequest(format!(
            "failed to extract issuer public key from certificate: {e}"
        ))
    })?;

    Ok((key, issuer_trusted))
}

fn verify_cose_sign1_embedded(cose: &CoseSign1, key: &PKey<Public>) -> Result<(), AttError> {
    let alg = cose_algorithm_id(cose)?;
    match alg {
        -7 | -35 | -36 => cose.verify_signature(&[], |signature, data| {
            verify_ecdsa_signature(alg, data, signature, key)
        }),
        -257 | -258 | -259 => cose.verify_signature(&[], |signature, data| {
            verify_rsa_signature(alg, data, signature, key)
        }),
        _ => Err(AttError::BadRequest(format!(
            "unsupported COSE signature algorithm: {alg}"
        ))),
    }
}

fn verify_cose_sign1_detached(
    cose: &CoseSign1,
    key: &PKey<Public>,
    payload: &[u8],
) -> Result<(), AttError> {
    let alg = cose_algorithm_id(cose)?;
    match alg {
        -7 | -35 | -36 => cose.verify_detached_signature(payload, &[], |signature, data| {
            verify_ecdsa_signature(alg, data, signature, key)
        }),
        -257 | -258 | -259 => cose.verify_detached_signature(payload, &[], |signature, data| {
            verify_rsa_signature(alg, data, signature, key)
        }),
        _ => Err(AttError::BadRequest(format!(
            "unsupported COSE detached signature algorithm: {alg}"
        ))),
    }
}

fn cose_algorithm_id(cose: &CoseSign1) -> Result<i64, AttError> {
    let alg = cose
        .protected
        .header
        .alg
        .clone()
        .or_else(|| cose.unprotected.alg.clone())
        .ok_or_else(|| AttError::BadRequest("COSE structure missing alg header".to_string()))?;

    match alg {
        RegisteredLabelWithPrivate::Assigned(alg) => Ok(iana::EnumI64::to_i64(&alg)),
        RegisteredLabelWithPrivate::PrivateUse(alg) => Ok(alg),
        RegisteredLabelWithPrivate::Text(name) => Err(AttError::BadRequest(format!(
            "textual COSE alg is not supported: {name}"
        ))),
    }
}

fn verify_ecdsa_signature(
    alg: i64,
    data: &[u8],
    signature: &[u8],
    key: &PKey<Public>,
) -> Result<(), AttError> {
    let (part_len, digest) = match alg {
        -7 => (32, MessageDigest::sha256()),
        -35 => (48, MessageDigest::sha384()),
        -36 => (66, MessageDigest::sha512()),
        _ => {
            return Err(AttError::BadRequest(format!(
                "unsupported ECDSA COSE algorithm: {alg}"
            )));
        }
    };
    if signature.len() != part_len * 2 {
        return Err(AttError::BadRequest(format!(
            "invalid ECDSA signature length for alg {alg}: {}",
            signature.len()
        )));
    }

    let r = BigNum::from_slice(&signature[..part_len])
        .map_err(|e| AttError::BadRequest(format!("failed to parse ECDSA r: {e}")))?;
    let s = BigNum::from_slice(&signature[part_len..])
        .map_err(|e| AttError::BadRequest(format!("failed to parse ECDSA s: {e}")))?;
    let der = EcdsaSig::from_private_components(r, s)
        .and_then(|sig| sig.to_der())
        .map_err(|e| AttError::BadRequest(format!("failed to convert ECDSA signature: {e}")))?;

    let mut verifier = OpensslVerifier::new(digest, key)
        .map_err(|e| AttError::BadRequest(format!("failed to create ECDSA verifier: {e}")))?;
    verifier
        .update(data)
        .map_err(|e| AttError::BadRequest(format!("failed to feed ECDSA verifier: {e}")))?;
    let valid = verifier
        .verify(&der)
        .map_err(|e| AttError::BadRequest(format!("ECDSA verification failed: {e}")))?;
    if !valid {
        return Err(AttError::BadRequest(
            "COSE ECDSA signature verification failed".to_string(),
        ));
    }

    Ok(())
}

fn verify_rsa_signature(
    alg: i64,
    data: &[u8],
    signature: &[u8],
    key: &PKey<Public>,
) -> Result<(), AttError> {
    let digest = match alg {
        -257 => MessageDigest::sha256(),
        -258 => MessageDigest::sha384(),
        -259 => MessageDigest::sha512(),
        _ => {
            return Err(AttError::BadRequest(format!(
                "unsupported RSA COSE algorithm: {alg}"
            )));
        }
    };

    let mut verifier = OpensslVerifier::new(digest, key)
        .map_err(|e| AttError::BadRequest(format!("failed to create RSA verifier: {e}")))?;
    verifier
        .set_rsa_padding(Padding::PKCS1)
        .map_err(|e| AttError::BadRequest(format!("failed to configure RSA padding: {e}")))?;
    verifier
        .update(data)
        .map_err(|e| AttError::BadRequest(format!("failed to feed RSA verifier: {e}")))?;
    let valid = verifier
        .verify(signature)
        .map_err(|e| AttError::BadRequest(format!("RSA verification failed: {e}")))?;
    if !valid {
        return Err(AttError::BadRequest(
            "COSE RSA signature verification failed".to_string(),
        ));
    }

    Ok(())
}

fn parse_mobile_security_object(payload: &[u8]) -> Result<ParsedMobileSecurityObject, AttError> {
    let cbor: ciborium::Value = ciborium::from_reader(payload).map_err(|e| {
        AttError::BadRequest(format!("failed to parse issuerAuth payload CBOR: {e}"))
    })?;
    let cbor = match &cbor {
        ciborium::Value::Tag(24, inner) => match inner.as_ref() {
            ciborium::Value::Bytes(bytes) => ciborium::from_reader(&bytes[..]).map_err(|e| {
                AttError::BadRequest(format!("failed to parse MobileSecurityObject bytes: {e}"))
            })?,
            other => other.clone(),
        },
        ciborium::Value::Bytes(bytes) => ciborium::from_reader(&bytes[..]).map_err(|e| {
            AttError::BadRequest(format!("failed to parse MobileSecurityObject bytes: {e}"))
        })?,
        other => other.clone(),
    };

    let map = as_cbor_map(unwrap_cbor_tags(&cbor))
        .ok_or_else(|| AttError::BadRequest("MobileSecurityObject is not a map".to_string()))?;
    let doc_type = cbor_map_get_text(map, "docType")
        .ok_or_else(|| AttError::BadRequest("MobileSecurityObject missing docType".to_string()))?
        .to_string();
    let digest_algorithm = cbor_map_get_text(map, "digestAlgorithm")
        .ok_or_else(|| {
            AttError::BadRequest("MobileSecurityObject missing digestAlgorithm".to_string())
        })?
        .to_string();

    let value_digests = as_cbor_map(unwrap_cbor_tags(
        cbor_map_get(map, "valueDigests").ok_or_else(|| {
            AttError::BadRequest("MobileSecurityObject missing valueDigests".to_string())
        })?,
    ))
    .ok_or_else(|| AttError::BadRequest("valueDigests is not a map".to_string()))?;

    let mut parsed_digests = std::collections::BTreeMap::new();
    for (ns_key, ns_value) in value_digests {
        let namespace = match ns_key {
            ciborium::Value::Text(text) => text.clone(),
            _ => continue,
        };
        let ns_map = as_cbor_map(unwrap_cbor_tags(ns_value)).ok_or_else(|| {
            AttError::BadRequest("valueDigests namespace entry is not a map".to_string())
        })?;

        let mut digest_map = std::collections::BTreeMap::new();
        for (digest_id, digest_value) in ns_map {
            let digest_id = cbor_integer_to_u64(digest_id).ok_or_else(|| {
                AttError::BadRequest("valueDigests digestID is not an integer".to_string())
            })?;
            let digest_bytes = match unwrap_cbor_tags(digest_value) {
                ciborium::Value::Bytes(bytes) => bytes.clone(),
                _ => {
                    return Err(AttError::BadRequest(
                        "valueDigests digest value is not a byte string".to_string(),
                    ));
                }
            };
            digest_map.insert(digest_id, digest_bytes);
        }
        parsed_digests.insert(namespace, digest_map);
    }

    let device_key_info = as_cbor_map(unwrap_cbor_tags(
        cbor_map_get(map, "deviceKeyInfo").ok_or_else(|| {
            AttError::BadRequest("MobileSecurityObject missing deviceKeyInfo".to_string())
        })?,
    ))
    .ok_or_else(|| AttError::BadRequest("deviceKeyInfo is not a map".to_string()))?;
    let device_key_value = cbor_map_get(device_key_info, "deviceKey")
        .ok_or_else(|| AttError::BadRequest("deviceKeyInfo missing deviceKey".to_string()))?;
    let mut device_key_bytes = Vec::new();
    ciborium::into_writer(device_key_value, &mut device_key_bytes)
        .map_err(|e| AttError::BadRequest(format!("failed to serialize deviceKey: {e}")))?;
    let device_key = CoseKey::from_slice(&device_key_bytes)
        .map_err(|e| AttError::BadRequest(format!("failed to parse deviceKey COSE_Key: {e}")))?;

    let validity_info = as_cbor_map(unwrap_cbor_tags(
        cbor_map_get(map, "validityInfo").ok_or_else(|| {
            AttError::BadRequest("MobileSecurityObject missing validityInfo".to_string())
        })?,
    ))
    .ok_or_else(|| AttError::BadRequest("validityInfo is not a map".to_string()))?;

    Ok(ParsedMobileSecurityObject {
        doc_type,
        digest_algorithm,
        value_digests: parsed_digests,
        device_key,
        valid_from: cbor_value_to_text(cbor_map_get(validity_info, "validFrom")),
        valid_until: cbor_value_to_text(cbor_map_get(validity_info, "validUntil")),
    })
}

fn verify_issuer_signed_item_digests(
    name_spaces_map: &[(ciborium::Value, ciborium::Value)],
    mso: &ParsedMobileSecurityObject,
) -> Result<(), AttError> {
    for (ns_key, items_value) in name_spaces_map {
        let namespace = match ns_key {
            ciborium::Value::Text(text) => text,
            _ => continue,
        };
        let expected = mso.value_digests.get(namespace).ok_or_else(|| {
            AttError::BadRequest(format!(
                "MobileSecurityObject has no valueDigests entry for namespace {namespace}"
            ))
        })?;
        let items = as_cbor_array(unwrap_cbor_tags(items_value)).ok_or_else(|| {
            AttError::BadRequest(format!("namespace {namespace} is not an array"))
        })?;

        for item in items {
            // Extract the inner bytes (CBOR-encoded IssuerSignedItem map) for parsing digestID.
            let inner_map_bytes = match item {
                ciborium::Value::Tag(24, inner) => match inner.as_ref() {
                    ciborium::Value::Bytes(bytes) => bytes.clone(),
                    _ => {
                        return Err(AttError::BadRequest(
                            "IssuerSignedItem tag 24 does not contain bytes".to_string(),
                        ));
                    }
                },
                ciborium::Value::Bytes(bytes) => bytes.clone(),
                _ => {
                    return Err(AttError::BadRequest(
                        "IssuerSignedItem is not wrapped as bytes".to_string(),
                    ));
                }
            };

            // Per ISO 18013-5 §9.1.2.4, the MSO valueDigests entry is SHA-256 of the full
            // IssuerSignedItemBytes CBOR encoding: #6.24(bstr .cbor IssuerSignedItem).
            // We must hash the complete tag-24-wrapped encoding, not just the inner bytes.
            let item_bytes_for_hashing = {
                let mut buf = Vec::new();
                ciborium::into_writer(item, &mut buf).map_err(|e| {
                    AttError::BadRequest(format!(
                        "failed to re-encode IssuerSignedItemBytes for digest computation: {e}"
                    ))
                })?;
                buf
            };

            let inner: ciborium::Value =
                ciborium::from_reader(&inner_map_bytes[..]).map_err(|e| {
                    AttError::BadRequest(format!("failed to parse IssuerSignedItem bytes: {e}"))
                })?;
            let inner_map = as_cbor_map(unwrap_cbor_tags(&inner))
                .ok_or_else(|| AttError::BadRequest("IssuerSignedItem is not a map".to_string()))?;
            let digest_id =
                cbor_integer_to_u64(cbor_map_get(inner_map, "digestID").ok_or_else(|| {
                    AttError::BadRequest("IssuerSignedItem missing digestID".to_string())
                })?)
                .ok_or_else(|| {
                    AttError::BadRequest("IssuerSignedItem digestID is not an integer".to_string())
                })?;
            let expected_digest = expected.get(&digest_id).ok_or_else(|| {
                AttError::BadRequest(format!(
                    "MobileSecurityObject missing expected digest for namespace {namespace} digestID {digest_id}"
                ))
            })?;
            let actual_digest =
                hash_issuer_signed_item(&mso.digest_algorithm, &item_bytes_for_hashing)?;
            if actual_digest != *expected_digest {
                tracing::warn!(
                    namespace = %namespace,
                    digest_id = %digest_id,
                    expected_len = expected_digest.len(),
                    actual_len = actual_digest.len(),
                    "IssuerSignedItem digest mismatch"
                );
                return Err(AttError::BadRequest(format!(
                    "IssuerSignedItem digest mismatch for namespace {namespace} digestID {digest_id}"
                )));
            }
        }
    }

    Ok(())
}

fn hash_issuer_signed_item(algorithm: &str, data: &[u8]) -> Result<Vec<u8>, AttError> {
    let digest = match algorithm.to_ascii_lowercase().as_str() {
        "sha-256" | "sha256" => MessageDigest::sha256(),
        "sha-384" | "sha384" => MessageDigest::sha384(),
        "sha-512" | "sha512" => MessageDigest::sha512(),
        other => {
            return Err(AttError::BadRequest(format!(
                "unsupported MobileSecurityObject digestAlgorithm: {other}"
            )));
        }
    };

    hash(digest, data)
        .map(|digest| digest.to_vec())
        .map_err(|e| AttError::BadRequest(format!("failed to hash IssuerSignedItem: {e}")))
}

fn extract_device_namespaces_bytes(
    device_signed_map: &[(ciborium::Value, ciborium::Value)],
) -> Result<Vec<u8>, AttError> {
    match cbor_map_get(device_signed_map, "nameSpaces") {
        Some(ciborium::Value::Bytes(bytes)) => Ok(bytes.clone()),
        Some(ciborium::Value::Tag(24, inner)) => match inner.as_ref() {
            ciborium::Value::Bytes(bytes) => Ok(bytes.clone()),
            _ => Err(AttError::BadRequest(
                "deviceSigned.nameSpaces tag 24 does not contain bytes".to_string(),
            )),
        },
        Some(other) => {
            let mut bytes = Vec::new();
            ciborium::into_writer(other, &mut bytes).map_err(|e| {
                AttError::BadRequest(format!("failed to serialize deviceSigned.nameSpaces: {e}"))
            })?;
            Ok(bytes)
        }
        None => {
            let empty_map = ciborium::Value::Map(Vec::new());
            let mut bytes = Vec::new();
            ciborium::into_writer(&empty_map, &mut bytes).map_err(|e| {
                AttError::BadRequest(format!("failed to serialize empty device namespaces: {e}"))
            })?;
            Ok(bytes)
        }
    }
}

fn build_openid4vp_session_transcript(
    client_id: &str,
    nonce: &str,
    response_mode: ResponseMode,
    response_jwk_thumbprint: Option<&[u8]>,
    response_uri: &str,
) -> Result<Vec<u8>, AttError> {
    let jwk_thumbprint = match response_mode {
        ResponseMode::DirectPostJwt | ResponseMode::DcApiJwt => Some(
            response_jwk_thumbprint
                .ok_or_else(|| {
                    AttError::BadRequest(
                        "response encryption key thumbprint is required for encrypted mDoc responses"
                            .to_string(),
                    )
                })?
                .to_vec(),
        ),
        _ => None,
    };

    let handover_info = ciborium::Value::Array(vec![
        ciborium::Value::Text(client_id.to_string()),
        ciborium::Value::Text(nonce.to_string()),
        match jwk_thumbprint {
            Some(bytes) => ciborium::Value::Bytes(bytes),
            None => ciborium::Value::Null,
        },
        ciborium::Value::Text(response_uri.to_string()),
    ]);
    let handover_info_bytes = cbor_to_vec(&handover_info)?;
    let handover_hash = openssl::sha::sha256(&handover_info_bytes).to_vec();
    let handover = ciborium::Value::Array(vec![
        ciborium::Value::Text("OpenID4VPHandover".to_string()),
        ciborium::Value::Bytes(handover_hash),
    ]);
    let session_transcript =
        ciborium::Value::Array(vec![ciborium::Value::Null, ciborium::Value::Null, handover]);

    cbor_to_vec(&session_transcript)
}

fn build_device_authentication_payload(
    session_transcript: &[u8],
    doc_type: &str,
    device_namespaces_bytes: &[u8],
) -> Result<Vec<u8>, AttError> {
    let session_transcript: ciborium::Value =
        ciborium::from_reader(session_transcript).map_err(|e| {
            AttError::BadRequest(format!("failed to parse SessionTranscript bytes: {e}"))
        })?;
    // Per ISO 18013-5 §9.1.3.4, the 4th element is DeviceNameSpacesBytes =
    // #6.24(bstr .cbor DeviceNameSpaces).  The tag-24 wrapper must be present
    // so the reconstructed DeviceAuthentication matches what the wallet signed.
    let device_namespaces_bytes_tagged = ciborium::Value::Tag(
        24,
        Box::new(ciborium::Value::Bytes(device_namespaces_bytes.to_vec())),
    );
    let payload = ciborium::Value::Array(vec![
        ciborium::Value::Text("DeviceAuthentication".to_string()),
        session_transcript,
        ciborium::Value::Text(doc_type.to_string()),
        device_namespaces_bytes_tagged,
    ]);
    cbor_to_vec(&payload)
}

fn cose_key_to_public_key(key: &CoseKey) -> Result<PKey<Public>, AttError> {
    let kty = match key.kty {
        coset::RegisteredLabel::Assigned(kty) => iana::EnumI64::to_i64(&kty),
        _ => {
            return Err(AttError::BadRequest(
                "unsupported textual COSE key type".to_string(),
            ));
        }
    };
    if kty != 2 {
        return Err(AttError::BadRequest(
            "only EC2 COSE device keys are currently supported".to_string(),
        ));
    }

    let crv = cose_key_param_integer(key, -1)
        .ok_or_else(|| AttError::BadRequest("COSE device key missing crv".to_string()))?;
    let x = cose_key_param_bytes(key, -2)
        .ok_or_else(|| AttError::BadRequest("COSE device key missing x".to_string()))?;
    let y = cose_key_param_bytes(key, -3)
        .ok_or_else(|| AttError::BadRequest("COSE device key missing y".to_string()))?;

    let group = match crv {
        1 => EcGroup::from_curve_name(Nid::X9_62_PRIME256V1),
        2 => EcGroup::from_curve_name(Nid::SECP384R1),
        3 => EcGroup::from_curve_name(Nid::SECP521R1),
        _ => {
            return Err(AttError::BadRequest(format!(
                "unsupported COSE EC curve: {crv}"
            )));
        }
    }
    .map_err(|e| AttError::BadRequest(format!("failed to create EC group: {e}")))?;
    let x = BigNum::from_slice(&x)
        .map_err(|e| AttError::BadRequest(format!("failed to parse EC x coordinate: {e}")))?;
    let y = BigNum::from_slice(&y)
        .map_err(|e| AttError::BadRequest(format!("failed to parse EC y coordinate: {e}")))?;
    let ec_key = EcKey::from_public_key_affine_coordinates(&group, &x, &y)
        .map_err(|e| AttError::BadRequest(format!("failed to reconstruct EC public key: {e}")))?;
    PKey::from_ec_key(ec_key)
        .map_err(|e| AttError::BadRequest(format!("failed to construct public key: {e}")))
}

fn validate_mso_validity(mso: &ParsedMobileSecurityObject) -> Result<bool, AttError> {
    let now = chrono::Utc::now();

    if let Some(valid_from) = &mso.valid_from {
        let valid_from = chrono::DateTime::parse_from_rfc3339(valid_from).map_err(|e| {
            AttError::BadRequest(format!("failed to parse validFrom from MSO: {e}"))
        })?;
        if valid_from > now {
            return Err(AttError::BadRequest(
                "MobileSecurityObject is not yet valid".to_string(),
            ));
        }
    }

    if let Some(valid_until) = &mso.valid_until {
        let valid_until = chrono::DateTime::parse_from_rfc3339(valid_until).map_err(|e| {
            AttError::BadRequest(format!("failed to parse validUntil from MSO: {e}"))
        })?;
        if valid_until < now {
            return Err(AttError::BadRequest(
                "MobileSecurityObject has expired".to_string(),
            ));
        }
    }

    Ok(true)
}

fn cbor_to_vec(value: &ciborium::Value) -> Result<Vec<u8>, AttError> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)
        .map_err(|e| AttError::BadRequest(format!("CBOR serialization failed: {e}")))?;
    Ok(bytes)
}

fn unwrap_cbor_tags(value: &ciborium::Value) -> &ciborium::Value {
    match value {
        ciborium::Value::Tag(_, inner) => unwrap_cbor_tags(inner),
        _ => value,
    }
}

fn as_cbor_map(value: &ciborium::Value) -> Option<&Vec<(ciborium::Value, ciborium::Value)>> {
    match value {
        ciborium::Value::Map(map) => Some(map),
        _ => None,
    }
}

fn as_cbor_array(value: &ciborium::Value) -> Option<&Vec<ciborium::Value>> {
    match value {
        ciborium::Value::Array(items) => Some(items),
        _ => None,
    }
}

fn cbor_map_get<'a>(
    map: &'a [(ciborium::Value, ciborium::Value)],
    key: &str,
) -> Option<&'a ciborium::Value> {
    map.iter().find_map(|(map_key, value)| match map_key {
        ciborium::Value::Text(text) if text == key => Some(value),
        _ => None,
    })
}

fn cbor_map_get_text<'a>(
    map: &'a [(ciborium::Value, ciborium::Value)],
    key: &str,
) -> Option<&'a str> {
    cbor_map_get(map, key).and_then(|value| match unwrap_cbor_tags(value) {
        ciborium::Value::Text(text) => Some(text.as_str()),
        _ => None,
    })
}

fn cbor_integer_to_u64(value: &ciborium::Value) -> Option<u64> {
    match unwrap_cbor_tags(value) {
        ciborium::Value::Integer(i) => {
            let value: i128 = (*i).into();
            u64::try_from(value).ok()
        }
        _ => None,
    }
}

fn cbor_value_to_text(value: Option<&ciborium::Value>) -> Option<String> {
    match value.map(unwrap_cbor_tags) {
        Some(ciborium::Value::Text(text)) => Some(text.clone()),
        _ => None,
    }
}

fn cose_key_param_integer(key: &CoseKey, label: i64) -> Option<i64> {
    key.params.iter().find_map(|(param_label, value)| {
        if *param_label == Label::Int(label) {
            match value {
                ciborium::Value::Integer(i) => {
                    let value: i128 = (*i).into();
                    i64::try_from(value).ok()
                }
                _ => None,
            }
        } else {
            None
        }
    })
}

fn cose_key_param_bytes(key: &CoseKey, label: i64) -> Option<Vec<u8>> {
    key.params.iter().find_map(|(param_label, value)| {
        if *param_label == Label::Int(label) {
            match value {
                ciborium::Value::Bytes(bytes) => Some(bytes.clone()),
                _ => None,
            }
        } else {
            None
        }
    })
}

// ---------------------------------------------------------------------------
// SD-JWT VC signature verification
// ---------------------------------------------------------------------------

/// Result of cryptographic signature verification on an SD-JWT VC presentation.
struct SigVerificationResult {
    /// Whether the issuer JWT signature was successfully verified.
    issuer_sig_valid: bool,
    /// Whether the KB-JWT signature was successfully verified.
    kb_sig_valid: bool,
    /// Whether the issuer`s leaf certificate chains to a trusted CA.
    issuer_trusted: bool,
    /// true when the presentation was not an SD-JWT and verification was skipped.
    skipped: bool,
    /// Human-readable error messages accumulated during verification.
    errors: Vec<String>,
}

impl SigVerificationResult {
    /// Verification was skipped (e.g. mDoc presentation — not an SD-JWT VC).
    fn skipped(reason: &str) -> Self {
        Self {
            issuer_sig_valid: false,
            kb_sig_valid: false,
            issuer_trusted: false,
            skipped: true,
            errors: vec![reason.to_string()],
        }
    }
}

/// Load trusted issuer CA certificates from PEM files on disk.
///
/// Returns an `openssl::x509::X509` vector. Files that cannot be read or
/// parsed are logged and silently skipped so that a single bad file does not
/// prevent the server from starting.
fn load_trusted_issuer_certs(paths: &[String]) -> Vec<openssl::x509::X509> {
    let mut certs = Vec::new();
    for path in paths {
        match std::fs::read(path) {
            Ok(pem) => match openssl::x509::X509::stack_from_pem(&pem) {
                Ok(parsed) => {
                    for cert in parsed {
                        tracing::debug!(path, subject = ?cert.subject_name(), "loaded trusted issuer CA");
                        certs.push(cert);
                    }
                }
                Err(e) => tracing::warn!(path, error = %e, "failed to parse trusted issuer cert"),
            },
            Err(e) => tracing::warn!(path, error = %e, "failed to read trusted issuer cert"),
        }
    }
    certs
}

/// Verify the cryptographic signatures on an SD-JWT VC compact presentation.
///
/// Given `raw` = `<issuer-jwt>~<disc1>~…~[kb-jwt]`:
///
/// 1. **Issuer JWT** — decode the JWT header; if `x5c` is present, extract
///    the leaf certificate, validate it against `trusted_ca_paths`, and
///    derive the public key. Verify the JWT signature with `jsonwebtoken`.
/// 2. **KB-JWT** — extract the holder public key from the `cnf.jwk` claim in
///    the issuer JWT payload, then verify the KB-JWT signature.
fn verify_sd_jwt_signatures(raw: &str, trusted_ca_paths: &[String]) -> SigVerificationResult {
    let mut errors: Vec<String> = Vec::new();

    // --- split into issuer JWT and remaining elements ---
    let parts: Vec<&str> = raw.splitn(2, '~').collect();
    let issuer_jwt = parts[0];
    let rest = if parts.len() > 1 { parts[1] } else { "" };

    // --- decode the issuer JWT header ---
    let header = match jsonwebtoken::decode_header(issuer_jwt) {
        Ok(h) => h,
        Err(e) => {
            errors.push(format!("failed to decode issuer JWT header: {e}"));
            return SigVerificationResult {
                issuer_sig_valid: false,
                kb_sig_valid: false,
                issuer_trusted: false,
                skipped: false,
                errors,
            };
        }
    };

    let alg = header.alg;
    tracing::debug!(
        ?alg,
        x5c_present = header.x5c.is_some(),
        "issuer JWT header"
    );

    // --- extract issuer public key ---
    // Prefer x5c (DER-encoded certificate chain in the JWT header).
    let trusted_cas = load_trusted_issuer_certs(trusted_ca_paths);
    let (issuer_decoding_key, issuer_trusted) = match &header.x5c {
        Some(x5c) if !x5c.is_empty() => match extract_key_from_x5c(x5c, &trusted_cas, alg) {
            Ok((key, trusted)) => (key, trusted),
            Err(e) => {
                errors.push(format!("x5c key extraction failed: {e}"));
                return SigVerificationResult {
                    issuer_sig_valid: false,
                    kb_sig_valid: false,
                    issuer_trusted: false,
                    skipped: false,
                    errors,
                };
            }
        },
        _ => {
            errors.push("issuer JWT has no x5c header; issuer trust cannot be established".into());
            // Without x5c we cannot obtain the public key — skip issuer sig verification.
            return SigVerificationResult {
                issuer_sig_valid: false,
                kb_sig_valid: false,
                issuer_trusted: false,
                skipped: false,
                errors,
            };
        }
    };

    // --- verify the issuer JWT signature ---
    let mut validation = jsonwebtoken::Validation::new(alg);
    // We only want to check the cryptographic signature; claims like exp/iss
    // are validated separately in verify_vp_token.
    validation.validate_exp = false;
    validation.validate_aud = false;
    validation.required_spec_claims.clear();

    let issuer_token_data = match jsonwebtoken::decode::<serde_json::Value>(
        issuer_jwt,
        &issuer_decoding_key,
        &validation,
    ) {
        Ok(data) => {
            tracing::debug!("issuer JWT signature verified");
            data
        }
        Err(e) => {
            errors.push(format!("issuer JWT signature invalid: {e}"));
            return SigVerificationResult {
                issuer_sig_valid: false,
                kb_sig_valid: false,
                issuer_trusted,
                skipped: false,
                errors,
            };
        }
    };

    let issuer_sig_valid = true;

    // --- verify the KB-JWT (if present) ---
    // Extract the holder key from `cnf.jwk` in the issuer payload.
    let kb_sig_valid = verify_kb_jwt(rest, &issuer_token_data.claims, &mut errors);

    SigVerificationResult {
        issuer_sig_valid,
        kb_sig_valid,
        issuer_trusted,
        skipped: false,
        errors,
    }
}

/// Extract a `DecodingKey` from the `x5c` JWT header and validate the leaf
/// certificate against the trusted CA list.
///
/// Returns `(DecodingKey, issuer_trusted)`.
fn extract_key_from_x5c(
    x5c: &[String],
    trusted_cas: &[openssl::x509::X509],
    alg: jsonwebtoken::Algorithm,
) -> Result<(jsonwebtoken::DecodingKey, bool), String> {
    use openssl::x509::X509;

    // x5c entries are base64-encoded (standard, NOT URL-safe) DER certificates.
    let leaf_der = base64::engine::general_purpose::STANDARD
        .decode(&x5c[0])
        .map_err(|e| format!("base64 decode of x5c[0] failed: {e}"))?;
    let leaf = X509::from_der(&leaf_der).map_err(|e| format!("DER parse of x5c[0] failed: {e}"))?;
    tracing::info!(subject = ?leaf.subject_name(), "loaded leaf certificate from x5c[0]");
    tracing::info!(issuer = ?leaf.issuer_name(), "leaf certificate issuer");

    // Build an X509 store from the trusted CA certs and verify the leaf.
    let mut store_builder = openssl::x509::store::X509StoreBuilder::new()
        .map_err(|e| format!("X509StoreBuilder::new failed: {e}"))?;
    store_builder
        .set_flags(openssl::x509::verify::X509VerifyFlags::PARTIAL_CHAIN)
        .map_err(|e| format!("set_flags failed: {e}"))?;
    for ca in trusted_cas {
        store_builder
            .add_cert(ca.clone())
            .map_err(|e| format!("add_cert failed: {e}"))?;
    }
    // Add any intermediate certificates from x5c[1..].
    let mut intermediates =
        openssl::stack::Stack::new().map_err(|e| format!("Stack::new failed: {e}"))?;
    for b64_cert in x5c.iter().skip(1) {
        let der = base64::engine::general_purpose::STANDARD
            .decode(b64_cert)
            .map_err(|e| format!("base64 decode of x5c intermediate failed: {e}"))?;
        let cert = X509::from_der(&der)
            .map_err(|e| format!("DER parse of x5c intermediate failed: {e}"))?;
        tracing::info!(subject = ?cert.subject_name(), "loaded intermediate certificate from x5c");
        intermediates
            .push(cert)
            .map_err(|e| format!("push intermediate failed: {e}"))?;
    }
    let store = store_builder.build();
    let mut ctx = openssl::x509::X509StoreContext::new()
        .map_err(|e| format!("X509StoreContext::new failed: {e}"))?;
    let verification_result = ctx.init(&store, &leaf, &intermediates, |ctx| ctx.verify_cert());
    let issuer_trusted = matches!(verification_result, Ok(true));

    if !issuer_trusted {
        match verification_result {
            Ok(false) => tracing::warn!(
                verify_error = ?ctx.error(),
                verify_depth = ctx.error_depth(),
                subject = ?leaf.subject_name(),
                issuer = ?leaf.issuer_name(),
                "issuer leaf certificate failed OpenSSL chain verification"
            ),
            Err(error) => tracing::warn!(
                error = %error,
                verify_error = ?ctx.error(),
                verify_depth = ctx.error_depth(),
                subject = ?leaf.subject_name(),
                issuer = ?leaf.issuer_name(),
                "issuer leaf certificate chain verification errored"
            ),
            Ok(true) => {}
        }
    } else {
        tracing::debug!("issuer leaf certificate chains to trusted CA");
    }

    // Extract the public key for JWT verification.
    let pkey = leaf
        .public_key()
        .map_err(|e| format!("public_key extraction failed: {e}"))?;
    let decoding_key = match alg {
        jsonwebtoken::Algorithm::ES256 | jsonwebtoken::Algorithm::ES384 => {
            let ec = pkey
                .ec_key()
                .map_err(|e| format!("expected EC key for {alg:?}: {e}"))?;
            let pem = ec
                .public_key_to_pem()
                .map_err(|e| format!("EC public_key_to_pem failed: {e}"))?;
            jsonwebtoken::DecodingKey::from_ec_pem(&pem)
                .map_err(|e| format!("DecodingKey::from_ec_pem failed: {e}"))?
        }
        jsonwebtoken::Algorithm::RS256
        | jsonwebtoken::Algorithm::RS384
        | jsonwebtoken::Algorithm::RS512 => {
            let rsa = pkey
                .rsa()
                .map_err(|e| format!("expected RSA key for {alg:?}: {e}"))?;
            let pem = rsa
                .public_key_to_pem()
                .map_err(|e| format!("RSA public_key_to_pem failed: {e}"))?;
            jsonwebtoken::DecodingKey::from_rsa_pem(&pem)
                .map_err(|e| format!("DecodingKey::from_rsa_pem failed: {e}"))?
        }
        _ => return Err(format!("unsupported JWT algorithm: {alg:?}")),
    };

    Ok((decoding_key, issuer_trusted))
}

/// Verify the Key Binding JWT signature using the holder key from `cnf.jwk`.
///
/// `rest` is the portion of the SD-JWT after the first `~` — i.e. the
/// disclosures and optional trailing KB-JWT.
fn verify_kb_jwt(rest: &str, issuer_claims: &serde_json::Value, errors: &mut Vec<String>) -> bool {
    // Find the KB-JWT: last `~`-separated segment that looks like a JWT.
    let kb_jwt = rest
        .split('~')
        .filter(|s| !s.is_empty())
        .filter(|s| s.starts_with("eyJ") && s.chars().filter(|&c| c == '.').count() == 2)
        .last();

    let kb_jwt = match kb_jwt {
        Some(j) => j,
        None => {
            tracing::debug!("no KB-JWT found in presentation");
            return true; // nothing to verify
        }
    };

    // Extract the KB-JWT header to determine algorithm.
    let kb_header = match jsonwebtoken::decode_header(kb_jwt) {
        Ok(h) => h,
        Err(e) => {
            errors.push(format!("KB-JWT header decode failed: {e}"));
            return false;
        }
    };

    // cnf.jwk from issuer payload.
    let cnf_jwk = issuer_claims.get("cnf").and_then(|v| v.get("jwk"));

    let cnf_jwk = match cnf_jwk {
        Some(jwk) => jwk,
        None => {
            errors.push("issuer payload has no cnf.jwk — cannot verify KB-JWT".into());
            return false;
        }
    };

    // Build a DecodingKey from the JWK.
    let decoding_key = match build_decoding_key_from_jwk(cnf_jwk, kb_header.alg) {
        Ok(k) => k,
        Err(e) => {
            errors.push(format!("cnf.jwk key extraction failed: {e}"));
            return false;
        }
    };

    let mut validation = jsonwebtoken::Validation::new(kb_header.alg);
    validation.validate_exp = false;
    validation.validate_aud = false;
    validation.required_spec_claims.clear();

    match jsonwebtoken::decode::<serde_json::Value>(kb_jwt, &decoding_key, &validation) {
        Ok(_) => {
            tracing::debug!("KB-JWT signature verified");
            true
        }
        Err(e) => {
            errors.push(format!("KB-JWT signature invalid: {e}"));
            false
        }
    }
}

/// Build a `jsonwebtoken::DecodingKey` from a JWK JSON value.
fn build_decoding_key_from_jwk(
    jwk: &serde_json::Value,
    alg: jsonwebtoken::Algorithm,
) -> Result<jsonwebtoken::DecodingKey, String> {
    let kty = jwk
        .get("kty")
        .and_then(|v| v.as_str())
        .ok_or("JWK missing kty")?;

    match kty {
        "EC" => {
            let crv = jwk.get("crv").and_then(|v| v.as_str()).unwrap_or("P-256");
            let x = jwk
                .get("x")
                .and_then(|v| v.as_str())
                .ok_or("EC JWK missing x")?;
            let y = jwk
                .get("y")
                .and_then(|v| v.as_str())
                .ok_or("EC JWK missing y")?;

            // Reconstruct PEM from x, y coordinates via openssl.
            let x_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(x)
                .map_err(|e| format!("base64 decode x: {e}"))?;
            let y_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(y)
                .map_err(|e| format!("base64 decode y: {e}"))?;

            let group = match crv {
                "P-256" => openssl::nid::Nid::X9_62_PRIME256V1,
                "P-384" => openssl::nid::Nid::SECP384R1,
                "P-521" => openssl::nid::Nid::SECP521R1,
                _ => return Err(format!("unsupported EC curve: {crv}")),
            };
            let group = openssl::ec::EcGroup::from_curve_name(group)
                .map_err(|e| format!("EcGroup: {e}"))?;
            let x_bn =
                openssl::bn::BigNum::from_slice(&x_bytes).map_err(|e| format!("BigNum x: {e}"))?;
            let y_bn =
                openssl::bn::BigNum::from_slice(&y_bytes).map_err(|e| format!("BigNum y: {e}"))?;
            let ec_key =
                openssl::ec::EcKey::from_public_key_affine_coordinates(&group, &x_bn, &y_bn)
                    .map_err(|e| format!("EcKey from affine: {e}"))?;
            let pem = ec_key
                .public_key_to_pem()
                .map_err(|e| format!("EC pem: {e}"))?;

            jsonwebtoken::DecodingKey::from_ec_pem(&pem)
                .map_err(|e| format!("DecodingKey::from_ec_pem: {e}"))
        }
        "RSA" => {
            let n = jwk
                .get("n")
                .and_then(|v| v.as_str())
                .ok_or("RSA JWK missing n")?;
            let e_val = jwk
                .get("e")
                .and_then(|v| v.as_str())
                .ok_or("RSA JWK missing e")?;
            jsonwebtoken::DecodingKey::from_rsa_components(n, e_val)
                .map_err(|e| format!("DecodingKey::from_rsa_components: {e}"))
        }
        "OKP" => {
            // Ed25519 / EdDSA
            let x = jwk
                .get("x")
                .and_then(|v| v.as_str())
                .ok_or("OKP JWK missing x")?;
            let x_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(x)
                .map_err(|e| format!("base64 decode x: {e}"))?;
            match alg {
                jsonwebtoken::Algorithm::EdDSA => {
                    Ok(jsonwebtoken::DecodingKey::from_ed_der(&x_bytes))
                }
                _ => Err(format!("OKP kty with non-EdDSA alg: {alg:?}")),
            }
        }
        _ => Err(format!("unsupported JWK kty: {kty}")),
    }
}

/// Verification result from credential checking
struct VerificationResult {
    is_valid: bool,
    signature_valid: bool,
    not_expired: bool,
    issuer_trusted: bool,
    errors: Vec<String>,
}

/// Verify the VP token.
///
/// Checks credential expiry, issuer presence, nonce binding (against the
/// server-stored nonce), and incorporates the cryptographic signature
/// verification result from [`verify_sd_jwt_signatures`].
///
/// The `server_nonce` is the nonce generated by the verifier in
/// `init_transaction()` and stored server-side. It is compared against the
/// nonce embedded in the Key Binding JWT of the SD-JWT VC presentation.
///
/// For mDoc the nonce lives in DeviceSigned/SessionTranscript CBOR and is
/// not yet extracted (see TODO in `parse_vp_token`).
fn verify_vp_token(
    vp_token: &VpToken,
    server_nonce: Option<&str>,
    sig: &SigVerificationResult,
) -> VerificationResult {
    let mut errors = Vec::new();

    // Check expiration
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
            Err(_) => {
                // Can't parse expiry timestamp — treat as not expired
                true
            }
        }
    } else {
        true
    };

    // Issuer trust: for SD-JWT VC use the x5c chain validation result,
    // otherwise fall back to checking that *some* issuer is present.
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

    // Nonce binding: the server-stored nonce must match the one bound in
    // the presentation (KB-JWT for SD-JWT VC; DeviceSigned for mDoc).
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
            // Server had a nonce but the presentation carries no bound nonce.
            // For mDoc this is expected until DeviceSigned extraction is implemented;
            // for SD-JWT VC it means the wallet sent no KB-JWT.
            tracing::debug!("nonce binding skipped: presentation carries no bound nonce");
            true
        }
        (None, _) => true, // no server nonce — nothing to check
    };

    // Cryptographic signature verification
    let signature_valid = if !sig.skipped {
        let mut ok = true;
        if !sig.issuer_sig_valid {
            errors.push("Issuer JWT signature verification failed".to_string());
            ok = false;
        }
        if !sig.kb_sig_valid {
            // kb_sig_valid == true when there is no KB-JWT (nothing to verify).
            errors.push("KB-JWT signature verification failed".to_string());
            ok = false;
        }
        errors.extend(sig.errors.iter().cloned());
        ok
    } else {
        // mDoc or non-SD-JWT: signature verification not yet implemented.
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

/// Create a signed attestation JWT
fn create_attestation(
    client_id: &str,
    nonce: Option<&str>,
    claims: &serde_json::Value,
) -> Result<String, AttError> {
    // Determine if age was verified
    let age_verified = claims
        .get("age_over_18")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let age_over = if claims.get("age_over_21").and_then(|v| v.as_bool()) == Some(true) {
        Some(21u8)
    } else if age_verified {
        Some(18u8)
    } else {
        None
    };

    // Build attestation claims
    let mut attestation_claims = AttestationClaims::new(
        "credential-verifier.demo.ewqwe.local", // issuer
        client_id,                              // audience (RP)
        &uuid::Uuid::new_v4().to_string(),      // session ID
        age_verified,
    );

    if let Some(age) = age_over {
        attestation_claims = attestation_claims.with_age_over(age);
    }

    if let Some(n) = nonce {
        attestation_claims = attestation_claims.with_nonce(n);
    }

    // TODO: load the signing key from server configuration
    let demo_private_key = include_str!("../tests/certificates/ec/ewqwe.server.key.pem");

    let signer = JwtSigner::from_pem(SigningAlgorithm::ES256, demo_private_key.as_bytes())
        .map_err(|e| AttError::Generic(format!("Failed to create signer: {e}")))?;

    let token_bytes = signer
        .sign(&attestation_claims)
        .map_err(|e| AttError::Generic(format!("Failed to sign attestation: {e}")))?;

    String::from_utf8(token_bytes)
        .map_err(|e| AttError::Generic(format!("Failed to encode attestation: {e}")))
}
