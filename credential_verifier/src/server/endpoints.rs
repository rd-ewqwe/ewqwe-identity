use crate::{
    AttError,
    attestation::{AttestationClaims, AttestationSigner, JwtSigner, SigningAlgorithm},
    mdoc_decoder,
    server::Version,
};
use actix_web::{HttpRequest, HttpResponse, web};
use base64::Engine;
use serde::{Deserialize, Serialize};

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

    /// Original nonce from the request
    #[serde(default)]
    pub nonce: Option<String>,

    /// Original state from the request
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
    // mDoc format
    issuer_signed: Option<IssuerSigned>,
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
/// exactly 2 dots); it is silently skipped here as we don't verify key binding in demo mode.
///
/// Returns a `VpToken` populated with the decoded claims and issuer from the JWT payload.
fn decode_sd_jwt_presentation(raw: &str) -> Result<VpToken, SdJwtDecodeError> {
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

    // Decode each disclosure and add the revealed claim
    // Disclosures are `~`-separated; skip empty strings and the optional KB-JWT at the end.
    for disclosure_str in rest.split('~') {
        if disclosure_str.is_empty() {
            continue;
        }
        // KB-JWT: a full JWT (3 dots, starts with "eyJ") — skip it
        let dot_count = disclosure_str.chars().filter(|&c| c == '.').count();
        if dot_count == 2 && disclosure_str.starts_with("eyJ") {
            tracing::debug!("Skipping Key Binding JWT in SD-JWT presentation");
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

    tracing::info!(
        "SD-JWT VC decoded: vct={}, issuer={}, claims={}",
        vct,
        issuer,
        claims.len()
    );

    Ok(VpToken {
        doc_type: Some(vct.clone()),
        namespace: Some(vct),
        claims: Some(serde_json::Value::Object(claims)),
        issuer: Some(issuer),
        issued_at,
        expires_at,
        issuer_signed: None,
    })
}

/// Parse VP token - handles both direct format and DCQL-wrapped format
fn parse_vp_token(vp_token_str: &str) -> Result<(VpToken, Option<String>), AttError> {
    // First, try parsing as DCQL format (object with credential IDs as keys)
    if let Ok(dcql_token) = serde_json::from_str::<DcqlVpToken>(vp_token_str) {
        tracing::info!("VP Token appears to be DCQL format");

        // Get the first credential from the DCQL response
        if let Some((credential_id, presentations)) = dcql_token.iter().next() {
            tracing::info!("  Credential ID: {}", credential_id);
            tracing::info!("  Presentations count: {}", presentations.len());

            if let Some(presentation) = presentations.first() {
                // The presentation might be:
                //   (a) SD-JWT VC compact string:  header.payload.sig~disc1~disc2~[kbjwt]
                //   (b) base64-encoded mDoc CBOR DeviceResponse
                //   (c) JSON object (legacy direct format)
                if let Some(encoded_str) = presentation.as_str() {
                    // (a) Detect SD-JWT VC: the compact format contains '~' separators.
                    if encoded_str.contains('~') {
                        tracing::info!(
                            "  Presentation is SD-JWT VC compact serialization (length: {})",
                            encoded_str.len()
                        );
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
                    tracing::info!(
                        "  Presentation is base64-encoded mDoc (length: {})",
                        encoded_str.len()
                    );

                    let decode_error_msg;
                    match mdoc_decoder::decode_mdoc_presentation(encoded_str) {
                        Ok(decoded) => {
                            tracing::info!(
                                "  mDoc decoded successfully: docType={}, namespaces={}",
                                decoded.doc_type,
                                decoded.namespaces.len()
                            );

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
                                issuer_signed: None,
                            };
                            return Ok((vp_token, Some(credential_id.clone())));
                        }
                        Err(e) => {
                            tracing::warn!("  mDoc CBOR decode failed: {}", e);
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
                        issuer_signed: None,
                    };
                    return Ok((vp_token, Some(credential_id.clone())));
                } else if presentation.is_object() {
                    // It's already a JSON object - try to parse as VpToken
                    tracing::info!("  Presentation is JSON object");
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
    tracing::info!("VP Token appears to be direct format");
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

/// Verify a credential presentation from a wallet
///
/// This endpoint receives a VP token from the webapp (which received it from the wallet),
/// verifies the credential, and returns a signed attestation if valid.
///
/// In this demo implementation, we perform simulated verification.
/// In production, this would:
/// 1. Verify the mDoc/JWT cryptographic signature
/// 2. Check the issuer against a trusted list
/// 3. Validate the credential hasn't expired
/// 4. Verify the nonce matches the original request
pub(crate) async fn verify_credential_endpoint(
    _req: HttpRequest,
    body: web::Json<VerifyCredentialRequest>,
) -> Result<HttpResponse, AttError> {
    tracing::info!("============================================");
    tracing::info!("=== CREDENTIAL VERIFIER: REQUEST RECEIVED ===");
    tracing::info!("============================================");
    tracing::info!("VP Token length: {}", body.vp_token.len());
    tracing::info!(
        "VP Token preview: {}...",
        &body.vp_token.chars().take(100).collect::<String>()
    );
    tracing::info!("Nonce: {:?}", body.nonce);
    tracing::info!("Client ID: {:?}", body.client_id);

    // Parse the VP token (handles both direct and DCQL formats)
    let (vp_token, credential_id) = parse_vp_token(&body.vp_token)?;

    tracing::info!("VP Token parsed successfully");
    if let Some(ref cred_id) = credential_id {
        tracing::info!("  DCQL credential_id: {}", cred_id);
    }
    tracing::info!("  doc_type: {:?}", vp_token.doc_type);
    tracing::info!("  namespace: {:?}", vp_token.namespace);
    tracing::info!("  issuer: {:?}", vp_token.issuer);

    // Extract claims from the VP token
    let claims = extract_claims(&vp_token);
    tracing::info!("Extracted claims: {}", claims);

    let doc_type = vp_token.doc_type.clone();
    let namespace = vp_token.namespace.clone();

    // Perform verification (simulated for demo)
    // In production, this would verify cryptographic signatures
    tracing::info!("Performing verification...");
    let verification_result = verify_vp_token(&vp_token, body.nonce.as_deref());
    tracing::info!(
        "Verification result: valid={}, sig={}, expired={}, trusted={}",
        verification_result.is_valid,
        verification_result.signature_valid,
        verification_result.not_expired,
        verification_result.issuer_trusted
    );

    if !verification_result.is_valid {
        tracing::warn!("Verification FAILED: {:?}", verification_result.errors);
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

    // Create and sign an attestation
    tracing::info!("Creating signed attestation...");
    let attestation = create_attestation(
        body.client_id.as_deref().unwrap_or("unknown-rp"),
        body.nonce.as_deref(),
        &claims,
    )?;
    tracing::info!(
        "Attestation created successfully, length: {}",
        attestation.len()
    );

    tracing::info!("=== CREDENTIAL VERIFIER: RETURNING SUCCESS ===");
    tracing::info!("============================================");

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

/// Verification result from credential checking
struct VerificationResult {
    is_valid: bool,
    signature_valid: bool,
    not_expired: bool,
    issuer_trusted: bool,
    errors: Vec<String>,
}

/// Verify the VP token (simulated for demo)
fn verify_vp_token(vp_token: &VpToken, _nonce: Option<&str>) -> VerificationResult {
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
                // Can't parse, assume not expired
                true
            }
        }
    } else {
        true
    };

    // Check issuer (simulated - in production would check against trusted issuers)
    let issuer_trusted = vp_token.issuer.is_some();
    if !issuer_trusted {
        errors.push("No issuer specified in credential".to_string());
    }

    // Signature verification is simulated
    // In production, this would verify the mDoc MSO signature or JWT signature
    let signature_valid = true;

    let is_valid = signature_valid && not_expired && issuer_trusted;

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
        "credential-verifier.ewqwe.local", // issuer
        client_id,                         // audience (RP)
        &uuid::Uuid::new_v4().to_string(), // session ID
        age_verified,
    );

    if let Some(age) = age_over {
        attestation_claims = attestation_claims.with_age_over(age);
    }

    if let Some(n) = nonce {
        attestation_claims = attestation_claims.with_nonce(n);
    }

    // For demo, we use a hardcoded key - in production this would be loaded from config
    // We'll use ES256 with a generated key for now
    let demo_private_key = include_str!("../tests/certificates/ec/ewqwe.server.key.pem");

    let signer = JwtSigner::from_pem(SigningAlgorithm::ES256, demo_private_key.as_bytes())
        .map_err(|e| AttError::Generic(format!("Failed to create signer: {e}")))?;

    let token_bytes = signer
        .sign(&attestation_claims)
        .map_err(|e| AttError::Generic(format!("Failed to sign attestation: {e}")))?;

    String::from_utf8(token_bytes)
        .map_err(|e| AttError::Generic(format!("Failed to encode attestation: {e}")))
}
