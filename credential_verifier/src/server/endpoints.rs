use crate::{
    AttError,
    attestation::{AttestationClaims, AttestationSigner, JwtSigner, SigningAlgorithm},
    server::Version,
};
use actix_session::Session;
use actix_web::{HttpRequest, HttpResponse, web};
use serde::{Deserialize, Serialize};

/// Request body for credential verification
#[derive(Debug, Clone, Deserialize)]
pub struct VerifyCredentialRequest {
    /// The VP token from the wallet (JSON string containing the credential)
    pub vp_token: String,

    /// Presentation submission with descriptor mapping
    pub presentation_submission: PresentationSubmission,

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
pub struct PresentationSubmission {
    pub id: String,
    pub definition_id: String,
    pub descriptor_map: Vec<DescriptorMapEntry>,
}

/// Descriptor map entry
#[derive(Debug, Clone, Deserialize)]
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

/// Parsed VP Token structure
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
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

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IssuerSigned {
    name_spaces: Option<serde_json::Value>,
}

pub(crate) async fn version_endpoint(
    _req: HttpRequest,
    session: Session,
) -> Result<HttpResponse, AttError> {
    let _user_id: String = session
        .get("user_id")
        .map_err(|e| AttError::Session(e.to_string()))?
        .ok_or_else(|| AttError::Session("Invalid session".to_owned()))?;
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

    // Parse the VP token
    let vp_token: VpToken = serde_json::from_str(&body.vp_token).map_err(|e| {
        tracing::error!("Failed to parse VP token: {e}");
        AttError::BadRequest(format!("Invalid VP token format: {e}"))
    })?;

    tracing::info!("VP Token parsed successfully");
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
