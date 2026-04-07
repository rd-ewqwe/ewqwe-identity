//! SD-JWT VC presentation decoding and cryptographic signature verification.
//!
//! Implements [IETF SD-JWT](https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-12.html)
//! presentation decoding, issuer JWT `x5c` certificate-chain validation, and
//! Key Binding JWT holder-binding verification.

use base64::Engine;

// ============================================================================
// Error types
// ============================================================================

/// Errors that can occur during SD-JWT VC decoding.
#[derive(Debug, thiserror::Error)]
pub(super) enum SdJwtDecodeError {
    #[error("not an SD-JWT: no '~' separator found")]
    NotSdJwt,
    #[error("malformed JWT: expected 3 dot-separated parts")]
    MalformedJwt,
    #[error("base64 decode failed: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("JSON parse failed: {0}")]
    Json(#[from] serde_json::Error),
}

// ============================================================================
// Return types
// ============================================================================

/// Intermediate result from decoding an SD-JWT VC compact presentation.
///
/// This is a plain data struct; the caller constructs the full
/// [`super::VpToken`] from these fields.
pub(super) struct DecodedSdJwt {
    pub(super) vct: String,
    pub(super) claims: serde_json::Map<String, serde_json::Value>,
    pub(super) issuer: String,
    pub(super) issued_at: Option<String>,
    pub(super) expires_at: Option<String>,
    /// Nonce extracted from the Key Binding JWT, if present.
    pub(super) nonce: Option<String>,
}

/// Result of cryptographic signature verification on an SD-JWT VC presentation.
pub(super) struct SigVerificationResult {
    /// Whether the issuer JWT signature was successfully verified.
    pub(super) issuer_sig_valid: bool,
    /// Whether the KB-JWT signature was successfully verified.
    pub(super) kb_sig_valid: bool,
    /// Whether the issuer's leaf certificate chains to a trusted CA.
    pub(super) issuer_trusted: bool,
    /// `true` when the presentation was not an SD-JWT and verification was skipped.
    pub(super) skipped: bool,
    /// Human-readable error messages accumulated during verification.
    pub(super) errors: Vec<String>,
}

impl SigVerificationResult {
    /// Build a result that represents skipped verification (e.g. non-SD-JWT credential).
    pub(super) fn skipped(reason: &str) -> Self {
        Self {
            issuer_sig_valid: false,
            kb_sig_valid: false,
            issuer_trusted: false,
            skipped: true,
            errors: vec![reason.to_string()],
        }
    }
}

// ============================================================================
// SD-JWT VC decoding
// ============================================================================

/// Decode an SD-JWT VC compact presentation.
///
/// Format (IETF SD-JWT §1): `<Issuer-Signed JWT>~<Disclosure1>~...~[KB-JWT]`
///
/// Each disclosure is a base64url-encoded JSON array: `[salt, claim_name, value]`.
/// The last `~`-separated element may be a Key Binding JWT (starts with "eyJ" and contains
/// exactly 2 dots). The nonce from the KB-JWT payload is extracted and returned.
pub(super) fn decode_sd_jwt_presentation(raw: &str) -> Result<DecodedSdJwt, SdJwtDecodeError> {
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
        .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0))
        .map(|dt| dt.to_rfc3339());
    let expires_at = payload
        .get("exp")
        .and_then(|v| v.as_i64())
        .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0))
        .map(|dt| dt.to_rfc3339());

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

    Ok(DecodedSdJwt {
        vct,
        claims,
        issuer,
        issued_at,
        expires_at,
        nonce: kb_nonce,
    })
}

// ============================================================================
// Signature verification
// ============================================================================

/// Verify the cryptographic signatures on an SD-JWT VC compact presentation.
///
/// Given `raw` = `<issuer-jwt>~<disc1>~…~[kb-jwt]`:
///
/// 1. **Issuer JWT** — the JWT header MUST contain `x5c` (required by HAIP §2 and
///    OpenID4VP §6.1.1). The leaf certificate is extracted and validated against the
///    trusted CA directory; its public key verifies the issuer JWT via `jsonwebtoken`.
///    Presentations without `x5c` are rejected.
/// 2. **KB-JWT** — the holder public key from the `cnf.jwk` claim in the issuer
///    payload verifies the KB-JWT signature.
pub(super) fn verify_sd_jwt_signatures(
    raw: &str,
    trusted_certs_dir: &str,
) -> SigVerificationResult {
    let mut errors: Vec<String> = Vec::new();

    let parts: Vec<&str> = raw.splitn(2, '~').collect();
    let issuer_jwt = parts[0];
    let rest = if parts.len() > 1 { parts[1] } else { "" };

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

    let trusted_cas = super::load_trusted_issuer_certs(trusted_certs_dir);
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
            // HAIP §2 and OpenID4VP §6.1.1 require `x5c` in the issuer JWT header.
            errors.push(
                "issuer JWT is missing the required x5c header; presentation rejected".into(),
            );
            return SigVerificationResult {
                issuer_sig_valid: false,
                kb_sig_valid: false,
                issuer_trusted: false,
                skipped: false,
                errors,
            };
        }
    };

    let mut validation = jsonwebtoken::Validation::new(alg);
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

    let kb_sig_valid = verify_kb_jwt(rest, &issuer_token_data.claims, &mut errors);

    SigVerificationResult {
        issuer_sig_valid: true,
        kb_sig_valid,
        issuer_trusted,
        skipped: false,
        errors,
    }
}

// ============================================================================
// Certificate chain and key helpers
// ============================================================================

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

    let leaf_der = base64::engine::general_purpose::STANDARD
        .decode(&x5c[0])
        .map_err(|e| format!("base64 decode of x5c[0] failed: {e}"))?;
    let leaf = X509::from_der(&leaf_der).map_err(|e| format!("DER parse of x5c[0] failed: {e}"))?;
    tracing::debug!(
        subject = ?leaf.subject_name(),
        issuer = ?leaf.issuer_name(),
        "loaded leaf certificate from x5c[0]"
    );

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
/// `rest` is the portion of the SD-JWT after the first `~` (disclosures + optional KB-JWT).
fn verify_kb_jwt(rest: &str, issuer_claims: &serde_json::Value, errors: &mut Vec<String>) -> bool {
    let kb_jwt = rest
        .split('~')
        .filter(|s| !s.is_empty())
        .filter(|s| s.starts_with("eyJ") && s.chars().filter(|&c| c == '.').count() == 2)
        .last();

    let kb_jwt = match kb_jwt {
        Some(j) => j,
        None => {
            tracing::debug!("no KB-JWT found in presentation");
            return true;
        }
    };

    let kb_header = match jsonwebtoken::decode_header(kb_jwt) {
        Ok(h) => h,
        Err(e) => {
            errors.push(format!("KB-JWT header decode failed: {e}"));
            return false;
        }
    };

    let cnf_jwk = issuer_claims.get("cnf").and_then(|v| v.get("jwk"));
    let cnf_jwk = match cnf_jwk {
        Some(jwk) => jwk,
        None => {
            errors.push("issuer payload has no cnf.jwk — cannot verify KB-JWT".into());
            return false;
        }
    };

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

            let x_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(x)
                .map_err(|e| format!("base64 decode x: {e}"))?;
            let y_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(y)
                .map_err(|e| format!("base64 decode y: {e}"))?;

            let nid = match crv {
                "P-256" => openssl::nid::Nid::X9_62_PRIME256V1,
                "P-384" => openssl::nid::Nid::SECP384R1,
                "P-521" => openssl::nid::Nid::SECP521R1,
                _ => return Err(format!("unsupported EC curve: {crv}")),
            };
            let group =
                openssl::ec::EcGroup::from_curve_name(nid).map_err(|e| format!("EcGroup: {e}"))?;
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
