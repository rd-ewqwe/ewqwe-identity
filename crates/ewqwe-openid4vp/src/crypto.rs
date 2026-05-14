//! Cryptographic operations for OpenID4VP.
//!
//! PEM parsing, X.509 certificate handling, JAR signing ([RFC 9101]),
//! JWE decryption for HAIP `direct_post.jwt` responses, and JWKS building.
//!
//! All cryptographic primitives use `openssl` — no `ring` or `aws-lc`.
//!
//! [RFC 9101]: https://www.rfc-editor.org/rfc/rfc9101
//! [RFC 7516]: https://www.rfc-editor.org/rfc/rfc7516
//! [RFC 7518 §4.6]: https://www.rfc-editor.org/rfc/rfc7518#section-4.6

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use openssl::{
    bn::{BigNum, BigNumContext},
    derive::Deriver,
    ec::{EcGroup, EcKey},
    hash::{Hasher, MessageDigest},
    nid::Nid,
    pkey::{PKey, Private},
    sign::Signer,
    symm::Cipher,
    x509::X509,
};
use serde::{Deserialize, Serialize};

use crate::error::{OpenID4VPError, OpenID4VPResult};

// ============================================================================
// Key Material Types
// ============================================================================

/// Key material for signing JWT Authorization Requests (JAR).
///
/// Loaded from PEM files via [`initialize_jar_key`]. Contains:
/// - ES256 signing key (OpenSSL `PKey<Private>`)
/// - Public key as JWK (for JWKS endpoint)
/// - X.509 certificate chain (for JWT `x5c` header)
/// - SAN DNS name (for `client_id` in HAIP profile)
/// - Certificate SHA-256 hash (for `x509_hash` client ID scheme)
pub struct JarKeyMaterial {
    /// OpenSSL private key for ES256 signing.
    signing_key: PKey<Private>,
    /// Public key as JWK JSON (no private `d` component).
    pub signing_key_jwk: serde_json::Value,
    /// X.509 certificate chain as base64-encoded DER strings (for JWT `x5c` header).
    pub x5c_chain: Vec<String>,
    /// SAN DNS name extracted from the leaf certificate.
    pub san_dns_name: String,
    /// Key identifier.
    pub key_id: String,
    /// SHA-256 hash of the leaf certificate (DER-encoded), base64url-encoded.
    /// Used for the `x509_hash` client ID scheme.
    pub cert_hash: String,
}

/// Key material for decrypting JWE responses from wallets (ECDH-ES).
///
/// Generated at startup via [`initialize_jwe_key`]. The public key
/// is shared with wallets through `client_metadata.jwks`.
pub struct JweKeyMaterial {
    /// ECDH P-256 private key for key agreement.
    private_key: PKey<Private>,
    /// Public key as JWK JSON (shared with wallet via `client_metadata.jwks`).
    pub public_jwk: serde_json::Value,
    /// Key identifier.
    pub key_id: String,
}

// ============================================================================
// PEM / DER Utilities
// ============================================================================

/// Parse PEM-encoded certificate chain into individual base64-encoded DER
/// certificates suitable for use in the JWT `x5c` header ([RFC 7515 §4.1.6]).
///
/// Each returned string is a base64 (standard, not URL-safe) encoding of
/// a single DER-encoded X.509 certificate.
///
/// [RFC 7515 §4.1.6]: https://www.rfc-editor.org/rfc/rfc7515#section-4.1.6
pub fn parse_pem_cert_chain(pem_chain: &str) -> Vec<String> {
    let mut certs = Vec::new();
    let mut in_cert = false;
    let mut current = String::new();

    for line in pem_chain.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("-----BEGIN CERTIFICATE-----") {
            in_cert = true;
            current.clear();
        } else if trimmed.starts_with("-----END CERTIFICATE-----") {
            in_cert = false;
            if !current.is_empty() {
                certs.push(current.clone());
            }
        } else if in_cert {
            current.push_str(trimmed);
        }
    }

    certs
}

/// Extract the first SAN IP address from a base64-encoded DER certificate.
/// Must be 4 bytes for IPv4 or 16 bytes for IPv6. Returns the raw bytes of the IP address.
///
/// Uses OpenSSL X.509 parsing.
pub fn extract_san_ip_from_cert(base64_der: &str) -> Option<Vec<u8>> {
    let der_bytes = STANDARD.decode(base64_der).ok()?;
    let cert = X509::from_der(&der_bytes).ok()?;
    let sans = cert.subject_alt_names()?;
    for name in sans.iter() {
        if let Some(ip) = name.ipaddress() {
            return Some(ip.to_vec());
        }
    }
    None
}

/// Extract the first SAN (DNS name or IP address) from a base64-encoded DER certificate.
///
/// Prefers DNS names over IP addresses. Returns the SAN value as a string.
/// This is useful for loading keys where the cert may have either type of SAN.
pub fn extract_san_from_cert(base64_der: &str) -> Option<String> {
    let der_bytes = STANDARD.decode(base64_der).ok()?;
    let cert = X509::from_der(&der_bytes).ok()?;
    let sans = cert.subject_alt_names()?;

    // Prefer DNS names
    for name in sans.iter() {
        if let Some(dns) = name.dnsname() {
            return Some(dns.to_string());
        }
    }
    // Fall back to IP addresses
    for name in sans.iter() {
        if let Some(ip) = name.ipaddress() {
            // IPv4 (4 bytes) or IPv6 (16 bytes)
            if ip.len() == 4 {
                return Some(format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]));
            } else if ip.len() == 16 {
                use std::net::Ipv6Addr;
                let mut octets = [0u8; 16];
                octets.copy_from_slice(ip);
                return Some(Ipv6Addr::from(octets).to_string());
            }
        }
    }
    None
}

/// Compute the SHA-256 hash of a DER-encoded X.509 certificate, returning
/// the base64url-encoded digest (no padding).
///
/// This is used for the `x509_hash` client ID scheme where the verifier's
/// `client_id` is `x509_hash:<base64url_sha256>` — a direct cryptographic
/// binding between the authorization request and the verifier's certificate.
///
/// Per OpenID4VP 1.0 §5.9.3 and HAIP, the wallet validates this by computing
/// the same hash from the leaf certificate in the JAR's `x5c` header and
/// comparing it to the `client_id` value.
pub fn compute_cert_hash(base64_der: &str) -> OpenID4VPResult<String> {
    let der_bytes = STANDARD
        .decode(base64_der)
        .map_err(|e| OpenID4VPError::Crypto(format!("Failed to decode base64 DER: {e}")))?;
    let digest = openssl::sha::sha256(&der_bytes);
    Ok(URL_SAFE_NO_PAD.encode(digest))
}

// ============================================================================
// Key Initialization
// ============================================================================

/// Load the JAR signing key and X.509 certificate chain from PEM strings.
///
/// Returns [`JarKeyMaterial`] needed for signing JWT Authorization Requests
/// per [RFC 9101]. The certificate chain is parsed to extract the SAN DNS
/// name used as the `client_id` in the HAIP profile.
///
/// # Arguments
///
/// * `cert_pem` — PEM-encoded X.509 certificate chain (leaf first)
/// * `key_pem` — PEM-encoded EC private key (PKCS#8 or SEC1 format)
/// * `key_id` — Key identifier for the `kid` header
///
/// [RFC 9101]: https://www.rfc-editor.org/rfc/rfc9101
pub fn initialize_jar_key(
    cert_pem: &str,
    key_pem: &str,
    key_id: &str,
) -> OpenID4VPResult<JarKeyMaterial> {
    // Parse certificate chain
    let x5c_chain = parse_pem_cert_chain(cert_pem);
    if x5c_chain.is_empty() {
        return Err(OpenID4VPError::Config(
            "No certificates found in PEM chain".into(),
        ));
    }

    // Extract SAN from leaf certificate (DNS name preferred, IP address as fallback).
    let san_dns_name = extract_san_from_cert(&x5c_chain[0]).ok_or_else(|| {
        OpenID4VPError::Config("Could not extract SAN (DNS or IP) from leaf certificate".into())
    })?;

    // Compute SHA-256 hash of leaf certificate (DER-encoded) for x509_hash scheme.
    let cert_hash = compute_cert_hash(&x5c_chain[0])?;

    // Load private key with openssl
    let signing_key = PKey::private_key_from_pem(key_pem.as_bytes())
        .map_err(|e| OpenID4VPError::Crypto(format!("Failed to load EC private key: {e}")))?;

    // Extract public key coordinates for JWK
    let ec_key = signing_key
        .ec_key()
        .map_err(|e| OpenID4VPError::Crypto(format!("Key is not EC: {e}")))?;
    let (x, y) = ec_public_key_coordinates(&ec_key)?;

    let signing_key_jwk = serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": x,
        "y": y,
        "kid": key_id,
        "use": "sig",
        "alg": "ES256"
    });

    tracing::info!(
        certs = x5c_chain.len(),
        san_dns = %san_dns_name,
        cert_hash = %cert_hash,
        key_id = %key_id,
        "Loaded JAR signing key"
    );

    Ok(JarKeyMaterial {
        signing_key,
        signing_key_jwk,
        x5c_chain,
        san_dns_name,
        key_id: key_id.to_string(),
        cert_hash,
    })
}

/// Extract x, y coordinates from an EC public key as base64url strings.
fn ec_public_key_coordinates(
    ec_key: &openssl::ec::EcKeyRef<impl openssl::pkey::HasPublic>,
) -> OpenID4VPResult<(String, String)> {
    let group = ec_key.group();
    let mut ctx =
        BigNumContext::new().map_err(|e| OpenID4VPError::Crypto(format!("BigNumContext: {e}")))?;

    let mut x_bn = BigNum::new().map_err(|e| OpenID4VPError::Crypto(format!("BigNum: {e}")))?;
    let mut y_bn = BigNum::new().map_err(|e| OpenID4VPError::Crypto(format!("BigNum: {e}")))?;

    ec_key
        .public_key()
        .affine_coordinates_gfp(group, &mut x_bn, &mut y_bn, &mut ctx)
        .map_err(|e| OpenID4VPError::Crypto(format!("Failed to get EC affine coordinates: {e}")))?;

    // P-256 coordinates are 32 bytes each, left-pad with zeros
    let x_bytes = x_bn
        .to_vec_padded(32)
        .map_err(|e| OpenID4VPError::Crypto(format!("x coordinate padding: {e}")))?;
    let y_bytes = y_bn
        .to_vec_padded(32)
        .map_err(|e| OpenID4VPError::Crypto(format!("y coordinate padding: {e}")))?;

    Ok((
        URL_SAFE_NO_PAD.encode(&x_bytes),
        URL_SAFE_NO_PAD.encode(&y_bytes),
    ))
}

/// Generate an ECDH P-256 key pair for decrypting JWE responses from wallets.
///
/// Used when `response_mode=direct_post.jwt` (HAIP profile). The public key
/// is shared with the wallet via `client_metadata.jwks`.
pub fn initialize_jwe_key(key_id: &str) -> OpenID4VPResult<JweKeyMaterial> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
        .map_err(|e| OpenID4VPError::Crypto(format!("P-256 group: {e}")))?;
    let ec_key = EcKey::generate(&group)
        .map_err(|e| OpenID4VPError::Crypto(format!("EC key generation: {e}")))?;
    let private_key = PKey::from_ec_key(ec_key.clone())
        .map_err(|e| OpenID4VPError::Crypto(format!("PKey from EC key: {e}")))?;

    let (x, y) = ec_public_key_coordinates(&ec_key)?;

    let public_jwk = serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": x,
        "y": y,
        "kid": key_id,
        "use": "enc",
        "alg": "ECDH-ES"
    });

    tracing::info!(key_id = %key_id, "Generated ECDH P-256 encryption key pair");

    Ok(JweKeyMaterial {
        private_key,
        public_jwk,
        key_id: key_id.to_string(),
    })
}

// ============================================================================
// JAR Signing (RFC 9101)
// ============================================================================

/// Payload for a JWT Authorization Request (JAR).
///
/// Contains all OpenID4VP-specific claims that go into the signed JWT.
#[derive(Debug, Clone, Serialize)]
pub struct JarPayload {
    pub client_id: String,
    pub client_id_scheme: String,
    pub response_mode: String,
    pub response_uri: String,
    pub state: String,
    pub nonce: String,
    pub dcql_query: serde_json::Value,
    pub client_metadata: serde_json::Value,
    /// Expiration time as Unix timestamp in **seconds**.
    #[serde(skip)]
    pub expires_at_secs: i64,
    /// Optional transaction data entries (§8.4). Each element is a pre-encoded
    /// base64url JSON string that will be included verbatim in the JAR.
    #[serde(skip)]
    pub transaction_data: Option<Vec<String>>,
}

/// Sign a JWT Authorization Request (JAR) per [RFC 9101].
///
/// Creates a compact JWS with:
/// - Algorithm: ES256 (P-256 ECDSA with SHA-256)
/// - Header: `typ=oauth-authz-req+jwt`, `kid`, `x5c` (full certificate chain)
/// - Payload: OpenID4VP authorization request claims
///
/// Uses openssl for ES256 signing with DER-to-JWS signature conversion.
///
/// [RFC 9101]: https://www.rfc-editor.org/rfc/rfc9101
pub fn sign_jar(payload: &JarPayload, jar_key: &JarKeyMaterial) -> OpenID4VPResult<String> {
    let now = chrono::Utc::now().timestamp();

    let mut jwt_claims = serde_json::json!({
        "iss": payload.client_id,
        "aud": "https://self-issued.me/v2",
        "iat": now,
        "exp": payload.expires_at_secs,
        "client_id": payload.client_id,
        "client_id_scheme": payload.client_id_scheme,
        "response_type": "vp_token",
        "response_mode": payload.response_mode,
        "response_uri": payload.response_uri,
        "state": payload.state,
        "nonce": payload.nonce,
        "dcql_query": payload.dcql_query,
        "client_metadata": payload.client_metadata,
    });

    // §8.4: include transaction_data when present
    if let Some(ref td) = payload.transaction_data
        && let Some(obj) = jwt_claims.as_object_mut()
    {
        obj.insert(
            "transaction_data".to_string(),
            serde_json::Value::Array(
                td.iter()
                    .map(|s| serde_json::Value::String(s.clone()))
                    .collect(),
            ),
        );
    }

    let header = serde_json::json!({
        "alg": "ES256",
        "typ": "oauth-authz-req+jwt",
        "kid": jar_key.key_id,
        "x5c": jar_key.x5c_chain,
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&header)
            .map_err(|e| OpenID4VPError::Crypto(format!("Header serialization: {e}")))?,
    );
    let claims_b64 = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&jwt_claims)
            .map_err(|e| OpenID4VPError::Crypto(format!("Claims serialization: {e}")))?,
    );

    let signing_input = format!("{header_b64}.{claims_b64}");

    // Sign with ES256 (ECDSA P-256 + SHA-256)
    let mut signer = Signer::new(MessageDigest::sha256(), &jar_key.signing_key)
        .map_err(|e| OpenID4VPError::Crypto(format!("Signer creation: {e}")))?;
    signer
        .update(signing_input.as_bytes())
        .map_err(|e| OpenID4VPError::Crypto(format!("Signer update: {e}")))?;
    let der_signature = signer
        .sign_to_vec()
        .map_err(|e| OpenID4VPError::Crypto(format!("ECDSA signing: {e}")))?;

    // Convert DER-encoded signature to JWS fixed-length format (r || s, 64 bytes)
    let jws_signature = der_ecdsa_to_jws(&der_signature)?;
    let sig_b64 = URL_SAFE_NO_PAD.encode(&jws_signature);

    Ok(format!("{signing_input}.{sig_b64}"))
}

/// Convert a DER-encoded ECDSA signature to the JWS fixed-length (r||s) format.
///
/// DER: SEQUENCE { INTEGER r, INTEGER s }
/// JWS: r (32 bytes, zero-padded) || s (32 bytes, zero-padded)
///
/// P-256 uses 32-byte integers, so total JWS signature is 64 bytes.
fn der_ecdsa_to_jws(der: &[u8]) -> OpenID4VPResult<Vec<u8>> {
    use openssl::ecdsa::EcdsaSig;
    let sig = EcdsaSig::from_der(der)
        .map_err(|e| OpenID4VPError::Crypto(format!("Invalid DER ECDSA signature: {e}")))?;
    let r_bytes = sig
        .r()
        .to_vec_padded(32)
        .map_err(|e| OpenID4VPError::Crypto(format!("ECDSA r padding: {e}")))?;
    let s_bytes = sig
        .s()
        .to_vec_padded(32)
        .map_err(|e| OpenID4VPError::Crypto(format!("ECDSA s padding: {e}")))?;
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&r_bytes);
    out.extend_from_slice(&s_bytes);
    Ok(out)
}

// ============================================================================
// JWE Decryption (ECDH-ES + A256GCM)
// ============================================================================

/// JWE protected header — parsed from the first component of the compact serialization.
#[derive(Debug, Deserialize)]
struct JweProtectedHeader {
    alg: String,
    enc: String,
    epk: Option<serde_json::Value>,
    #[serde(default)]
    apu: Option<String>,
    #[serde(default)]
    apv: Option<String>,
}

/// Decrypted wallet response from a JWE (`direct_post.jwt` mode).
#[derive(Debug, Clone)]
pub struct DecryptedWalletResponse {
    pub vp_token: String,
    pub presentation_submission: Option<String>,
    pub state: String,
}

/// Decrypt a JWE compact serialization from the EUDI wallet.
///
/// Supports ECDH-ES direct key agreement with A128GCM or A256GCM content
/// encryption, as used in the HAIP profile's `direct_post.jwt` response mode.
///
/// The decrypted content may be a nested JWS (decoded without signature
/// verification) or a plain JSON payload. In both cases, extracts
/// `vp_token`, `presentation_submission`, and `state`.
///
/// # JWE Structure
///
/// ```text
/// BASE64URL(header) . (empty) . BASE64URL(iv) . BASE64URL(ciphertext) . BASE64URL(tag)
/// ```
///
/// For ECDH-ES (direct key agreement), the encrypted key component is empty.
pub fn decrypt_jwe_response(
    jwe_compact: &str,
    jwe_key: &JweKeyMaterial,
) -> OpenID4VPResult<DecryptedWalletResponse> {
    let parts: Vec<&str> = jwe_compact.split('.').collect();
    if parts.len() != 5 {
        return Err(OpenID4VPError::Crypto(format!(
            "Invalid JWE: expected 5 parts, got {}",
            parts.len()
        )));
    }

    // Parse protected header
    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|e| OpenID4VPError::Crypto(format!("Invalid JWE header base64: {e}")))?;
    let header: JweProtectedHeader = serde_json::from_slice(&header_bytes)
        .map_err(|e| OpenID4VPError::Crypto(format!("Invalid JWE header JSON: {e}")))?;

    // Validate algorithm
    if header.alg != "ECDH-ES" {
        return Err(OpenID4VPError::Crypto(format!(
            "Unsupported JWE alg: {} (expected ECDH-ES)",
            header.alg
        )));
    }

    // Determine key size and cipher from enc algorithm (RFC 7518 §5.3)
    let (key_bits, cipher) = match header.enc.as_str() {
        "A128GCM" => (128u32, Cipher::aes_128_gcm()),
        "A256GCM" => (256u32, Cipher::aes_256_gcm()),
        _ => {
            return Err(OpenID4VPError::Crypto(format!(
                "Unsupported JWE enc: {} (expected A128GCM or A256GCM)",
                header.enc
            )));
        }
    };

    // For ECDH-ES, the encrypted key (parts[1]) should be empty

    // Decode IV, ciphertext, and authentication tag
    let iv = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|e| OpenID4VPError::Crypto(format!("Invalid JWE IV base64: {e}")))?;
    let ciphertext = URL_SAFE_NO_PAD
        .decode(parts[3])
        .map_err(|e| OpenID4VPError::Crypto(format!("Invalid JWE ciphertext base64: {e}")))?;
    let tag = URL_SAFE_NO_PAD
        .decode(parts[4])
        .map_err(|e| OpenID4VPError::Crypto(format!("Invalid JWE tag base64: {e}")))?;

    if iv.len() != 12 {
        return Err(OpenID4VPError::Crypto(format!(
            "Invalid JWE IV length: {} (expected 12 bytes for AES-GCM)",
            iv.len()
        )));
    }

    // Extract ephemeral public key from header
    let epk = header
        .epk
        .as_ref()
        .ok_or_else(|| OpenID4VPError::Crypto("JWE header missing 'epk'".into()))?;
    let sender_public_key = jwk_to_openssl_ec_key(epk)?;
    let sender_pkey = PKey::from_ec_key(sender_public_key)
        .map_err(|e| OpenID4VPError::Crypto(format!("PKey from sender EC key: {e}")))?;

    // ECDH key agreement: compute shared secret Z
    let mut deriver = Deriver::new(&jwe_key.private_key)
        .map_err(|e| OpenID4VPError::Crypto(format!("ECDH deriver creation: {e}")))?;
    deriver
        .set_peer(&sender_pkey)
        .map_err(|e| OpenID4VPError::Crypto(format!("ECDH set peer: {e}")))?;
    let shared_secret = deriver
        .derive_to_vec()
        .map_err(|e| OpenID4VPError::Crypto(format!("ECDH key agreement: {e}")))?;

    // Derive Content Encryption Key via Concat KDF (RFC 7518 §4.6.2)
    let apu = header
        .apu
        .as_deref()
        .map(|s| URL_SAFE_NO_PAD.decode(s))
        .transpose()
        .map_err(|e| OpenID4VPError::Crypto(format!("Invalid apu base64: {e}")))?;
    let apv = header
        .apv
        .as_deref()
        .map(|s| URL_SAFE_NO_PAD.decode(s))
        .transpose()
        .map_err(|e| OpenID4VPError::Crypto(format!("Invalid apv base64: {e}")))?;

    let cek = concat_kdf_sha256(
        &shared_secret,
        &header.enc,
        apu.as_deref(),
        apv.as_deref(),
        key_bits,
    );

    // Decrypt with AES-GCM (128 or 256 depending on enc)
    // AAD = ASCII bytes of the base64url-encoded protected header
    let plaintext = openssl::symm::decrypt_aead(
        cipher,
        &cek,
        Some(&iv),
        parts[0].as_bytes(), // AAD
        &ciphertext,
        &tag,
    )
    .map_err(|_| OpenID4VPError::Crypto("JWE AES-GCM decryption failed".into()))?;

    // Parse decrypted content
    let decrypted_text = String::from_utf8(plaintext)
        .map_err(|e| OpenID4VPError::Crypto(format!("Decrypted JWE is not valid UTF-8: {e}")))?;

    parse_decrypted_wallet_response(&decrypted_text)
}

/// Parse a JWK object (with `x` and `y` coordinates) into an OpenSSL EC public key.
fn jwk_to_openssl_ec_key(jwk: &serde_json::Value) -> OpenID4VPResult<EcKey<openssl::pkey::Public>> {
    let x = jwk["x"]
        .as_str()
        .ok_or_else(|| OpenID4VPError::Crypto("JWK missing 'x' coordinate".into()))?;
    let y = jwk["y"]
        .as_str()
        .ok_or_else(|| OpenID4VPError::Crypto("JWK missing 'y' coordinate".into()))?;

    let x_bytes = URL_SAFE_NO_PAD
        .decode(x)
        .map_err(|e| OpenID4VPError::Crypto(format!("Invalid JWK 'x' base64: {e}")))?;
    let y_bytes = URL_SAFE_NO_PAD
        .decode(y)
        .map_err(|e| OpenID4VPError::Crypto(format!("Invalid JWK 'y' base64: {e}")))?;

    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
        .map_err(|e| OpenID4VPError::Crypto(format!("P-256 group: {e}")))?;

    let x_bn = BigNum::from_slice(&x_bytes)
        .map_err(|e| OpenID4VPError::Crypto(format!("BigNum from x: {e}")))?;
    let y_bn = BigNum::from_slice(&y_bytes)
        .map_err(|e| OpenID4VPError::Crypto(format!("BigNum from y: {e}")))?;

    let ec_key = EcKey::from_public_key_affine_coordinates(&group, &x_bn, &y_bn)
        .map_err(|e| OpenID4VPError::Crypto(format!("Invalid P-256 public key: {e}")))?;

    Ok(ec_key)
}

/// Parse the decrypted JWE content, which may be a nested JWS or plain JSON.
///
/// For nested JWS: decodes the payload (second part) without signature verification.
/// For plain JSON: parses directly.
///
/// The `vp_token` may be a JSON string (base64url-encoded CBOR for mso_mdoc)
/// or a JSON object. Similarly, `presentation_submission` may be a string or
/// an object. Non-string values are serialized to their JSON representation.
fn parse_decrypted_wallet_response(text: &str) -> OpenID4VPResult<DecryptedWalletResponse> {
    let payload: serde_json::Value = if text.matches('.').count() == 2 {
        // Nested JWS — decode payload without verification (second part)
        let jws_parts: Vec<&str> = text.split('.').collect();
        let payload_bytes = URL_SAFE_NO_PAD.decode(jws_parts[1]).map_err(|e| {
            OpenID4VPError::Crypto(format!("Invalid nested JWS payload base64: {e}"))
        })?;
        serde_json::from_slice(&payload_bytes)
            .map_err(|e| OpenID4VPError::Crypto(format!("Invalid nested JWS payload JSON: {e}")))?
    } else {
        serde_json::from_str(text)
            .map_err(|e| OpenID4VPError::Crypto(format!("Invalid decrypted JSON: {e}")))?
    };

    tracing::debug!(
        keys = ?payload.as_object().map(|o| o.keys().collect::<Vec<_>>()),
        "Decrypted wallet response payload keys"
    );

    // Extract vp_token — may be a string or a JSON value (serialize non-strings)
    let vp_token = match &payload["vp_token"] {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Null => String::new(),
        other => serde_json::to_string(other).unwrap_or_default(),
    };

    // Extract presentation_submission — may be a string or JSON object
    let presentation_submission = match &payload["presentation_submission"] {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Null => None,
        other => Some(serde_json::to_string(other).unwrap_or_default()),
    };

    // Extract state — string value
    let state = match &payload["state"] {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Null => String::new(),
        other => serde_json::to_string(other).unwrap_or_default(),
    };

    tracing::debug!(
        vp_token_len = vp_token.len(),
        has_presentation_submission = presentation_submission.is_some(),
        state_len = state.len(),
        "Parsed decrypted wallet response"
    );

    Ok(DecryptedWalletResponse {
        vp_token,
        presentation_submission,
        state,
    })
}

/// Concat KDF using SHA-256 ([RFC 7518 §4.6.2] / NIST SP 800-56A).
///
/// Derives a symmetric key from the ECDH shared secret for JWE content encryption.
/// SHA-256 produces 256 bits per iteration; only one iteration is needed for
/// key lengths ≤ 256 bits. The output is truncated to `key_length_bits`.
///
/// Uses OpenSSL's SHA-256 implementation.
///
/// [RFC 7518 §4.6.2]: https://www.rfc-editor.org/rfc/rfc7518#section-4.6.2
fn concat_kdf_sha256(
    shared_secret: &[u8],
    algorithm: &str,
    apu: Option<&[u8]>,
    apv: Option<&[u8]>,
    key_length_bits: u32,
) -> Vec<u8> {
    let mut hasher = Hasher::new(MessageDigest::sha256()).expect("SHA-256 hasher");

    // Round number (4 bytes, big-endian, starting at 1)
    hasher.update(&1u32.to_be_bytes()).expect("hash update");

    // Shared secret Z
    hasher.update(shared_secret).expect("hash update");

    // AlgorithmID: length-prefixed algorithm name
    hasher
        .update(&(algorithm.len() as u32).to_be_bytes())
        .expect("hash update");
    hasher.update(algorithm.as_bytes()).expect("hash update");

    // PartyUInfo: length-prefixed apu (or zero-length)
    match apu {
        Some(data) => {
            hasher
                .update(&(data.len() as u32).to_be_bytes())
                .expect("hash update");
            hasher.update(data).expect("hash update");
        }
        None => hasher.update(&0u32.to_be_bytes()).expect("hash update"),
    }

    // PartyVInfo: length-prefixed apv (or zero-length)
    match apv {
        Some(data) => {
            hasher
                .update(&(data.len() as u32).to_be_bytes())
                .expect("hash update");
            hasher.update(data).expect("hash update");
        }
        None => hasher.update(&0u32.to_be_bytes()).expect("hash update"),
    }

    // SuppPubInfo: key length in bits (4 bytes, big-endian)
    hasher
        .update(&key_length_bits.to_be_bytes())
        .expect("hash update");

    let result = hasher.finish().expect("hash finish");
    let key_length_bytes = (key_length_bits / 8) as usize;
    result[..key_length_bytes].to_vec()
}

// ============================================================================
// Public JWKS
// ============================================================================

/// Build the public JWK Set containing the JAR signing key.
///
/// Serves the JWKS at `.well-known/jwks.json` for wallets to verify
/// the signature on JWT Authorization Requests (JAR).
pub fn build_public_jwk_set(jar_key: &JarKeyMaterial) -> serde_json::Value {
    serde_json::json!({
        "keys": [jar_key.signing_key_jwk.clone()]
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_pem_cert_chain() {
        let pem = concat!(
            "-----BEGIN CERTIFICATE-----\n",
            "AAAA\n",
            "BBBB\n",
            "-----END CERTIFICATE-----\n",
            "-----BEGIN CERTIFICATE-----\n",
            "CCCC\n",
            "DDDD\n",
            "-----END CERTIFICATE-----\n",
        );
        let chain = parse_pem_cert_chain(pem);
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0], "AAAABBBB");
        assert_eq!(chain[1], "CCCCDDDD");
    }

    #[test]
    fn test_parse_empty_pem() {
        let chain = parse_pem_cert_chain("");
        assert!(chain.is_empty());
    }

    #[test]
    fn test_parse_pem_with_whitespace() {
        let pem = concat!(
            "  -----BEGIN CERTIFICATE-----  \n",
            "  AAAA  \n",
            "  BBBB  \n",
            "  -----END CERTIFICATE-----  \n",
        );
        let chain = parse_pem_cert_chain(pem);
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0], "AAAABBBB");
    }

    #[test]
    fn test_jwk_to_p256_public_key_roundtrip() {
        // Generate a key, convert to JWK, then parse back
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let ec_key = EcKey::generate(&group).unwrap();
        let (x, y) = ec_public_key_coordinates(&ec_key).unwrap();

        let jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": x,
            "y": y,
        });

        let parsed = jwk_to_openssl_ec_key(&jwk).unwrap();
        // Compare the public key points
        let mut ctx = BigNumContext::new().unwrap();
        assert!(
            ec_key
                .public_key()
                .eq(&group, parsed.public_key(), &mut ctx)
                .unwrap()
        );
    }

    #[test]
    fn test_jwk_missing_coordinate() {
        let jwk = serde_json::json!({"kty": "EC", "crv": "P-256", "x": "AAAA"});
        assert!(jwk_to_openssl_ec_key(&jwk).is_err());
    }

    #[test]
    fn test_concat_kdf_sha256_deterministic() {
        let secret = [0x42u8; 32];
        let key1 = concat_kdf_sha256(&secret, "A256GCM", None, None, 256);
        let key2 = concat_kdf_sha256(&secret, "A256GCM", None, None, 256);
        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 32); // 256 bits
    }

    #[test]
    fn test_concat_kdf_sha256_a128gcm_key_length() {
        let secret = [0x42u8; 32];
        let key = concat_kdf_sha256(&secret, "A128GCM", None, None, 128);
        assert_eq!(key.len(), 16); // 128 bits
    }

    #[test]
    fn test_concat_kdf_sha256_different_alg() {
        let secret = [0x42u8; 32];
        let key1 = concat_kdf_sha256(&secret, "A256GCM", None, None, 256);
        let key2 = concat_kdf_sha256(&secret, "A128GCM", None, None, 128);
        // Different lengths, can't directly compare, but first 16 bytes should differ
        // because the algorithm name and keydatalen in the hash input differ
        assert_ne!(&key1[..16], &key2[..]);
    }

    #[test]
    fn test_concat_kdf_sha256_with_apu_apv() {
        let secret = [0x42u8; 32];
        let key1 = concat_kdf_sha256(&secret, "A256GCM", None, None, 256);
        let key2 = concat_kdf_sha256(&secret, "A256GCM", Some(b"sender"), Some(b"receiver"), 256);
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_initialize_jwe_key() {
        let jwe_key = initialize_jwe_key("test-enc-key-1").unwrap();
        assert_eq!(jwe_key.key_id, "test-enc-key-1");
        assert_eq!(jwe_key.public_jwk["kty"], "EC");
        assert_eq!(jwe_key.public_jwk["crv"], "P-256");
        assert_eq!(jwe_key.public_jwk["use"], "enc");
        assert_eq!(jwe_key.public_jwk["alg"], "ECDH-ES");
        assert!(jwe_key.public_jwk["x"].is_string());
        assert!(jwe_key.public_jwk["y"].is_string());
    }

    #[test]
    fn test_jwe_encrypt_decrypt_roundtrip() {
        // Generate our JWE decryption key
        let jwe_key = initialize_jwe_key("test-key").unwrap();

        // Simulate what a wallet does: encrypt a response to our public key
        let plaintext = serde_json::json!({
            "vp_token": "test-vp-token-123",
            "presentation_submission": "test-submission",
            "state": "test-state-abc"
        });
        let plaintext_bytes = serde_json::to_vec(&plaintext).unwrap();

        // 1. Wallet generates ephemeral ECDH key pair
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let eph_ec = EcKey::generate(&group).unwrap();
        let (eph_x, eph_y) = ec_public_key_coordinates(&eph_ec).unwrap();
        let eph_pkey = PKey::from_ec_key(eph_ec).unwrap();

        // 2. Wallet does ECDH with our public key
        // Re-create our public key from the JWK
        let our_pub_ec = jwk_to_openssl_ec_key(&jwe_key.public_jwk).unwrap();
        let our_pub_pkey = PKey::from_ec_key(our_pub_ec).unwrap();

        let mut deriver = Deriver::new(&eph_pkey).unwrap();
        deriver.set_peer(&our_pub_pkey).unwrap();
        let wallet_shared = deriver.derive_to_vec().unwrap();

        // 3. Derive CEK
        let cek = concat_kdf_sha256(&wallet_shared, "A256GCM", None, None, 256);

        // 4. Encrypt with AES-256-GCM using openssl
        let iv_bytes = [0x01u8; 12]; // Deterministic IV for testing

        // Build protected header
        let header = serde_json::json!({
            "alg": "ECDH-ES",
            "enc": "A256GCM",
            "epk": {
                "kty": "EC",
                "crv": "P-256",
                "x": eph_x,
                "y": eph_y
            }
        });
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());

        let mut tag = vec![0u8; 16];
        let ct = openssl::symm::encrypt_aead(
            Cipher::aes_256_gcm(),
            &cek,
            Some(&iv_bytes),
            header_b64.as_bytes(), // AAD
            &plaintext_bytes,
            &mut tag,
        )
        .expect("encryption should succeed");

        // 5. Build JWE compact serialization
        let jwe = format!(
            "{}.{}.{}.{}.{}",
            header_b64,
            "", // empty encrypted key for ECDH-ES
            URL_SAFE_NO_PAD.encode(iv_bytes),
            URL_SAFE_NO_PAD.encode(&ct),
            URL_SAFE_NO_PAD.encode(&tag),
        );

        // 6. Decrypt and verify
        let result = decrypt_jwe_response(&jwe, &jwe_key).unwrap();
        assert_eq!(result.vp_token, "test-vp-token-123");
        assert_eq!(
            result.presentation_submission.as_deref(),
            Some("test-submission")
        );
        assert_eq!(result.state, "test-state-abc");
    }

    #[test]
    fn test_decrypt_jwe_invalid_parts() {
        let jwe_key = initialize_jwe_key("k").unwrap();
        let result = decrypt_jwe_response("only.three.parts", &jwe_key);
        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("expected 5 parts"));
    }

    /// Helper to load test cert chain: server cert (leaf, with SAN) + CA chain
    fn load_test_cert_chain() -> (String, String) {
        let base = env!("CARGO_MANIFEST_DIR");
        let cert_dir = format!("{base}/../../certificates/signer");
        // The server cert has the SAN (IP:127.0.0.1) and must come first (leaf)
        let server_cert = std::fs::read_to_string(format!("{cert_dir}/ewqwe.signer.leaf.cert.pem"))
            .expect("test server cert");
        let ca_chain = std::fs::read_to_string(format!("{cert_dir}/ewqwe.signer.ca.pem"))
            .expect("test CA chain");
        let key_pem = std::fs::read_to_string(format!("{cert_dir}/ewqwe.signer.leaf.key.pem"))
            .expect("test key");
        // Build full chain: leaf first, then CA
        let full_chain = format!("{server_cert}{ca_chain}");
        (full_chain, key_pem)
    }

    #[test]
    fn test_initialize_jar_key_with_test_certs() {
        let (cert_pem, key_pem) = load_test_cert_chain();

        let jar_key = initialize_jar_key(&cert_pem, &key_pem, "test-key-1").unwrap();
        assert_eq!(jar_key.key_id, "test-key-1");
        assert!(
            jar_key.x5c_chain.len() >= 2,
            "Should have server cert + CA cert"
        );
        // Test certs use IP SAN (127.0.0.1), not DNS
        assert_eq!(jar_key.san_dns_name, "demo.ewqwe.local");
        assert_eq!(jar_key.signing_key_jwk["kty"], "EC");
        assert_eq!(jar_key.signing_key_jwk["crv"], "P-256");
        assert_eq!(jar_key.signing_key_jwk["alg"], "ES256");

        // cert_hash must be a non-empty base64url string
        assert!(!jar_key.cert_hash.is_empty(), "cert_hash must be non-empty");
        assert!(
            jar_key.cert_hash.contains('_')
                || jar_key.cert_hash.contains('-')
                || jar_key.cert_hash.chars().all(|c| c.is_ascii_alphanumeric()),
            "cert_hash should be base64url (alphanumeric, -, _)"
        );
        // SHA-256 produces 32 bytes = 43 base64url chars (no padding)
        assert_eq!(jar_key.cert_hash.len(), 43);
    }

    #[test]
    fn test_sign_jar_with_test_certs() {
        let (cert_pem, key_pem) = load_test_cert_chain();

        let jar_key = initialize_jar_key(&cert_pem, &key_pem, "test-key-1").unwrap();

        let payload = JarPayload {
            client_id: format!("x509_hash:{}", jar_key.cert_hash),
            client_id_scheme: "x509_hash".to_string(),
            response_mode: "direct_post.jwt".to_string(),
            response_uri: "https://rp.example.com/ewqwe_api/openid4vp/direct_post".to_string(),
            state: "state-123".to_string(),
            nonce: "nonce-456".to_string(),
            dcql_query: serde_json::json!({"credentials": []}),
            client_metadata: serde_json::json!({"client_name": "Test"}),
            expires_at_secs: chrono::Utc::now().timestamp() + 300,
            transaction_data: None,
        };

        let jwt = sign_jar(&payload, &jar_key).unwrap();

        // Verify JWT structure: 3 dot-separated base64url parts
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);

        // Decode and verify header
        let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["typ"], "oauth-authz-req+jwt");
        assert_eq!(header["kid"], "test-key-1");
        assert!(header["x5c"].is_array());

        // Decode and verify payload claims
        let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
        assert_eq!(claims["response_type"], "vp_token");
        assert_eq!(claims["response_mode"], "direct_post.jwt");
        assert_eq!(claims["state"], "state-123");
        assert_eq!(claims["nonce"], "nonce-456");
        assert_eq!(claims["aud"], "https://self-issued.me/v2");
    }

    #[test]
    fn test_build_public_jwk_set() {
        let (cert_pem, key_pem) = load_test_cert_chain();

        let jar_key = initialize_jar_key(&cert_pem, &key_pem, "test-key-1").unwrap();
        let jwks = build_public_jwk_set(&jar_key);

        assert!(jwks["keys"].is_array());
        let keys = jwks["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["kty"], "EC");
        assert_eq!(keys[0]["use"], "sig");
        assert_eq!(keys[0]["alg"], "ES256");
        // Must NOT contain private key component
        assert!(keys[0].get("d").is_none());
    }

    #[test]
    fn test_extract_san_dns_vs_ip() {
        let base = env!("CARGO_MANIFEST_DIR");
        let cert_dir = format!("{base}/../../certificates/signer");

        // The server cert has DNS SAN, not IP SAN
        let server_cert = std::fs::read_to_string(format!("{cert_dir}/ewqwe.signer.leaf.cert.pem"))
            .expect("test server cert");
        let chain = parse_pem_cert_chain(&server_cert);
        assert_eq!(chain.len(), 1);

        // extract_san_ip should return 127.0.0.1
        let ip_san = extract_san_ip_from_cert(&chain[0]);
        assert_eq!(
            ip_san,
            Some(vec![127, 0, 0, 1]),
            "Expected 127.0.0.1, got {:?}",
            ip_san
        );

        // extract_san should return the DNS name first
        let any_san = extract_san_from_cert(&chain[0]);
        assert_eq!(any_san, Some("demo.ewqwe.local".to_string()));
    }

    #[test]
    fn test_compute_cert_hash_is_deterministic() {
        let base = env!("CARGO_MANIFEST_DIR");
        let cert_dir = format!("{base}/../../certificates/signer");
        let server_cert = std::fs::read_to_string(format!("{cert_dir}/ewqwe.signer.leaf.cert.pem"))
            .expect("test server cert");
        let chain = parse_pem_cert_chain(&server_cert);
        assert_eq!(chain.len(), 1);

        // Hash must be deterministic
        let hash1 = compute_cert_hash(&chain[0]).unwrap();
        let hash2 = compute_cert_hash(&chain[0]).unwrap();
        assert_eq!(hash1, hash2, "cert hash must be deterministic");

        // SHA-256 → 43 base64url characters (no padding)
        assert_eq!(hash1.len(), 43, "base64url SHA-256 must be 43 chars");

        // Different certificate should produce different hash.
        // The TLS server cert is a different cert from the signer leaf,
        // so their hashes must differ.
        let tls_cert_dir = format!("{base}/../../certificates/tls");
        let tls_cert = std::fs::read_to_string(format!("{tls_cert_dir}/ewqwe.server.cert.pem"))
            .expect("test TLS server cert");
        let tls_chain = parse_pem_cert_chain(&tls_cert);
        assert_eq!(tls_chain.len(), 1);
        let hash_tls = compute_cert_hash(&tls_chain[0]).unwrap();
        assert_ne!(
            hash1, hash_tls,
            "Different leaf certs must produce different hashes"
        );
    }
}
