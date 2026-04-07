//! SD-JWT VC building and signing.
//!
//! Builds **EU Age Verification Profile** (`eu.europa.ec.av.1`) and
//! **EUDI PID** (`eu.europa.ec.eudi.pid.1`) SD-JWT Verifiable Credentials with
//! an x5c chain in the issuer JWT header and a Key Binding JWT signed by the
//! device private key.
//!
//! Format: `<issuer-jwt>~<kb-jwt>`
//!
//! The issuer JWT uses **ES256** (ECDSA P-256 SHA-256).  All credential claims
//! are placed in the issuer JWT payload as clear-text (no selective-disclosure
//! entries); selective disclosure can be added by callers if needed.

use base64::Engine as _;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use openssl::pkey::{PKey, Private};
use serde_json::{Value as Json, json};

use crate::{error::Result, util::now_unix};

/// Build an **EU Age Verification Profile** SD-JWT VC.
///
/// - `vct = "eu.europa.ec.av.1"`
/// - Claim: `over_18 = true`
/// - `cnf.jwk` contains the device public key for KB-JWT verification.
///
/// Returns `"<issuer-jwt>~<kb-jwt>"`.
pub fn build_eu_age_sd_jwt(
    issuer_key: &PKey<Private>,
    issuer_cert_der: &[u8],
    device_pubkey_jwk: &Json,
    device_key: &PKey<Private>,
    nonce: &str,
    client_id: &str,
) -> Result<String> {
    let now = now_unix();
    let payload = json!({
        "iss": "https://test-issuer.example",
        "vct": "eu.europa.ec.av.1",
        "iat": now,
        "exp": now + 3600,
        "over_18": true,
        "cnf": { "jwk": device_pubkey_jwk },
    });
    let issuer_jwt = sign_issuer_jwt(issuer_key, issuer_cert_der, payload)?;
    let kb_jwt = sign_kb_jwt(device_key, nonce, client_id)?;
    Ok(format!("{issuer_jwt}~{kb_jwt}"))
}

/// Build a **EUDI PID SD-JWT VC**.
///
/// - `vct = "eu.europa.ec.eudi.pid.1"`
/// - Claims: `given_name`, `family_name`, `birth_date`, `age_over_18`
/// - `cnf.jwk` contains the device public key for KB-JWT verification.
///
/// Returns `"<issuer-jwt>~<kb-jwt>"`.
pub fn build_eudi_pid_sd_jwt(
    issuer_key: &PKey<Private>,
    issuer_cert_der: &[u8],
    device_pubkey_jwk: &Json,
    device_key: &PKey<Private>,
    nonce: &str,
    client_id: &str,
) -> Result<String> {
    let now = now_unix();
    let payload = json!({
        "iss": "https://test-issuer.example",
        "vct": "eu.europa.ec.eudi.pid.1",
        "iat": now,
        "exp": now + 3600,
        "given_name": "Test",
        "family_name": "User",
        "birth_date": "1990-01-01",
        "age_over_18": true,
        "cnf": { "jwk": device_pubkey_jwk },
    });
    let issuer_jwt = sign_issuer_jwt(issuer_key, issuer_cert_der, payload)?;
    let kb_jwt = sign_kb_jwt(device_key, nonce, client_id)?;
    Ok(format!("{issuer_jwt}~{kb_jwt}"))
}

// ============================================================================
// Private helpers
// ============================================================================

/// Sign an SD-JWT issuer payload with ES256.
///
/// Places the issuer leaf certificate DER (base64-standard encoded) in the
/// JWT `x5c` header for chain validation by the verifier.
fn sign_issuer_jwt(
    issuer_key: &PKey<Private>,
    issuer_cert_der: &[u8],
    payload: Json,
) -> Result<String> {
    let issuer_cert_b64 = base64::engine::general_purpose::STANDARD.encode(issuer_cert_der);
    let mut header = Header::new(Algorithm::ES256);
    header.x5c = Some(vec![issuer_cert_b64]);

    let key_pem = issuer_key.private_key_to_pem_pkcs8()?;
    let encoding_key = EncodingKey::from_ec_pem(&key_pem)?;

    Ok(jsonwebtoken::encode(&header, &payload, &encoding_key)?)
}

/// Sign an SD-JWT Key Binding JWT with the device private key.
///
/// The `nonce` claim binds the KB-JWT to the server's transaction (replay
/// prevention); `aud` identifies the relying party (client_id).
fn sign_kb_jwt(device_key: &PKey<Private>, nonce: &str, aud: &str) -> Result<String> {
    let kb_payload = json!({
        "nonce": nonce,
        "aud":   aud,
        "iat":   now_unix(),
    });
    let header = Header::new(Algorithm::ES256);
    let key_pem = device_key.private_key_to_pem_pkcs8()?;
    let encoding_key = EncodingKey::from_ec_pem(&key_pem)?;
    Ok(jsonwebtoken::encode(&header, &kb_payload, &encoding_key)?)
}
