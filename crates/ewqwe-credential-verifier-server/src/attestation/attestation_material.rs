//! Pre-loaded attestation issuer signing material.
//!
//! The attestation issuer certificate and private key (configured through
//! [`crate::ServerParams`], falling back to the TLS certificate/key) are read
//! from disk **once during server startup** and kept in memory for the lifetime
//! of the process.
//!
//! Request handlers therefore never touch the file system for attestation
//! signing data — they only consume this in-memory snapshot.  Restart the
//! server to pick up certificate or key rotations.

use base64::Engine as _;
use openssl::{bn::BigNumContext, nid::Nid, x509::X509};

use crate::{
    AttError, AttResult, ServerParams,
    attestation::{JwtSigner, SigningAlgorithm},
};

/// Attestation issuer signing material, loaded once at startup.
///
/// See [`AttestationMaterial::load`] for the configuration semantics.
pub struct AttestationMaterial {
    /// Subject CN of the issuer certificate — used as the `iss` claim.
    issuer: String,
    /// ES256 JWT signer with the certificate fingerprint embedded as `kid`.
    signer: JwtSigner,
    /// Public verification JWK (EC P-256) served at the JWKS endpoint.
    ///
    /// `None` when the issuer certificate is not an EC P-256 key — the JWKS
    /// simply omits the attestation key in that case (matching previous
    /// per-request behaviour).
    jwk: Option<serde_json::Value>,
}

impl AttestationMaterial {
    /// Load and parse the attestation issuer certificate and signing key.
    ///
    /// Returns `Ok(None)` when no issuer certificate is configured at all
    /// (e.g. an HTTP-mode bootstrap server before certificates are provisioned);
    /// the `/verify` endpoints then fail with a configuration error, exactly as
    /// they did when the per-request file reads could not resolve a certificate.
    ///
    /// Returns `Err` when a certificate *is* configured but cannot be read or
    /// parsed — the server fails fast at startup instead of producing failing
    /// attestations per request.
    pub fn load(server_params: &ServerParams) -> AttResult<Option<Self>> {
        let cert_path = match server_params.attestation_issuer_certificate_path() {
            Ok(path) => path,
            Err(_) => return Ok(None),
        };

        let key_path = server_params.attestation_issuer_key_path().map_err(|e| {
            AttError::Config(format!(
                "Attestation issuer certificate '{cert_path}' is configured but no matching \
                 signing key is available: {e}"
            ))
        })?;

        let cert_pem = std::fs::read(cert_path).map_err(|e| {
            AttError::Config(format!(
                "Failed to read attestation issuer certificate '{cert_path}': {e}"
            ))
        })?;
        let cert = X509::from_pem(&cert_pem).map_err(|e| {
            AttError::Config(format!(
                "Failed to parse attestation issuer certificate '{cert_path}': {e}"
            ))
        })?;

        let issuer = cert
            .subject_name()
            .entries_by_nid(Nid::COMMONNAME)
            .next()
            .and_then(|e| e.data().to_string().ok())
            .map(|cn| cn.to_string())
            .ok_or_else(|| {
                AttError::Config(format!(
                    "No CN found in attestation issuer certificate subject: {cert_path}"
                ))
            })?;

        let cert_der = cert.to_der().map_err(|e| {
            AttError::Config(format!(
                "Failed to DER-encode attestation issuer certificate '{cert_path}': {e}"
            ))
        })?;
        // SHA-256 fingerprint of the DER cert → stable, unique kid.
        let fingerprint = openssl::sha::sha256(&cert_der);
        let kid = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(fingerprint);

        // Non-EC certificates cannot be published in the EC JWKS — non-fatal.
        let jwk = build_ec_jwk(&cert, &cert_der, &kid);

        let key_pem = std::fs::read(key_path).map_err(|e| {
            AttError::Config(format!(
                "Failed to read attestation issuer key '{key_path}': {e}"
            ))
        })?;
        let signer = JwtSigner::from_pem(SigningAlgorithm::ES256, &key_pem).map_err(|e| {
            AttError::Generic(format!("Failed to create attestation issuer signer: {e}"))
        })?;
        let signer = signer.with_key_id(&kid);

        tracing::info!(
            issuer = %issuer,
            jwk_published = jwk.is_some(),
            "Loaded attestation issuer signing material at startup"
        );

        Ok(Some(Self {
            issuer,
            signer,
            jwk,
        }))
    }

    /// The issuer CN used as the `iss` claim of signed attestations.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The signer used to sign attestation JWTs (with `kid` embedded).
    #[must_use]
    pub fn signer(&self) -> &JwtSigner {
        &self.signer
    }

    /// The public verification JWK to publish on the JWKS endpoint.
    #[must_use]
    pub fn jwk(&self) -> Option<&serde_json::Value> {
        self.jwk.as_ref()
    }
}

/// Build the EC P-256 public JWK for the issuer certificate.
///
/// Returns `None` (with a warning) when the certificate does not carry an
/// EC P-256 public key or the coordinates cannot be extracted — the JWKS then
/// simply omits the attestation key.
fn build_ec_jwk(cert: &X509, cert_der: &[u8], kid: &str) -> Option<serde_json::Value> {
    let pub_key = cert
        .public_key()
        .map_err(|e| tracing::warn!(%e, "Failed to extract attestation public key"))
        .ok()?;
    let ec_key = pub_key
        .ec_key()
        .map_err(|e| tracing::warn!(%e, "Attestation certificate public key is not EC"))
        .ok()?;

    let group = ec_key.group();
    let point = ec_key.public_key();
    let mut bn_ctx = BigNumContext::new()
        .map_err(|e| tracing::warn!(%e, "BigNumContext creation failed"))
        .ok()?;
    let mut x = openssl::bn::BigNum::new().ok()?;
    let mut y = openssl::bn::BigNum::new().ok()?;
    point
        .affine_coordinates_gfp(group, &mut x, &mut y, &mut bn_ctx)
        .map_err(|e| tracing::warn!(%e, "Failed to extract EC coordinates"))
        .ok()?;

    let x_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(x.to_vec());
    let y_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(y.to_vec());

    // x5c: standard base64 (not URL-safe) of the raw DER certificate (RFC 7517 §4.7).
    let x5c = base64::engine::general_purpose::STANDARD.encode(cert_der);

    Some(serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "use": "sig",
        "alg": "ES256",
        "kid": kid,
        "x": x_b64,
        "y": y_b64,
        "x5c": [x5c]
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::make_test_server_params;

    #[test]
    fn loads_material_from_tls_certificate_fallback() {
        let params = make_test_server_params(true, "test_user");
        let material = AttestationMaterial::load(&params)
            .expect("load should succeed")
            .expect("TLS certificates are configured, so material must be available");

        assert!(!material.issuer().is_empty());
        // The test server certificate is an EC P-256 key, so a JWK is published.
        let jwk = material.jwk().expect("test certificate is EC P-256");
        assert_eq!(jwk["kty"], "EC");
        assert_eq!(jwk["alg"], "ES256");
        assert!(jwk["kid"].as_str().is_some());

        // The signer must produce a well-formed JWT with the expected kid header.
        let claims =
            crate::attestation::Attestation::new(material.issuer(), "rp.example.com", "txn-1");
        let token = material
            .signer()
            .sign_to_string(&claims)
            .expect("signing should succeed");
        assert_eq!(token.split('.').count(), 3);
        let header = jsonwebtoken::decode_header(&token).expect("valid JWT header");
        assert_eq!(header.kid, Some(jwk["kid"].as_str().unwrap().to_string()));
    }

    #[test]
    fn returns_none_when_no_issuer_certificate_configured() {
        let mut params = make_test_server_params(true, "test_user");
        params.tls_params = None;
        params.attestation_issuer_certificate = None;
        params.attestation_issuer_key = None;

        let material = AttestationMaterial::load(&params).expect("load should succeed");
        assert!(material.is_none());
    }

    #[test]
    fn fails_fast_when_configured_certificate_is_missing() {
        let mut params = make_test_server_params(true, "test_user");
        // Point at a certificate that does not exist on disk.
        params.attestation_issuer_certificate = Some("/nonexistent/issuer.cert.pem".to_string());
        params.attestation_issuer_key = Some("/nonexistent/issuer.key.pem".to_string());

        let result = AttestationMaterial::load(&params);
        assert!(result.is_err());
    }
}
