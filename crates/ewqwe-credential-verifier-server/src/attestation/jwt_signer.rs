//! JWT signing for age verification attestations.
//!
//! Supports RS256 (RSA) and ES256 (ECDSA P-256) algorithms.

use crate::{AttResult, AttResultHelper, attestation::Attestation};
use jsonwebtoken::{Algorithm, EncodingKey, Header};

/// Supported signing algorithms for JWT attestations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningAlgorithm {
    /// RSA PKCS#1 with SHA-256 (RS256)
    RS256,
    /// ECDSA with P-256 curve and SHA-256 (ES256)
    ES256,
}

impl SigningAlgorithm {
    /// Returns the JWT algorithm identifier.
    #[must_use]
    pub const fn as_jwt_algorithm(&self) -> Algorithm {
        match self {
            Self::RS256 => Algorithm::RS256,
            Self::ES256 => Algorithm::ES256,
        }
    }

    /// Returns the algorithm name as a string.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::RS256 => "RS256",
            Self::ES256 => "ES256",
        }
    }
}

/// JWT-based attestation signer.
///
/// Signs attestation claims using RS256 or ES256 algorithms.
///
/// # Example
///
/// ```rust,ignore
/// let signer = JwtSigner::from_pem(SigningAlgorithm::ES256, &private_key_pem)?;
/// let token = signer.sign(&claims)?;
/// println!("JWT: {}", String::from_utf8_lossy(&token));
/// ```
pub struct JwtSigner {
    algorithm: SigningAlgorithm,
    encoding_key: EncodingKey,
    /// Optional key ID to include in the JWT header
    key_id: Option<String>,
}

impl JwtSigner {
    /// Creates a new JWT signer from a PEM-encoded private key.
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The signing algorithm to use
    /// * `pem_key` - PEM-encoded private key (PKCS#8 or PKCS#1 for RSA, SEC1 or PKCS#8 for EC)
    ///
    /// # Errors
    ///
    /// Returns an error if the key cannot be parsed.
    pub fn from_pem(algorithm: SigningAlgorithm, pem_key: &[u8]) -> AttResult<Self> {
        let encoding_key = match algorithm {
            SigningAlgorithm::RS256 => {
                EncodingKey::from_rsa_pem(pem_key).context("failed to parse RSA private key")?
            }
            SigningAlgorithm::ES256 => {
                EncodingKey::from_ec_pem(pem_key).context("failed to parse EC private key")?
            }
        };

        Ok(Self {
            algorithm,
            encoding_key,
            key_id: None,
        })
    }

    /// Creates a new JWT signer from DER-encoded private key bytes.
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The signing algorithm to use
    /// * `der_key` - DER-encoded private key
    ///
    /// # Errors
    ///
    /// Returns an error if the key cannot be parsed.
    pub fn from_der(algorithm: SigningAlgorithm, der_key: &[u8]) -> AttResult<Self> {
        let encoding_key = match algorithm {
            SigningAlgorithm::RS256 => EncodingKey::from_rsa_der(der_key),
            SigningAlgorithm::ES256 => EncodingKey::from_ec_der(der_key),
        };

        Ok(Self {
            algorithm,
            encoding_key,
            key_id: None,
        })
    }

    /// Sets the key ID to include in the JWT header.
    #[must_use]
    pub fn with_key_id(mut self, kid: &str) -> Self {
        self.key_id = Some(kid.to_owned());
        self
    }

    /// Signs the attestation claims and returns the JWT as a string.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    pub fn sign_to_string(&self, attestation: &Attestation) -> AttResult<String> {
        let mut header = Header::new(self.algorithm.as_jwt_algorithm());
        header.kid = self.key_id.clone();

        jsonwebtoken::encode(&header, attestation, &self.encoding_key)
            .context("failed to sign JWT attestation")
    }
}

impl super::AttestationSigner for JwtSigner {
    fn sign(&self, attestation: &Attestation) -> AttResult<Vec<u8>> {
        let jwt = self.sign_to_string(attestation)?;
        Ok(jwt.into_bytes())
    }

    fn algorithm(&self) -> &str {
        self.algorithm.as_str()
    }
}

#[cfg(test)]
mod jwt_tests {
    use super::*;
    use jsonwebtoken::{DecodingKey, Validation};

    const TEST_EC_PRIVATE_KEY: &[u8] =
        include_bytes!("../../../../../certificates/signer/ewqwe.signer.leaf.key.pem");
    const TEST_EC_PUBLIC_CERT: &[u8] =
        include_bytes!("../../../../../certificates/signer/ewqwe.signer.leaf.cert.pem");

    #[test]
    fn test_sign_with_es256() {
        let signer = JwtSigner::from_pem(SigningAlgorithm::ES256, TEST_EC_PRIVATE_KEY)
            .expect("failed to create ES256 signer");

        let mut cred_claims = serde_json::Map::new();
        cred_claims.insert("age_over_18".to_owned(), serde_json::Value::Bool(true));
        let claims = Attestation::new("verifier.example.com", "rp.example.com", "session-123")
            .with_doc_type("org.iso.18013.5.1.mDL")
            .with_credential_claims(cred_claims);

        let token = signer.sign_to_string(&claims).expect("failed to sign");

        // Verify the token structure (3 parts separated by dots)
        assert_eq!(token.split('.').count(), 3);

        // Verify we can decode and validate the token
        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_audience(&["rp.example.com"]);
        validation.set_issuer(&["verifier.example.com"]);

        // Extract public key from certificate
        let public_key = extract_public_key_from_cert(TEST_EC_PUBLIC_CERT);
        let decoding_key =
            DecodingKey::from_ec_pem(&public_key).expect("failed to create decoding key");

        let decoded = jsonwebtoken::decode::<Attestation>(&token, &decoding_key, &validation)
            .expect("failed to decode token");

        assert_eq!(
            decoded.claims.credential_claims.get("age_over_18"),
            Some(&serde_json::Value::Bool(true))
        );
        assert_eq!(
            decoded.claims.doc_type,
            Some("org.iso.18013.5.1.mDL".to_owned())
        );
    }

    #[test]
    fn test_signer_with_key_id() {
        let signer = JwtSigner::from_pem(SigningAlgorithm::ES256, TEST_EC_PRIVATE_KEY)
            .expect("failed to create signer")
            .with_key_id("key-2024-01");

        let claims = Attestation::new("issuer", "audience", "sub");
        let token = signer.sign_to_string(&claims).expect("failed to sign");

        // Decode header to verify key ID
        let header = jsonwebtoken::decode_header(&token).expect("failed to decode header");
        assert_eq!(header.kid, Some("key-2024-01".to_owned()));
    }

    /// Helper to extract public key PEM from X.509 certificate PEM
    fn extract_public_key_from_cert(cert_pem: &[u8]) -> Vec<u8> {
        use openssl::x509::X509;

        let cert = X509::from_pem(cert_pem).expect("failed to parse certificate");
        let public_key = cert.public_key().expect("failed to get public key");

        public_key
            .public_key_to_pem()
            .expect("failed to export EC public key")
    }
}
