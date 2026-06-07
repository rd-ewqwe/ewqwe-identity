//! COSE (CBOR Object Signing and Encryption) signing for age verification attestations.
//!
//! Implements COSE_Sign1 structure as per RFC 8152, supporting ES256 and RS256 algorithms.
//! This is the CBOR-based counterpart to JWT attestations.

use crate::{AttResult, AttResultHelper, attestation::Attestation};
use coset::{
    CborSerializable, CoseSign1, CoseSign1Builder, HeaderBuilder, iana::Algorithm as CoseAlgorithm,
};
use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Private},
    sign::Signer as OpensslSigner,
};

/// Supported signing algorithms for COSE attestations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoseSigningAlgorithm {
    /// ECDSA with P-256 curve and SHA-256 (ES256)
    ES256,
    /// RSA PKCS#1 with SHA-256 (PS256 in COSE, but we use RS256 semantics)
    RS256,
}

impl CoseSigningAlgorithm {
    /// Returns the COSE algorithm identifier.
    #[must_use]
    pub const fn as_cose_algorithm(&self) -> CoseAlgorithm {
        match self {
            // ES256 = -7 in COSE
            Self::ES256 => CoseAlgorithm::ES256,
            // Note: For RSA, COSE prefers PS256 (-37), but RS256 (-257) is also used
            Self::RS256 => CoseAlgorithm::RS256,
        }
    }

    /// Returns the algorithm name as a string.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ES256 => "ES256",
            Self::RS256 => "RS256",
        }
    }
}

/// COSE-based attestation signer.
///
/// Signs attestation claims using COSE_Sign1 structure (RFC 8152).
///
/// # Example
///
/// ```rust,ignore
/// let signer = CoseSigner::from_pem(CoseSigningAlgorithm::ES256, &private_key_pem)?;
/// let cose_bytes = signer.sign(&claims)?;
/// ```
pub struct CoseSigner {
    algorithm: CoseSigningAlgorithm,
    private_key: PKey<Private>,
    /// Optional key ID to include in the COSE header
    key_id: Option<Vec<u8>>,
}

impl CoseSigner {
    /// Creates a new COSE signer from a PEM-encoded private key.
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The signing algorithm to use
    /// * `pem_key` - PEM-encoded private key
    ///
    /// # Errors
    ///
    /// Returns an error if the key cannot be parsed.
    pub fn from_pem(algorithm: CoseSigningAlgorithm, pem_key: &[u8]) -> AttResult<Self> {
        let private_key =
            PKey::private_key_from_pem(pem_key).context("failed to parse private key PEM")?;

        Ok(Self {
            algorithm,
            private_key,
            key_id: None,
        })
    }

    /// Creates a new COSE signer from DER-encoded private key bytes.
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The signing algorithm to use
    /// * `der_key` - DER-encoded private key (PKCS#8)
    ///
    /// # Errors
    ///
    /// Returns an error if the key cannot be parsed.
    pub fn from_der(algorithm: CoseSigningAlgorithm, der_key: &[u8]) -> AttResult<Self> {
        let private_key =
            PKey::private_key_from_der(der_key).context("failed to parse private key DER")?;

        Ok(Self {
            algorithm,
            private_key,
            key_id: None,
        })
    }

    /// Sets the key ID to include in the COSE protected header.
    #[must_use]
    pub fn with_key_id(mut self, kid: &[u8]) -> Self {
        self.key_id = Some(kid.to_vec());
        self
    }

    /// Signs the attestation claims and returns the COSE_Sign1 structure as CBOR bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    pub fn sign_to_bytes(&self, claims: &Attestation) -> AttResult<Vec<u8>> {
        // Serialize claims to CBOR
        let mut payload = Vec::new();
        ciborium::into_writer(claims, &mut payload)
            .context("failed to serialize claims to CBOR")?;

        // Build protected header
        let mut protected_builder =
            HeaderBuilder::new().algorithm(self.algorithm.as_cose_algorithm());
        if let Some(ref kid) = self.key_id {
            protected_builder = protected_builder.key_id(kid.clone());
        }
        let protected = protected_builder.build();

        // Build COSE_Sign1 structure (initially without signature)
        let cose_sign1_builder = CoseSign1Builder::new()
            .protected(protected.clone())
            .payload(payload.clone());

        // Create the Sig_structure for signing (as per RFC 8152 Section 4.4)
        let cose_sign1 = cose_sign1_builder.build();
        let sig_structure = cose_sign1.tbs_data(&[]);

        // Sign the Sig_structure
        let signature = self.create_signature(&sig_structure)?;

        // Build final COSE_Sign1 with signature
        let final_cose = CoseSign1Builder::new()
            .protected(protected)
            .payload(payload)
            .signature(signature)
            .build();

        // Serialize to CBOR
        let bytes = final_cose.to_vec().map_err(|e| {
            crate::AttError::Generic(format!("failed to serialize COSE_Sign1 to CBOR: {e:?}"))
        })?;

        Ok(bytes)
    }

    /// Creates the cryptographic signature over the given data.
    fn create_signature(&self, data: &[u8]) -> AttResult<Vec<u8>> {
        match self.algorithm {
            CoseSigningAlgorithm::ES256 => self.sign_ecdsa(data),
            CoseSigningAlgorithm::RS256 => self.sign_rsa(data),
        }
    }

    /// Signs data using ECDSA with P-256.
    fn sign_ecdsa(&self, data: &[u8]) -> AttResult<Vec<u8>> {
        let mut signer = OpensslSigner::new(MessageDigest::sha256(), &self.private_key)
            .context("failed to create ECDSA signer")?;

        signer.update(data).context("failed to update signer")?;

        let der_signature = signer
            .sign_to_vec()
            .context("failed to create ECDSA signature")?;

        // Convert DER signature to fixed-length format for COSE (r || s, each 32 bytes for P-256)
        Self::der_to_fixed_signature(&der_signature)
    }

    /// Signs data using RSA with PKCS#1 v1.5 and SHA-256.
    fn sign_rsa(&self, data: &[u8]) -> AttResult<Vec<u8>> {
        let mut signer = OpensslSigner::new(MessageDigest::sha256(), &self.private_key)
            .context("failed to create RSA signer")?;

        signer.update(data).context("failed to update signer")?;

        signer
            .sign_to_vec()
            .context("failed to create RSA signature")
    }

    /// Converts a DER-encoded ECDSA signature to fixed-length format (r || s).
    ///
    /// COSE requires signatures in fixed-length format, not DER.
    fn der_to_fixed_signature(der: &[u8]) -> AttResult<Vec<u8>> {
        use openssl::ecdsa::EcdsaSig;

        let sig = EcdsaSig::from_der(der).context("failed to parse DER signature")?;

        let r = sig
            .r()
            .to_vec_padded(32)
            .context("failed to pad r component")?;
        let s = sig
            .s()
            .to_vec_padded(32)
            .context("failed to pad s component")?;

        let mut fixed = Vec::with_capacity(64);
        fixed.extend_from_slice(&r);
        fixed.extend_from_slice(&s);

        Ok(fixed)
    }
}

impl super::AttestationSigner for CoseSigner {
    fn sign(&self, claims: &Attestation) -> AttResult<Vec<u8>> {
        self.sign_to_bytes(claims)
    }

    fn algorithm(&self) -> &str {
        self.algorithm.as_str()
    }
}

/// Verifies a COSE_Sign1 attestation.
///
/// # Arguments
///
/// * `cose_bytes` - The CBOR-encoded COSE_Sign1 structure
/// * `public_key_pem` - PEM-encoded public key or certificate
///
/// # Returns
///
/// The verified [`Attestation`] if verification succeeds.
///
/// # Errors
///
/// Returns an error if verification fails or the structure is invalid.
pub fn verify_cose_attestation(
    cose_bytes: &[u8],
    public_key_pem: &[u8],
    algorithm: CoseSigningAlgorithm,
) -> AttResult<Attestation> {
    // Parse COSE_Sign1
    let cose_sign1 = CoseSign1::from_slice(cose_bytes).map_err(|e| {
        crate::AttError::Generic(format!("failed to parse COSE_Sign1 structure: {e:?}"))
    })?;

    // Get the payload
    let payload = cose_sign1
        .payload
        .as_ref()
        .context("COSE_Sign1 missing payload")?;

    // Get signature
    let signature = &cose_sign1.signature;

    // Build Sig_structure for verification
    let sig_structure = cose_sign1.tbs_data(&[]);

    // Load public key
    let public_key =
        PKey::public_key_from_pem(public_key_pem).context("failed to parse public key PEM")?;

    // Verify signature
    let verified = match algorithm {
        CoseSigningAlgorithm::ES256 => verify_ecdsa(&sig_structure, signature, &public_key)?,
        CoseSigningAlgorithm::RS256 => verify_rsa(&sig_structure, signature, &public_key)?,
    };

    if !verified {
        crate::auth_bail!("COSE signature verification failed");
    }

    // Deserialize claims from payload
    let claims: Attestation = ciborium::from_reader(payload.as_slice())
        .context("failed to deserialize claims from CBOR")?;

    Ok(claims)
}

/// Verifies an ECDSA signature.
fn verify_ecdsa(
    data: &[u8],
    signature: &[u8],
    public_key: &PKey<openssl::pkey::Public>,
) -> AttResult<bool> {
    use openssl::ecdsa::EcdsaSig;

    // Convert fixed-length signature back to DER
    if signature.len() != 64 {
        crate::auth_bail!(
            "invalid ECDSA signature length: expected 64, got {}",
            signature.len()
        );
    }

    let r =
        openssl::bn::BigNum::from_slice(&signature[..32]).context("failed to parse r component")?;
    let s =
        openssl::bn::BigNum::from_slice(&signature[32..]).context("failed to parse s component")?;

    let ecdsa_sig =
        EcdsaSig::from_private_components(r, s).context("failed to create ECDSA signature")?;

    let der_sig = ecdsa_sig
        .to_der()
        .context("failed to convert signature to DER")?;

    let mut verifier = openssl::sign::Verifier::new(MessageDigest::sha256(), public_key)
        .context("failed to create verifier")?;

    verifier.update(data).context("failed to update verifier")?;

    verifier
        .verify(&der_sig)
        .context("ECDSA verification failed")
}

/// Verifies an RSA signature.
fn verify_rsa(
    data: &[u8],
    signature: &[u8],
    public_key: &PKey<openssl::pkey::Public>,
) -> AttResult<bool> {
    let mut verifier = openssl::sign::Verifier::new(MessageDigest::sha256(), public_key)
        .context("failed to create RSA verifier")?;

    verifier.update(data).context("failed to update verifier")?;

    verifier
        .verify(signature)
        .context("RSA verification failed")
}

#[cfg(test)]
mod cose_tests {
    use super::*;

    // Test EC P-256 private key (for testing only!)
    const TEST_EC_PRIVATE_KEY: &[u8] =
        include_bytes!("../../../../../certificates/signer/ewqwe.signer.leaf.key.pem");
    const TEST_EC_PUBLIC_CERT: &[u8] =
        include_bytes!("../../../../../certificates/signer/ewqwe.signer.leaf.cert.pem");

    #[test]
    fn test_sign_and_verify_es256() {
        let signer = CoseSigner::from_pem(CoseSigningAlgorithm::ES256, TEST_EC_PRIVATE_KEY)
            .expect("failed to create ES256 signer");

        let mut cred_claims = serde_json::Map::new();
        cred_claims.insert("age_over_18".to_owned(), serde_json::Value::Bool(true));
        let claims = Attestation::new("verifier.example.com", "rp.example.com", "session-123")
            .with_doc_type("org.iso.18013.5.1.mDL")
            .with_credential_claims(cred_claims);

        let cose_bytes = signer.sign_to_bytes(&claims).expect("failed to sign");

        // Verify the COSE structure starts with the CBOR tag for COSE_Sign1 (18)
        // or the array marker
        assert!(!cose_bytes.is_empty());

        // Extract public key and verify
        let public_key_pem = extract_public_key_from_cert(TEST_EC_PUBLIC_CERT);
        let verified_claims =
            verify_cose_attestation(&cose_bytes, &public_key_pem, CoseSigningAlgorithm::ES256)
                .expect("failed to verify");

        assert_eq!(
            verified_claims.credential_claims.get("age_over_18"),
            Some(&serde_json::Value::Bool(true))
        );
        assert_eq!(
            verified_claims.doc_type,
            Some("org.iso.18013.5.1.mDL".to_owned())
        );
    }

    #[test]
    fn test_signer_with_key_id() {
        let signer = CoseSigner::from_pem(CoseSigningAlgorithm::ES256, TEST_EC_PRIVATE_KEY)
            .expect("failed to create signer")
            .with_key_id(b"key-2024-01");

        let claims = Attestation::new("issuer", "audience", "sub");
        let cose_bytes = signer.sign_to_bytes(&claims).expect("failed to sign");

        // Parse and check the key ID is in the protected header
        let cose_sign1 = CoseSign1::from_slice(&cose_bytes).expect("failed to parse COSE_Sign1");

        let protected = cose_sign1.protected.header;
        assert_eq!(protected.key_id, b"key-2024-01".to_vec());
    }

    /// Helper to extract public key PEM from X.509 certificate PEM
    fn extract_public_key_from_cert(cert_pem: &[u8]) -> Vec<u8> {
        use openssl::x509::X509;

        let cert = X509::from_pem(cert_pem).expect("failed to parse certificate");
        let public_key = cert.public_key().expect("failed to get public key");
        public_key
            .public_key_to_pem()
            .expect("failed to export public key")
    }
}
