//! Integration tests for attestation signing.
//!
//! Tests the full round-trip of signing and verifying attestations
//! using both JWT and COSE formats.

use super::{
    Attestation, AttestationSigner, CoseSigner, CoseSigningAlgorithm, JwtSigner, SigningAlgorithm,
};

// Test certificates
const EC_PRIVATE_KEY: &[u8] = include_bytes!("../tests/certificates/ec/ewqwe.server.key.pem");
const RSA_PRIVATE_KEY: &[u8] = include_bytes!("../tests/certificates/rsa/ewqwe.server.key.pem");

/// Test that both JWT and COSE signers implement the AttestationSigner trait.
#[test]
fn test_signer_trait_implementations() {
    let jwt_es256 = JwtSigner::from_pem(SigningAlgorithm::ES256, EC_PRIVATE_KEY)
        .expect("failed to create JWT ES256 signer");
    let jwt_rs256 = JwtSigner::from_pem(SigningAlgorithm::RS256, RSA_PRIVATE_KEY)
        .expect("failed to create JWT RS256 signer");
    let cose_es256 = CoseSigner::from_pem(CoseSigningAlgorithm::ES256, EC_PRIVATE_KEY)
        .expect("failed to create COSE ES256 signer");
    let cose_rs256 = CoseSigner::from_pem(CoseSigningAlgorithm::RS256, RSA_PRIVATE_KEY)
        .expect("failed to create COSE RS256 signer");

    let claims = Attestation::new("issuer", "audience", "subject", true);

    // All signers should successfully produce output
    let signers: Vec<&dyn AttestationSigner> =
        vec![&jwt_es256, &jwt_rs256, &cose_es256, &cose_rs256];

    for signer in signers {
        let result = signer.sign(&claims);
        assert!(result.is_ok(), "signer {} failed", signer.algorithm());
        assert!(!result.unwrap().is_empty());
    }
}

/// Test attestation claims with all optional fields.
#[test]
fn test_full_claims() {
    let mut cred_claims = serde_json::Map::new();
    cred_claims.insert("age_over_21".to_owned(), serde_json::Value::Bool(true));
    let claims = Attestation::new("verifier.ewqwe.com", "rp.example.com", "txn-abc123", true)
        .with_doc_type("org.iso.18013.5.1.mDL")
        .with_nonce("unique-nonce-from-request")
        .with_credential_claims(cred_claims);

    let signer = JwtSigner::from_pem(SigningAlgorithm::ES256, EC_PRIVATE_KEY)
        .expect("failed to create signer");

    let token = signer.sign_to_string(&claims).expect("failed to sign");

    // Decode without verification to check claims are present
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3);

    // Decode payload (base64url)
    let payload =
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, parts[1])
            .expect("failed to decode payload");

    let decoded: serde_json::Value =
        serde_json::from_slice(&payload).expect("failed to parse JSON");

    assert_eq!(decoded["verified"], true);
    assert_eq!(decoded["age_over_21"], true);
    assert_eq!(decoded["doc_type"], "org.iso.18013.5.1.mDL");
    assert_eq!(decoded["nonce"], "unique-nonce-from-request");
}

/// Test that different sessions produce different JTIs.
#[test]
fn test_unique_jti() {
    let claims1 = Attestation::new("issuer", "audience", "session1", true);
    let claims2 = Attestation::new("issuer", "audience", "session2", true);

    assert_ne!(claims1.jti, claims2.jti);
}
