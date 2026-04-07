//! Attestation signing module for EU Age Verification.
//!
//! This module provides functionality to sign age verification attestations
//! in both JWT and CBOR formats, supporting RS256 (RSA) and ES256 (ECDSA P-256) algorithms.
//!
//! # Attestation Format
//!
//! The attestation confirms that the credential verifier has successfully verified
//! a Proof of Age from a wallet, and the subject meets the age requirement.
//!
//! # Supported Algorithms
//!
//! - **RS256**: RSA PKCS#1 signatures with SHA-256
//! - **ES256**: ECDSA signatures with P-256 curve and SHA-256
//!
//! # Example
//!
//! ```rust,ignore
//! use credential_verifier::attestation::{
//!     AttestationClaims, JwtSigner, SigningAlgorithm, AttestationSigner
//! };
//!
//! let claims = AttestationClaims::new(
//!     "verifier.example.com",
//!     "rp.example.com",
//!     "session-123",
//!     true, // age requirement met
//! );
//!
//! let signer = JwtSigner::from_pem(SigningAlgorithm::ES256, &private_key_pem)?;
//! let token = signer.sign(&claims)?;
//! ```

mod claims;
mod cose_signer;
mod jwt_signer;
#[cfg(test)]
mod tests;

pub use claims::AttestationClaims;
pub use cose_signer::{CoseSigner, CoseSigningAlgorithm, verify_cose_attestation};
pub use jwt_signer::{JwtSigner, SigningAlgorithm};

/// Common trait for attestation signers (JWT, CBOR, etc.)
pub trait AttestationSigner {
    /// Signs the attestation claims and returns the encoded attestation.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    fn sign(&self, claims: &AttestationClaims) -> crate::AttResult<Vec<u8>>;

    /// Returns the algorithm identifier used by this signer.
    fn algorithm(&self) -> &str;
}
