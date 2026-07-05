//! Error types for `ewqwe_digital_credential`.

use serde::Serialize;
use thiserror::Error;

/// All errors produced by this crate.
#[derive(Debug, Error, Serialize)]
pub enum CredentialError {
    /// An OpenSSL operation failed (key generation, signing, X.509 building).
    #[error("OpenSSL error: {0}")]
    OpenSsl(String),

    /// A JWT encoding / decoding operation failed.
    #[error("JWT error: {0}")]
    Jwt(String),

    /// CBOE sérialisation or deserialization failed.
    #[error("CBOR error: {0}")]
    Cbor(String),

    /// A required field was missing or had an unexpected value during credential building.
    #[error("Credential building error: {0}")]
    Build(String),

    /// An incoming credential presentation was malformed, its signature was invalid,
    /// or a required field was missing during verification.
    #[error("Invalid presentation: {0}")]
    InvalidPresentation(String),

    /// An error linked to time operations (e.g., expiration checks).
    #[error("Time error: {0}")]
    Time(String),

    /// An error linked to serialization operations (e.g., JSON encoding/decoding).
    #[error("Serde error: {0}")]
    Serde(String),
}

/// Convenience alias.
pub type CredentialResult<T> = std::result::Result<T, CredentialError>;

impl From<openssl::error::ErrorStack> for CredentialError {
    fn from(e: openssl::error::ErrorStack) -> Self {
        Self::OpenSsl(e.to_string())
    }
}

impl From<jsonwebtoken::errors::Error> for CredentialError {
    fn from(e: jsonwebtoken::errors::Error) -> Self {
        Self::Jwt(e.to_string())
    }
}
