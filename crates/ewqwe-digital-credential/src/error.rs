//! Error types for `ewqwe_digital_credential`.

use thiserror::Error;

/// All errors produced by this crate.
#[derive(Debug, Error)]
pub enum CredentialError {
    /// An OpenSSL operation failed (key generation, signing, X.509 building).
    #[error("OpenSSL error: {0}")]
    OpenSsl(#[from] openssl::error::ErrorStack),

    /// A JWT encoding / decoding operation failed.
    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    /// CBOR serialisation or deserialisation failed.
    #[error("CBOR error: {0}")]
    Cbor(String),

    /// A required field was missing or had an unexpected value.
    #[error("Credential building error: {0}")]
    Build(String),
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, CredentialError>;
