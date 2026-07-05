//! OpenID4VP error types for the Relying Party backend.
//!
//! These errors cover the OpenID4VP transaction lifecycle:
//! initialization, authorization request serving, wallet response handling,
//! and credential verification.

use thiserror::Error;

/// Errors that can occur during OpenID4VP operations.
#[derive(Error, Debug)]
pub enum OpenID4VPError {
    /// Transaction not found by ID or state.
    #[error("not found: {0}")]
    NotFound(String),

    /// Transaction has expired past its TTL.
    #[error("expired: {0}")]
    Expired(String),

    /// Invalid or malformed request from the client.
    #[error("bad request: {0}")]
    BadRequest(String),

    /// Cryptographic operation failed (JAR signing, JWE decryption, key loading).
    #[error("crypto error: {0}")]
    Crypto(String),

    /// Configuration error (missing certs, invalid paths, etc.).
    #[error("configuration error: {0}")]
    Config(String),

    /// Internal/unexpected error.
    #[error("internal error: {0}")]
    Internal(String),

    /// Error occurred while decoding a VP token.
    #[error("decoding error: {0}")]
    DecodingError(String),
}

impl From<openssl::error::ErrorStack> for OpenID4VPError {
    fn from(e: openssl::error::ErrorStack) -> Self {
        OpenID4VPError::Crypto(e.to_string())
    }
}

/// Convenience type alias for OpenID4VP results.
pub type OpenID4VPResult<T> = Result<T, OpenID4VPError>;
