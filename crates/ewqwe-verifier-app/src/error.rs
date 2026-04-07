//! Error types for the Verifier App.

use thiserror::Error;

/// Errors returned by Verifier App operations.
#[derive(Debug, Error)]
pub enum VerifierAppError {
    #[error("storage error: {0}")]
    Storage(String),

    #[error("not found")]
    NotFound,

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("configuration error: {0}")]
    Config(String),
}

/// Convenience `Result` alias for Verifier App operations.
pub type VerifierAppResult<T> = Result<T, VerifierAppError>;
