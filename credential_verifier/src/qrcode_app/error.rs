//! Error types for the QR Code APP.

use thiserror::Error;

/// Errors returned by QR Code APP operations.
#[derive(Debug, Error)]
pub enum QrcodeAppError {
    #[error("storage error: {0}")]
    Storage(String),

    #[error("not found")]
    NotFound,

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("configuration error: {0}")]
    Config(String),
}

/// Convenience `Result` alias for QR Code APP operations.
pub type QrcodeAppResult<T> = Result<T, QrcodeAppError>;

impl From<QrcodeAppError> for crate::AttError {
    fn from(e: QrcodeAppError) -> Self {
        match &e {
            QrcodeAppError::NotFound => crate::AttError::BadRequest("not found".to_string()),
            QrcodeAppError::Conflict(msg) => crate::AttError::BadRequest(msg.clone()),
            _ => crate::AttError::Generic(e.to_string()),
        }
    }
}
