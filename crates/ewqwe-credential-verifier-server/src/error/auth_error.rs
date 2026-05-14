use thiserror::Error;

impl From<ewqwe_credential_verifier_ui::error::VerifierAppError> for AttError {
    fn from(e: ewqwe_credential_verifier_ui::error::VerifierAppError) -> Self {
        use ewqwe_credential_verifier_ui::error::VerifierAppError;
        match e {
            VerifierAppError::NotFound => AttError::BadRequest("not found".to_string()),
            VerifierAppError::Conflict(msg) => AttError::BadRequest(msg),
            VerifierAppError::Storage(msg) | VerifierAppError::Config(msg) => {
                AttError::Generic(msg)
            }
        }
    }
}

// Each error type must have a corresponding HTTP status code (see `kmip_endpoint.rs`)
#[derive(Error, Debug)]
pub enum AttError {
    // Generic error with a message
    #[error("error: {0}")]
    Generic(String),

    // Error related to unexpected error
    #[error("unexpected error: {0}")]
    Unexpected(String),

    // Error related to server configuration issues
    #[error("configuration error: {0}")]
    Config(String),

    // Error related to invalid user request
    #[error("bad request: {0}")]
    BadRequest(String),

    // Error related to authentication failure
    #[error("authentication error: {0}")]
    Authentication(String),

    #[cfg(test)]
    #[error("test error: {0}")]
    Test(String),
}
