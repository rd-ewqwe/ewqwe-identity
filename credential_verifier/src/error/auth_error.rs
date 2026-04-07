use thiserror::Error;

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

    #[cfg(test)]
    #[error("test error: {0}")]
    Test(String),
}
