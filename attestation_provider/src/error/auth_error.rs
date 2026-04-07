use thiserror::Error;

// Each error type must have a corresponding HTTP status code (see `kmip_endpoint.rs`)
#[derive(Error, Debug)]
pub enum AuthError {
    // A generic authentication error
    #[error("authentication error: {0}")]
    Generic(String),

    // Error related to unexpected authentication errors
    #[error("unexpected authentication error: {0}")]
    Unexpected(String),

    // Error related to an invalid JsON Web Token (JWT)
    #[error("JWT error: {0}")]
    JWT(String),

    // Error related to JSON Web Key Sets (JWKS)
    #[error("JWKS error: {0}")]
    JWKS(String),

    // Error related to JWT configuration issues
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Authentication server error: {0}")]
    AuthServer(String),
}
