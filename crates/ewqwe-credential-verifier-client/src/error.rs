use thiserror::Error;

/// All errors produced by the ewqwe-digital-identity crate.
#[derive(Debug, Error)]
pub enum ApiError {
    /// Client configuration error (bad URL, missing certificate, etc.).
    #[error("configuration error: {0}")]
    Config(String),

    /// HTTP transport error (connection refused, timeout, TLS handshake, etc.).
    #[error("HTTP transport error: {0}")]
    Transport(#[from] reqwest::Error),

    /// The server returned a non-2xx status code.
    ///
    /// Contains the HTTP status code and the body text for diagnostics.
    #[error("server error {status}: {body}")]
    Server { status: u16, body: String },

    /// The server returned a response body that could not be parsed as the
    /// expected JSON type.
    #[error("JSON decode error: {0}")]
    Decode(#[from] serde_json::Error),

    /// A URL construction error — typically a programming error in the caller.
    #[error("URL error: {0}")]
    Url(#[from] url::ParseError),
}

/// Convenience type alias for `Result<T, ApiError>`.
pub type Result<T> = std::result::Result<T, ApiError>;
