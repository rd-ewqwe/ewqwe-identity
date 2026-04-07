mod authenticated_user;
pub use authenticated_user::AuthenticatedUser;

pub mod attestation;

pub mod journal;

pub use ewqwe_verifier_app as verifier_app;

mod server;
pub use server::{ServerParams, start_server};

mod error;
pub use error::{AttError, AttResult, AttResultHelper};

mod parameters;
pub use parameters::{IdpParams, JwtParams, ProxyParams, TlsParams};

pub mod tls;

#[cfg(test)]
#[allow(dead_code)]
#[allow(clippy::expect_used)]
mod tests;
