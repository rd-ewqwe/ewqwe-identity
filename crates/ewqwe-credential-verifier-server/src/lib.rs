mod authenticated_user;
pub use authenticated_user::AuthenticatedUser;

pub mod attestation;

pub mod journal;

pub use ewqwe_credential_verifier_ui;

mod server;
pub use server::services::{ServerComponents, configure_services};
pub use server::start_server;

mod error;
pub use error::{AttError, AttResult, AttResultHelper};

mod parameters;
pub use parameters::{IdpParams, JwtParams, ProxyParams, ServerParams, TlsParams};

pub mod tls;

#[cfg(test)]
#[allow(dead_code)]
#[allow(clippy::expect_used)]
mod tests;
