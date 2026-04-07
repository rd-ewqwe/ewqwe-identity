mod authenticated_user;
pub use authenticated_user::AuthenticatedUser;

mod server;
pub use server::{AuthServerParams, start_auth_server};

mod error;
pub use error::{AuthError, AuthResult, AuthResultHelper};

mod parameters;
pub use parameters::{IdpParams, JwtParams, ProxyParams, TlsParams};

pub mod tls;

#[cfg(test)]
#[allow(dead_code)]
#[allow(clippy::expect_used)]
mod tests;
