//! # `ewqwe_digital_credential`
//!
//! Building and signing **EU Age Verification** and **EUDI** credentials in all
//! standard formats:
//!
//! - **SD-JWT VC** — EU Age Verification Profile (`eu.europa.ec.av.1`) and
//!   EUDI Person Identification Data (`eu.europa.ec.eudi.pid.1`)
//! - **mDoc / DeviceResponse** — ISO/IEC 18013-5 with OpenID4VP `SessionTranscript`
//!
//! The crate also provides [`CredentialIssuer`], a two-level ephemeral PKI
//! (CA → issuer leaf + device holder key) used in test scenarios and wallet
//! demonstrations.
//!
//! ## Quick start — issue an EU Age SD-JWT
//!
//! ```rust,no_run
//! use ewqwe_digital_credential::CredentialIssuer;
//!
//! let issuer = CredentialIssuer::generate().expect("generate issuer keys");
//!
//! // Write the CA cert PEM to your server's trusted CA directory, then:
//! let sd_jwt = issuer.build_eu_age_sd_jwt("my-nonce", "my-client-id");
//! // sd_jwt is "<issuer-jwt>~<kb-jwt>" ready for OpenID4VP presentation
//! ```
//!
//! ## Quick start — issue a EUDI PID mDoc
//!
//! ```rust,no_run
//! use ewqwe_digital_credential::CredentialIssuer;
//!
//! let issuer = CredentialIssuer::generate().expect("generate issuer keys");
//! let mdoc_b64 = issuer.build_eudi_mdoc(
//!     "my-nonce",
//!     "redirect_uri:https://verifier.example/callback",
//!     "https://verifier.example/callback",
//! );
//! // mdoc_b64 is a base64url-encoded CBOR DeviceResponse
//! ```

pub mod error;
pub mod issuer;
pub mod mdoc;
pub mod pki;
pub mod sd_jwt;
pub(crate) mod util;

pub use error::{CredentialError, Result};
pub use issuer::CredentialIssuer;
