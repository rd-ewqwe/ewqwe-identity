//! `ewqwe_openid4vp` — OpenID4VP Relying Party backend library.
//!
//! Implements the server-side OpenID4VP protocol for the EU Age Verification system:
//! - **Transaction lifecycle** management (init → wallet response → verification)
//! - **DCQL query building** per OpenID4VP 1.0 §6
//! - **Protocol profiles**: HAIP (EUDI Wallet) and Annex A (Age Verification Apps)
//! - **Credential type configs**: mDL (ISO 18013-5), PID, Proof of Age
//! - **Transaction store**: In-memory with TTL-based cleanup
//!
//! - **Crypto operations**: JAR signing (RFC 9101), JWE decryption (ECDH-ES + A256GCM),
//!   PEM/X.509 handling, JWKS building
//!
//! Future modules (not yet implemented):
//! - `service`: `OpenID4VPService` orchestrating the full transaction lifecycle
//!
//! # Architecture
//!
//! This crate is used by the `credential_verifier` server to implement
//! OpenID4VP endpoints. The RP webapp (`server.ts`) proxies wallet traffic
//! to the credential verifier, which uses this crate internally.
//!
//! ```text
//! ┌─────────┐  proxy   ┌────────────────────┐  uses  ┌──────────────────┐
//! │  RP     │ ───────> │ Credential Verifier │ ────> │  ewqwe_openid4vp │
//! │ webapp  │          │   (actix-web)       │       │  (this crate)    │
//! └─────────┘          └────────────────────┘       └──────────────────┘
//! ```
//!
//! # References
//!
//! - [OpenID4VP 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
//! - [EU Age Verification Profile (Annex A)](https://ageverification.dev/Technical%20Specification/annexes/annex-A/annex-A-av-profile)
//! - [ISO/IEC 18013-5](https://www.iso.org/standard/69084.html)

pub mod config;
pub mod crypto;
pub mod dcql;
pub mod error;
pub mod service;
pub mod stores;
pub mod transaction;
pub mod types;

// Re-export key types for convenience.
pub use config::{determine_profile, get_credential_type, get_profile};
pub use crypto::{
    DecryptedWalletResponse, JarKeyMaterial, JarPayload, JweKeyMaterial, build_public_jwk_set,
    compute_cert_hash, decrypt_jwe_response, initialize_jar_key, initialize_jwe_key, sign_jar,
};
pub use dcql::{
    build_age_verification_query, build_age_verification_query_with_fallback,
    build_default_dcql_for_credential_type, convert_presentation_definition_to_dcql,
    generate_nonce, get_default_age_verification_dcql,
};
pub use error::{OpenID4VPError, OpenID4VPResult};
pub use service::{HaipConfig, OpenID4VPService, OpenID4VPServiceConfig};
pub use transaction::{
    DynTransactionStore, TransactionStore, TransactionStoreBackend, TransactionStoreParams,
};
pub use types::{
    AuthorizationRequestResult, ClientIdScheme, ClientMetadata, DCQLQuery, InitTransactionRequest,
    InitTransactionResponse, OpenID4VPResponse, OpenID4VPTransaction, ProfileId, ResponseMode,
    TransactionDataEntry, TransactionStatus, TransactionStatusResult, WalletAuthorizationError,
};
