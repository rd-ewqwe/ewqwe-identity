/*!
Typed request/response models for the ewQwe credential-verifier REST API.

All types satisfy `serde::{Serialize, Deserialize}` so they are ready to use
as HTTP bodies and can be shared between the transport layer, application code,
and tests.

Standards references:
- OpenID4VP 1.0: <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html>
- DCQL: OpenID4VP 1.0 §6
- ISO/IEC 18013-5 (mDL/mDoc)
- EU Age Verification Profile: <https://ageverification.dev/>
*/

use serde::{Deserialize, Serialize};
use serde_json::Value;

// // ============================================================================
// // Request / Response — /ewqwe_api/verify
// // ============================================================================

// /// Request body for `POST /ewqwe_api/verify`.
// ///
// /// Submit a VP Token to the credential-verifier for signature and policy validation.
// ///
// /// # Mutual TLS
// ///
// /// This endpoint requires a valid client certificate unless the server has
// /// `disable_authentication = true` in its configuration. Provide
// /// `client_cert_pem` / `client_key_pem` in [`ClientOptions`](crate::ClientOptions).
// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct VerifyRequest {
//     /// JSON-encoded `Record<credentialQueryId, presentation[]>` (OpenID4VP §8.1).
//     pub vp_token: String,

//     /// DIF Presentation Exchange submission — omit for DCQL flows.
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub presentation_submission: Option<PresentationSubmission>,

//     /// `state` from the original Authorization Request.
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub state: Option<String>,

//     /// The RP's `client_id` — required when there is no `state` (W3C DC API flow).
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub client_id: Option<String>,
// }

// /// Presentation submission structure from OpenID4VP.
// #[derive(Debug, Clone, Serialize, Deserialize)]
// #[allow(dead_code)] // Part of OpenID4VP spec, used with presentation_definition (not DCQL)
// pub struct PresentationSubmission {
//     pub id: String,
//     pub definition_id: String,
//     pub descriptor_map: Vec<DescriptorMapEntry>,
// }

// impl VerifyRequest {
//     /// Create a minimal `VerifyRequest` from a raw VP Token.
//     pub fn new(vp_token: impl Into<String>) -> Self {
//         Self {
//             vp_token: vp_token.into(),
//             presentation_submission: None,
//             state: None,
//             client_id: None,
//         }
//     }

//     /// Attach the OAuth `state` from the Authorization Request.
//     pub fn with_state(mut self, state: impl Into<String>) -> Self {
//         self.state = Some(state.into());
//         self
//     }

//     /// Attach the RP's `client_id` (required for DC API flows without `state`).
//     pub fn with_client_id(mut self, client_id: impl Into<String>) -> Self {
//         self.client_id = Some(client_id.into());
//         self
//     }
// }

// /// Per-claim verification flags returned alongside the signed attestation.
// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct VerificationDetails {
//     /// Cryptographic signature over the credential is valid.
//     pub signature_valid: bool,
//     /// Credential has not expired.
//     pub not_expired: bool,
//     /// Issuing authority is trusted by the credential-verifier.
//     pub issuer_trusted: bool,
// }

// /// Response from `POST /ewqwe_api/verify`.
// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct VerifyResponse {
//     /// `true` → credential was successfully verified.
//     pub success: bool,
//     /// Human-readable outcome message.
//     pub message: String,
//     /// Signed JWT attestation. Always present. Contains `verified`, `doc_type`,
//     /// and all credential claims the verifier extracted.
//     #[serde(default)]
//     pub attestation: String,
//     /// Optional detailed verification flags.
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub verification_details: Option<VerificationDetails>,
//     /// Validation error messages on failure.
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub errors: Option<Vec<String>>,
// }

// ============================================================================
// JWKS
// ============================================================================

/// JSON Web Key Set returned by `GET /ewqwe_api/openid4vp/.well-known/jwks.json`.
///
/// Used by the RP to verify JWT attestations signed by the credential-verifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwkSet {
    pub keys: Vec<Value>,
}

// ============================================================================
// Version
// ============================================================================

/// Response from `GET /version`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionResponse {
    pub version: String,
}
