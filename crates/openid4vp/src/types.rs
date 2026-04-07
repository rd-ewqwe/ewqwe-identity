//! Type definitions for OpenID4VP Relying Party backend.
//!
//! Mirrors the TypeScript types from `@ewqwe/digital-identity` and
//! `@ewqwe/digital-identity-backend`, covering:
//! - DCQL (Digital Credentials Query Language) — OpenID4VP §6
//! - Protocol profiles (HAIP, Annex A)
//! - Credential type configurations (mDL, PID, Proof of Age)
//! - OpenID4VP request/response structures
//! - Transaction lifecycle types
//!
//! References:
//! - <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html>
//! - <https://ageverification.dev/Technical%20Specification/annexes/annex-A/annex-A-av-profile>

use serde::{Deserialize, Serialize};

// ============================================================================
// DCQL Types (OpenID4VP §6)
// ============================================================================

/// A single claims query within a DCQL credential query.
///
/// Specifies which claim to request from the credential, using a Claims Path
/// Pointer as defined in OpenID4VP 1.0 §7.
///
/// For `mso_mdoc` format, `path` MUST contain exactly two string elements:
/// the namespace and the data element identifier (§7.2).
///
/// For JSON-based formats, `path` contains one or more strings/integers
/// representing a JSON path (§7.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DCQLClaimsQuery {
    /// Optional identifier for this claims query.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// Claims Path Pointer — for mso_mdoc: `["namespace", "element"]` (§7.2).
    pub path: Vec<String>,

    /// Acceptable values for this claim.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<serde_json::Value>>,

    /// Whether the RP intends to retain this data element.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intent_to_retain: Option<bool>,
}

/// A credential query within DCQL, specifying which credential to request.
///
/// Each credential query selects a credential format and the claims to extract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DCQLCredentialQuery {
    /// Unique identifier for this credential query (used as key in `vp_token` response).
    pub id: String,

    /// Credential format: `"mso_mdoc"`, `"dc+sd-jwt"`, `"vc+sd-jwt"`, etc.
    pub format: String,

    /// Format-specific metadata (e.g., `doctype_value` for mDocs).
    ///
    /// Per OpenID4VP 1.0 §6.1, `meta` is OPTIONAL in a Credential Query.
    /// However, the EUDI Wallet reference implementation (Kotlin/kotlinx.serialization)
    /// requires this field to be present. We always serialize it (defaulting to `{}`)
    /// for compatibility.
    ///
    /// See: <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1>
    #[serde(default)]
    pub meta: DCQLCredentialMeta,

    /// Claims to request from this credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims: Option<Vec<DCQLClaimsQuery>>,

    /// Named sets of claims — the wallet must satisfy at least one set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_sets: Option<Vec<Vec<String>>>,

    /// Whether to request multiple presentations of this credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub multiple: Option<bool>,

    /// Whether cryptographic holder binding is required.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_cryptographic_holder_binding: Option<bool>,
}

/// Format-specific metadata for a DCQL credential query.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DCQLCredentialMeta {
    /// Document type for mDoc format (e.g., `"org.iso.18013.5.1.mDL"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doctype_value: Option<String>,

    /// Verifiable Credential Type values (for SD-JWT VC).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vct_values: Option<Vec<String>>,

    /// Type values (for JSON-LD VCs).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_values: Option<Vec<String>>,
}

/// Credential set query — specifies which combinations of credentials are acceptable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DCQLCredentialSetQuery {
    /// Each inner `Vec<String>` is a set of credential query IDs that together satisfy the request.
    pub options: Vec<Vec<String>>,

    /// Whether this credential set is required (default: true).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,

    /// Human-readable purpose of this credential set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
}

/// A complete DCQL query — the top-level structure for requesting credentials.
///
/// ```json
/// {
///     "credentials": [
///         { "id": "age_proof", "format": "mso_mdoc", ... }
///     ],
///     "credential_sets": [
///         { "options": [["age_proof"]] }
///     ]
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DCQLQuery {
    /// One or more credential queries.
    pub credentials: Vec<DCQLCredentialQuery>,

    /// Optional credential set constraints.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_sets: Option<Vec<DCQLCredentialSetQuery>>,
}

// ============================================================================
// Protocol Profile Types
// ============================================================================

/// Protocol profile identifier.
///
/// - `Haip`: High Assurance Interoperability Profile (EUDI Wallet)
/// - `AnnexA`: EU Age Verification Profile (Annex A)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProfileId {
    /// High Assurance Interoperability Profile for EUDI Wallets.
    Haip,
    /// EU Age Verification Profile (Annex A) for age verification apps.
    AnnexA,
}

impl std::fmt::Display for ProfileId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProfileId::Haip => write!(f, "haip"),
            ProfileId::AnnexA => write!(f, "annex-a"),
        }
    }
}

/// Client ID scheme used in authorization requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientIdScheme {
    /// X.509 Subject Alternative Name DNS (HAIP).
    X509SanDns,
    /// Redirect URI (Annex A).
    RedirectUri,
}

impl std::fmt::Display for ClientIdScheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientIdScheme::X509SanDns => write!(f, "x509_san_dns"),
            ClientIdScheme::RedirectUri => write!(f, "redirect_uri"),
        }
    }
}

/// Response mode for wallet responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResponseMode {
    /// Plain direct_post (Annex A).
    #[serde(rename = "direct_post")]
    DirectPost,
    /// Encrypted direct_post.jwt (HAIP).
    #[serde(rename = "direct_post.jwt")]
    DirectPostJwt,
}

impl std::fmt::Display for ResponseMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResponseMode::DirectPost => write!(f, "direct_post"),
            ResponseMode::DirectPostJwt => write!(f, "direct_post.jwt"),
        }
    }
}

/// A complete protocol profile configuration.
#[derive(Debug, Clone)]
pub struct ProtocolProfile {
    pub id: ProfileId,
    pub name: &'static str,
    pub description: &'static str,
    pub client_id_scheme: ClientIdScheme,
    pub response_mode: ResponseMode,
    /// URL schemes used by wallets (e.g., `"eudi-openid4vp://"`, `"av://"`).
    pub url_schemes: &'static [&'static str],
    /// Whether JAR signing is required.
    pub requires_jar_signing: bool,
}

// ============================================================================
// Credential Type Configuration
// ============================================================================

/// Known credential type identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialType {
    /// Mobile Driver's License (ISO 18013-5).
    Mdl,
    /// European Personal Identification Data.
    NationalId,
    /// EU Proof of Age attestation.
    ProofOfAge,
}

impl std::fmt::Display for CredentialType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CredentialType::Mdl => write!(f, "mdl"),
            CredentialType::NationalId => write!(f, "national-id"),
            CredentialType::ProofOfAge => write!(f, "proof-of-age"),
        }
    }
}

/// Definition of a single claim within a credential type.
#[derive(Debug, Clone)]
pub struct ClaimDefinition {
    /// Claim identifier (e.g., `"age_over_18"`, `"family_name"`).
    pub id: &'static str,
    /// Human-readable name.
    pub name: &'static str,
    /// JSON path for DCQL queries.
    pub path: &'static str,
    /// Optional description.
    pub description: Option<&'static str>,
}

/// Configuration for a credential type.
#[derive(Debug, Clone)]
pub struct CredentialTypeConfig {
    pub id: CredentialType,
    pub name: &'static str,
    /// Document type (e.g., `"org.iso.18013.5.1.mDL"`).
    pub doc_type: &'static str,
    /// Namespace (e.g., `"org.iso.18013.5.1"`).
    pub namespace: &'static str,
    /// Default protocol profile.
    pub profile: ProfileId,
    /// Available claims.
    pub claims: &'static [ClaimDefinition],
}

// ============================================================================
// OpenID4VP Transaction Types
// ============================================================================

/// Transaction status in the OpenID4VP flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionStatus {
    /// Waiting for wallet response.
    Pending,
    /// Wallet response received, not yet verified.
    Received,
    /// Credential verified successfully.
    Verified,
    /// Verification or processing failed.
    Error,
    /// Transaction TTL exceeded.
    Expired,
}

/// Data received from a wallet via `direct_post` or `direct_post.jwt`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletDirectPostData {
    pub vp_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub presentation_submission: Option<String>,
    pub state: String,
}

/// Client metadata included in authorization requests.
///
/// Extends the basic metadata with JWE encryption parameters
/// and VP format capabilities needed for the HAIP profile.
///
/// See: <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html> §5
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vp_formats: Option<serde_json::Value>,
    /// Alias used in authorization requests.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vp_formats_supported: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_encrypted_response_alg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_encrypted_response_enc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_signed_response_alg: Option<String>,
}

impl Default for ClientMetadata {
    fn default() -> Self {
        Self {
            client_name: Some("ewQwe Age Verification Demo".to_string()),
            logo_uri: None,
            vp_formats: Some(serde_json::json!({
                "mso_mdoc": {
                    "issuerauth_alg_values": [-7, -35, -36],
                    "deviceauth_alg_values": [-7, -35, -36]
                }
            })),
            vp_formats_supported: None,
            jwks: None,
            authorization_encrypted_response_alg: None,
            authorization_encrypted_response_enc: None,
            authorization_signed_response_alg: None,
        }
    }
}

/// A complete OpenID4VP transaction, tracking lifecycle from initiation
/// through wallet response to verification.
#[derive(Debug, Clone)]
pub struct OpenID4VPTransaction {
    pub id: String,
    pub state: String,
    pub nonce: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub status: TransactionStatus,
    pub dcql_query: DCQLQuery,
    pub client_id: String,
    pub client_id_scheme: ClientIdScheme,
    pub response_uri: String,
    pub response_mode: ResponseMode,
    pub profile: ProfileId,
    pub wallet_response: Option<WalletDirectPostData>,
    pub verification_result: Option<serde_json::Value>,
    pub error_message: Option<String>,
    pub client_metadata: Option<ClientMetadata>,
}

// ============================================================================
// API Request / Response Types
// ============================================================================

/// Request body for `POST /api/openid4vp/init`.
///
/// The RP sends this to the credential verifier to start a new transaction.
/// `public_url` tells the verifier which URL the wallet should use for
/// `response_uri` and `request_uri` (since the RP proxies wallet traffic).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitTransactionRequest {
    /// **Required**: The RP's public URL that the wallet will interact with.
    /// Used to construct `response_uri` and `request_uri`.
    pub public_url: String,

    /// Explicit DCQL query. If omitted, a default age verification query is used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dcql_query: Option<DCQLQuery>,

    /// Legacy presentation_definition (will be converted to DCQL).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub presentation_definition: Option<serde_json::Value>,

    /// Optional nonce (auto-generated if omitted).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,

    /// RP metadata for wallet display.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_metadata: Option<ClientMetadata>,

    /// Protocol profile to use: `"haip"` or `"annex-a"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<ProfileId>,

    /// Credential type shorthand: `"mdl"`, `"national-id"`, `"proof-of-age"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_type: Option<String>,
}

/// Response from `POST /api/openid4vp/init`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitTransactionResponse {
    /// Unique transaction ID for polling status.
    pub transaction_id: String,
    /// Constructed client_id.
    pub client_id: String,
    /// Client ID scheme used.
    pub client_id_scheme: String,
    /// URI where wallet fetches the authorization request.
    pub request_uri: String,
    /// Full authorization request URI for QR code / deep link.
    pub authorization_request_uri: String,
    /// Alias for `authorization_request_uri`.
    pub deep_link_uri: String,
    /// Seconds until transaction expires.
    pub expires_in: i64,
    /// Selected protocol profile.
    pub profile: ProfileId,
}

/// Response from `GET /api/openid4vp/status/:id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionStatusResult {
    pub status: TransactionStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vp_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub presentation_submission: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
}

/// Result of building an authorization request (JAR or plain JSON).
#[derive(Debug, Clone)]
pub struct AuthorizationRequestResult {
    /// The content body (JWT string or JSON string).
    pub body: String,
    /// Content-Type header value.
    pub content_type: String,
}
