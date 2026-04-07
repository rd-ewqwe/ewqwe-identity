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

// ============================================================================
// VP Format Capabilities (vp_formats / vp_formats_supported)
// ============================================================================

/// Per-format parameters for **ISO/IEC 18013-5 mDoc** (`mso_mdoc`).
///
/// Algorithm identifiers are **COSE integer IDs** (RFC 8152, IANA COSE Algorithms):
///
/// | Value | Algorithm         |
/// |-------|-------------------|
/// | `-7`  | ES256 (P-256+SHA-256)  |
/// | `-35` | ES384 (P-384+SHA-384)  |
/// | `-36` | ES512 (P-521+SHA-512)  |
/// | `-8`  | EdDSA              |
///
/// See: <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.2.2>
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MsoMdocVpFormat {
    /// COSE algorithm IDs accepted for the IssuerAuth `COSE_Sign1` structure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuerauth_alg_values: Option<Vec<i32>>,

    /// COSE algorithm IDs accepted for DeviceSignature or DeviceMac.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deviceauth_alg_values: Option<Vec<i32>>,
}

/// Per-format parameters for **IETF SD-JWT VC** (`dc+sd-jwt` / `vc+sd-jwt`).
///
/// Algorithm identifiers use **JOSE string names** (RFC 7518), and MUST be
/// fully-specified algorithm identifiers per
/// [draft-ietf-jose-fully-specified-algorithms].
///
/// See: <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.3.4>
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SdJwtVcVpFormat {
    /// JOSE algorithm identifiers for the Issuer-signed SD-JWT (`alg` JOSE header).
    #[serde(rename = "sd-jwt_alg_values", skip_serializing_if = "Option::is_none")]
    pub sd_jwt_alg_values: Option<Vec<String>>,

    /// JOSE algorithm identifiers for the Key Binding JWT (`alg` JOSE header).
    #[serde(rename = "kb-jwt_alg_values", skip_serializing_if = "Option::is_none")]
    pub kb_jwt_alg_values: Option<Vec<String>>,
}

/// Per-format parameters for **W3C VC signed as JWT** (`jwt_vc_json`).
///
/// See: <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.1.3.1.3>
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct JwtVcJsonVpFormat {
    /// JOSE algorithm identifiers for the Verifiable Credential / Presentation
    /// (`alg` JWS header, RFC 7515).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg_values: Option<Vec<String>>,
}

/// Per-format parameters for **W3C VC with Linked Data Proofs** (`ldp_vc`).
///
/// See: <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.1.3.2.3>
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LdpVcVpFormat {
    /// Data Integrity proof type identifiers (e.g. `"DataIntegrityProof"`,
    /// `"Ed25519Signature2020"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_type_values: Option<Vec<String>>,

    /// Cryptosuite identifiers when `proof_type_values` includes
    /// `"DataIntegrityProof"` (e.g. `"ecdsa-rdfc-2019"`, `"bbs-2023"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptosuite_values: Option<Vec<String>>,
}

/// VP format capabilities included in `client_metadata`.
///
/// Each field corresponds to a **Credential Format Identifier** defined in
/// OpenID4VP 1.0 Appendix B. The server re-keys this object from `vp_formats`
/// (request body field) to `vp_formats_supported` (wire field sent to the wallet).
///
/// Format identifiers are a fixed enumeration per OpenID4VP 1.0 §11.1:
/// `mso_mdoc`, `dc+sd-jwt`, `vc+sd-jwt`, `jwt_vc_json`, `ldp_vc`.
///
/// See: <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-11.1>
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VpFormats {
    /// ISO/IEC 18013-5 Mobile Documents (§B.2).
    /// Algorithm IDs use COSE integers (RFC 8152).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mso_mdoc: Option<MsoMdocVpFormat>,

    /// IETF SD-JWT VC — current IANA-registered identifier, canonical since Nov 2024 (§B.3).
    #[serde(rename = "dc+sd-jwt", skip_serializing_if = "Option::is_none")]
    pub dc_sd_jwt: Option<SdJwtVcVpFormat>,

    /// IETF SD-JWT VC — legacy identifier, superseded by `dc+sd-jwt` (§B.3).
    /// Both SHOULD be accepted during the transitional period per
    /// draft-ietf-oauth-sd-jwt-vc §3.2.1.
    #[serde(rename = "vc+sd-jwt", skip_serializing_if = "Option::is_none")]
    pub vc_sd_jwt: Option<SdJwtVcVpFormat>,

    /// W3C VC signed as JWT, without JSON-LD (§B.1.3.1).
    #[serde(rename = "jwt_vc_json", skip_serializing_if = "Option::is_none")]
    pub jwt_vc_json: Option<JwtVcJsonVpFormat>,

    /// W3C VC with Linked Data / Data Integrity Proofs (§B.1.3.2).
    #[serde(rename = "ldp_vc", skip_serializing_if = "Option::is_none")]
    pub ldp_vc: Option<LdpVcVpFormat>,
}

// ============================================================================
// Client Metadata
// ============================================================================

/// Client metadata included in authorization requests.
///
/// Only the fields the frontend can meaningfully supply are included here.
/// Security-sensitive server-side fields are always injected by the server:
///
/// | Wire field (sent to wallet)                   | Source           |
/// |-----------------------------------------------|------------------|
/// | `client_name`                                 | this struct      |
/// | `logo_uri`                                    | this struct      |
/// | `vp_formats_supported`                        | `vp_formats` below, re-keyed |
/// | `jwks`                                        | server ephemeral key (HAIP only) |
/// | `authorization_encrypted_response_alg`        | server — hardcoded `"ECDH-ES"` (HAIP only) |
/// | `authorization_encrypted_response_enc`        | server — hardcoded `"A256GCM"` (HAIP only) |
///
/// ### Encryption note (HAIP, OpenID4VP §8.3 + HAIP §5)
/// For the HAIP profile (`direct_post.jwt`), HAIP §5 mandates:
/// - `alg`: **`ECDH-ES`** (direct key agreement, RFC 7518 §4.6) with P-256 keys — MUST be supported.
/// - `enc`: any JWE content-encryption algorithm; default per OpenID4VP §8.3 is
///   **`A128GCM`**. This server uses **`A256GCM`** for stronger 256-bit keys.
///
/// These are server-controlled (not caller-supplied) because the server generates
/// the per-request ephemeral key pair and must be able to decrypt the wallet response.
///
/// See: <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.9>
/// See: <https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html#section-5>
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientMetadata {
    /// Wallet-facing display name for the Relying Party (RFC 7591 `client_name`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,

    /// Wallet-facing logo URI for the Relying Party (RFC 7591 `logo_uri`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_uri: Option<String>,

    /// Credential format capabilities (OpenID4VP §11.1, Appendix B).
    ///
    /// Stored as `vp_formats` in the request body; re-keyed to
    /// `vp_formats_supported` by the server when sending to the wallet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vp_formats: Option<VpFormats>,
}

impl Default for ClientMetadata {
    fn default() -> Self {
        Self {
            client_name: Some("ewQwe Age Verification Demo".to_string()),
            logo_uri: None,
            // ES256=-7, ES384=-35, ES512=-36 (COSE algorithm integer IDs per RFC 8152)
            vp_formats: Some(VpFormats {
                mso_mdoc: Some(MsoMdocVpFormat {
                    issuerauth_alg_values: Some(vec![-7, -35, -36]),
                    deviceauth_alg_values: Some(vec![-7, -35, -36]),
                }),
                ..Default::default()
            }),
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
///
/// The frontend counterpart is `InitTransactionRequest` in `@ewqwe/digital-identity`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitTransactionRequest {
    /// **Required**: The RP's public URL that the wallet will interact with.
    /// Used to construct `response_uri` and `request_uri`.
    pub public_url: String,

    /// DCQL query specifying the credentials to request.
    /// If omitted, a default age verification query is used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dcql_query: Option<DCQLQuery>,

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
