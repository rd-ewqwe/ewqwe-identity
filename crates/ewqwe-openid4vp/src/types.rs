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

/// A single component in a Claims Path Pointer (OpenID4VP 1.0 §7).
///
/// Per §7, a claims path pointer is a **non-empty** array of:
///
/// - [`Key`](ClaimsPathComponent::Key) — a string, navigating into a named
///   field of the currently selected JSON object(s).
/// - [`Index`](ClaimsPathComponent::Index) — a non-negative integer, selecting
///   the element at that position within the currently selected array(s).
/// - [`All`](ClaimsPathComponent::All) — JSON `null`, selecting **all**
///   elements of the currently selected array(s).
///
/// For ISO mdoc-based credentials (§7.2) the path MUST contain exactly two
/// `Key` components: the namespace and the data element identifier.
///
/// Serializes/deserializes as JSON string | number | null.
#[derive(Debug, Clone, PartialEq)]
pub enum ClaimsPathComponent {
    /// String key — navigate into the named field of a JSON object.
    Key(String),
    /// Non-negative integer index — select the element at this position in an array.
    Index(u32),
    /// Null — select all elements of the currently selected array(s) (§7.1).
    All,
}

impl serde::Serialize for ClaimsPathComponent {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Key(s) => serializer.serialize_str(s),
            Self::Index(i) => serializer.serialize_u32(*i),
            Self::All => serializer.serialize_none(),
        }
    }
}

impl<'de> serde::Deserialize<'de> for ClaimsPathComponent {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = ClaimsPathComponent;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "a string, non-negative integer, or null")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(ClaimsPathComponent::Key(v.to_string()))
            }

            fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Self::Value, E> {
                Ok(ClaimsPathComponent::Key(v))
            }

            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Self::Value, E> {
                u32::try_from(v)
                    .map(ClaimsPathComponent::Index)
                    .map_err(|_| E::custom(format!("index {v} out of range for u32")))
            }

            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Self::Value, E> {
                if v < 0 {
                    return Err(E::custom(format!(
                        "negative integer {v} is not a valid claims path component"
                    )));
                }
                u32::try_from(v as u64)
                    .map(ClaimsPathComponent::Index)
                    .map_err(|_| E::custom(format!("index {v} out of range for u32")))
            }

            fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(ClaimsPathComponent::All)
            }

            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(ClaimsPathComponent::All)
            }
        }

        deserializer.deserialize_any(Visitor)
    }
}

impl From<String> for ClaimsPathComponent {
    fn from(s: String) -> Self {
        Self::Key(s)
    }
}

impl From<&str> for ClaimsPathComponent {
    fn from(s: &str) -> Self {
        Self::Key(s.to_string())
    }
}

impl From<u32> for ClaimsPathComponent {
    fn from(i: u32) -> Self {
        Self::Index(i)
    }
}

impl std::fmt::Display for ClaimsPathComponent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Key(s) => write!(f, "{s}"),
            Self::Index(i) => write!(f, "{i}"),
            Self::All => write!(f, "null"),
        }
    }
}

/// A single claims query within a DCQL credential query.
///
/// Specifies which claim to request from the credential, using a Claims Path
/// Pointer as defined in OpenID4VP 1.0 §7.
///
/// For `mso_mdoc` format, `path` MUST contain exactly two [`ClaimsPathComponent::Key`]
/// elements: the namespace and the data element identifier (§7.2).
///
/// For JSON-based formats, `path` may contain strings, non-negative integers,
/// and/or nulls representing a JSON path (§7.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DCQLClaimsQuery {
    /// Optional identifier for this claims query.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// Claims Path Pointer (§7): a non-empty array of strings, non-negative
    /// integers, and/or nulls.
    ///
    /// For `mso_mdoc`: exactly `[Key(namespace), Key(element)]` (§7.2).
    /// For JSON-based credentials: one or more components per §7.1.
    pub path: Vec<ClaimsPathComponent>,

    /// Acceptable values for this claim.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<serde_json::Value>>,

    /// Whether the RP intends to retain this data element.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intent_to_retain: Option<bool>,
}

/// Type identifier for a `trusted_authorities` entry — specifies which trust framework
/// mechanism is used to identify the issuer authority.
///
/// Defined by OpenID4VP 1.0 §6.1.1.
///
/// See: <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1>
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustedAuthorityType {
    /// X.509 Authority Key Identifier, base64url-encoded (§6.1.1.1).
    ///
    /// The raw byte representation MUST match the `AuthorityKeyIdentifier` extension
    /// of an X.509 certificate in the credential's certificate chain.
    Aki,

    /// ETSI Trusted List identifier (§6.1.1.2).
    ///
    /// The trust chain of a matching credential MUST contain at least one X.509
    /// certificate matching an entry of the referenced Trusted List or its cascading lists.
    EtsiTl,

    /// OpenID Federation Entity Identifier (§6.1.1.3).
    ///
    /// A valid trust path including this entity identifier must be constructible from
    /// a matching credential.
    OpenidFederation,
}

impl std::fmt::Display for TrustedAuthorityType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrustedAuthorityType::Aki => write!(f, "aki"),
            TrustedAuthorityType::EtsiTl => write!(f, "etsi_tl"),
            TrustedAuthorityType::OpenidFederation => write!(f, "openid_federation"),
        }
    }
}

/// A single entry in `trusted_authorities` — identifies an authority or trust framework
/// that certifies credential issuers the Verifier will accept.
///
/// A Credential is considered a match if it satisfies **at least one** entry in
/// the `trusted_authorities` array for any one of the provided types.
///
/// See: <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1>
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedAuthority {
    /// Type identifier for the trust framework.
    #[serde(rename = "type")]
    pub authority_type: TrustedAuthorityType,

    /// Non-empty array of values interpreted according to `authority_type`.
    pub values: Vec<String>,
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

    /// Expected authorities or trust frameworks that certify issuers the Verifier will accept.
    ///
    /// OPTIONAL. A non-empty array as defined in §6.1.1. Every Credential returned by the
    /// Wallet SHOULD match at least one of the conditions. The Verifier still bears its own
    /// responsibility to verify issuer trust independently; this field is a hint to the Wallet
    /// to avoid sending credentials that would likely be rejected.
    ///
    /// See: <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trusted_authorities: Option<Vec<TrustedAuthority>>,

    /// Whether cryptographic holder binding is required.
    ///
    /// OPTIONAL. Default value is `true` per §6.1 — use [`Self::requires_holder_binding()`]
    /// to obtain the effective value rather than unwrapping this field directly.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_cryptographic_holder_binding: Option<bool>,
}

impl DCQLCredentialQuery {
    /// Returns the effective value of `require_cryptographic_holder_binding`.
    ///
    /// Per OpenID4VP 1.0 §6.1, the default is `true` when the field is absent.
    #[inline]
    pub fn requires_holder_binding(&self) -> bool {
        self.require_cryptographic_holder_binding.unwrap_or(true)
    }
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

impl DCQLQuery {
    /// Validate the structural rules from OpenID4VP 1.0 §6 and §6.4.1.
    ///
    /// Returns `Ok(())` when the query is structurally valid, or `Err(String)` with a
    /// human-readable description of the first violation found.
    ///
    /// Rules enforced (referencing spec sections):
    ///
    /// **§6 — Top level**
    /// - `credentials` MUST be non-empty.
    /// - Credential query `id` values MUST be unique across `credentials`.
    /// - `credential_sets`, if present, MUST be non-empty.
    /// - Each `credential_sets` option element MUST reference a valid credential query `id`.
    ///
    /// **§6.1 — Credential Query**
    /// - Each credential query `id` MUST be a non-empty string of alphanumeric, `-`, or `_`.
    /// - `trusted_authorities`, if present, MUST be non-empty.
    ///
    /// **§6.3 & §6.4.1 — Claims / claim_sets**
    /// - `claim_sets` MUST NOT be present when `claims` is absent.
    /// - Claim `id` values MUST be unique within a single `claims` array.
    /// - When `claim_sets` is present, every claim MUST have a non-empty `id`.
    /// - Every identifier referenced in `claim_sets` MUST appear in `claims`.
    pub fn is_valid(&self) -> Result<(), String> {
        // §6: credentials MUST be non-empty.
        if self.credentials.is_empty() {
            return Err("DCQL query 'credentials' must be non-empty".into());
        }

        // §6.1: credential query IDs must be unique.
        let mut seen_cred_ids = std::collections::HashSet::new();
        for cred in &self.credentials {
            // ID must be non-empty and consist only of [A-Za-z0-9_-].
            if cred.id.is_empty()
                || !cred
                    .id
                    .chars()
                    .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
            {
                return Err(format!(
                    "Credential query id {:?} must be a non-empty alphanumeric/underscore/hyphen string",
                    cred.id
                ));
            }
            if !seen_cred_ids.insert(cred.id.as_str()) {
                return Err(format!(
                    "Duplicate credential query id {:?} in 'credentials'",
                    cred.id
                ));
            }

            // §6.1.1: trusted_authorities, if present, must be non-empty.
            if let Some(ta) = &cred.trusted_authorities
                && ta.is_empty()
            {
                return Err(format!(
                    "Credential query {:?}: 'trusted_authorities' must be non-empty when present",
                    cred.id
                ));
            }

            // §6.4.1: claim_sets MUST NOT be present if claims is absent.
            if cred.claim_sets.is_some() && cred.claims.is_none() {
                return Err(format!(
                    "Credential query {:?}: 'claim_sets' must not be present when 'claims' is absent",
                    cred.id
                ));
            }

            if let Some(claims) = &cred.claims {
                // Claim IDs must be unique within the claims array.
                let mut seen_claim_ids = std::collections::HashSet::new();
                for claim in claims {
                    if let Some(id) = &claim.id {
                        if id.is_empty()
                            || !id
                                .chars()
                                .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
                        {
                            return Err(format!(
                                "Credential query {:?}: claim id {:?} must be a non-empty alphanumeric/underscore/hyphen string",
                                cred.id, id
                            ));
                        }
                        if !seen_claim_ids.insert(id.as_str()) {
                            return Err(format!(
                                "Credential query {:?}: duplicate claim id {:?}",
                                cred.id, id
                            ));
                        }
                    }
                }

                if let Some(claim_sets) = &cred.claim_sets {
                    // §6.4.1: all claims must have an id when claim_sets is present.
                    for claim in claims {
                        if claim.id.is_none() {
                            return Err(format!(
                                "Credential query {:?}: all claims must have an 'id' when 'claim_sets' is present",
                                cred.id
                            ));
                        }
                    }
                    // Every id referenced in claim_sets must exist in claims.
                    for set in claim_sets {
                        for ref_id in set {
                            if !seen_claim_ids.contains(ref_id.as_str()) {
                                return Err(format!(
                                    "Credential query {:?}: 'claim_sets' references unknown claim id {:?}",
                                    cred.id, ref_id
                                ));
                            }
                        }
                    }
                }
            }
        }

        // §6: credential_sets, if present, must be non-empty and reference valid credential IDs.
        if let Some(cred_sets) = &self.credential_sets {
            if cred_sets.is_empty() {
                return Err("'credential_sets' must be non-empty when present".into());
            }
            for cs in cred_sets {
                for option_set in &cs.options {
                    for ref_id in option_set {
                        if !seen_cred_ids.contains(ref_id.as_str()) {
                            return Err(format!(
                                "'credential_sets' option references unknown credential query id {:?}",
                                ref_id
                            ));
                        }
                    }
                }
            }
        }

        Ok(())
    }
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
///
/// Specifies how the Wallet must interpret and validate the `client_id`.
/// The prefix is prepended to the original client identifier with a `:`
/// separator on the wire (e.g. `x509_san_dns:rp.example.com`).
///
/// See: <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.9.3>
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientIdScheme {
    /// X.509 Subject Alternative Name DNS entry (HAIP profile). The leaf
    /// certificate's `dNSName` SAN must match the bare `client_id` value.
    X509SanDns,
    /// The original `client_id` is the Redirect URI itself (Annex A profile).
    /// No request signing required.
    RedirectUri,
    /// X.509 Subject Alternative Name URI entry. Like `x509_san_dns` but uses
    /// a `uniformResourceIdentifier` SAN field instead.
    X509SanUri,
    /// Decentralized Identifier (DID). Request must be signed with a key from
    /// the DID Document's `verificationMethod` property.
    Did,
    /// X.509 certificate SHA-256 hash (HAIP profile). The `client_id` value is
    /// the base64url-encoded SHA-256 digest of the DER-encoded leaf certificate.
    /// More robust than `x509_san_dns` because it does not depend on DNS
    /// resolution and is a direct cryptographic binding to the certificate.
    X509Hash,
}

impl std::fmt::Display for ClientIdScheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientIdScheme::X509SanDns => write!(f, "x509_san_dns"),
            ClientIdScheme::RedirectUri => write!(f, "redirect_uri"),
            ClientIdScheme::X509SanUri => write!(f, "x509_san_uri"),
            ClientIdScheme::Did => write!(f, "did"),
            ClientIdScheme::X509Hash => write!(f, "x509_hash"),
        }
    }
}

/// Response mode for wallet responses (OpenID4VP 1.0 §5.2, Appendix A.2).
///
/// | Value              | Description                                                         |
/// |--------------------|---------------------------------------------------------------------|
/// | `fragment`         | Default for `vp_token`; response in redirect URL fragment           |
/// | `direct_post`      | Wallet POSTs response to `response_uri` (cross-device, Annex A)     |
/// | `direct_post.jwt`  | Like `direct_post` but response is encrypted JWE (HAIP mandatory)   |
/// | `dc_api`           | Response via W3C Digital Credentials API, unencrypted               |
/// | `dc_api.jwt`       | Response via W3C DC API, encrypted JWE (§8.3)                       |
///
/// See: <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.2>
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResponseMode {
    /// Default for `vp_token`; Authorization Response parameters encoded in
    /// the redirect URL fragment (same-device flow, §5.6).
    #[serde(rename = "fragment")]
    Fragment,
    /// Wallet sends an HTTP POST to `response_uri` (cross-device, §8.2).
    /// Used by the Annex A profile.
    #[serde(rename = "direct_post")]
    DirectPost,
    /// Like `direct_post` but the response is an encrypted JWT (JWE, §8.3.1).
    /// Mandatory for the HAIP profile.
    #[serde(rename = "direct_post.jwt")]
    DirectPostJwt,
    /// Response delivered via the W3C Digital Credentials API, unencrypted
    /// (Appendix A.2).
    #[serde(rename = "dc_api")]
    DcApi,
    /// Response delivered via the W3C Digital Credentials API, encrypted JWE
    /// (Appendix A.2 + §8.3).
    #[serde(rename = "dc_api.jwt")]
    DcApiJwt,
}

impl std::fmt::Display for ResponseMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResponseMode::Fragment => write!(f, "fragment"),
            ResponseMode::DirectPost => write!(f, "direct_post"),
            ResponseMode::DirectPostJwt => write!(f, "direct_post.jwt"),
            ResponseMode::DcApi => write!(f, "dc_api"),
            ResponseMode::DcApiJwt => write!(f, "dc_api.jwt"),
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

// ============================================================================
// Verification request/response types
// ============================================================================

/// Request body for credential verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)] // Fields are part of OpenID4VP spec but may not all be actively used
pub struct VerifyCredentialRequest {
    /// The VP token from the wallet (JSON string containing the credential).
    pub vp_token: String,

    /// Presentation submission with descriptor mapping.
    /// Optional because DCQL-based responses (OpenID4VP Section 8.1) don't include
    /// `presentation_submission` — the `vp_token` itself is structured with credential IDs as keys.
    #[serde(default)]
    pub presentation_submission: Option<PresentationSubmission>,

    /// Original state from the request.
    /// Used to look up the server-stored transaction nonce for replay prevention.
    #[serde(default)]
    pub state: Option<String>,

    /// Client ID (relying party identifier).
    #[serde(default)]
    pub client_id: Option<String>,
}

/// Presentation submission structure from OpenID4VP.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)] // Part of OpenID4VP spec, used with presentation_definition (not DCQL)
pub struct PresentationSubmission {
    pub id: String,
    pub definition_id: String,
    pub descriptor_map: Vec<DescriptorMapEntry>,
}

/// Descriptor map entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)] // Part of OpenID4VP spec
pub struct DescriptorMapEntry {
    pub id: String,
    pub format: String,
    pub path: String,
}

/// Response from credential verification.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VerifyCredentialResponse {
    /// Whether verification was successful.
    pub success: bool,

    /// Human-readable message.
    pub message: String,

    /// Verification details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_details: Option<VerificationDetails>,

    /// Signed attestation JWT (always present).
    pub attestation: String,

    /// Errors (if failed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
}

/// Details about the verification process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationDetails {
    pub signature_valid: bool,
    pub not_expired: bool,
    pub issuer_trusted: bool,
}

/// Error response sent by the Wallet to the Verifier's `response_uri` (§8.5).
///
/// Instead of a VP Token the Wallet can send an error code when it cannot or will
/// not fulfil the Authorization Request.  The Verifier MUST respond HTTP 200 + `{}`
/// regardless (§8.2).
///
/// Error codes (§8.5):
/// - `invalid_request` — malformed / unsupported request parameters
/// - `access_denied` — no matching credentials, user denied consent, or auth failed
/// - `vp_formats_not_supported` — no supported VP format found
/// - `invalid_request_uri_method` — unsupported `request_uri_method` value
/// - `invalid_transaction_data` — `transaction_data` claim could not be processed
/// - `wallet_unavailable` — wallet cannot be invoked (§15.9.1)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WalletAuthorizationError {
    /// Error code from §8.5 (e.g. `"access_denied"`).
    pub error: String,

    /// Human-readable error description (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,

    /// The `state` value from the Authorization Request echoed back by the wallet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

/// OpenID4VP Authorization Response received via `direct_post` or `direct_post.jwt` (§8.2).
///
/// When `response_type=vp_token`, the VP Token is returned in the Authorization Response.
/// With `direct_post`, the Wallet HTTP-POSTs this structure to the Verifier's `response_uri`
/// encoded as `application/x-www-form-urlencoded`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenID4VPResponse {
    /// JSON-encoded `Record<credentialQueryId, presentation[]>` per OpenID4VP
    /// 1.0 §8.1. Each key is the `id` from a DCQL Credential Query; each value
    /// is an array of base64url-encoded credential presentations.
    pub vp_token: String,

    /// **Deprecated — absent in OpenID4VP 1.0 DCQL responses.**
    ///
    /// `presentation_submission` belongs to the DIF Presentation Exchange
    /// protocol (`presentation_definition`) and is not returned when the
    /// request uses `dcql_query` (§8.1). The `vp_token` JSON object structure
    /// itself maps presentations to credential queries.
    /// Kept here only for backward-compatibility with wallets on older drafts.
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

/// A decoded entry from the `transaction_data` Authorization Request parameter (§8.4).
///
/// The Authorization Request MAY include `transaction_data` — a non-empty array of
/// base64url-encoded JSON objects, each describing a transaction the wallet is asked
/// to authorise (e.g. a payment, consent, or contract signing).
///
/// The wallet MUST cryptographically bind these entries into its credential
/// presentations:
/// - **SD-JWT VC**: via `transaction_data_hashes` (and `transaction_data_hashes_alg`)
///   in the Key Binding JWT (§B.3.3.1).
/// - **mdoc**: via the `DeviceSigned` structure (§B.2.1).
///
/// The credential verifier echoes the raw `transaction_data` strings back to the
/// RP (in [`TransactionStatusResult`]) so it can verify those hashes against the
/// presented credential.
///
/// Reference: <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.4>
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionDataEntry {
    /// Transaction data type identifier — identifies the schema of this entry
    /// (REQUIRED per §8.4).
    #[serde(rename = "type")]
    pub data_type: String,

    /// DCQL Credential Query IDs (from the `dcql_query`) that can be used to
    /// authorise this transaction data entry (REQUIRED per §8.4).
    pub credential_ids: Vec<String>,

    /// Hash algorithm(s) the RP accepts for `transaction_data_hashes` in the
    /// SD-JWT VC Key Binding JWT (§B.3.3.1, OPTIONAL).
    ///
    /// Values are string identifiers from the
    /// [IANA Named Information Hash Algorithm registry](https://www.iana.org/assignments/named-information/named-information.xhtml)
    /// (e.g. `"sha-256"`, `"sha-384"`).
    /// When absent the wallet MUST use `"sha-256"` (the default).
    /// Only meaningful for `dc+sd-jwt` credential formats.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_data_hashes_alg: Option<Vec<String>>,

    /// Type-specific parameters (arbitrary extra fields defined by the `type` schema).
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, serde_json::Value>,
}

/// A complete OpenID4VP transaction, tracking lifecycle from initiation
/// through wallet response to verification.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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
    pub wallet_response: Option<OpenID4VPResponse>,
    pub wallet_error: Option<WalletAuthorizationError>,
    pub verification_result: Option<serde_json::Value>,
    pub error_message: Option<String>,
    pub client_metadata: Option<ClientMetadata>,
    /// Transaction data entries (§8.4). When present, forwarded to the wallet
    /// in the Authorization Request so it can bind them into its credential
    /// presentations. Echoed back in [`TransactionStatusResult`] for RP
    /// hash verification.
    pub transaction_data: Option<Vec<String>>,
}

// ============================================================================
// API Request / Response Types
// ============================================================================

/// Request body for `POST /ewqwe_api/openid4vp/init`.
///
/// The RP sends this to the credential verifier to start a new transaction.
///
/// The frontend counterpart is `InitTransactionRequest` in `@ewqwe/digital-identity`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InitTransactionRequest {
    /// DCQL query specifying the credentials to request.
    /// If omitted, a default age verification query is used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dcql_query: Option<DCQLQuery>,

    /// Optional nonce (auto-generated if omitted).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,

    /// Optional OAuth/OpenID4VP state value maintained by the client.
    ///
    /// When omitted, the delegated verifier service generates a fresh request-id
    /// and uses it as the wallet-facing `state` value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,

    /// RP metadata for wallet display.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_metadata: Option<ClientMetadata>,

    /// Protocol profile to use: `"haip"` or `"annex-a"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<ProfileId>,

    /// Credential type shorthand: `"mdl"`, `"national-id"`, `"proof-of-age"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_type: Option<String>,

    /// Transaction data entries (§8.4). Each element is a base64url-encoded
    /// JSON string describing a transaction the wallet is asked to authorise.
    /// When present, these are forwarded verbatim in the Authorization Request
    /// and echoed back in the status result for RP hash verification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_data: Option<Vec<String>>,
}

impl InitTransactionRequest {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_credential_type(mut self, credential_type: impl Into<String>) -> Self {
        self.credential_type = Some(credential_type.into());
        self
    }

    pub fn with_transaction_data(mut self, transaction_data: impl Into<Vec<String>>) -> Self {
        self.transaction_data = Some(transaction_data.into());
        self
    }

    pub fn with_dcql_query(mut self, dcql_query: impl Into<DCQLQuery>) -> Self {
        self.dcql_query = Some(dcql_query.into());
        self
    }

    pub fn with_nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }

    pub fn with_state(mut self, state: impl Into<String>) -> Self {
        self.state = Some(state.into());
        self
    }

    pub fn with_client_metadata(mut self, client_metadata: impl Into<ClientMetadata>) -> Self {
        self.client_metadata = Some(client_metadata.into());
        self
    }

    pub fn with_profile(mut self, profile: impl Into<ProfileId>) -> Self {
        self.profile = Some(profile.into());
        self
    }
}

/// Response from `POST /ewqwe_api/openid4vp/init`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitTransactionResponse {
    /// Unique transaction ID for polling status.
    pub transaction_id: String,

    /// Constructed client_id.
    pub client_id: String,

    /// Client ID scheme used.
    pub client_id_scheme: ClientIdScheme,

    /// URI where wallet fetches the authorization request.
    pub request_uri: String,

    /// Full authorization request URI for QR code / deep link.
    pub authorization_request_uri: String,

    /// Seconds until transaction expires.
    pub expires_in: i64,

    /// Selected protocol profile.
    pub profile: ProfileId,

    /// QR code as a `data:image/svg+xml;base64,...` data URL, ready to assign
    /// to an `<img src>`. Only populated for cross-device flows.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qr_code_data_url: Option<String>,
}

/// Response from `GET /ewqwe_api/openid4vp/status/:id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionStatusResult {
    pub status: TransactionStatus,

    /// Seconds until the transaction expires. Present when `status == "pending"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<i64>,

    /// The Authorization Response received from the wallet (OpenID4VP 1.0 §8.1 + §8.2).
    /// Only populated when `status == "received"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_response: Option<OpenID4VPResponse>,

    /// The `nonce` from the original Authorization Request (§5.2).
    /// Needed by the frontend for VP Token replay protection (§14.1).
    /// Only populated when `status == "received"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,

    /// Error response sent by the Wallet (§8.5). Present when `status == "error"`
    /// and the error originated from the wallet (not an internal server error).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wallet_error: Option<WalletAuthorizationError>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,

    /// The original `transaction_data` from the Authorization Request (§8.4).
    /// Present when `status == "received"` so the RP can verify the hashes
    /// that the wallet embedded in its credential presentations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_data: Option<Vec<String>>,
}

/// Result of building an authorization request (JAR or plain JSON).
#[derive(Debug, Clone)]
pub struct AuthorizationRequestResult {
    /// The content body (JWT string or JSON string).
    pub body: String,
    /// Content-Type header value.
    pub content_type: String,
}
