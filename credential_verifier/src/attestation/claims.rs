//! Attestation for credential verification events.
//!
//! Defines the structure of claims included in signed attestations.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

/// Claims included in a signed credential verification attestation.
///
/// This structure follows JWT registered claim conventions. All credential-specific
/// claims (age_over_18, given_name, etc.) are stored in the flattened
/// `credential_claims` map and not as dedicated typed fields — keeping this
/// struct credential-format-agnostic.
///
/// The `verified` claim is the single typed result: `true` means the full
/// cryptographic and policy verification pipeline succeeded; `false` means it
/// did not. Credential claims are only populated when `verified` is `true`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    // ============== JWT Registered Claims ==============
    /// Issuer - the credential verifier's identifier (e.g., domain name)
    pub iss: String,

    /// Subject - the transaction identifier that triggered this attestation
    pub sub: String,

    /// Audience - the relying party's identifier
    pub aud: String,

    /// Expiration time (Unix timestamp)
    pub exp: i64,

    /// Issued at time (Unix timestamp)
    pub iat: i64,

    /// Not before time (Unix timestamp)
    pub nbf: i64,

    /// JWT ID - unique identifier for this attestation
    pub jti: String,

    // ============== Verification Result ==============
    /// Whether the full verification pipeline succeeded.
    ///
    /// When `false` the `credential_claims` map is empty — the presented
    /// credential was not trusted enough to assert anything about its content.
    pub verified: bool,

    /// Nonce from the original OpenID4VP request (for replay prevention)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,

    // ============== Credential Metadata ==============
    /// The credential document type (e.g. "org.iso.18013.5.1.mDL", SD-JWT `vct`)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doc_type: Option<String>,

    /// The credential namespace (e.g. "org.iso.18013.5.1")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,

    // ============== Verified Credential Attributes ==============
    /// The verified attribute claims from the presented credential, flattened
    /// into the attestation JWT at the top level. Only populated when
    /// `verified` is `true`. The relying party extracts domain-specific claims
    /// (e.g. `age_over_18`, `given_name`) directly from this map after
    /// parsing and verifying the attestation JWT signature.
    #[serde(flatten)]
    pub credential_claims: serde_json::Map<String, serde_json::Value>,
}

impl Attestation {
    /// Default attestation validity duration (5 minutes).
    pub const DEFAULT_VALIDITY_SECONDS: i64 = 300;

    /// Creates a new attestation with standard timestamps.
    ///
    /// # Arguments
    ///
    /// * `issuer` - The credential verifier's identifier
    /// * `audience` - The relying party's identifier
    /// * `transaction_id` - The verification transaction identifier
    /// * `verified` - Whether the full verification pipeline succeeded
    #[must_use]
    pub fn new(issuer: &str, audience: &str, transaction_id: &str, verified: bool) -> Self {
        let now = Utc::now();
        Self::with_timestamps(issuer, audience, transaction_id, verified, now, None)
    }

    /// Creates an attestation with custom timestamps and validity.
    #[must_use]
    pub fn with_timestamps(
        issuer: &str,
        audience: &str,
        transaction_id: &str,
        verified: bool,
        issued_at: DateTime<Utc>,
        validity_seconds: Option<i64>,
    ) -> Self {
        let validity = validity_seconds.unwrap_or(Self::DEFAULT_VALIDITY_SECONDS);
        let expiration = issued_at + Duration::seconds(validity);

        Self {
            iss: issuer.to_owned(),
            sub: transaction_id.to_owned(),
            aud: audience.to_owned(),
            exp: expiration.timestamp(),
            iat: issued_at.timestamp(),
            nbf: issued_at.timestamp(),
            jti: uuid::Uuid::new_v4().to_string(),
            verified,
            nonce: None,
            doc_type: None,
            namespace: None,
            credential_claims: serde_json::Map::new(),
        }
    }

    /// Sets the credential document type (e.g. "org.iso.18013.5.1.mDL").
    #[must_use]
    pub fn with_doc_type(mut self, doc_type: &str) -> Self {
        self.doc_type = Some(doc_type.to_owned());
        self
    }

    /// Sets the credential namespace (e.g. "org.iso.18013.5.1").
    #[must_use]
    pub fn with_namespace(mut self, namespace: &str) -> Self {
        self.namespace = Some(namespace.to_owned());
        self
    }

    /// Sets the nonce from the OpenID4VP request.
    #[must_use]
    pub fn with_nonce(mut self, nonce: &str) -> Self {
        self.nonce = Some(nonce.to_owned());
        self
    }

    /// Attaches all verified attribute claims from the presented credential.
    ///
    /// These are flattened into the attestation JWT at the top level so the
    /// relying party can access them after parsing and verifying the JWT.
    /// Should only be called when `verified` is `true`.
    #[must_use]
    pub fn with_credential_claims(
        mut self,
        claims: serde_json::Map<String, serde_json::Value>,
    ) -> Self {
        self.credential_claims = claims;
        self
    }

    /// Checks if the attestation is currently valid (not expired, not before nbf).
    #[must_use]
    pub fn is_valid_now(&self) -> bool {
        let now = Utc::now().timestamp();
        now >= self.nbf && now < self.exp
    }
}

#[cfg(test)]
mod claim_tests {
    use super::*;

    #[test]
    fn test_new_claims() {
        let attestation =
            Attestation::new("verifier.example.com", "rp.example.com", "txn-123", true);

        assert_eq!(attestation.iss, "verifier.example.com");
        assert_eq!(attestation.aud, "rp.example.com");
        assert_eq!(attestation.sub, "txn-123");
        assert!(attestation.verified);
        assert!(attestation.is_valid_now());
    }

    #[test]
    fn test_builder_pattern() {
        let mut claims = serde_json::Map::new();
        claims.insert("age_over_18".to_owned(), serde_json::Value::Bool(true));
        let attestation = Attestation::new("verifier", "rp", "txn-456", true)
            .with_nonce("random-nonce-value")
            .with_doc_type("org.iso.18013.5.1.mDL")
            .with_namespace("org.iso.18013.5.1")
            .with_credential_claims(claims);

        assert_eq!(attestation.nonce, Some("random-nonce-value".to_owned()));
        assert_eq!(
            attestation.doc_type,
            Some("org.iso.18013.5.1.mDL".to_owned())
        );
        assert_eq!(attestation.namespace, Some("org.iso.18013.5.1".to_owned()));
        assert_eq!(
            attestation.credential_claims.get("age_over_18"),
            Some(&serde_json::Value::Bool(true))
        );
    }
}
