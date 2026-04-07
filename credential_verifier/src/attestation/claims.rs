//! Attestation claims for EU Age Verification.
//!
//! Defines the structure of claims included in signed attestations.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

/// Claims included in a signed age verification attestation.
///
/// This structure follows JWT registered claim conventions while adding
/// custom claims specific to the EU Age Verification profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationClaims {
    // ============== JWT Registered Claims ==============
    /// Issuer - the credential verifier's identifier (e.g., domain name)
    pub iss: String,

    /// Subject - the session or transaction identifier
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

    // ============== EU Age Verification Claims ==============
    /// Whether the age requirement was met (the main verification result)
    #[serde(rename = "age_verified")]
    pub age_verified: bool,

    /// The age threshold that was verified (e.g., 18, 21)
    #[serde(rename = "age_over", skip_serializing_if = "Option::is_none")]
    pub age_over: Option<u8>,

    /// The namespace used for verification (e.g., "eu.europa.ec.av.1")
    #[serde(rename = "av_namespace", skip_serializing_if = "Option::is_none")]
    pub av_namespace: Option<String>,

    /// Nonce from the original OpenID4VP request (for binding)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

impl AttestationClaims {
    /// Default attestation validity duration (5 minutes).
    pub const DEFAULT_VALIDITY_SECONDS: i64 = 300;

    /// Creates new attestation claims with standard timestamps.
    ///
    /// # Arguments
    ///
    /// * `issuer` - The credential verifier's identifier
    /// * `audience` - The relying party's identifier
    /// * `session_id` - The session or transaction identifier
    /// * `age_verified` - Whether the age requirement was met
    ///
    /// # Returns
    ///
    /// New `AttestationClaims` with current timestamps and default validity.
    #[must_use]
    pub fn new(issuer: &str, audience: &str, session_id: &str, age_verified: bool) -> Self {
        let now = Utc::now();
        Self::with_timestamps(issuer, audience, session_id, age_verified, now, None)
    }

    /// Creates attestation claims with custom timestamps and validity.
    ///
    /// # Arguments
    ///
    /// * `issuer` - The credential verifier's identifier
    /// * `audience` - The relying party's identifier
    /// * `session_id` - The session or transaction identifier
    /// * `age_verified` - Whether the age requirement was met
    /// * `issued_at` - When the attestation was issued
    /// * `validity_seconds` - How long the attestation is valid (defaults to 5 minutes)
    #[must_use]
    pub fn with_timestamps(
        issuer: &str,
        audience: &str,
        session_id: &str,
        age_verified: bool,
        issued_at: DateTime<Utc>,
        validity_seconds: Option<i64>,
    ) -> Self {
        let validity = validity_seconds.unwrap_or(Self::DEFAULT_VALIDITY_SECONDS);
        let expiration = issued_at + Duration::seconds(validity);

        Self {
            iss: issuer.to_owned(),
            sub: session_id.to_owned(),
            aud: audience.to_owned(),
            exp: expiration.timestamp(),
            iat: issued_at.timestamp(),
            nbf: issued_at.timestamp(),
            jti: uuid::Uuid::new_v4().to_string(),
            age_verified,
            age_over: None,
            av_namespace: None,
            nonce: None,
        }
    }

    /// Sets the age threshold that was verified.
    #[must_use]
    pub fn with_age_over(mut self, age: u8) -> Self {
        self.age_over = Some(age);
        self
    }

    /// Sets the namespace used for verification.
    #[must_use]
    pub fn with_namespace(mut self, namespace: &str) -> Self {
        self.av_namespace = Some(namespace.to_owned());
        self
    }

    /// Sets the nonce from the OpenID4VP request.
    #[must_use]
    pub fn with_nonce(mut self, nonce: &str) -> Self {
        self.nonce = Some(nonce.to_owned());
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
        let claims = AttestationClaims::new(
            "verifier.example.com",
            "rp.example.com",
            "session-123",
            true,
        );

        assert_eq!(claims.iss, "verifier.example.com");
        assert_eq!(claims.aud, "rp.example.com");
        assert_eq!(claims.sub, "session-123");
        assert!(claims.age_verified);
        assert!(claims.is_valid_now());
    }

    #[test]
    fn test_builder_pattern() {
        let claims = AttestationClaims::new("verifier", "rp", "session", true)
            .with_age_over(18)
            .with_namespace("eu.europa.ec.av.1")
            .with_nonce("random-nonce-value");

        assert_eq!(claims.age_over, Some(18));
        assert_eq!(claims.av_namespace, Some("eu.europa.ec.av.1".to_owned()));
        assert_eq!(claims.nonce, Some("random-nonce-value".to_owned()));
    }
}
