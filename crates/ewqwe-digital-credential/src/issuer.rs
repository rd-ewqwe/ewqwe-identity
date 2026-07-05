//! [`CredentialIssuer`] — ephemeral two-level PKI + credential signing.
//!
//! Generates a self-signed CA, an issuer leaf certificate (signed by the CA),
//! and a device holder key pair, all in-memory using EC P-256.
//!
//! Provides convenience methods that delegate to the [`sd_jwt`] and [`mdoc`]
//! modules to build fully-signed credentials of every supported type.
//!
//! # Security
//!
//! - All private key material lives in memory and is **never written to disk**.
//! - Only [`CredentialIssuer::ca_cert_pem`] (a *public* certificate) is
//!   intended to be written to disk — specifically to the server's
//!   `credential_issuer_ca_dir` so that the verifier can trust credentials
//!   produced by this issuer.
//! - Every call to [`CredentialIssuer::generate`] produces fresh, independent
//!   key pairs.

use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey},
    nid::Nid,
    pkey::{PKey, Private},
};
use serde_json::Value as Json;

use crate::{
    CredentialError,
    error::CredentialResult,
    mdoc::{build_eudi_pid_mdoc, ec_key_to_public_jwk},
    pki::{build_ca_cert, build_issuer_cert},
    sd_jwt::{build_eu_age_sd_jwt, build_eudi_pid_sd_jwt},
};

/// An ephemeral credential-issuing authority.
///
/// Holds a two-level PKI (CA → issuer leaf) and a device holder key pair used
/// to build and sign test and demonstration credentials.  Create a new instance
/// with [`CredentialIssuer::generate`], then:
///
/// 1. Write [`ca_cert_pem`](Self::ca_cert_pem) to the verifier's
///    `credential_issuer_ca_dir`.
/// 2. Call one of the `build_*` methods to produce a signed credential.
pub struct CredentialIssuer {
    /// PEM of the self-signed CA certificate.
    ///
    /// Write this to the credential verifier's `credential_issuer_ca_dir`
    /// before starting the server so the verifier trusts credentials issued
    /// by this authority.
    pub ca_cert_pem: Vec<u8>,

    /// DER-encoded issuer leaf certificate (placed in `x5c[0]`).
    pub issuer_cert_der: Vec<u8>,

    /// DER-encoded CA certificate (placed in `x5c[1]` for chain building).
    ca_cert_der: Vec<u8>,

    /// Issuer private key (EC P-256) — signs SD-JWT issuer JWTs and mDoc
    /// `IssuerAuth` COSE_Sign1.
    issuer_key: PKey<Private>,

    /// Device / holder private key (EC P-256) — signs SD-JWT KB-JWTs and the
    /// mDoc `DeviceSignature` COSE_Sign1.
    device_key: PKey<Private>,

    /// Device public key as JWK (`cnf.jwk` in SD-JWT payloads and for KB-JWT
    /// verification).
    pub device_pubkey_jwk: Json,
}

impl CredentialIssuer {
    /// Generate a fresh ephemeral issuing authority.
    ///
    /// Creates three independent EC P-256 key pairs (CA, issuer leaf, device
    /// holder) and builds the corresponding X.509 certificates.
    pub fn generate() -> CredentialResult<Self> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;

        let ca_key = PKey::from_ec_key(EcKey::generate(&group)?)?;
        let issuer_key = PKey::from_ec_key(EcKey::generate(&group)?)?;
        let device_key = PKey::from_ec_key(EcKey::generate(&group)?)?;

        let ca_cert = build_ca_cert(&ca_key)?;
        let issuer_cert = build_issuer_cert(&ca_key, &ca_cert, &issuer_key)?;

        let ca_cert_pem = ca_cert.to_pem()?;
        let ca_cert_der = ca_cert.to_der()?;
        let issuer_cert_der = issuer_cert.to_der()?;

        let device_ec = device_key.ec_key()?;
        let device_pubkey_jwk = ec_key_to_public_jwk(&device_ec)?;

        Ok(Self {
            ca_cert_pem,
            issuer_cert_der,
            ca_cert_der,
            issuer_key,
            device_key,
            device_pubkey_jwk,
        })
    }

    // -------------------------------------------------------------------------
    // SD-JWT credential builders
    // -------------------------------------------------------------------------

    /// Build a signed **EU Age Verification Profile** SD-JWT VC.
    ///
    /// - `vct = "eu.europa.ec.av.1"`, claim `over_18 = true`
    /// - The KB-JWT binds to `nonce` for replay prevention.
    ///
    /// Returns `"<issuer-jwt>~<kb-jwt>"`.
    pub fn build_eu_age_sd_jwt(&self, nonce: &str, client_id: &str) -> CredentialResult<String> {
        build_eu_age_sd_jwt(
            &self.issuer_key,
            &self.issuer_cert_der,
            &self.device_pubkey_jwk,
            &self.device_key,
            nonce,
            client_id,
        )
    }

    /// Build a signed **EUDI PID SD-JWT VC**.
    ///
    /// - `vct = "eu.europa.ec.eudi.pid.1"`
    /// - Claims: `given_name`, `family_name`, `birth_date`, `age_over_18`
    ///
    /// Returns `"<issuer-jwt>~<kb-jwt>"`.
    pub fn build_eudi_sd_jwt(&self, nonce: &str, client_id: &str) -> CredentialResult<String> {
        build_eudi_pid_sd_jwt(
            &self.issuer_key,
            &self.issuer_cert_der,
            &self.device_pubkey_jwk,
            &self.device_key,
            nonce,
            client_id,
        )
    }

    // -------------------------------------------------------------------------
    // mDoc credential builder
    // -------------------------------------------------------------------------

    /// Build a signed **EUDI PID mDoc** `DeviceResponse`.
    ///
    /// - `docType = "eu.europa.ec.eudi.pid.1"` (ISO 18013-5)
    /// - Claims: `given_name`, `family_name`, `birth_date`, `age_over_18`
    /// - `DeviceSignature` bound to `SessionTranscript` via OpenID4VP handover.
    ///
    /// Returns a **base64url-encoded** CBOR `DeviceResponse`.
    pub fn build_eudi_mdoc(
        &self,
        nonce: &str,
        client_id: &str,
        response_uri: &str,
    ) -> CredentialResult<String> {
        build_eudi_pid_mdoc(
            &self.issuer_key,
            &self.issuer_cert_der,
            &self.ca_cert_der,
            &self.device_key,
            nonce,
            client_id,
            response_uri,
        )
    }

    // -------------------------------------------------------------------------
    // Key material accessors
    // -------------------------------------------------------------------------

    /// Return the device public key as a compact JWK byte string.
    ///
    /// Useful for embedding the holder key in external credential payloads.
    pub fn device_pubkey_jwk_bytes(&self) -> CredentialResult<Vec<u8>> {
        serde_json::to_vec(&self.device_pubkey_jwk)
            .map_err(|e| CredentialError::Serde(e.to_string()))
    }

    /// Extract raw (x, y) coordinates from the device public key.
    ///
    /// Each coordinate is zero-padded to 32 bytes (P-256 field size).
    pub fn device_pubkey_raw_xy(&self) -> CredentialResult<(Vec<u8>, Vec<u8>)> {
        let ec = self.device_key.ec_key()?;
        let group = ec.group();
        let point = ec.public_key();
        let mut ctx = BigNumContext::new()?;
        let mut x = BigNum::new()?;
        let mut y = BigNum::new()?;
        point.affine_coordinates_gfp(group, &mut x, &mut y, &mut ctx)?;
        Ok((x.to_vec_padded(32)?, y.to_vec_padded(32)?))
    }
}
