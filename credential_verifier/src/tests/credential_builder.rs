//! Test-only ephemeral credential builder for end-to-end verification tests.
//!
//! Generates an ephemeral two-level PKI (self-signed CA → issuer leaf) using EC
//! P-256 keys and builds properly-signed test credentials in the three formats
//! exercised by the end-to-end verification tests:
//!
//! - **EU Age Verification Profile SD-JWT VC** (`eu.europa.ec.av.1`)
//! - **EUDI PID SD-JWT VC** (`eu.europa.ec.eudi.pid.1`)
//! - **EUDI PID mDoc** (ISO/IEC 18013-5 `DeviceResponse`)
//!
//! # Security notes
//!
//! - All **private key material** is generated in memory and is **never written
//!   to disk** or stored beyond the test binary lifetime.
//! - Only the **public CA certificate PEM** is written to a caller-supplied
//!   temporary directory so that `load_credential_issuer_cas()` can discover it.
//! - Every call to [`EphemeralIssuer::generate`] produces *fresh*, independent
//!   keys — no shared state between test runs.
//! - This module is compiled **exclusively** under `#[cfg(test)]`.
//!
//! # CBOR / COSE construction
//!
//! The mDoc is built from scratch using `ciborium` for CBOR serialisation and
//! raw OpenSSL ECDSA for signing.  The `SessionTranscript` and
//! `DeviceAuthentication` structures are reconstructed using the exact same
//! algorithm as `credential_verifier::server::verify_endpoint::mdoc` so that
//! the DeviceSignature round-trips correctly through the production verifier.

use base64::Engine as _;
use ciborium::Value as Cbor;
use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey},
    ecdsa::EcdsaSig,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    sign::Signer,
    x509::{
        X509, X509Builder, X509NameBuilder,
        extension::{BasicConstraints, KeyUsage},
    },
};
use serde_json::{Value as Json, json};

// ============================================================================
// Public types
// ============================================================================

/// In-memory credential-issuing authority for tests.
///
/// Holds a two-level PKI where the CA signs the issuer leaf certificate, and a
/// separate device key acts as the wallet holder (SD-JWT KB-JWT + mDoc
/// `DeviceSignature`).  The CA's public certificate PEM must be written to the
/// server's `credential_issuer_ca_dir` before starting the test server.
pub struct EphemeralIssuer {
    /// PEM of the self-signed CA certificate.  Write this to the test server's
    /// `credential_issuer_ca_dir` so the verifier trusts credentials issued by
    /// `issuer_key`.
    pub ca_cert_pem: Vec<u8>,

    /// DER-encoded issuer leaf certificate.  Placed in `x5c[0]` of every
    /// credential header.
    pub issuer_cert_der: Vec<u8>,

    /// DER-encoded CA certificate.  Placed in `x5c[1]` of every credential header
    /// so the verifier can build the full chain without the CA cert on disk.
    ca_cert_der: Vec<u8>,

    /// Issuer private key (EC P-256).  Signs the SD-JWT issuer JWT and the mDoc
    /// `IssuerAuth` COSE_Sign1.
    issuer_key: PKey<Private>,

    /// Device / holder private key (EC P-256).  Signs SD-JWT KB-JWTs and the
    /// mDoc `DeviceSignature` COSE_Sign1.
    device_key: PKey<Private>,

    /// Device public key serialised as a JSON-serialisable JWK (`cnf.jwk` in
    /// SD-JWT issuer payloads and as the reference for KB-JWT verification).
    pub device_pubkey_jwk: Json,
}

impl EphemeralIssuer {
    /// Generate a fresh ephemeral issuing authority with independent EC P-256
    /// key pairs for CA, issuer leaf, and device holder functions.
    pub fn generate() -> Result<Self, openssl::error::ErrorStack> {
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

    // -----------------------------------------------------------------------
    // SD-JWT VC builders
    // -----------------------------------------------------------------------

    /// Build a signed **EU Age Verification Profile** SD-JWT VC.
    ///
    /// `vct` = `"eu.europa.ec.av.1"` with an inline `over_18 = true` claim.
    /// The KB-JWT binds to `nonce` (replay prevention) and is signed by the
    /// device key.
    ///
    /// Format: `<issuer-jwt>~<kb-jwt>`
    pub fn build_eu_age_sd_jwt(&self, nonce: &str, client_id: &str) -> String {
        let now = now_unix();
        let payload = json!({
            "iss": "https://test-issuer.example",
            "vct": "eu.europa.ec.av.1",
            "iat": now,
            "exp": now + 3600,
            "over_18": true,
            "cnf": { "jwk": self.device_pubkey_jwk },
        });
        let issuer_jwt = self.sign_issuer_jwt(payload);
        let kb_jwt = self.sign_kb_jwt(nonce, client_id);
        format!("{issuer_jwt}~{kb_jwt}")
    }

    /// Build a signed **EUDI PID 1 SD-JWT VC**.
    ///
    /// `vct` = `"eu.europa.ec.eudi.pid.1"` with inline `given_name`,
    /// `family_name`, `birth_date`, and `age_over_18` claims.
    pub fn build_eudi_sd_jwt(&self, nonce: &str, client_id: &str) -> String {
        let now = now_unix();
        let payload = json!({
            "iss": "https://test-issuer.example",
            "vct": "eu.europa.ec.eudi.pid.1",
            "iat": now,
            "exp": now + 3600,
            "given_name": "Test",
            "family_name": "User",
            "birth_date": "1990-01-01",
            "age_over_18": true,
            "cnf": { "jwk": self.device_pubkey_jwk },
        });
        let issuer_jwt = self.sign_issuer_jwt(payload);
        let kb_jwt = self.sign_kb_jwt(nonce, client_id);
        format!("{issuer_jwt}~{kb_jwt}")
    }

    // -----------------------------------------------------------------------
    // mDoc DeviceResponse builder
    // -----------------------------------------------------------------------

    /// Build a signed EUDI PID mDoc `DeviceResponse`.
    ///
    /// `docType` = `"eu.europa.ec.eudi.pid.1"` with namespace claims
    /// `given_name`, `family_name`, `birth_date`, `age_over_18`.
    ///
    /// The `IssuerAuth` COSE_Sign1 is signed by `issuer_key` with the issuer
    /// certificate in the `x5c` unprotected header.
    ///
    /// The `DeviceSignature` COSE_Sign1 is signed by `device_key` over the
    /// OpenID4VP `SessionTranscript` reconstructed from `client_id`, `nonce`,
    /// and `response_uri` — exactly as the verifier will reconstruct it.
    ///
    /// Returns the base64url-encoded CBOR DeviceResponse.
    pub fn build_eudi_mdoc(&self, nonce: &str, client_id: &str, response_uri: &str) -> String {
        let doc_type = "eu.europa.ec.eudi.pid.1";
        let namespace = "eu.europa.ec.eudi.pid.1";

        let claims: &[(&str, Cbor)] = &[
            ("given_name", Cbor::Text("Test".to_owned())),
            ("family_name", Cbor::Text("User".to_owned())),
            ("birth_date", Cbor::Text("1990-01-01".to_owned())),
            ("age_over_18", Cbor::Bool(true)),
        ];

        // ── 1. IssuerSignedItems + MSO valueDigests ──────────────────────
        let (issuer_items, value_digests) = build_issuer_signed_items(namespace, claims);

        // ── 2. Device key → COSE_Key for MSO deviceKeyInfo ───────────────
        let device_ec = self.device_key.ec_key().expect("device EC key");
        let device_cose_key_cbor = build_ec_cose_key_cbor(&device_ec);

        // ── 3. MobileSecurityObject ───────────────────────────────────────
        let now = now_unix();
        let valid_from = unix_to_rfc3339(now);
        let valid_until = unix_to_rfc3339(now + 365 * 24 * 3600);
        let mso = build_mso(
            doc_type,
            namespace,
            &value_digests,
            &device_cose_key_cbor,
            &valid_from,
            &valid_until,
        );
        let mso_bytes = cbor_to_vec(&mso);

        // ── 4. IssuerAuth COSE_Sign1 (embedded payload, x5c in unprotected)
        let issuer_protected = es256_protected_header_bytes();
        let issuer_sig_data = cose_sign1_sig_structure(&issuer_protected, b"", &mso_bytes);
        let issuer_sig = ecdsa_p256_sign_raw(&issuer_sig_data, &self.issuer_key);

        let x5chain = Cbor::Array(vec![
            Cbor::Bytes(self.issuer_cert_der.clone()),
            Cbor::Bytes(self.ca_cert_der.clone()),
        ]);
        let issuer_auth = build_cose_sign1(
            &issuer_protected,
            vec![(Cbor::Integer(33_i64.into()), x5chain)],
            Some(mso_bytes),
            issuer_sig,
        );

        // ── 5. SessionTranscript + DeviceAuthentication ───────────────────
        let empty_map_bytes = cbor_to_vec(&Cbor::Map(vec![])); // CBOR({}) = 0xa0

        let session_transcript_bytes =
            build_openid4vp_session_transcript_direct_post(client_id, nonce, response_uri);

        let device_auth_raw =
            build_device_authentication(&session_transcript_bytes, doc_type, &empty_map_bytes);

        // ISO 18013-5 §9.1.3.4: sign over DeviceAuthenticationBytes =
        // #6.24(bstr .cbor DeviceAuthentication)
        let device_auth_bytes = cbor_to_vec(&Cbor::Tag(24, Box::new(Cbor::Bytes(device_auth_raw))));

        // ── 6. DeviceSignature COSE_Sign1 (detached payload) ─────────────
        let device_protected = es256_protected_header_bytes();
        let device_sig_data = cose_sign1_sig_structure(&device_protected, b"", &device_auth_bytes);
        let device_sig = ecdsa_p256_sign_raw(&device_sig_data, &self.device_key);

        let device_signature_cose = build_cose_sign1(
            &device_protected,
            vec![], // no unprotected entries
            None,   // detached payload
            device_sig,
        );

        // DeviceNameSpacesBstr = #6.24(bstr .cbor {})
        let device_ns_tag24 = Cbor::Tag(24, Box::new(Cbor::Bytes(empty_map_bytes)));

        // ── 7. Assemble DeviceResponse ────────────────────────────────────
        let device_response = Cbor::Map(vec![
            (
                Cbor::Text("documents".to_owned()),
                Cbor::Array(vec![Cbor::Map(vec![
                    (
                        Cbor::Text("docType".to_owned()),
                        Cbor::Text(doc_type.to_owned()),
                    ),
                    (
                        Cbor::Text("issuerSigned".to_owned()),
                        Cbor::Map(vec![
                            (
                                Cbor::Text("nameSpaces".to_owned()),
                                Cbor::Map(vec![(
                                    Cbor::Text(namespace.to_owned()),
                                    Cbor::Array(issuer_items),
                                )]),
                            ),
                            (Cbor::Text("issuerAuth".to_owned()), issuer_auth),
                        ]),
                    ),
                    (
                        Cbor::Text("deviceSigned".to_owned()),
                        Cbor::Map(vec![
                            (Cbor::Text("nameSpaces".to_owned()), device_ns_tag24),
                            (
                                Cbor::Text("deviceAuth".to_owned()),
                                Cbor::Map(vec![(
                                    Cbor::Text("deviceSignature".to_owned()),
                                    device_signature_cose,
                                )]),
                            ),
                        ]),
                    ),
                ])]),
            ),
            (Cbor::Text("status".to_owned()), Cbor::Integer(0_i64.into())),
        ]);

        let bytes = cbor_to_vec(&device_response);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    // -----------------------------------------------------------------------
    // Private signing helpers
    // -----------------------------------------------------------------------

    /// Sign an SD-JWT issuer payload.
    ///
    /// Adds the issuer leaf certificate in `x5c[0]` (base64-standard encoded
    /// DER) to the JWT header so the verifier can chain-validate it.
    fn sign_issuer_jwt(&self, payload: Json) -> String {
        use jsonwebtoken::{Algorithm, EncodingKey, Header};

        let issuer_cert_b64 =
            base64::engine::general_purpose::STANDARD.encode(&self.issuer_cert_der);

        let mut header = Header::new(Algorithm::ES256);
        header.x5c = Some(vec![issuer_cert_b64]);

        let key_pem = self
            .issuer_key
            .private_key_to_pem_pkcs8()
            .expect("issuer key → PKCS8 PEM");
        let encoding_key =
            EncodingKey::from_ec_pem(&key_pem).expect("issuer EncodingKey from EC PEM");

        jsonwebtoken::encode(&header, &payload, &encoding_key).expect("sign issuer JWT")
    }

    /// Sign an SD-JWT Key Binding JWT with the device private key.
    ///
    /// The `nonce` claim binds the KB-JWT to the server's transaction (replay
    /// prevention); `aud` identifies the relying party.
    fn sign_kb_jwt(&self, nonce: &str, aud: &str) -> String {
        use jsonwebtoken::{Algorithm, EncodingKey, Header};

        let kb_payload = json!({
            "nonce": nonce,
            "aud":   aud,
            "iat":   now_unix(),
        });

        let header = Header::new(Algorithm::ES256);
        let key_pem = self
            .device_key
            .private_key_to_pem_pkcs8()
            .expect("device key → PKCS8 PEM");
        let encoding_key =
            EncodingKey::from_ec_pem(&key_pem).expect("device EncodingKey from EC PEM");

        jsonwebtoken::encode(&header, &kb_payload, &encoding_key).expect("sign KB-JWT")
    }
}

// ============================================================================
// X.509 helpers (private)
// ============================================================================

/// Build a self-signed CA certificate from `ca_key`.
fn build_ca_cert(ca_key: &PKey<Private>) -> Result<X509, openssl::error::ErrorStack> {
    let mut b = X509Builder::new()?;
    b.set_version(2)?;
    let serial_bn = BigNum::from_u32(1)?;
    let serial_num = Asn1Integer::from_bn(&serial_bn)?;
    b.set_serial_number(&serial_num)?;

    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_text("CN", "ewQwe Test Credential CA")?;
    name.append_entry_by_text("O", "ewQwe Test")?;
    let name = name.build();
    b.set_subject_name(&name)?;
    b.set_issuer_name(&name)?; // self-signed

    let not_before = Asn1Time::days_from_now(0)?;
    let not_after = Asn1Time::days_from_now(365)?;
    b.set_not_before(&not_before)?;
    b.set_not_after(&not_after)?;
    b.set_pubkey(ca_key)?;

    b.append_extension(BasicConstraints::new().critical().ca().build()?)?;
    b.append_extension(
        KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()?,
    )?;

    b.sign(ca_key, MessageDigest::sha256())?;
    Ok(b.build())
}

/// Build an issuer leaf certificate signed by `ca_key` / `ca_cert`.
fn build_issuer_cert(
    ca_key: &PKey<Private>,
    ca_cert: &X509,
    issuer_key: &PKey<Private>,
) -> Result<X509, openssl::error::ErrorStack> {
    let mut b = X509Builder::new()?;
    b.set_version(2)?;
    let serial_bn = BigNum::from_u32(2)?;
    let serial_num = Asn1Integer::from_bn(&serial_bn)?;
    b.set_serial_number(&serial_num)?;

    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_text("CN", "ewQwe Test Credential Issuer")?;
    name.append_entry_by_text("O", "ewQwe Test")?;
    let name = name.build();
    b.set_subject_name(&name)?;
    b.set_issuer_name(ca_cert.subject_name())?;

    let not_before = Asn1Time::days_from_now(0)?;
    let not_after = Asn1Time::days_from_now(365)?;
    b.set_not_before(&not_before)?;
    b.set_not_after(&not_after)?;
    b.set_pubkey(issuer_key)?;

    b.append_extension(BasicConstraints::new().build()?)?;

    b.sign(ca_key, MessageDigest::sha256())?;
    Ok(b.build())
}

// ============================================================================
// Key helpers (private)
// ============================================================================

/// Extract the public key coordinates from an EC private key and serialise them
/// as a JWK `{"kty":"EC","crv":"P-256","x":…,"y":…}`.
fn ec_key_to_public_jwk(ec: &EcKey<Private>) -> Result<Json, openssl::error::ErrorStack> {
    let group = ec.group();
    let point = ec.public_key();
    let mut ctx = BigNumContext::new()?;
    let mut x = BigNum::new()?;
    let mut y = BigNum::new()?;
    point.affine_coordinates_gfp(group, &mut x, &mut y, &mut ctx)?;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    Ok(json!({
        "kty": "EC",
        "crv": "P-256",
        "x": b64.encode(x.to_vec_padded(32)?),
        "y": b64.encode(y.to_vec_padded(32)?),
    }))
}

/// Serialise an EC private key's public component as a COSE_Key CBOR value.
///
/// Encoding: `{1:2, 3:-7, -1:1, -2:x_bytes, -3:y_bytes}` (kty=EC2, alg=ES256, crv=P-256).
fn build_ec_cose_key_cbor(ec: &EcKey<Private>) -> Vec<u8> {
    let group = ec.group();
    let point = ec.public_key();
    let mut ctx = BigNumContext::new().expect("BigNumContext");
    let mut x = BigNum::new().expect("BigNum x");
    let mut y = BigNum::new().expect("BigNum y");
    point
        .affine_coordinates_gfp(group, &mut x, &mut y, &mut ctx)
        .expect("affine_coordinates_gfp");

    let x_bytes = x.to_vec_padded(32).expect("x padded");
    let y_bytes = y.to_vec_padded(32).expect("y padded");

    let cose_key = Cbor::Map(vec![
        // kty = EC2
        (Cbor::Integer(1_i64.into()), Cbor::Integer(2_i64.into())),
        // alg = ES256
        (Cbor::Integer(3_i64.into()), Cbor::Integer((-7_i64).into())),
        // crv = P-256
        (Cbor::Integer((-1_i64).into()), Cbor::Integer(1_i64.into())),
        // x coordinate
        (Cbor::Integer((-2_i64).into()), Cbor::Bytes(x_bytes)),
        // y coordinate
        (Cbor::Integer((-3_i64).into()), Cbor::Bytes(y_bytes)),
    ]);
    cbor_to_vec(&cose_key)
}

// ============================================================================
// ECDSA signing (private)
// ============================================================================

/// Sign `data` with P-256 ECDSA SHA-256 and return the raw fixed-length R‖S
/// (64 bytes) signature required by COSE ES256.
///
/// OpenSSL returns DER, which is converted to raw IEEE P1363 form so that the
/// verifier's `verify_ecdsa_signature` can validate it.
fn ecdsa_p256_sign_raw(data: &[u8], key: &PKey<Private>) -> Vec<u8> {
    let mut signer = Signer::new(MessageDigest::sha256(), key).expect("Signer::new");
    signer.update(data).expect("Signer::update");
    let der = signer.sign_to_vec().expect("Signer::sign_to_vec");
    let sig = EcdsaSig::from_der(&der).expect("EcdsaSig::from_der");
    let mut r = sig.r().to_vec_padded(32).expect("r padded");
    let mut s = sig.s().to_vec_padded(32).expect("s padded");
    r.append(&mut s);
    r
}

// ============================================================================
// COSE building helpers (private)
// ============================================================================

/// Return the CBOR-encoded protected header for ES256: `{1: -7}`.
fn es256_protected_header_bytes() -> Vec<u8> {
    cbor_to_vec(&Cbor::Map(vec![(
        Cbor::Integer(1_i64.into()),
        Cbor::Integer((-7_i64).into()),
    )]))
}

/// Compute the `Sig_Structure` bytes (RFC 8152 §4.4) for a COSE_Sign1.
///
/// ```text
/// Sig_Structure = ["Signature1", bstr protected, bstr external_aad, bstr payload]
/// ```
fn cose_sign1_sig_structure(protected: &[u8], external_aad: &[u8], payload: &[u8]) -> Vec<u8> {
    cbor_to_vec(&Cbor::Array(vec![
        Cbor::Text("Signature1".to_owned()),
        Cbor::Bytes(protected.to_vec()),
        Cbor::Bytes(external_aad.to_vec()),
        Cbor::Bytes(payload.to_vec()),
    ]))
}

/// Construct a COSE_Sign1 CBOR tag-18 value.
///
/// `payload = None` produces a **detached** signature (nil in the array).
///
/// The layout is:
/// ```text
/// COSE_Sign1 = #18([protected: bstr, unprotected: {}, payload: bstr/nil, signature: bstr])
/// ```
fn build_cose_sign1(
    protected_bytes: &[u8],
    unprotected_entries: Vec<(Cbor, Cbor)>,
    payload: Option<Vec<u8>>,
    signature: Vec<u8>,
) -> Cbor {
    Cbor::Tag(
        18,
        Box::new(Cbor::Array(vec![
            Cbor::Bytes(protected_bytes.to_vec()),
            Cbor::Map(unprotected_entries),
            match payload {
                Some(p) => Cbor::Bytes(p),
                None => Cbor::Null,
            },
            Cbor::Bytes(signature),
        ])),
    )
}

// ============================================================================
// mDoc construction helpers (private)
// ============================================================================

/// Build `IssuerSignedItem` CBOR arrays and the corresponding MSO value
/// digests.
///
/// Returns `(tag24-wrapped items for nameSpaces array, [(digestID, digest)])`.
///
/// Per ISO 18013-5 §9.1.2.4 the digest covers the full
/// `IssuerSignedItemBytes` CBOR encoding: `#6.24(bstr .cbor IssuerSignedItem)`.
fn build_issuer_signed_items(
    namespace: &str,
    claims: &[(&str, Cbor)],
) -> (Vec<Cbor>, Vec<(u64, Vec<u8>)>) {
    let _ = namespace; // namespace is embedded in the nameSpaces map by the caller
    let mut items = Vec::new();
    let mut digests = Vec::new();

    for (idx, (name, value)) in claims.iter().enumerate() {
        let digest_id = idx as u64;
        // Fresh random bytes per item (pseudo-random salt using uuid).
        let random = uuid::Uuid::new_v4().to_bytes_le().to_vec();

        let item_map = Cbor::Map(vec![
            (
                Cbor::Text("digestID".to_owned()),
                Cbor::Integer((digest_id as i64).into()),
            ),
            (Cbor::Text("random".to_owned()), Cbor::Bytes(random)),
            (
                Cbor::Text("elementIdentifier".to_owned()),
                Cbor::Text((*name).to_owned()),
            ),
            (Cbor::Text("elementValue".to_owned()), value.clone()),
        ]);
        let item_cbor = cbor_to_vec(&item_map);

        // IssuerSignedItemBytes = #6.24(bstr .cbor IssuerSignedItem)
        let tag24 = Cbor::Tag(24, Box::new(Cbor::Bytes(item_cbor)));
        // digest = SHA-256(CBOR(tag24))  ← same as verifier's hash computation
        let tag24_bytes = cbor_to_vec(&tag24);
        let digest = sha256_digest(&tag24_bytes);

        digests.push((digest_id, digest));
        items.push(tag24);
    }

    (items, digests)
}

/// Build the `MobileSecurityObject` CBOR map.
//
// All date strings are RFC 3339 / tdate text values, which is what
// `cbor_value_to_text()` in the verifier expects.
fn build_mso(
    doc_type: &str,
    namespace: &str,
    value_digests: &[(u64, Vec<u8>)],
    device_key_cose_cbor: &[u8],
    valid_from: &str,
    valid_until: &str,
) -> Cbor {
    let device_key_value: Cbor =
        ciborium::from_reader(device_key_cose_cbor).expect("parse device COSE_Key");

    let digest_entries: Vec<(Cbor, Cbor)> = value_digests
        .iter()
        .map(|(id, d)| (Cbor::Integer((*id as i64).into()), Cbor::Bytes(d.clone())))
        .collect();

    Cbor::Map(vec![
        (
            Cbor::Text("version".to_owned()),
            Cbor::Text("1.0".to_owned()),
        ),
        (
            Cbor::Text("digestAlgorithm".to_owned()),
            Cbor::Text("SHA-256".to_owned()),
        ),
        (
            Cbor::Text("valueDigests".to_owned()),
            Cbor::Map(vec![(
                Cbor::Text(namespace.to_owned()),
                Cbor::Map(digest_entries),
            )]),
        ),
        (
            Cbor::Text("deviceKeyInfo".to_owned()),
            Cbor::Map(vec![(Cbor::Text("deviceKey".to_owned()), device_key_value)]),
        ),
        (
            Cbor::Text("docType".to_owned()),
            Cbor::Text(doc_type.to_owned()),
        ),
        (
            Cbor::Text("validityInfo".to_owned()),
            Cbor::Map(vec![
                (
                    Cbor::Text("signed".to_owned()),
                    Cbor::Text(valid_from.to_owned()),
                ),
                (
                    Cbor::Text("validFrom".to_owned()),
                    Cbor::Text(valid_from.to_owned()),
                ),
                (
                    Cbor::Text("validUntil".to_owned()),
                    Cbor::Text(valid_until.to_owned()),
                ),
            ]),
        ),
    ])
}

/// Build the CBOR bytes of an OpenID4VP `SessionTranscript` for a
/// `direct_post` (non-encrypted) response mode.
///
/// This mirrors `build_openid4vp_session_transcript` in
/// `credential_verifier::server::verify_endpoint::mdoc` for
/// `ResponseMode::DirectPost`.
///
/// ```text
/// SessionTranscript = [null, null, ["OpenID4VPHandover", SHA-256(CBOR([client_id, nonce, null, response_uri]))]]
/// ```
pub fn build_openid4vp_session_transcript_direct_post(
    client_id: &str,
    nonce: &str,
    response_uri: &str,
) -> Vec<u8> {
    let handover_info = Cbor::Array(vec![
        Cbor::Text(client_id.to_owned()),
        Cbor::Text(nonce.to_owned()),
        Cbor::Null, // jwk_thumbprint = None for DirectPost / non-encrypted
        Cbor::Text(response_uri.to_owned()),
    ]);
    let handover_info_bytes = cbor_to_vec(&handover_info);
    let handover_hash = openssl::sha::sha256(&handover_info_bytes).to_vec();

    let handover = Cbor::Array(vec![
        Cbor::Text("OpenID4VPHandover".to_owned()),
        Cbor::Bytes(handover_hash),
    ]);

    cbor_to_vec(&Cbor::Array(vec![Cbor::Null, Cbor::Null, handover]))
}

/// Build the `DeviceAuthentication` CBOR bytes.
///
/// Mirrors `build_device_authentication_payload` in the verifier.
///
/// ```text
/// DeviceAuthentication = ["DeviceAuthentication", SessionTranscript, docType,
///                          #6.24(bstr .cbor DeviceNameSpaces)]
/// ```
fn build_device_authentication(
    session_transcript_bytes: &[u8],
    doc_type: &str,
    device_namespace_bytes: &[u8],
) -> Vec<u8> {
    let session_transcript: Cbor =
        ciborium::from_reader(session_transcript_bytes).expect("parse SessionTranscript");

    let device_namespaces_bstr =
        Cbor::Tag(24, Box::new(Cbor::Bytes(device_namespace_bytes.to_vec())));

    cbor_to_vec(&Cbor::Array(vec![
        Cbor::Text("DeviceAuthentication".to_owned()),
        session_transcript,
        Cbor::Text(doc_type.to_owned()),
        device_namespaces_bstr,
    ]))
}

// ============================================================================
// Generic helpers (private)
// ============================================================================

fn cbor_to_vec(value: &Cbor) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).expect("CBOR serialisation");
    buf
}

fn sha256_digest(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::new().chain_update(data).finalize().to_vec()
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock")
        .as_secs() as i64
}

fn unix_to_rfc3339(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .expect("valid timestamp")
        .to_rfc3339()
}
