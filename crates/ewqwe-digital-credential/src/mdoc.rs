//! ISO/IEC 18013-5 mDoc / `DeviceResponse` building and signing.
//!
//! Builds a complete EUDI PID 1 `DeviceResponse` CBOR structure with:
//!
//! - **`IssuerAuth`** COSE_Sign1 signed by the issuer key (ESP256), with the
//!   issuer certificate chain in the unprotected `x5chain` header (label 33).
//! - **`MobileSecurityObject`** (MSO) containing SHA-256 `valueDigests` of all
//!   `IssuerSignedItem`s and the device public key as a `COSE_Key`.
//! - **`DeviceSignature`** COSE_Sign1 (detached payload) signed by the device
//!   key over `DeviceAuthenticationBytes`, which are bound to the OpenID4VP
//!   `SessionTranscript` for the given `client_id`, `nonce`, and `response_uri`.
//!
//! The CBOR layout is compatible with the production credential verifier's
//! `mdoc` verification module.

use base64::Engine as _;
use ciborium::Value as Cbor;
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::EcKey,
    ecdsa::EcdsaSig,
    hash::MessageDigest,
    pkey::{PKey, Private},
    sign::Signer,
};
use serde_json::{Value as Json, json};

use crate::{
    CredentialError,
    error::CredentialResult,
    util::{cbor_to_vec, now_unix, sha256, unix_to_rfc3339},
};

/// Build a signed EUDI PID mDoc `DeviceResponse`.
///
/// `docType = "eu.europa.ec.eudi.pid.1"` with namespace claims:
/// `given_name`, `family_name`, `birth_date`, `age_over_18`.
///
/// Returns the **base64url-encoded** CBOR `DeviceResponse`.
pub fn build_eudi_pid_mdoc(
    issuer_key: &PKey<Private>,
    issuer_cert_der: &[u8],
    ca_cert_der: &[u8],
    device_key: &PKey<Private>,
    nonce: &str,
    client_id: &str,
    response_uri: &str,
) -> CredentialResult<String> {
    let doc_type = "eu.europa.ec.eudi.pid.1";
    let namespace = "eu.europa.ec.eudi.pid.1";

    let claims: &[(&str, Cbor)] = &[
        ("given_name", Cbor::Text("Test".to_owned())),
        ("family_name", Cbor::Text("User".to_owned())),
        ("birth_date", Cbor::Text("1990-01-01".to_owned())),
        ("age_over_18", Cbor::Bool(true)),
    ];

    // ── 1. IssuerSignedItems + MSO valueDigests ──────────────────────────
    let IssuerSignedItems {
        items: issuer_items,
        digests: value_digests,
    } = build_issuer_signed_items(namespace, claims)?;

    // ── 2. Device key → COSE_Key for MSO deviceKeyInfo ───────────────────
    let device_ec = device_key.ec_key()?;
    let device_cose_key_cbor = build_ec_cose_key_cbor(&device_ec)?;

    // ── 3. MobileSecurityObject ───────────────────────────────────────────
    let now = now_unix()?;
    let valid_from = unix_to_rfc3339(now)?;
    let valid_until = unix_to_rfc3339(now + 365 * 24 * 3600)?;
    let mso = build_mso(
        doc_type,
        namespace,
        &value_digests,
        &device_cose_key_cbor,
        &valid_from,
        &valid_until,
    )?;
    let mso_bytes = cbor_to_vec(&mso)?;

    // ── 4. IssuerAuth COSE_Sign1 ──────────────────────────────────────────
    let issuer_protected = es256_protected_header_bytes()?;
    let issuer_sig_data = cose_sign1_sig_structure(&issuer_protected, b"", &mso_bytes)?;
    let issuer_sig = ecdsa_p256_sign_raw(&issuer_sig_data, issuer_key)?;

    let x5chain = Cbor::Array(vec![
        Cbor::Bytes(issuer_cert_der.to_vec()),
        Cbor::Bytes(ca_cert_der.to_vec()),
    ]);
    let issuer_auth = build_cose_sign1(
        &issuer_protected,
        vec![(Cbor::Integer(33_i64.into()), x5chain)],
        Some(mso_bytes),
        issuer_sig,
    );

    // ── 5. SessionTranscript + DeviceAuthentication ───────────────────────
    let empty_map_bytes = cbor_to_vec(&Cbor::Map(vec![]))?;
    let session_transcript_bytes =
        build_openid4vp_session_transcript_direct_post(client_id, nonce, response_uri)?;

    let device_auth_raw =
        build_device_authentication(&session_transcript_bytes, doc_type, &empty_map_bytes)?;

    // ISO 18013-5 §9.1.3.4: DeviceAuthenticationBytes = #6.24(bstr .cbor DeviceAuthentication)
    let device_auth_bytes = cbor_to_vec(&Cbor::Tag(24, Box::new(Cbor::Bytes(device_auth_raw))))?;

    // ── 6. DeviceSignature COSE_Sign1 (detached payload) ─────────────────
    let device_protected = es256_protected_header_bytes()?;
    let device_sig_data = cose_sign1_sig_structure(&device_protected, b"", &device_auth_bytes)?;
    let device_sig = ecdsa_p256_sign_raw(&device_sig_data, device_key)?;

    let device_signature_cose = build_cose_sign1(
        &device_protected,
        vec![], // no unprotected entries
        None,   // detached payload
        device_sig,
    );

    // DeviceNameSpacesBstr = #6.24(bstr .cbor {})
    let device_ns_tag24 = Cbor::Tag(24, Box::new(Cbor::Bytes(empty_map_bytes)));

    // ── 7. Assemble DeviceResponse ────────────────────────────────────────
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

    let bytes = cbor_to_vec(&device_response)?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

/// Extract the P-256 public key coordinates from an EC key and encode them as
/// a JWK `{"kty":"EC","crv":"P-256","x":…,"y":…}`.
pub fn ec_key_to_public_jwk(ec: &EcKey<Private>) -> CredentialResult<Json> {
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

/// Build an OpenID4VP `SessionTranscript` for a `direct_post` response mode.
///
/// ```text
/// SessionTranscript = [null, null,
///   ["OpenID4VPHandover", SHA-256(CBOR([client_id, nonce, null, response_uri]))]]
/// ```
///
/// Mirrors `build_openid4vp_session_transcript` in the credential verifier for
/// `ResponseMode::DirectPost`.
pub fn build_openid4vp_session_transcript_direct_post(
    client_id: &str,
    nonce: &str,
    response_uri: &str,
) -> CredentialResult<Vec<u8>> {
    let handover_info = Cbor::Array(vec![
        Cbor::Text(client_id.to_owned()),
        Cbor::Text(nonce.to_owned()),
        Cbor::Null, // jwk_thumbprint = None for DirectPost / non-encrypted
        Cbor::Text(response_uri.to_owned()),
    ]);
    let handover_info_bytes = cbor_to_vec(&handover_info)?;
    let handover_hash = sha256(&handover_info_bytes);

    let handover = Cbor::Array(vec![
        Cbor::Text("OpenID4VPHandover".to_owned()),
        Cbor::Bytes(handover_hash),
    ]);

    cbor_to_vec(&Cbor::Array(vec![Cbor::Null, Cbor::Null, handover]))
}

// ============================================================================
// Private helpers
// ============================================================================

pub struct IssuerSignedItems {
    pub items: Vec<Cbor>,
    pub digests: Vec<(u64, Vec<u8>)>,
}

/// Build `IssuerSignedItem` CBOR arrays and MSO `valueDigests`.
///
/// Per ISO 18013-5 §9.1.2.4 the digest covers the full
/// `IssuerSignedItemBytes` = `#6.24(bstr .cbor IssuerSignedItem)`.
fn build_issuer_signed_items(
    _namespace: &str,
    claims: &[(&str, Cbor)],
) -> CredentialResult<IssuerSignedItems> {
    let mut items = Vec::new();
    let mut digests = Vec::new();

    for (idx, (name, value)) in claims.iter().enumerate() {
        let digest_id = idx as u64;
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
        let item_cbor = cbor_to_vec(&item_map)?;

        // IssuerSignedItemBytes = #6.24(bstr .cbor IssuerSignedItem)
        let tag24 = Cbor::Tag(24, Box::new(Cbor::Bytes(item_cbor)));
        let tag24_bytes = cbor_to_vec(&tag24)?;
        let digest = sha256(&tag24_bytes);

        digests.push((digest_id, digest));
        items.push(tag24);
    }

    Ok(IssuerSignedItems { items, digests })
}

/// Build a `MobileSecurityObject` CBOR map.
fn build_mso(
    doc_type: &str,
    namespace: &str,
    value_digests: &[(u64, Vec<u8>)],
    device_key_cose_cbor: &[u8],
    valid_from: &str,
    valid_until: &str,
) -> CredentialResult<Cbor> {
    let device_key_value: Cbor = ciborium::from_reader(device_key_cose_cbor)
        .map_err(|e| CredentialError::Serde(e.to_string()))?;

    let digest_entries: Vec<(Cbor, Cbor)> = value_digests
        .iter()
        .map(|(id, d)| (Cbor::Integer((*id as i64).into()), Cbor::Bytes(d.clone())))
        .collect();

    Ok(Cbor::Map(vec![
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
    ]))
}

/// Build the `DeviceAuthentication` CBOR bytes.
///
/// ```text
/// DeviceAuthentication = ["DeviceAuthentication", SessionTranscript, docType,
///                          #6.24(bstr .cbor DeviceNameSpaces)]
/// ```
fn build_device_authentication(
    session_transcript_bytes: &[u8],
    doc_type: &str,
    device_namespace_bytes: &[u8],
) -> CredentialResult<Vec<u8>> {
    let session_transcript: Cbor = ciborium::from_reader(session_transcript_bytes)
        .map_err(|e| CredentialError::Serde(e.to_string()))?;

    let device_namespaces_bstr =
        Cbor::Tag(24, Box::new(Cbor::Bytes(device_namespace_bytes.to_vec())));

    cbor_to_vec(&Cbor::Array(vec![
        Cbor::Text("DeviceAuthentication".to_owned()),
        session_transcript,
        Cbor::Text(doc_type.to_owned()),
        device_namespaces_bstr,
    ]))
}

/// Serialise an EC private key's public component as a COSE_Key CBOR value.
///
/// `{1:2, 3:-7, -1:1, -2:x_bytes, -3:y_bytes}` (kty=EC2, alg=ES256, crv=P-256).
fn build_ec_cose_key_cbor(ec: &EcKey<Private>) -> CredentialResult<Vec<u8>> {
    let group = ec.group();
    let point = ec.public_key();
    let mut ctx = BigNumContext::new()?;
    let mut x = BigNum::new()?;
    let mut y = BigNum::new()?;
    point.affine_coordinates_gfp(group, &mut x, &mut y, &mut ctx)?;

    let x_bytes = x.to_vec_padded(32)?;
    let y_bytes = y.to_vec_padded(32)?;

    let cose_key = Cbor::Map(vec![
        (Cbor::Integer(1_i64.into()), Cbor::Integer(2_i64.into())), // kty = EC2
        (Cbor::Integer(3_i64.into()), Cbor::Integer((-7_i64).into())), // alg = ES256
        (Cbor::Integer((-1_i64).into()), Cbor::Integer(1_i64.into())), // crv = P-256
        (Cbor::Integer((-2_i64).into()), Cbor::Bytes(x_bytes)),     // x
        (Cbor::Integer((-3_i64).into()), Cbor::Bytes(y_bytes)),     // y
    ]);
    cbor_to_vec(&cose_key)
}

/// Sign `data` with P-256 ECDSA SHA-256 and return the raw R‖S (64 bytes)
/// IEEE P1363 form used by COSE ES256.
fn ecdsa_p256_sign_raw(data: &[u8], key: &PKey<Private>) -> CredentialResult<Vec<u8>> {
    let mut signer = Signer::new(MessageDigest::sha256(), key)?;
    signer.update(data)?;
    let der = signer.sign_to_vec()?;
    let sig = EcdsaSig::from_der(&der)?;
    let mut r = sig.r().to_vec_padded(32)?;
    let mut s = sig.s().to_vec_padded(32)?;
    r.append(&mut s);
    Ok(r)
}

/// Return the CBOR-encoded protected header bytes for ES256: `{1: -7}`.
fn es256_protected_header_bytes() -> CredentialResult<Vec<u8>> {
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
fn cose_sign1_sig_structure(
    protected: &[u8],
    external_aad: &[u8],
    payload: &[u8],
) -> CredentialResult<Vec<u8>> {
    cbor_to_vec(&Cbor::Array(vec![
        Cbor::Text("Signature1".to_owned()),
        Cbor::Bytes(protected.to_vec()),
        Cbor::Bytes(external_aad.to_vec()),
        Cbor::Bytes(payload.to_vec()),
    ]))
}

/// Construct a `COSE_Sign1` CBOR tag-18 value.
///
/// `payload = None` produces a **detached** signature (nil in the array).
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
