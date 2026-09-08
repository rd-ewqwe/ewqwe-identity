//! mDoc / CBOR presentation verification (ISO/IEC 18013-5).
//!
//! Handles `DeviceResponse` CBOR decoding, `IssuerAuth` `COSE_Sign1`
//! verification, `IssuerSigned` digest validation, and `DeviceSignature`
//! holder-binding verification over the reconstructed OpenID4VP
//! `SessionTranscript`.
//!
//! # Entry point
//!
//! [`verify_mdoc_presentation`] is the single public entry point.  It
//! performs the full chain of checks:
//!
//! 1. Base64(url) decode → CBOR parse → navigate `DeviceResponse`.
//! 2. Extract `IssuerAuth` `COSE_Sign1`, verify `x5chain` certificate chain,
//!    and verify the issuer signature.
//! 3. Parse the `MobileSecurityObject` (MSO) from the issuer payload,
//!    validate `docType`, reconstruct digest map.
//! 4. Verify each `IssuerSignedItem` digest against the MSO.
//! 5. Parse `DeviceSigned`, verify the `DeviceSignature` `COSE_Sign1`
//!    over the reconstructed `SessionTranscript`.
//! 6. Validate MSO validity dates.

use base64::Engine;
use coset::{CborSerializable, CoseKey, CoseSign1, Label, RegisteredLabelWithPrivate, iana};
use openssl::{
    bn::BigNum,
    ec::{EcGroup, EcKey},
    ecdsa::EcdsaSig,
    hash::{MessageDigest, hash},
    nid::Nid,
    pkey::{PKey, Public},
    rsa::Padding,
    sign::Verifier as OpensslVerifier,
    x509::X509,
};

use crate::{
    error::{CredentialError, CredentialResult},
    mdoc_decoder,
    util::{
        as_cbor_array, as_cbor_map, cbor_integer_to_u64, cbor_map_get, cbor_map_get_text,
        cbor_to_vec_fallible, cbor_value_to_text, unwrap_cbor_tags,
    },
};

// ============================================================================
// Public types
// ============================================================================

/// Result of a successful mDoc presentation verification.
pub struct MdocVerificationResult {
    /// All disclosed claims (JSON representation of the single/primary
    /// namespace, or nested by namespace).
    pub claims: serde_json::Value,
    /// The `docType` string from the document, e.g. `"org.iso.18013.5.1.mDL"`.
    pub doc_type: String,
    /// The primary namespace, e.g. `"org.iso.18013.5.1"`.
    pub namespace: String,
    /// Whether the `MobileSecurityObject` validity window includes the current time.
    pub not_expired: bool,
    /// Whether the issuer certificate chain was validated against a trusted CA.
    pub issuer_trusted: bool,
}

struct ParsedMobileSecurityObject {
    doc_type: String,
    digest_algorithm: String,
    value_digests: std::collections::BTreeMap<String, std::collections::BTreeMap<u64, Vec<u8>>>,
    device_key: CoseKey,
    valid_from: Option<String>,
    valid_until: Option<String>,
}

// ============================================================================
// Public verification entry point
// ============================================================================

/// Verify an mDoc/`DeviceResponse` compact presentation end-to-end.
///
/// # Parameters
///
/// - `encoded`    — Base64URL or Base64 encoded `DeviceResponse` CBOR.
/// - `client_id`  — The `client_id` from the OpenID4VP request.
/// - `nonce`      — The `nonce` from the OpenID4VP request.
/// - `response_uri` — The `response_uri` from the OpenID4VP request.
/// - `response_mode_requires_encryption` — `true` when the session used
///   `response_mode=direct_post.jwt` or `dc_api.jwt`.
/// - `response_jwk_thumbprint` — The JWK thumbprint of the encryption key
///   used in the response.  Required when `response_mode_requires_encryption`
///   is `true`.
/// - `trusted_cas` — DER-encoded certificates of trusted issuer CAs.
///
/// Returns a [`MdocVerificationResult`] on success or a
/// [`CredentialError::InvalidPresentation`] on any failure.
pub fn verify_mdoc_presentation(
    encoded: &str,
    client_id: &str,
    nonce: &str,
    response_uri: &str,
    response_mode_requires_encryption: bool,
    response_jwk_thumbprint: Option<&[u8]>,
    trusted_cas: &[X509],
) -> CredentialResult<MdocVerificationResult> {
    let decoded = mdoc_decoder::decode_mdoc_presentation(encoded).map_err(|e| {
        CredentialError::InvalidPresentation(format!("mDoc CBOR decode failed: {e}"))
    })?;

    let bytes = decode_base64url_or_base64(encoded).map_err(|e| {
        CredentialError::InvalidPresentation(format!("mDoc base64 decode failed: {e}"))
    })?;
    let cbor: ciborium::Value = ciborium::from_reader(&bytes[..]).map_err(|e| {
        CredentialError::InvalidPresentation(format!("mDoc CBOR parse failed: {e}"))
    })?;
    let document = extract_first_document(&cbor)?;
    let document_map = as_cbor_map(document).ok_or_else(|| {
        CredentialError::InvalidPresentation("mDoc document is not a CBOR map".to_string())
    })?;

    let doc_type = cbor_map_get_text(document_map, "docType")
        .ok_or_else(|| {
            CredentialError::InvalidPresentation("mDoc document missing docType".to_string())
        })?
        .to_string();

    let issuer_signed =
        unwrap_cbor_tags(cbor_map_get(document_map, "issuerSigned").ok_or_else(|| {
            CredentialError::InvalidPresentation("mDoc missing issuerSigned".to_string())
        })?);
    let issuer_signed_map = as_cbor_map(issuer_signed).ok_or_else(|| {
        CredentialError::InvalidPresentation("issuerSigned is not a CBOR map".to_string())
    })?;
    let name_spaces = unwrap_cbor_tags(cbor_map_get(issuer_signed_map, "nameSpaces").ok_or_else(
        || CredentialError::InvalidPresentation("issuerSigned missing nameSpaces".to_string()),
    )?);
    let name_spaces_map = as_cbor_map(name_spaces).ok_or_else(|| {
        CredentialError::InvalidPresentation("issuerSigned.nameSpaces is not a map".to_string())
    })?;

    let issuer_auth =
        parse_cose_sign1_from_value(cbor_map_get(issuer_signed_map, "issuerAuth").ok_or_else(
            || CredentialError::InvalidPresentation("issuerSigned missing issuerAuth".to_string()),
        )?)?;
    let issuer_chain = extract_x5chain_from_cose(&issuer_auth)?;
    let (issuer_key, issuer_trusted) = verify_cose_certificate_chain(&issuer_chain, trusted_cas)?;
    verify_cose_sign1_embedded(&issuer_auth, &issuer_key)?;

    let mso = parse_mobile_security_object(issuer_auth.payload.as_deref().ok_or_else(|| {
        CredentialError::InvalidPresentation("issuerAuth missing payload".to_string())
    })?)?;

    if mso.doc_type != doc_type {
        return Err(CredentialError::InvalidPresentation(
            "mDoc docType does not match MobileSecurityObject docType".to_string(),
        ));
    }

    verify_issuer_signed_item_digests(name_spaces_map, &mso)?;

    let device_signed =
        unwrap_cbor_tags(cbor_map_get(document_map, "deviceSigned").ok_or_else(|| {
            CredentialError::InvalidPresentation("mDoc missing deviceSigned".to_string())
        })?);
    let device_signed_map = as_cbor_map(device_signed).ok_or_else(|| {
        CredentialError::InvalidPresentation("deviceSigned is not a CBOR map".to_string())
    })?;
    let device_name_spaces_bytes = extract_device_namespaces_bytes(device_signed_map)?;
    let device_auth = unwrap_cbor_tags(cbor_map_get(device_signed_map, "deviceAuth").ok_or_else(
        || CredentialError::InvalidPresentation("deviceSigned missing deviceAuth".to_string()),
    )?);
    let device_auth_map = as_cbor_map(device_auth).ok_or_else(|| {
        CredentialError::InvalidPresentation("deviceAuth is not a CBOR map".to_string())
    })?;

    let device_signature = cbor_map_get(device_auth_map, "deviceSignature").ok_or_else(|| {
        CredentialError::InvalidPresentation(
            "deviceAuth.deviceMac is not supported by this verifier; expected deviceSignature"
                .to_string(),
        )
    })?;
    let device_signature = parse_cose_sign1_from_value(device_signature)?;
    let session_transcript = build_openid4vp_session_transcript(
        client_id,
        nonce,
        response_uri,
        response_mode_requires_encryption,
        response_jwk_thumbprint,
    )?;
    let device_authentication_raw = build_device_authentication_payload(
        &session_transcript,
        &doc_type,
        &device_name_spaces_bytes,
    )?;
    // ISO 18013-5 §9.1.3.4: DeviceAuthenticationBytes = #6.24(bstr .cbor DeviceAuthentication)
    // The wallet signs over DeviceAuthenticationBytes, not raw DeviceAuthentication.
    let device_authentication_bytes = cbor_to_vec_fallible(&ciborium::Value::Tag(
        24,
        Box::new(ciborium::Value::Bytes(device_authentication_raw)),
    ))?;
    let device_key = cose_key_to_public_key(&mso.device_key)?;
    verify_cose_sign1_detached(&device_signature, &device_key, &device_authentication_bytes)?;

    let namespace = decoded.namespaces.keys().next().cloned().ok_or_else(|| {
        CredentialError::InvalidPresentation("mDoc presentation contains no namespaces".to_string())
    })?;
    let claims = if decoded.namespaces.len() == 1 {
        let (_, ns_claims) = decoded.namespaces.into_iter().next().ok_or_else(|| {
            CredentialError::InvalidPresentation(
                "mDoc presentation contains no namespaces".to_string(),
            )
        })?;
        serde_json::Value::Object(ns_claims.into_iter().collect())
    } else {
        let mut obj = serde_json::Map::new();
        for (ns, ns_claims) in decoded.namespaces {
            let ns_obj: serde_json::Map<String, serde_json::Value> =
                ns_claims.into_iter().collect();
            obj.insert(ns, serde_json::Value::Object(ns_obj));
        }
        serde_json::Value::Object(obj)
    };

    tracing::info!(
        claim_count = claims.as_object().map(|o| o.len()).unwrap_or(0),
        has_portrait = claims.as_object().and_then(|o| o.get("portrait")).is_some(),
        "mDoc verification claims extracted"
    );
    if let Some(portrait_val) = claims
        .as_object()
        .and_then(|o| o.get("portrait"))
        .and_then(|v| v.as_str())
    {
        tracing::info!(
            portrait_len = portrait_val.len(),
            portrait_prefix = %portrait_val.chars().take(40).collect::<String>(),
            "Portrait in verification claims"
        );
    }

    let not_expired = validate_mso_validity(&mso)?;

    Ok(MdocVerificationResult {
        claims,
        doc_type,
        namespace,
        not_expired,
        issuer_trusted,
    })
}

// ============================================================================
// CBOR helpers local to verification
// ============================================================================

fn decode_base64url_or_base64(input: &str) -> std::result::Result<Vec<u8>, base64::DecodeError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(input)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(input))
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(input))
}

fn extract_first_document(cbor: &ciborium::Value) -> CredentialResult<&ciborium::Value> {
    let cbor = unwrap_cbor_tags(cbor);
    let map = as_cbor_map(cbor).ok_or_else(|| {
        CredentialError::InvalidPresentation("mDoc top-level value is not a map".to_string())
    })?;
    if let Some(documents) = cbor_map_get(map, "documents") {
        let documents = as_cbor_array(unwrap_cbor_tags(documents)).ok_or_else(|| {
            CredentialError::InvalidPresentation(
                "mDoc DeviceResponse.documents is not an array".to_string(),
            )
        })?;
        documents.first().ok_or_else(|| {
            CredentialError::InvalidPresentation(
                "mDoc DeviceResponse.documents is empty".to_string(),
            )
        })
    } else {
        Ok(cbor)
    }
}

// ============================================================================
// COSE helpers
// ============================================================================

fn parse_cose_sign1_from_value(value: &ciborium::Value) -> CredentialResult<CoseSign1> {
    let untagged = match value {
        ciborium::Value::Tag(18, inner) => inner.as_ref().clone(),
        other => other.clone(),
    };
    let mut bytes = Vec::new();
    ciborium::into_writer(&untagged, &mut bytes).map_err(|e| {
        CredentialError::InvalidPresentation(format!("COSE serialization failed: {e}"))
    })?;
    CoseSign1::from_slice(&bytes)
        .map_err(|e| CredentialError::InvalidPresentation(format!("COSE_Sign1 parse failed: {e}")))
}

fn extract_x5chain_from_cose(cose: &CoseSign1) -> CredentialResult<Vec<Vec<u8>>> {
    for headers in [&cose.protected.header, &cose.unprotected] {
        for (label, value) in &headers.rest {
            if *label == Label::Int(33) {
                return match value {
                    ciborium::Value::Bytes(cert) => Ok(vec![cert.clone()]),
                    ciborium::Value::Array(items) => items
                        .iter()
                        .map(|item| match item {
                            ciborium::Value::Bytes(cert) => Ok(cert.clone()),
                            _ => Err(CredentialError::InvalidPresentation(
                                "COSE x5chain array contains a non-byte-string certificate"
                                    .to_string(),
                            )),
                        })
                        .collect(),
                    _ => Err(CredentialError::InvalidPresentation(
                        "COSE x5chain header is neither a byte string nor an array".to_string(),
                    )),
                };
            }
        }
    }

    Err(CredentialError::InvalidPresentation(
        "issuerAuth is missing COSE x5chain header parameter 33".to_string(),
    ))
}

fn verify_cose_certificate_chain(
    cert_chain: &[Vec<u8>],
    trusted_cas: &[X509],
) -> CredentialResult<(PKey<Public>, bool)> {
    let leaf = cert_chain.first().ok_or_else(|| {
        CredentialError::InvalidPresentation(
            "issuerAuth x5chain does not contain a leaf certificate".to_string(),
        )
    })?;
    let leaf = X509::from_der(leaf).map_err(|e| {
        CredentialError::InvalidPresentation(format!("failed to parse issuer leaf cert: {e}"))
    })?;

    let mut store_builder = openssl::x509::store::X509StoreBuilder::new().map_err(|e| {
        CredentialError::InvalidPresentation(format!(
            "failed to create X509 trust store builder: {e}"
        ))
    })?;
    store_builder
        .set_flags(openssl::x509::verify::X509VerifyFlags::PARTIAL_CHAIN)
        .map_err(|e| {
            CredentialError::InvalidPresentation(format!("failed to set X509 verify flags: {e}"))
        })?;
    for ca in trusted_cas {
        store_builder.add_cert(ca.clone()).map_err(|e| {
            CredentialError::InvalidPresentation(format!("failed to add trusted issuer CA: {e}"))
        })?;
    }

    let mut intermediates = openssl::stack::Stack::new().map_err(|e| {
        CredentialError::InvalidPresentation(format!("failed to create intermediate stack: {e}"))
    })?;
    for cert in cert_chain.iter().skip(1) {
        let cert = X509::from_der(cert).map_err(|e| {
            CredentialError::InvalidPresentation(format!(
                "failed to parse issuer intermediate cert: {e}"
            ))
        })?;
        intermediates.push(cert).map_err(|e| {
            CredentialError::InvalidPresentation(format!("failed to push intermediate cert: {e}"))
        })?;
    }

    let store = store_builder.build();
    let mut ctx = openssl::x509::X509StoreContext::new().map_err(|e| {
        CredentialError::InvalidPresentation(format!("failed to create X509 store context: {e}"))
    })?;
    let verification_result = ctx.init(&store, &leaf, &intermediates, |ctx| ctx.verify_cert());

    let trusted = match verification_result {
        Ok(true) => true,
        Ok(false) => {
            // output the leaf and certificate chain in PEM format for debugging
            let leaf_pem = leaf
                .to_pem()
                .map(|pem| String::from_utf8_lossy(&pem).to_string())
                .unwrap_or_else(|e| format!("<failed to convert leaf to PEM: {e}>"));
            let chain_pem: Vec<String> = cert_chain
                .iter()
                .map(|cert_der| {
                    X509::from_der(cert_der)
                        .and_then(|c| c.to_pem())
                        .map(|pem| String::from_utf8_lossy(&pem).to_string())
                        .unwrap_or_else(|e| format!("<failed to convert cert to PEM: {e}>"))
                })
                .collect();

            tracing::warn!(
                leaf_pem = %leaf_pem,
                chain_pem = %chain_pem.join(""),
                error = %ctx.error(),
                error_depth = %ctx.error_depth(),
                subject = ?leaf.subject_name(),
                issuer = ?leaf.issuer_name(),
                "issuerAuth certificate chain is not trusted"
            );
            false
        }
        Err(e) => {
            tracing::error!(
                "issuerAuth certificate chain verification error: {e} (openssl={}, depth={}, subject={:?}, issuer={:?})",
                ctx.error(),
                ctx.error_depth(),
                leaf.subject_name(),
                leaf.issuer_name(),
            );
            false
        }
    };

    let key = leaf.public_key().map_err(|e| {
        CredentialError::InvalidPresentation(format!(
            "failed to extract issuer public key from certificate: {e}"
        ))
    })?;

    Ok((key, trusted))
}

fn verify_cose_sign1_embedded(cose: &CoseSign1, key: &PKey<Public>) -> CredentialResult<()> {
    let alg = cose_algorithm_id(cose)?;
    match alg {
        -7 | -35 | -36 => cose.verify_signature(&[], |signature, data| {
            verify_ecdsa_signature(alg, data, signature, key)
        }),
        #[allow(clippy::manual_range_patterns)]
        -257 | -258 | -259 => cose.verify_signature(&[], |signature, data| {
            verify_rsa_signature(alg, data, signature, key)
        }),
        _ => Err(CredentialError::InvalidPresentation(format!(
            "unsupported COSE signature algorithm: {alg}"
        ))),
    }
}

fn verify_cose_sign1_detached(
    cose: &CoseSign1,
    key: &PKey<Public>,
    payload: &[u8],
) -> CredentialResult<()> {
    let alg = cose_algorithm_id(cose)?;
    match alg {
        -7 | -35 | -36 => cose.verify_detached_signature(payload, &[], |signature, data| {
            verify_ecdsa_signature(alg, data, signature, key)
        }),
        #[allow(clippy::manual_range_patterns)]
        -257 | -258 | -259 => cose.verify_detached_signature(payload, &[], |signature, data| {
            verify_rsa_signature(alg, data, signature, key)
        }),
        _ => Err(CredentialError::InvalidPresentation(format!(
            "unsupported COSE detached signature algorithm: {alg}"
        ))),
    }
}

fn cose_algorithm_id(cose: &CoseSign1) -> CredentialResult<i64> {
    let alg = cose
        .protected
        .header
        .alg
        .clone()
        .or_else(|| cose.unprotected.alg.clone())
        .ok_or_else(|| {
            CredentialError::InvalidPresentation("COSE structure missing alg header".to_string())
        })?;

    match alg {
        RegisteredLabelWithPrivate::Assigned(alg) => Ok(iana::EnumI64::to_i64(&alg)),
        RegisteredLabelWithPrivate::PrivateUse(alg) => Ok(alg),
        RegisteredLabelWithPrivate::Text(name) => Err(CredentialError::InvalidPresentation(
            format!("textual COSE alg is not supported: {name}"),
        )),
    }
}

fn verify_ecdsa_signature(
    alg: i64,
    data: &[u8],
    signature: &[u8],
    key: &PKey<Public>,
) -> CredentialResult<()> {
    let (part_len, digest) = match alg {
        -7 => (32, MessageDigest::sha256()),
        -35 => (48, MessageDigest::sha384()),
        -36 => (66, MessageDigest::sha512()),
        _ => {
            return Err(CredentialError::InvalidPresentation(format!(
                "unsupported ECDSA COSE algorithm: {alg}"
            )));
        }
    };
    if signature.len() != part_len * 2 {
        return Err(CredentialError::InvalidPresentation(format!(
            "invalid ECDSA signature length for alg {alg}: {}",
            signature.len()
        )));
    }

    let r = BigNum::from_slice(&signature[..part_len]).map_err(|e| {
        CredentialError::InvalidPresentation(format!("failed to parse ECDSA r: {e}"))
    })?;
    let s = BigNum::from_slice(&signature[part_len..]).map_err(|e| {
        CredentialError::InvalidPresentation(format!("failed to parse ECDSA s: {e}"))
    })?;
    let der = EcdsaSig::from_private_components(r, s)
        .and_then(|sig| sig.to_der())
        .map_err(|e| {
            CredentialError::InvalidPresentation(format!("failed to convert ECDSA signature: {e}"))
        })?;

    let mut verifier = OpensslVerifier::new(digest, key).map_err(|e| {
        CredentialError::InvalidPresentation(format!("failed to create ECDSA verifier: {e}"))
    })?;
    verifier.update(data).map_err(|e| {
        CredentialError::InvalidPresentation(format!("failed to feed ECDSA verifier: {e}"))
    })?;
    let valid = verifier.verify(&der).map_err(|e| {
        CredentialError::InvalidPresentation(format!("ECDSA verification failed: {e}"))
    })?;
    if !valid {
        return Err(CredentialError::InvalidPresentation(
            "COSE ECDSA signature verification failed".to_string(),
        ));
    }

    Ok(())
}

fn verify_rsa_signature(
    alg: i64,
    data: &[u8],
    signature: &[u8],
    key: &PKey<Public>,
) -> CredentialResult<()> {
    let digest = match alg {
        -257 => MessageDigest::sha256(),
        -258 => MessageDigest::sha384(),
        -259 => MessageDigest::sha512(),
        _ => {
            return Err(CredentialError::InvalidPresentation(format!(
                "unsupported RSA COSE algorithm: {alg}"
            )));
        }
    };

    let mut verifier = OpensslVerifier::new(digest, key).map_err(|e| {
        CredentialError::InvalidPresentation(format!("failed to create RSA verifier: {e}"))
    })?;
    verifier.set_rsa_padding(Padding::PKCS1).map_err(|e| {
        CredentialError::InvalidPresentation(format!("failed to configure RSA padding: {e}"))
    })?;
    verifier.update(data).map_err(|e| {
        CredentialError::InvalidPresentation(format!("failed to feed RSA verifier: {e}"))
    })?;
    let valid = verifier.verify(signature).map_err(|e| {
        CredentialError::InvalidPresentation(format!("RSA verification failed: {e}"))
    })?;
    if !valid {
        return Err(CredentialError::InvalidPresentation(
            "COSE RSA signature verification failed".to_string(),
        ));
    }

    Ok(())
}

fn cose_key_param_integer(key: &CoseKey, label: i64) -> Option<i64> {
    key.params.iter().find_map(|(param_label, value)| {
        if *param_label == Label::Int(label) {
            match value {
                ciborium::Value::Integer(i) => {
                    let value: i128 = (*i).into();
                    i64::try_from(value).ok()
                }
                _ => None,
            }
        } else {
            None
        }
    })
}

fn cose_key_param_bytes(key: &CoseKey, label: i64) -> Option<Vec<u8>> {
    key.params.iter().find_map(|(param_label, value)| {
        if *param_label == Label::Int(label) {
            match value {
                ciborium::Value::Bytes(bytes) => Some(bytes.clone()),
                _ => None,
            }
        } else {
            None
        }
    })
}

// ============================================================================
// MSO parsing and validation
// ============================================================================

fn parse_mobile_security_object(payload: &[u8]) -> CredentialResult<ParsedMobileSecurityObject> {
    let cbor: ciborium::Value = ciborium::from_reader(payload).map_err(|e| {
        CredentialError::InvalidPresentation(format!(
            "failed to parse issuerAuth payload CBOR: {e}"
        ))
    })?;
    let cbor = match &cbor {
        ciborium::Value::Tag(24, inner) => match inner.as_ref() {
            ciborium::Value::Bytes(bytes) => ciborium::from_reader(&bytes[..]).map_err(|e| {
                CredentialError::InvalidPresentation(format!(
                    "failed to parse MobileSecurityObject bytes: {e}"
                ))
            })?,
            other => other.clone(),
        },
        ciborium::Value::Bytes(bytes) => ciborium::from_reader(&bytes[..]).map_err(|e| {
            CredentialError::InvalidPresentation(format!(
                "failed to parse MobileSecurityObject bytes: {e}"
            ))
        })?,
        other => other.clone(),
    };

    let map = as_cbor_map(unwrap_cbor_tags(&cbor)).ok_or_else(|| {
        CredentialError::InvalidPresentation("MobileSecurityObject is not a map".to_string())
    })?;
    let doc_type = cbor_map_get_text(map, "docType")
        .ok_or_else(|| {
            CredentialError::InvalidPresentation("MobileSecurityObject missing docType".to_string())
        })?
        .to_string();
    let digest_algorithm = cbor_map_get_text(map, "digestAlgorithm")
        .ok_or_else(|| {
            CredentialError::InvalidPresentation(
                "MobileSecurityObject missing digestAlgorithm".to_string(),
            )
        })?
        .to_string();

    let value_digests = as_cbor_map(unwrap_cbor_tags(
        cbor_map_get(map, "valueDigests").ok_or_else(|| {
            CredentialError::InvalidPresentation(
                "MobileSecurityObject missing valueDigests".to_string(),
            )
        })?,
    ))
    .ok_or_else(|| CredentialError::InvalidPresentation("valueDigests is not a map".to_string()))?;

    let mut parsed_digests = std::collections::BTreeMap::new();
    for (ns_key, ns_value) in value_digests {
        let namespace = match ns_key {
            ciborium::Value::Text(text) => text.clone(),
            _ => continue,
        };
        let ns_map = as_cbor_map(unwrap_cbor_tags(ns_value)).ok_or_else(|| {
            CredentialError::InvalidPresentation(
                "valueDigests namespace entry is not a map".to_string(),
            )
        })?;

        let mut digest_map = std::collections::BTreeMap::new();
        for (digest_id, digest_value) in ns_map {
            let digest_id = cbor_integer_to_u64(digest_id).ok_or_else(|| {
                CredentialError::InvalidPresentation(
                    "valueDigests digestID is not an integer".to_string(),
                )
            })?;
            let digest_bytes = match unwrap_cbor_tags(digest_value) {
                ciborium::Value::Bytes(bytes) => bytes.clone(),
                _ => {
                    return Err(CredentialError::InvalidPresentation(
                        "valueDigests digest value is not a byte string".to_string(),
                    ));
                }
            };
            digest_map.insert(digest_id, digest_bytes);
        }
        parsed_digests.insert(namespace, digest_map);
    }

    let device_key_info = as_cbor_map(unwrap_cbor_tags(
        cbor_map_get(map, "deviceKeyInfo").ok_or_else(|| {
            CredentialError::InvalidPresentation(
                "MobileSecurityObject missing deviceKeyInfo".to_string(),
            )
        })?,
    ))
    .ok_or_else(|| {
        CredentialError::InvalidPresentation("deviceKeyInfo is not a map".to_string())
    })?;
    let device_key_value = cbor_map_get(device_key_info, "deviceKey").ok_or_else(|| {
        CredentialError::InvalidPresentation("deviceKeyInfo missing deviceKey".to_string())
    })?;
    let mut device_key_bytes = Vec::new();
    ciborium::into_writer(device_key_value, &mut device_key_bytes).map_err(|e| {
        CredentialError::InvalidPresentation(format!("failed to serialize deviceKey: {e}"))
    })?;
    let device_key = CoseKey::from_slice(&device_key_bytes).map_err(|e| {
        CredentialError::InvalidPresentation(format!("failed to parse deviceKey COSE_Key: {e}"))
    })?;

    let validity_info = as_cbor_map(unwrap_cbor_tags(
        cbor_map_get(map, "validityInfo").ok_or_else(|| {
            CredentialError::InvalidPresentation(
                "MobileSecurityObject missing validityInfo".to_string(),
            )
        })?,
    ))
    .ok_or_else(|| CredentialError::InvalidPresentation("validityInfo is not a map".to_string()))?;

    Ok(ParsedMobileSecurityObject {
        doc_type,
        digest_algorithm,
        value_digests: parsed_digests,
        device_key,
        valid_from: cbor_value_to_text(cbor_map_get(validity_info, "validFrom")),
        valid_until: cbor_value_to_text(cbor_map_get(validity_info, "validUntil")),
    })
}

fn verify_issuer_signed_item_digests(
    name_spaces_map: &[(ciborium::Value, ciborium::Value)],
    mso: &ParsedMobileSecurityObject,
) -> CredentialResult<()> {
    for (ns_key, items_value) in name_spaces_map {
        let namespace = match ns_key {
            ciborium::Value::Text(text) => text,
            _ => continue,
        };
        let expected = mso.value_digests.get(namespace).ok_or_else(|| {
            CredentialError::InvalidPresentation(format!(
                "MobileSecurityObject has no valueDigests entry for namespace {namespace}"
            ))
        })?;
        let items = as_cbor_array(unwrap_cbor_tags(items_value)).ok_or_else(|| {
            CredentialError::InvalidPresentation(format!("namespace {namespace} is not an array"))
        })?;

        for item in items {
            let inner_map_bytes = match item {
                ciborium::Value::Tag(24, inner) => match inner.as_ref() {
                    ciborium::Value::Bytes(bytes) => bytes.clone(),
                    _ => {
                        return Err(CredentialError::InvalidPresentation(
                            "IssuerSignedItem tag 24 does not contain bytes".to_string(),
                        ));
                    }
                },
                ciborium::Value::Bytes(bytes) => bytes.clone(),
                _ => {
                    return Err(CredentialError::InvalidPresentation(
                        "IssuerSignedItem is not wrapped as bytes".to_string(),
                    ));
                }
            };

            // Per ISO 18013-5 §9.1.2.4, the MSO valueDigests entry is SHA-256 of the full
            // IssuerSignedItemBytes CBOR encoding: #6.24(bstr .cbor IssuerSignedItem).
            let item_bytes_for_hashing = {
                let mut buf = Vec::new();
                ciborium::into_writer(item, &mut buf).map_err(|e| {
                    CredentialError::InvalidPresentation(format!(
                        "failed to re-encode IssuerSignedItemBytes for digest computation: {e}"
                    ))
                })?;
                buf
            };

            let inner: ciborium::Value =
                ciborium::from_reader(&inner_map_bytes[..]).map_err(|e| {
                    CredentialError::InvalidPresentation(format!(
                        "failed to parse IssuerSignedItem bytes: {e}"
                    ))
                })?;
            let inner_map = as_cbor_map(unwrap_cbor_tags(&inner)).ok_or_else(|| {
                CredentialError::InvalidPresentation("IssuerSignedItem is not a map".to_string())
            })?;
            let digest_id =
                cbor_integer_to_u64(cbor_map_get(inner_map, "digestID").ok_or_else(|| {
                    CredentialError::InvalidPresentation(
                        "IssuerSignedItem missing digestID".to_string(),
                    )
                })?)
                .ok_or_else(|| {
                    CredentialError::InvalidPresentation(
                        "IssuerSignedItem digestID is not an integer".to_string(),
                    )
                })?;
            let expected_digest = expected.get(&digest_id).ok_or_else(|| {
                CredentialError::InvalidPresentation(format!(
                    "MobileSecurityObject missing expected digest for namespace {namespace} digestID {digest_id}"
                ))
            })?;
            let actual_digest =
                hash_issuer_signed_item(&mso.digest_algorithm, &item_bytes_for_hashing)?;
            if actual_digest != *expected_digest {
                tracing::warn!(
                    namespace = %namespace,
                    digest_id = %digest_id,
                    expected_len = expected_digest.len(),
                    actual_len = actual_digest.len(),
                    "IssuerSignedItem digest mismatch"
                );
                return Err(CredentialError::InvalidPresentation(format!(
                    "IssuerSignedItem digest mismatch for namespace {namespace} digestID {digest_id}"
                )));
            }
        }
    }

    Ok(())
}

fn hash_issuer_signed_item(algorithm: &str, data: &[u8]) -> CredentialResult<Vec<u8>> {
    let digest = match algorithm.to_ascii_lowercase().as_str() {
        "sha-256" | "sha256" => MessageDigest::sha256(),
        "sha-384" | "sha384" => MessageDigest::sha384(),
        "sha-512" | "sha512" => MessageDigest::sha512(),
        other => {
            return Err(CredentialError::InvalidPresentation(format!(
                "unsupported MobileSecurityObject digestAlgorithm: {other}"
            )));
        }
    };

    hash(digest, data)
        .map(|digest| digest.to_vec())
        .map_err(|e| {
            CredentialError::InvalidPresentation(format!("failed to hash IssuerSignedItem: {e}"))
        })
}

// ============================================================================
// DeviceSigned / SessionTranscript
// ============================================================================

fn extract_device_namespaces_bytes(
    device_signed_map: &[(ciborium::Value, ciborium::Value)],
) -> CredentialResult<Vec<u8>> {
    match cbor_map_get(device_signed_map, "nameSpaces") {
        Some(ciborium::Value::Bytes(bytes)) => Ok(bytes.clone()),
        Some(ciborium::Value::Tag(24, inner)) => match inner.as_ref() {
            ciborium::Value::Bytes(bytes) => Ok(bytes.clone()),
            _ => Err(CredentialError::InvalidPresentation(
                "deviceSigned.nameSpaces tag 24 does not contain bytes".to_string(),
            )),
        },
        Some(other) => {
            let mut bytes = Vec::new();
            ciborium::into_writer(other, &mut bytes).map_err(|e| {
                CredentialError::InvalidPresentation(format!(
                    "failed to serialize deviceSigned.nameSpaces: {e}"
                ))
            })?;
            Ok(bytes)
        }
        None => {
            let empty_map = ciborium::Value::Map(Vec::new());
            let mut bytes = Vec::new();
            ciborium::into_writer(&empty_map, &mut bytes).map_err(|e| {
                CredentialError::InvalidPresentation(format!(
                    "failed to serialize empty device namespaces: {e}"
                ))
            })?;
            Ok(bytes)
        }
    }
}

/// Reconstruct the OpenID4VP `SessionTranscript` CBOR byte string.
///
/// This builds the same structure as `HandoverBytes` in the AV profile:
///
/// ```text
/// HandoverInfo = [ClientId, Nonce, JwkThumbprint / null, ResponseUri]
/// OID4VPHandover = ["OpenID4VPHandover", SHA-256(HandoverInfo)]
/// SessionTranscript = [null, null, OID4VPHandover]
/// ```
///
/// `requires_encryption` should be `true` when the response mode is
/// `direct_post.jwt` or `dc_api.jwt` (the encrypted variants).
pub fn build_openid4vp_session_transcript(
    client_id: &str,
    nonce: &str,
    response_uri: &str,
    requires_encryption: bool,
    response_jwk_thumbprint: Option<&[u8]>,
) -> CredentialResult<Vec<u8>> {
    let jwk_thumbprint = if requires_encryption {
        Some(
            response_jwk_thumbprint
                .ok_or_else(|| {
                    CredentialError::InvalidPresentation(
                        "response encryption key thumbprint is required for encrypted mDoc responses"
                            .to_string(),
                    )
                })?
                .to_vec(),
        )
    } else {
        None
    };

    let handover_info = ciborium::Value::Array(vec![
        ciborium::Value::Text(client_id.to_string()),
        ciborium::Value::Text(nonce.to_string()),
        match jwk_thumbprint {
            Some(bytes) => ciborium::Value::Bytes(bytes),
            None => ciborium::Value::Null,
        },
        ciborium::Value::Text(response_uri.to_string()),
    ]);
    let handover_info_bytes = cbor_to_vec_fallible(&handover_info)?;
    let handover_hash = openssl::sha::sha256(&handover_info_bytes).to_vec();
    let handover = ciborium::Value::Array(vec![
        ciborium::Value::Text("OpenID4VPHandover".to_string()),
        ciborium::Value::Bytes(handover_hash),
    ]);
    let session_transcript =
        ciborium::Value::Array(vec![ciborium::Value::Null, ciborium::Value::Null, handover]);

    cbor_to_vec_fallible(&session_transcript)
}

fn build_device_authentication_payload(
    session_transcript: &[u8],
    doc_type: &str,
    device_namespaces_bytes: &[u8],
) -> CredentialResult<Vec<u8>> {
    let session_transcript: ciborium::Value =
        ciborium::from_reader(session_transcript).map_err(|e| {
            CredentialError::InvalidPresentation(format!(
                "failed to parse SessionTranscript bytes: {e}"
            ))
        })?;
    // Per ISO 18013-5 §9.1.3.4, the 4th element is DeviceNameSpacesBytes =
    // #6.24(bstr .cbor DeviceNameSpaces). The tag-24 wrapper must be present
    // so the reconstructed DeviceAuthentication matches what the wallet signed.
    let device_namespaces_bytes_tagged = ciborium::Value::Tag(
        24,
        Box::new(ciborium::Value::Bytes(device_namespaces_bytes.to_vec())),
    );
    let payload = ciborium::Value::Array(vec![
        ciborium::Value::Text("DeviceAuthentication".to_string()),
        session_transcript,
        ciborium::Value::Text(doc_type.to_string()),
        device_namespaces_bytes_tagged,
    ]);
    cbor_to_vec_fallible(&payload)
}

fn cose_key_to_public_key(key: &CoseKey) -> CredentialResult<PKey<Public>> {
    let kty = match key.kty {
        coset::RegisteredLabel::Assigned(kty) => iana::EnumI64::to_i64(&kty),
        _ => {
            return Err(CredentialError::InvalidPresentation(
                "unsupported textual COSE key type".to_string(),
            ));
        }
    };
    if kty != 2 {
        return Err(CredentialError::InvalidPresentation(
            "only EC2 COSE device keys are currently supported".to_string(),
        ));
    }

    let crv = cose_key_param_integer(key, -1).ok_or_else(|| {
        CredentialError::InvalidPresentation("COSE device key missing crv".to_string())
    })?;
    let x = cose_key_param_bytes(key, -2).ok_or_else(|| {
        CredentialError::InvalidPresentation("COSE device key missing x".to_string())
    })?;
    let y = cose_key_param_bytes(key, -3).ok_or_else(|| {
        CredentialError::InvalidPresentation("COSE device key missing y".to_string())
    })?;

    let group = match crv {
        1 => EcGroup::from_curve_name(Nid::X9_62_PRIME256V1),
        2 => EcGroup::from_curve_name(Nid::SECP384R1),
        3 => EcGroup::from_curve_name(Nid::SECP521R1),
        _ => {
            return Err(CredentialError::InvalidPresentation(format!(
                "unsupported COSE EC curve: {crv}"
            )));
        }
    }
    .map_err(|e| CredentialError::InvalidPresentation(format!("failed to create EC group: {e}")))?;
    let x = BigNum::from_slice(&x).map_err(|e| {
        CredentialError::InvalidPresentation(format!("failed to parse EC x coordinate: {e}"))
    })?;
    let y = BigNum::from_slice(&y).map_err(|e| {
        CredentialError::InvalidPresentation(format!("failed to parse EC y coordinate: {e}"))
    })?;
    let ec_key = EcKey::from_public_key_affine_coordinates(&group, &x, &y).map_err(|e| {
        CredentialError::InvalidPresentation(format!("failed to reconstruct EC public key: {e}"))
    })?;
    PKey::from_ec_key(ec_key).map_err(|e| {
        CredentialError::InvalidPresentation(format!("failed to construct public key: {e}"))
    })
}

fn validate_mso_validity(mso: &ParsedMobileSecurityObject) -> CredentialResult<bool> {
    let now = chrono::Utc::now();

    if let Some(valid_from) = &mso.valid_from {
        let valid_from = chrono::DateTime::parse_from_rfc3339(valid_from).map_err(|e| {
            CredentialError::InvalidPresentation(format!("failed to parse validFrom from MSO: {e}"))
        })?;
        if valid_from > now {
            return Err(CredentialError::InvalidPresentation(
                "MobileSecurityObject is not yet valid".to_string(),
            ));
        }
    }

    if let Some(valid_until) = &mso.valid_until {
        let valid_until = chrono::DateTime::parse_from_rfc3339(valid_until).map_err(|e| {
            CredentialError::InvalidPresentation(format!(
                "failed to parse validUntil from MSO: {e}"
            ))
        })?;
        if valid_until < now {
            return Err(CredentialError::InvalidPresentation(
                "MobileSecurityObject has expired".to_string(),
            ));
        }
    }

    Ok(true)
}
