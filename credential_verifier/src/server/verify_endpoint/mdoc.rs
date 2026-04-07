//! mDoc / CBOR presentation verification (ISO/IEC 18013-5).
//!
//! Handles DeviceResponse CBOR decoding, IssuerAuth COSE_Sign1 verification,
//! IssuerSigned digest validation, and DeviceSignature holder-binding
//! verification over the reconstructed OpenID4VP SessionTranscript.

use crate::{AttError, mdoc_decoder};
use base64::Engine;
use coset::{CborSerializable, CoseKey, CoseSign1, Label, RegisteredLabelWithPrivate, iana};
use ewqwe_openid4vp::{OpenID4VPTransaction, ResponseMode};
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

// ============================================================================
// Public (within module) types
// ============================================================================

pub(super) struct MdocVerificationResult {
    pub(super) claims: serde_json::Value,
    pub(super) doc_type: String,
    pub(super) namespace: String,
    pub(super) not_expired: bool,
    pub(super) issuer_trusted: bool,
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
// mDoc presentation verification
// ============================================================================

pub(super) fn verify_mdoc_presentation(
    encoded: &str,
    transaction: &OpenID4VPTransaction,
    response_jwk_thumbprint: Option<&[u8]>,
    trusted_certs_dir: &str,
) -> Result<MdocVerificationResult, AttError> {
    let decoded = mdoc_decoder::decode_mdoc_presentation(encoded)
        .map_err(|e| AttError::BadRequest(format!("mDoc CBOR decode failed: {e}")))?;

    let bytes = decode_base64url_or_base64(encoded)
        .map_err(|e| AttError::BadRequest(format!("mDoc base64 decode failed: {e}")))?;
    let cbor: ciborium::Value = ciborium::from_reader(&bytes[..])
        .map_err(|e| AttError::BadRequest(format!("mDoc CBOR parse failed: {e}")))?;
    let document = extract_first_document(&cbor)?;
    let document_map = as_cbor_map(document)
        .ok_or_else(|| AttError::BadRequest("mDoc document is not a CBOR map".to_string()))?;

    let doc_type = cbor_map_get_text(document_map, "docType")
        .ok_or_else(|| AttError::BadRequest("mDoc document missing docType".to_string()))?
        .to_string();

    let issuer_signed = unwrap_cbor_tags(
        cbor_map_get(document_map, "issuerSigned")
            .ok_or_else(|| AttError::BadRequest("mDoc missing issuerSigned".to_string()))?,
    );
    let issuer_signed_map = as_cbor_map(issuer_signed)
        .ok_or_else(|| AttError::BadRequest("issuerSigned is not a CBOR map".to_string()))?;
    let name_spaces = unwrap_cbor_tags(
        cbor_map_get(issuer_signed_map, "nameSpaces")
            .ok_or_else(|| AttError::BadRequest("issuerSigned missing nameSpaces".to_string()))?,
    );
    let name_spaces_map = as_cbor_map(name_spaces)
        .ok_or_else(|| AttError::BadRequest("issuerSigned.nameSpaces is not a map".to_string()))?;

    let issuer_auth = parse_cose_sign1_from_value(
        cbor_map_get(issuer_signed_map, "issuerAuth")
            .ok_or_else(|| AttError::BadRequest("issuerSigned missing issuerAuth".to_string()))?,
    )?;
    let issuer_chain = extract_x5chain_from_cose(&issuer_auth)?;
    let (issuer_key, issuer_trusted) =
        verify_cose_certificate_chain(&issuer_chain, trusted_certs_dir)?;
    verify_cose_sign1_embedded(&issuer_auth, &issuer_key)?;

    let mso = parse_mobile_security_object(
        issuer_auth
            .payload
            .as_deref()
            .ok_or_else(|| AttError::BadRequest("issuerAuth missing payload".to_string()))?,
    )?;

    if mso.doc_type != doc_type {
        return Err(AttError::BadRequest(
            "mDoc docType does not match MobileSecurityObject docType".to_string(),
        ));
    }

    verify_issuer_signed_item_digests(name_spaces_map, &mso)?;

    let device_signed = unwrap_cbor_tags(
        cbor_map_get(document_map, "deviceSigned")
            .ok_or_else(|| AttError::BadRequest("mDoc missing deviceSigned".to_string()))?,
    );
    let device_signed_map = as_cbor_map(device_signed)
        .ok_or_else(|| AttError::BadRequest("deviceSigned is not a CBOR map".to_string()))?;
    let device_name_spaces_bytes = extract_device_namespaces_bytes(device_signed_map)?;
    let device_auth = unwrap_cbor_tags(
        cbor_map_get(device_signed_map, "deviceAuth")
            .ok_or_else(|| AttError::BadRequest("deviceSigned missing deviceAuth".to_string()))?,
    );
    let device_auth_map = as_cbor_map(device_auth)
        .ok_or_else(|| AttError::BadRequest("deviceAuth is not a CBOR map".to_string()))?;

    let device_signature = cbor_map_get(device_auth_map, "deviceSignature").ok_or_else(|| {
        AttError::BadRequest(
            "deviceAuth.deviceMac is not supported by this verifier; expected deviceSignature"
                .to_string(),
        )
    })?;
    let device_signature = parse_cose_sign1_from_value(device_signature)?;
    let session_transcript = build_openid4vp_session_transcript(
        &transaction.client_id,
        &transaction.nonce,
        transaction.response_mode,
        response_jwk_thumbprint,
        &transaction.response_uri,
    )?;
    let device_authentication_raw = build_device_authentication_payload(
        &session_transcript,
        &doc_type,
        &device_name_spaces_bytes,
    )?;
    // ISO 18013-5 §9.1.3.4: DeviceAuthenticationBytes = #6.24(bstr .cbor DeviceAuthentication)
    // The wallet signs over DeviceAuthenticationBytes, not raw DeviceAuthentication.
    let device_authentication_bytes = cbor_to_vec(&ciborium::Value::Tag(
        24,
        Box::new(ciborium::Value::Bytes(device_authentication_raw)),
    ))?;
    let device_key = cose_key_to_public_key(&mso.device_key)?;
    verify_cose_sign1_detached(&device_signature, &device_key, &device_authentication_bytes)?;

    let namespace = decoded.namespaces.keys().next().cloned().ok_or_else(|| {
        // there has to be a namespace
        AttError::BadRequest("mDoc presentation contains no namespaces".to_string())
    })?;
    let claims = if decoded.namespaces.len() == 1 {
        let (_, ns_claims) = decoded.namespaces.into_iter().next().unwrap();
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
// CBOR helpers
// ============================================================================

fn decode_base64url_or_base64(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(input)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(input))
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(input))
}

fn extract_first_document(cbor: &ciborium::Value) -> Result<&ciborium::Value, AttError> {
    let cbor = unwrap_cbor_tags(cbor);
    let map = as_cbor_map(cbor)
        .ok_or_else(|| AttError::BadRequest("mDoc top-level value is not a map".to_string()))?;
    if let Some(documents) = cbor_map_get(map, "documents") {
        let documents = as_cbor_array(unwrap_cbor_tags(documents)).ok_or_else(|| {
            AttError::BadRequest("mDoc DeviceResponse.documents is not an array".to_string())
        })?;
        documents.first().ok_or_else(|| {
            AttError::BadRequest("mDoc DeviceResponse.documents is empty".to_string())
        })
    } else {
        Ok(cbor)
    }
}

pub(super) fn cbor_to_vec(value: &ciborium::Value) -> Result<Vec<u8>, AttError> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)
        .map_err(|e| AttError::BadRequest(format!("CBOR serialization failed: {e}")))?;
    Ok(bytes)
}

pub(super) fn unwrap_cbor_tags(value: &ciborium::Value) -> &ciborium::Value {
    match value {
        ciborium::Value::Tag(_, inner) => unwrap_cbor_tags(inner),
        _ => value,
    }
}

pub(super) fn as_cbor_map(
    value: &ciborium::Value,
) -> Option<&Vec<(ciborium::Value, ciborium::Value)>> {
    match value {
        ciborium::Value::Map(map) => Some(map),
        _ => None,
    }
}

fn as_cbor_array(value: &ciborium::Value) -> Option<&Vec<ciborium::Value>> {
    match value {
        ciborium::Value::Array(items) => Some(items),
        _ => None,
    }
}

pub(super) fn cbor_map_get<'a>(
    map: &'a [(ciborium::Value, ciborium::Value)],
    key: &str,
) -> Option<&'a ciborium::Value> {
    map.iter().find_map(|(map_key, value)| match map_key {
        ciborium::Value::Text(text) if text == key => Some(value),
        _ => None,
    })
}

fn cbor_map_get_text<'a>(
    map: &'a [(ciborium::Value, ciborium::Value)],
    key: &str,
) -> Option<&'a str> {
    cbor_map_get(map, key).and_then(|value| match unwrap_cbor_tags(value) {
        ciborium::Value::Text(text) => Some(text.as_str()),
        _ => None,
    })
}

fn cbor_integer_to_u64(value: &ciborium::Value) -> Option<u64> {
    match unwrap_cbor_tags(value) {
        ciborium::Value::Integer(i) => {
            let value: i128 = (*i).into();
            u64::try_from(value).ok()
        }
        _ => None,
    }
}

fn cbor_value_to_text(value: Option<&ciborium::Value>) -> Option<String> {
    match value.map(unwrap_cbor_tags) {
        Some(ciborium::Value::Text(text)) => Some(text.clone()),
        _ => None,
    }
}

// ============================================================================
// COSE helpers
// ============================================================================

fn parse_cose_sign1_from_value(value: &ciborium::Value) -> Result<CoseSign1, AttError> {
    let untagged = match value {
        ciborium::Value::Tag(18, inner) => inner.as_ref().clone(),
        other => other.clone(),
    };
    let mut bytes = Vec::new();
    ciborium::into_writer(&untagged, &mut bytes)
        .map_err(|e| AttError::BadRequest(format!("COSE serialization failed: {e}")))?;
    CoseSign1::from_slice(&bytes)
        .map_err(|e| AttError::BadRequest(format!("COSE_Sign1 parse failed: {e}")))
}

fn extract_x5chain_from_cose(cose: &CoseSign1) -> Result<Vec<Vec<u8>>, AttError> {
    for headers in [&cose.protected.header, &cose.unprotected] {
        for (label, value) in &headers.rest {
            if *label == Label::Int(33) {
                return match value {
                    ciborium::Value::Bytes(cert) => Ok(vec![cert.clone()]),
                    ciborium::Value::Array(items) => items
                        .iter()
                        .map(|item| match item {
                            ciborium::Value::Bytes(cert) => Ok(cert.clone()),
                            _ => Err(AttError::BadRequest(
                                "COSE x5chain array contains a non-byte-string certificate"
                                    .to_string(),
                            )),
                        })
                        .collect(),
                    _ => Err(AttError::BadRequest(
                        "COSE x5chain header is neither a byte string nor an array".to_string(),
                    )),
                };
            }
        }
    }

    Err(AttError::BadRequest(
        "issuerAuth is missing COSE x5chain header parameter 33".to_string(),
    ))
}

fn verify_cose_certificate_chain(
    cert_chain: &[Vec<u8>],
    trusted_certs_dir: &str,
) -> Result<(PKey<Public>, bool), AttError> {
    let leaf = cert_chain.first().ok_or_else(|| {
        AttError::BadRequest("issuerAuth x5chain does not contain a leaf certificate".to_string())
    })?;
    let leaf = X509::from_der(leaf)
        .map_err(|e| AttError::BadRequest(format!("failed to parse issuer leaf cert: {e}")))?;

    let trusted_cas = super::load_trusted_issuer_certs(trusted_certs_dir);
    let mut store_builder = openssl::x509::store::X509StoreBuilder::new().map_err(|e| {
        AttError::Generic(format!("failed to create X509 trust store builder: {e}"))
    })?;
    store_builder
        .set_flags(openssl::x509::verify::X509VerifyFlags::PARTIAL_CHAIN)
        .map_err(|e| AttError::Generic(format!("failed to set X509 verify flags: {e}")))?;
    for ca in trusted_cas {
        store_builder
            .add_cert(ca)
            .map_err(|e| AttError::Generic(format!("failed to add trusted issuer CA: {e}")))?;
    }

    let mut intermediates = openssl::stack::Stack::new()
        .map_err(|e| AttError::Generic(format!("failed to create intermediate stack: {e}")))?;
    for cert in cert_chain.iter().skip(1) {
        let cert = X509::from_der(cert).map_err(|e| {
            AttError::BadRequest(format!("failed to parse issuer intermediate cert: {e}"))
        })?;
        intermediates
            .push(cert)
            .map_err(|e| AttError::Generic(format!("failed to push intermediate cert: {e}")))?;
    }

    let store = store_builder.build();
    let mut ctx = openssl::x509::X509StoreContext::new()
        .map_err(|e| AttError::Generic(format!("failed to create X509 store context: {e}")))?;
    let verification_result = ctx.init(&store, &leaf, &intermediates, |ctx| ctx.verify_cert());

    match verification_result {
        Ok(true) => {}
        Ok(false) => {
            return Err(AttError::BadRequest(format!(
                "issuerAuth certificate chain failed verification: {} (depth={}, subject={:?}, issuer={:?})",
                ctx.error(),
                ctx.error_depth(),
                leaf.subject_name(),
                leaf.issuer_name(),
            )));
        }
        Err(e) => {
            return Err(AttError::Generic(format!(
                "issuerAuth certificate chain verification error: {e} (openssl={}, depth={}, subject={:?}, issuer={:?})",
                ctx.error(),
                ctx.error_depth(),
                leaf.subject_name(),
                leaf.issuer_name(),
            )));
        }
    }

    let key = leaf.public_key().map_err(|e| {
        AttError::BadRequest(format!(
            "failed to extract issuer public key from certificate: {e}"
        ))
    })?;

    Ok((key, true))
}

fn verify_cose_sign1_embedded(cose: &CoseSign1, key: &PKey<Public>) -> Result<(), AttError> {
    let alg = cose_algorithm_id(cose)?;
    match alg {
        -7 | -35 | -36 => cose.verify_signature(&[], |signature, data| {
            verify_ecdsa_signature(alg, data, signature, key)
        }),
        #[allow(clippy::manual_range_patterns)]
        -257 | -258 | -259 => cose.verify_signature(&[], |signature, data| {
            verify_rsa_signature(alg, data, signature, key)
        }),
        _ => Err(AttError::BadRequest(format!(
            "unsupported COSE signature algorithm: {alg}"
        ))),
    }
}

fn verify_cose_sign1_detached(
    cose: &CoseSign1,
    key: &PKey<Public>,
    payload: &[u8],
) -> Result<(), AttError> {
    let alg = cose_algorithm_id(cose)?;
    match alg {
        -7 | -35 | -36 => cose.verify_detached_signature(payload, &[], |signature, data| {
            verify_ecdsa_signature(alg, data, signature, key)
        }),
        #[allow(clippy::manual_range_patterns)]
        -257 | -258 | -259 => cose.verify_detached_signature(payload, &[], |signature, data| {
            verify_rsa_signature(alg, data, signature, key)
        }),
        _ => Err(AttError::BadRequest(format!(
            "unsupported COSE detached signature algorithm: {alg}"
        ))),
    }
}

fn cose_algorithm_id(cose: &CoseSign1) -> Result<i64, AttError> {
    let alg = cose
        .protected
        .header
        .alg
        .clone()
        .or_else(|| cose.unprotected.alg.clone())
        .ok_or_else(|| AttError::BadRequest("COSE structure missing alg header".to_string()))?;

    match alg {
        RegisteredLabelWithPrivate::Assigned(alg) => Ok(iana::EnumI64::to_i64(&alg)),
        RegisteredLabelWithPrivate::PrivateUse(alg) => Ok(alg),
        RegisteredLabelWithPrivate::Text(name) => Err(AttError::BadRequest(format!(
            "textual COSE alg is not supported: {name}"
        ))),
    }
}

fn verify_ecdsa_signature(
    alg: i64,
    data: &[u8],
    signature: &[u8],
    key: &PKey<Public>,
) -> Result<(), AttError> {
    let (part_len, digest) = match alg {
        -7 => (32, MessageDigest::sha256()),
        -35 => (48, MessageDigest::sha384()),
        -36 => (66, MessageDigest::sha512()),
        _ => {
            return Err(AttError::BadRequest(format!(
                "unsupported ECDSA COSE algorithm: {alg}"
            )));
        }
    };
    if signature.len() != part_len * 2 {
        return Err(AttError::BadRequest(format!(
            "invalid ECDSA signature length for alg {alg}: {}",
            signature.len()
        )));
    }

    let r = BigNum::from_slice(&signature[..part_len])
        .map_err(|e| AttError::BadRequest(format!("failed to parse ECDSA r: {e}")))?;
    let s = BigNum::from_slice(&signature[part_len..])
        .map_err(|e| AttError::BadRequest(format!("failed to parse ECDSA s: {e}")))?;
    let der = EcdsaSig::from_private_components(r, s)
        .and_then(|sig| sig.to_der())
        .map_err(|e| AttError::BadRequest(format!("failed to convert ECDSA signature: {e}")))?;

    let mut verifier = OpensslVerifier::new(digest, key)
        .map_err(|e| AttError::BadRequest(format!("failed to create ECDSA verifier: {e}")))?;
    verifier
        .update(data)
        .map_err(|e| AttError::BadRequest(format!("failed to feed ECDSA verifier: {e}")))?;
    let valid = verifier
        .verify(&der)
        .map_err(|e| AttError::BadRequest(format!("ECDSA verification failed: {e}")))?;
    if !valid {
        return Err(AttError::BadRequest(
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
) -> Result<(), AttError> {
    let digest = match alg {
        -257 => MessageDigest::sha256(),
        -258 => MessageDigest::sha384(),
        -259 => MessageDigest::sha512(),
        _ => {
            return Err(AttError::BadRequest(format!(
                "unsupported RSA COSE algorithm: {alg}"
            )));
        }
    };

    let mut verifier = OpensslVerifier::new(digest, key)
        .map_err(|e| AttError::BadRequest(format!("failed to create RSA verifier: {e}")))?;
    verifier
        .set_rsa_padding(Padding::PKCS1)
        .map_err(|e| AttError::BadRequest(format!("failed to configure RSA padding: {e}")))?;
    verifier
        .update(data)
        .map_err(|e| AttError::BadRequest(format!("failed to feed RSA verifier: {e}")))?;
    let valid = verifier
        .verify(signature)
        .map_err(|e| AttError::BadRequest(format!("RSA verification failed: {e}")))?;
    if !valid {
        return Err(AttError::BadRequest(
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

fn parse_mobile_security_object(payload: &[u8]) -> Result<ParsedMobileSecurityObject, AttError> {
    let cbor: ciborium::Value = ciborium::from_reader(payload).map_err(|e| {
        AttError::BadRequest(format!("failed to parse issuerAuth payload CBOR: {e}"))
    })?;
    let cbor = match &cbor {
        ciborium::Value::Tag(24, inner) => match inner.as_ref() {
            ciborium::Value::Bytes(bytes) => ciborium::from_reader(&bytes[..]).map_err(|e| {
                AttError::BadRequest(format!("failed to parse MobileSecurityObject bytes: {e}"))
            })?,
            other => other.clone(),
        },
        ciborium::Value::Bytes(bytes) => ciborium::from_reader(&bytes[..]).map_err(|e| {
            AttError::BadRequest(format!("failed to parse MobileSecurityObject bytes: {e}"))
        })?,
        other => other.clone(),
    };

    let map = as_cbor_map(unwrap_cbor_tags(&cbor))
        .ok_or_else(|| AttError::BadRequest("MobileSecurityObject is not a map".to_string()))?;
    let doc_type = cbor_map_get_text(map, "docType")
        .ok_or_else(|| AttError::BadRequest("MobileSecurityObject missing docType".to_string()))?
        .to_string();
    let digest_algorithm = cbor_map_get_text(map, "digestAlgorithm")
        .ok_or_else(|| {
            AttError::BadRequest("MobileSecurityObject missing digestAlgorithm".to_string())
        })?
        .to_string();

    let value_digests = as_cbor_map(unwrap_cbor_tags(
        cbor_map_get(map, "valueDigests").ok_or_else(|| {
            AttError::BadRequest("MobileSecurityObject missing valueDigests".to_string())
        })?,
    ))
    .ok_or_else(|| AttError::BadRequest("valueDigests is not a map".to_string()))?;

    let mut parsed_digests = std::collections::BTreeMap::new();
    for (ns_key, ns_value) in value_digests {
        let namespace = match ns_key {
            ciborium::Value::Text(text) => text.clone(),
            _ => continue,
        };
        let ns_map = as_cbor_map(unwrap_cbor_tags(ns_value)).ok_or_else(|| {
            AttError::BadRequest("valueDigests namespace entry is not a map".to_string())
        })?;

        let mut digest_map = std::collections::BTreeMap::new();
        for (digest_id, digest_value) in ns_map {
            let digest_id = cbor_integer_to_u64(digest_id).ok_or_else(|| {
                AttError::BadRequest("valueDigests digestID is not an integer".to_string())
            })?;
            let digest_bytes = match unwrap_cbor_tags(digest_value) {
                ciborium::Value::Bytes(bytes) => bytes.clone(),
                _ => {
                    return Err(AttError::BadRequest(
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
            AttError::BadRequest("MobileSecurityObject missing deviceKeyInfo".to_string())
        })?,
    ))
    .ok_or_else(|| AttError::BadRequest("deviceKeyInfo is not a map".to_string()))?;
    let device_key_value = cbor_map_get(device_key_info, "deviceKey")
        .ok_or_else(|| AttError::BadRequest("deviceKeyInfo missing deviceKey".to_string()))?;
    let mut device_key_bytes = Vec::new();
    ciborium::into_writer(device_key_value, &mut device_key_bytes)
        .map_err(|e| AttError::BadRequest(format!("failed to serialize deviceKey: {e}")))?;
    let device_key = CoseKey::from_slice(&device_key_bytes)
        .map_err(|e| AttError::BadRequest(format!("failed to parse deviceKey COSE_Key: {e}")))?;

    let validity_info = as_cbor_map(unwrap_cbor_tags(
        cbor_map_get(map, "validityInfo").ok_or_else(|| {
            AttError::BadRequest("MobileSecurityObject missing validityInfo".to_string())
        })?,
    ))
    .ok_or_else(|| AttError::BadRequest("validityInfo is not a map".to_string()))?;

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
) -> Result<(), AttError> {
    for (ns_key, items_value) in name_spaces_map {
        let namespace = match ns_key {
            ciborium::Value::Text(text) => text,
            _ => continue,
        };
        let expected = mso.value_digests.get(namespace).ok_or_else(|| {
            AttError::BadRequest(format!(
                "MobileSecurityObject has no valueDigests entry for namespace {namespace}"
            ))
        })?;
        let items = as_cbor_array(unwrap_cbor_tags(items_value)).ok_or_else(|| {
            AttError::BadRequest(format!("namespace {namespace} is not an array"))
        })?;

        for item in items {
            let inner_map_bytes = match item {
                ciborium::Value::Tag(24, inner) => match inner.as_ref() {
                    ciborium::Value::Bytes(bytes) => bytes.clone(),
                    _ => {
                        return Err(AttError::BadRequest(
                            "IssuerSignedItem tag 24 does not contain bytes".to_string(),
                        ));
                    }
                },
                ciborium::Value::Bytes(bytes) => bytes.clone(),
                _ => {
                    return Err(AttError::BadRequest(
                        "IssuerSignedItem is not wrapped as bytes".to_string(),
                    ));
                }
            };

            // Per ISO 18013-5 §9.1.2.4, the MSO valueDigests entry is SHA-256 of the full
            // IssuerSignedItemBytes CBOR encoding: #6.24(bstr .cbor IssuerSignedItem).
            let item_bytes_for_hashing = {
                let mut buf = Vec::new();
                ciborium::into_writer(item, &mut buf).map_err(|e| {
                    AttError::BadRequest(format!(
                        "failed to re-encode IssuerSignedItemBytes for digest computation: {e}"
                    ))
                })?;
                buf
            };

            let inner: ciborium::Value =
                ciborium::from_reader(&inner_map_bytes[..]).map_err(|e| {
                    AttError::BadRequest(format!("failed to parse IssuerSignedItem bytes: {e}"))
                })?;
            let inner_map = as_cbor_map(unwrap_cbor_tags(&inner))
                .ok_or_else(|| AttError::BadRequest("IssuerSignedItem is not a map".to_string()))?;
            let digest_id =
                cbor_integer_to_u64(cbor_map_get(inner_map, "digestID").ok_or_else(|| {
                    AttError::BadRequest("IssuerSignedItem missing digestID".to_string())
                })?)
                .ok_or_else(|| {
                    AttError::BadRequest("IssuerSignedItem digestID is not an integer".to_string())
                })?;
            let expected_digest = expected.get(&digest_id).ok_or_else(|| {
                AttError::BadRequest(format!(
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
                return Err(AttError::BadRequest(format!(
                    "IssuerSignedItem digest mismatch for namespace {namespace} digestID {digest_id}"
                )));
            }
        }
    }

    Ok(())
}

fn hash_issuer_signed_item(algorithm: &str, data: &[u8]) -> Result<Vec<u8>, AttError> {
    let digest = match algorithm.to_ascii_lowercase().as_str() {
        "sha-256" | "sha256" => MessageDigest::sha256(),
        "sha-384" | "sha384" => MessageDigest::sha384(),
        "sha-512" | "sha512" => MessageDigest::sha512(),
        other => {
            return Err(AttError::BadRequest(format!(
                "unsupported MobileSecurityObject digestAlgorithm: {other}"
            )));
        }
    };

    hash(digest, data)
        .map(|digest| digest.to_vec())
        .map_err(|e| AttError::BadRequest(format!("failed to hash IssuerSignedItem: {e}")))
}

// ============================================================================
// DeviceSigned / SessionTranscript
// ============================================================================

fn extract_device_namespaces_bytes(
    device_signed_map: &[(ciborium::Value, ciborium::Value)],
) -> Result<Vec<u8>, AttError> {
    match cbor_map_get(device_signed_map, "nameSpaces") {
        Some(ciborium::Value::Bytes(bytes)) => Ok(bytes.clone()),
        Some(ciborium::Value::Tag(24, inner)) => match inner.as_ref() {
            ciborium::Value::Bytes(bytes) => Ok(bytes.clone()),
            _ => Err(AttError::BadRequest(
                "deviceSigned.nameSpaces tag 24 does not contain bytes".to_string(),
            )),
        },
        Some(other) => {
            let mut bytes = Vec::new();
            ciborium::into_writer(other, &mut bytes).map_err(|e| {
                AttError::BadRequest(format!("failed to serialize deviceSigned.nameSpaces: {e}"))
            })?;
            Ok(bytes)
        }
        None => {
            let empty_map = ciborium::Value::Map(Vec::new());
            let mut bytes = Vec::new();
            ciborium::into_writer(&empty_map, &mut bytes).map_err(|e| {
                AttError::BadRequest(format!("failed to serialize empty device namespaces: {e}"))
            })?;
            Ok(bytes)
        }
    }
}

fn build_openid4vp_session_transcript(
    client_id: &str,
    nonce: &str,
    response_mode: ResponseMode,
    response_jwk_thumbprint: Option<&[u8]>,
    response_uri: &str,
) -> Result<Vec<u8>, AttError> {
    let jwk_thumbprint = match response_mode {
        ResponseMode::DirectPostJwt | ResponseMode::DcApiJwt => Some(
            response_jwk_thumbprint
                .ok_or_else(|| {
                    AttError::BadRequest(
                        "response encryption key thumbprint is required for encrypted mDoc responses"
                            .to_string(),
                    )
                })?
                .to_vec(),
        ),
        _ => None,
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
    let handover_info_bytes = cbor_to_vec(&handover_info)?;
    let handover_hash = openssl::sha::sha256(&handover_info_bytes).to_vec();
    let handover = ciborium::Value::Array(vec![
        ciborium::Value::Text("OpenID4VPHandover".to_string()),
        ciborium::Value::Bytes(handover_hash),
    ]);
    let session_transcript =
        ciborium::Value::Array(vec![ciborium::Value::Null, ciborium::Value::Null, handover]);

    cbor_to_vec(&session_transcript)
}

fn build_device_authentication_payload(
    session_transcript: &[u8],
    doc_type: &str,
    device_namespaces_bytes: &[u8],
) -> Result<Vec<u8>, AttError> {
    let session_transcript: ciborium::Value =
        ciborium::from_reader(session_transcript).map_err(|e| {
            AttError::BadRequest(format!("failed to parse SessionTranscript bytes: {e}"))
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
    cbor_to_vec(&payload)
}

fn cose_key_to_public_key(key: &CoseKey) -> Result<PKey<Public>, AttError> {
    let kty = match key.kty {
        coset::RegisteredLabel::Assigned(kty) => iana::EnumI64::to_i64(&kty),
        _ => {
            return Err(AttError::BadRequest(
                "unsupported textual COSE key type".to_string(),
            ));
        }
    };
    if kty != 2 {
        return Err(AttError::BadRequest(
            "only EC2 COSE device keys are currently supported".to_string(),
        ));
    }

    let crv = cose_key_param_integer(key, -1)
        .ok_or_else(|| AttError::BadRequest("COSE device key missing crv".to_string()))?;
    let x = cose_key_param_bytes(key, -2)
        .ok_or_else(|| AttError::BadRequest("COSE device key missing x".to_string()))?;
    let y = cose_key_param_bytes(key, -3)
        .ok_or_else(|| AttError::BadRequest("COSE device key missing y".to_string()))?;

    let group = match crv {
        1 => EcGroup::from_curve_name(Nid::X9_62_PRIME256V1),
        2 => EcGroup::from_curve_name(Nid::SECP384R1),
        3 => EcGroup::from_curve_name(Nid::SECP521R1),
        _ => {
            return Err(AttError::BadRequest(format!(
                "unsupported COSE EC curve: {crv}"
            )));
        }
    }
    .map_err(|e| AttError::BadRequest(format!("failed to create EC group: {e}")))?;
    let x = BigNum::from_slice(&x)
        .map_err(|e| AttError::BadRequest(format!("failed to parse EC x coordinate: {e}")))?;
    let y = BigNum::from_slice(&y)
        .map_err(|e| AttError::BadRequest(format!("failed to parse EC y coordinate: {e}")))?;
    let ec_key = EcKey::from_public_key_affine_coordinates(&group, &x, &y)
        .map_err(|e| AttError::BadRequest(format!("failed to reconstruct EC public key: {e}")))?;
    PKey::from_ec_key(ec_key)
        .map_err(|e| AttError::BadRequest(format!("failed to construct public key: {e}")))
}

fn validate_mso_validity(mso: &ParsedMobileSecurityObject) -> Result<bool, AttError> {
    let now = chrono::Utc::now();

    if let Some(valid_from) = &mso.valid_from {
        let valid_from = chrono::DateTime::parse_from_rfc3339(valid_from).map_err(|e| {
            AttError::BadRequest(format!("failed to parse validFrom from MSO: {e}"))
        })?;
        if valid_from > now {
            return Err(AttError::BadRequest(
                "MobileSecurityObject is not yet valid".to_string(),
            ));
        }
    }

    if let Some(valid_until) = &mso.valid_until {
        let valid_until = chrono::DateTime::parse_from_rfc3339(valid_until).map_err(|e| {
            AttError::BadRequest(format!("failed to parse validUntil from MSO: {e}"))
        })?;
        if valid_until < now {
            return Err(AttError::BadRequest(
                "MobileSecurityObject has expired".to_string(),
            ));
        }
    }

    Ok(true)
}
