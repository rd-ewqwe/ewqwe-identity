//! mDoc / ISO 18013-5 CBOR decoder.
//!
//! Decodes a base64-encoded mDoc `DeviceResponse` (or bare `Document`) and
//! extracts the issuer-signed claims from the `IssuerSignedItem` structures
//! embedded as CBOR Tag 24 byte-strings inside `nameSpaces`.
//!
//! This module performs **claim extraction only** — no cryptographic
//! verification.  See [`crate::mdoc_verification`] for signature and
//! certificate-chain verification.
//!
//! # ISO 18013-5 structure (simplified)
//! ```text
//! DeviceResponse = {
//!   "version": tstr,
//!   "documents": [Document],
//!   "status": uint
//! }
//!
//! Document = {
//!   "docType": tstr,
//!   "issuerSigned": {
//!     "nameSpaces": { namespace => [IssuerSignedItem_tagged] },
//!     "issuerAuth":  COSE_Sign1
//!   },
//!   "deviceSigned": { ... }
//! }
//!
//! IssuerSignedItem_tagged = #6.24(bstr)   -- Tag 24 wrapping CBOR-encoded item
//!
//! IssuerSignedItem = {
//!   "digestID":          uint,
//!   "random":            bstr,
//!   "elementIdentifier": tstr,
//!   "elementValue":      any
//! }
//! ```

use base64::Engine;
use ciborium::Value as Cbor;
use std::collections::BTreeMap;

use crate::{
    error::{CredentialError, Result},
    util::{
        as_cbor_array, as_cbor_map, cbor_map_get, cbor_map_get_text, cbor_to_json, cbor_type_name,
        unwrap_cbor_tags,
    },
};

// ============================================================================
// Public types
// ============================================================================

/// Result of decoding an mDoc presentation (claim extraction, no crypto).
#[derive(Debug, Clone)]
pub struct DecodedMdoc {
    /// The document type (e.g. `eu.europa.ec.eudi.pid.1`).
    pub doc_type: String,
    /// Claims keyed by `namespace → claim_name → JSON value`.
    pub namespaces: BTreeMap<String, BTreeMap<String, serde_json::Value>>,
}

// ============================================================================
// Public API
// ============================================================================

/// Decode a base64-encoded mDoc byte-string into structured claims (no crypto).
///
/// Accepts base64url (no padding), base64url (padded), or standard base64.
/// The input may be a full `DeviceResponse` or a bare `Document`.
///
/// Returns a [`DecodedMdoc`] on success.  No signature or certificate
/// verification is performed — see [`crate::mdoc_verification::verify_mdoc_presentation`]
/// for full cryptographic verification.
pub fn decode_mdoc_presentation(encoded: &str) -> Result<DecodedMdoc> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(encoded))
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(encoded))
        .map_err(|e| CredentialError::InvalidPresentation(format!("base64 decode failed: {e}")))?;

    let cbor: Cbor = ciborium::from_reader(&bytes[..])
        .map_err(|e| CredentialError::InvalidPresentation(format!("CBOR parse failed: {e}")))?;

    let document = extract_document(&cbor)?;
    parse_document(document)
}

// ============================================================================
// Internal helpers
// ============================================================================

fn extract_document(val: &Cbor) -> Result<&Cbor> {
    let val = unwrap_cbor_tags(val);
    let map = as_cbor_map(val).ok_or_else(|| {
        CredentialError::InvalidPresentation(format!(
            "expected top-level CBOR map, got {}",
            cbor_type_name(val)
        ))
    })?;

    if let Some(docs_val) = cbor_map_get(map, "documents") {
        let docs = as_cbor_array(docs_val).ok_or_else(|| {
            CredentialError::InvalidPresentation("'documents' is not an array".into())
        })?;
        docs.first().ok_or_else(|| {
            CredentialError::InvalidPresentation("'documents' array is empty".into())
        })
    } else if cbor_map_get(map, "docType").is_some() {
        Ok(val)
    } else {
        Err(CredentialError::InvalidPresentation(
            "CBOR map has neither 'documents' nor 'docType'".into(),
        ))
    }
}

fn parse_document(doc: &Cbor) -> Result<DecodedMdoc> {
    let doc = unwrap_cbor_tags(doc);
    let map = as_cbor_map(doc)
        .ok_or_else(|| CredentialError::InvalidPresentation("Document is not a CBOR map".into()))?;

    let doc_type = cbor_map_get_text(map, "docType")
        .ok_or_else(|| CredentialError::InvalidPresentation("missing 'docType'".into()))?
        .to_owned();

    let issuer_signed = cbor_map_get(map, "issuerSigned")
        .ok_or_else(|| CredentialError::InvalidPresentation("missing 'issuerSigned'".into()))?;
    let issuer_signed = unwrap_cbor_tags(issuer_signed);
    let issuer_signed_map = as_cbor_map(issuer_signed).ok_or_else(|| {
        CredentialError::InvalidPresentation("'issuerSigned' is not a map".into())
    })?;

    let name_spaces_val = cbor_map_get(issuer_signed_map, "nameSpaces").ok_or_else(|| {
        CredentialError::InvalidPresentation("missing 'nameSpaces' in issuerSigned".into())
    })?;
    let name_spaces_val = unwrap_cbor_tags(name_spaces_val);
    let name_spaces_map = as_cbor_map(name_spaces_val)
        .ok_or_else(|| CredentialError::InvalidPresentation("'nameSpaces' is not a map".into()))?;

    let mut namespaces = BTreeMap::new();

    for (ns_key, ns_items) in name_spaces_map {
        let ns_name = match ns_key {
            Cbor::Text(t) => t.clone(),
            _ => continue,
        };
        let items_array = match as_cbor_array(ns_items) {
            Some(a) => a,
            None => continue,
        };

        let mut claims = BTreeMap::new();
        for tagged_item in items_array {
            match parse_issuer_signed_item(tagged_item) {
                Ok((name, value)) => {
                    claims.insert(name, value);
                }
                Err(e) => {
                    tracing::warn!("failed to parse IssuerSignedItem: {e}");
                }
            }
        }
        namespaces.insert(ns_name, claims);
    }

    Ok(DecodedMdoc {
        doc_type,
        namespaces,
    })
}

fn parse_issuer_signed_item(val: &Cbor) -> Result<(String, serde_json::Value)> {
    let inner_cbor = unwrap_tag24_bytes(val)?;
    let map = as_cbor_map(&inner_cbor).ok_or_else(|| {
        CredentialError::InvalidPresentation("IssuerSignedItem is not a map".into())
    })?;

    let element_id = cbor_map_get_text(map, "elementIdentifier")
        .ok_or_else(|| CredentialError::InvalidPresentation("missing 'elementIdentifier'".into()))?
        .to_owned();

    let element_value = cbor_map_get(map, "elementValue")
        .ok_or_else(|| CredentialError::InvalidPresentation("missing 'elementValue'".into()))?;

    Ok((element_id, cbor_to_json(element_value)))
}

/// Decode CBOR Tag 24 (a byte string containing more CBOR) to the inner value.
fn unwrap_tag24_bytes(val: &Cbor) -> Result<Cbor> {
    match val {
        Cbor::Tag(24, inner) => match inner.as_ref() {
            Cbor::Bytes(b) => ciborium::from_reader(&b[..]).map_err(|e| {
                CredentialError::InvalidPresentation(format!("Tag 24 inner CBOR: {e}"))
            }),
            other => Ok(other.clone()),
        },
        Cbor::Bytes(b) => ciborium::from_reader(&b[..])
            .map_err(|e| CredentialError::InvalidPresentation(format!("untagged bytes CBOR: {e}"))),
        other => {
            if as_cbor_map(other).is_some() {
                Ok(other.clone())
            } else {
                Err(CredentialError::InvalidPresentation(format!(
                    "expected Tag(24) or Bytes, got {}",
                    cbor_type_name(other)
                )))
            }
        }
    }
}
