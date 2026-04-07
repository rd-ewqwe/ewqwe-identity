//! mDoc / ISO 18013-5 CBOR decoder
//!
//! Decodes a base64-encoded mDoc `DeviceResponse` (or bare `Document`) as returned by
//! EUDI / AV wallets.  The decoder extracts the issuer-signed claims from the
//! `IssuerSignedItem` structures embedded as CBOR Tag 24 byte-strings inside
//! `nameSpaces`.
//!
//! ISO 18013-5 structure (simplified):
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
//!     "issuerAuth": COSE_Sign1
//!   },
//!   "deviceSigned": { ... }
//! }
//!
//! IssuerSignedItem_tagged = #6.24(bstr)   -- Tag 24 wrapping CBOR-encoded item
//!
//! IssuerSignedItem = {
//!   "digestID": uint,
//!   "random": bstr,
//!   "elementIdentifier": tstr,
//!   "elementValue": any
//! }
//! ```

use base64::Engine;
use ciborium::Value as CborValue;
use std::collections::BTreeMap;

/// Errors that can occur during mDoc decoding.
#[derive(Debug, thiserror::Error)]
pub enum MdocDecodeError {
    #[error("base64 decode failed: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("CBOR parse failed: {0}")]
    Cbor(String),
    #[error("unexpected CBOR structure: {0}")]
    Structure(String),
}

/// Result of decoding an mDoc presentation.
#[derive(Debug, Clone)]
pub struct DecodedMdoc {
    /// The document type (e.g. `eu.europa.ec.eudi.pid.1`)
    pub doc_type: String,
    /// Claims keyed by namespace → claim_name → JSON value
    pub namespaces: BTreeMap<String, BTreeMap<String, serde_json::Value>>,
}

/// Decode a base64-encoded mDoc byte-string into structured claims.
///
/// The input is typically the base64url- or standard-base64-encoded bytes that
/// the wallet puts into the DCQL `vp_token` map value.  It may be either a
/// full `DeviceResponse` or a bare `Document`.
pub fn decode_mdoc_presentation(encoded: &str) -> Result<DecodedMdoc, MdocDecodeError> {
    // Try base64url first (no padding), then standard base64
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(encoded))
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(encoded))?;

    tracing::debug!("mDoc CBOR bytes length: {}", bytes.len());

    let cbor: CborValue =
        ciborium::from_reader(&bytes[..]).map_err(|e| MdocDecodeError::Cbor(e.to_string()))?;

    // The top level is either a DeviceResponse (map with "documents") or a
    // bare Document (map with "docType").
    let document = extract_document(&cbor)?;
    parse_document(document)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Navigate from the top-level CBOR value down to the first Document.
fn extract_document(val: &CborValue) -> Result<&CborValue, MdocDecodeError> {
    // If the outer value is a Tag (e.g. Tag 24), unwrap it first.
    let val = unwrap_tags(val);

    let map = as_map(val).ok_or_else(|| {
        MdocDecodeError::Structure(format!(
            "expected top-level CBOR map, got {:?}",
            cbor_type_name(val)
        ))
    })?;

    // Check if this is a DeviceResponse (has "documents" key)
    if let Some(docs_val) = map_get(map, "documents") {
        let docs = as_array(docs_val)
            .ok_or_else(|| MdocDecodeError::Structure("'documents' is not an array".into()))?;
        docs.first()
            .ok_or_else(|| MdocDecodeError::Structure("'documents' array is empty".into()))
    } else if map_get(map, "docType").is_some() {
        // It's already a bare Document
        Ok(val)
    } else {
        Err(MdocDecodeError::Structure(
            "CBOR map has neither 'documents' nor 'docType'".into(),
        ))
    }
}

/// Parse a single `Document` CBOR value.
fn parse_document(doc: &CborValue) -> Result<DecodedMdoc, MdocDecodeError> {
    let doc = unwrap_tags(doc);
    let map =
        as_map(doc).ok_or_else(|| MdocDecodeError::Structure("Document is not a map".into()))?;

    // docType
    let doc_type = map_get_text(map, "docType")
        .ok_or_else(|| MdocDecodeError::Structure("missing 'docType'".into()))?
        .to_owned();

    tracing::debug!("mDoc docType: {}", doc_type);

    // issuerSigned.nameSpaces
    let issuer_signed = map_get(map, "issuerSigned")
        .ok_or_else(|| MdocDecodeError::Structure("missing 'issuerSigned'".into()))?;
    let issuer_signed = unwrap_tags(issuer_signed);
    let issuer_signed_map = as_map(issuer_signed)
        .ok_or_else(|| MdocDecodeError::Structure("'issuerSigned' is not a map".into()))?;

    let name_spaces_val = map_get(issuer_signed_map, "nameSpaces")
        .ok_or_else(|| MdocDecodeError::Structure("missing 'nameSpaces' in issuerSigned".into()))?;
    let name_spaces_val = unwrap_tags(name_spaces_val);
    let name_spaces_map = as_map(name_spaces_val)
        .ok_or_else(|| MdocDecodeError::Structure("'nameSpaces' is not a map".into()))?;

    let mut namespaces = BTreeMap::new();

    for (ns_key, ns_items) in name_spaces_map {
        let ns_name = match ns_key {
            CborValue::Text(t) => t.clone(),
            _ => continue,
        };

        let items_array = match as_array(ns_items) {
            Some(a) => a,
            None => continue,
        };

        tracing::debug!(
            "  namespace '{}': {} IssuerSignedItems",
            ns_name,
            items_array.len()
        );

        let mut claims = BTreeMap::new();

        for tagged_item in items_array {
            match parse_issuer_signed_item(tagged_item) {
                Ok((name, value)) => {
                    tracing::debug!("    claim: {} = {}", name, value);
                    claims.insert(name, value);
                }
                Err(e) => {
                    tracing::warn!("    failed to parse IssuerSignedItem: {}", e);
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

/// Parse a single `IssuerSignedItem`, which is wrapped in CBOR Tag 24.
///
/// Tag 24 contains a byte string that is itself CBOR-encoded.  Inside is a map
/// with at least `elementIdentifier` (tstr) and `elementValue` (any).
fn parse_issuer_signed_item(
    val: &CborValue,
) -> Result<(String, serde_json::Value), MdocDecodeError> {
    // Unwrap Tag 24 → byte string → decode inner CBOR
    let inner_cbor = unwrap_tag24_bytes(val)?;

    let map = as_map(&inner_cbor)
        .ok_or_else(|| MdocDecodeError::Structure("IssuerSignedItem is not a map".into()))?;

    let element_id = map_get_text(map, "elementIdentifier")
        .ok_or_else(|| MdocDecodeError::Structure("missing 'elementIdentifier'".into()))?
        .to_owned();

    let element_value = map_get(map, "elementValue")
        .ok_or_else(|| MdocDecodeError::Structure("missing 'elementValue'".into()))?;

    let json_value = cbor_to_json(element_value);

    Ok((element_id, json_value))
}

/// Unwrap CBOR Tag 24 which wraps a byte string containing more CBOR.
fn unwrap_tag24_bytes(val: &CborValue) -> Result<CborValue, MdocDecodeError> {
    match val {
        CborValue::Tag(24, inner) => {
            match inner.as_ref() {
                CborValue::Bytes(b) => ciborium::from_reader(&b[..])
                    .map_err(|e| MdocDecodeError::Cbor(format!("inner Tag 24 CBOR: {e}"))),
                // Some implementations put the value directly (already decoded)
                other => Ok(other.clone()),
            }
        }
        // If not tagged, try treating it as-is (some wallets omit the tag)
        CborValue::Bytes(b) => ciborium::from_reader(&b[..])
            .map_err(|e| MdocDecodeError::Cbor(format!("untagged bytes CBOR: {e}"))),
        other => {
            // Maybe it's already an unwrapped map
            if as_map(other).is_some() {
                Ok(other.clone())
            } else {
                Err(MdocDecodeError::Structure(format!(
                    "expected Tag(24) or Bytes, got {:?}",
                    cbor_type_name(other)
                )))
            }
        }
    }
}

/// Recursively strip CBOR tags to get to the actual value.
fn unwrap_tags(val: &CborValue) -> &CborValue {
    match val {
        CborValue::Tag(_, inner) => unwrap_tags(inner),
        _ => val,
    }
}

// ---------------------------------------------------------------------------
// CBOR ↔ JSON conversion
// ---------------------------------------------------------------------------

/// Convert a CBOR value to a serde_json::Value for the API response.
fn cbor_to_json(val: &CborValue) -> serde_json::Value {
    match val {
        CborValue::Bool(b) => serde_json::Value::Bool(*b),
        CborValue::Integer(i) => {
            let n: i128 = (*i).into();
            serde_json::json!(n)
        }
        CborValue::Float(f) => serde_json::json!(f),
        CborValue::Text(s) => serde_json::Value::String(s.clone()),
        CborValue::Bytes(b) => {
            // Try to interpret as UTF-8 string first (some wallets encode strings as bytes)
            if let Ok(s) = std::str::from_utf8(b) {
                serde_json::Value::String(s.to_owned())
            } else {
                // Return as base64
                serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(b))
            }
        }
        CborValue::Array(arr) => serde_json::Value::Array(arr.iter().map(cbor_to_json).collect()),
        CborValue::Map(entries) => {
            let obj: serde_json::Map<String, serde_json::Value> = entries
                .iter()
                .filter_map(|(k, v)| {
                    let key = match k {
                        CborValue::Text(s) => s.clone(),
                        CborValue::Integer(i) => {
                            let n: i128 = (*i).into();
                            n.to_string()
                        }
                        _ => return None,
                    };
                    Some((key, cbor_to_json(v)))
                })
                .collect();
            serde_json::Value::Object(obj)
        }
        CborValue::Null => serde_json::Value::Null,
        // CBOR Tag wrapping another value — peel and convert the inner value
        CborValue::Tag(tag, inner) => {
            // Tag 0 = date/time string, Tag 1 = epoch timestamp
            // Tag 1004 = full-date (RFC 3339 date string) — used by mDL for dates
            match *tag {
                0 | 1004 => cbor_to_json(inner),
                1 => cbor_to_json(inner),
                _ => cbor_to_json(inner),
            }
        }
        _ => serde_json::Value::Null,
    }
}

// ---------------------------------------------------------------------------
// CBOR map helpers
// ---------------------------------------------------------------------------

fn as_map(val: &CborValue) -> Option<&Vec<(CborValue, CborValue)>> {
    match val {
        CborValue::Map(m) => Some(m),
        _ => None,
    }
}

fn as_array(val: &CborValue) -> Option<&Vec<CborValue>> {
    match val {
        CborValue::Array(a) => Some(a),
        _ => None,
    }
}

/// Look up a text-keyed entry in a CBOR map.
fn map_get<'a>(map: &'a [(CborValue, CborValue)], key: &str) -> Option<&'a CborValue> {
    map.iter().find_map(|(k, v)| match k {
        CborValue::Text(t) if t == key => Some(v),
        _ => None,
    })
}

fn map_get_text<'a>(map: &'a [(CborValue, CborValue)], key: &str) -> Option<&'a str> {
    map_get(map, key).and_then(|v| match v {
        CborValue::Text(t) => Some(t.as_str()),
        _ => None,
    })
}

fn cbor_type_name(val: &CborValue) -> &'static str {
    match val {
        CborValue::Bool(_) => "Bool",
        CborValue::Integer(_) => "Integer",
        CborValue::Float(_) => "Float",
        CborValue::Text(_) => "Text",
        CborValue::Bytes(_) => "Bytes",
        CborValue::Array(_) => "Array",
        CborValue::Map(_) => "Map",
        CborValue::Null => "Null",
        CborValue::Tag(_, _) => "Tag",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cbor_to_json_primitives() {
        assert_eq!(
            cbor_to_json(&CborValue::Bool(true)),
            serde_json::json!(true)
        );
        assert_eq!(
            cbor_to_json(&CborValue::Text("hello".into())),
            serde_json::json!("hello")
        );
        assert_eq!(cbor_to_json(&CborValue::Null), serde_json::Value::Null);
        assert_eq!(
            cbor_to_json(&CborValue::Integer(42.into())),
            serde_json::json!(42)
        );
    }

    #[test]
    fn test_cbor_to_json_tagged_date() {
        // Tag 1004 wrapping a date string (used by mDL)
        let tagged = CborValue::Tag(1004, Box::new(CborValue::Text("1990-01-15".into())));
        assert_eq!(cbor_to_json(&tagged), serde_json::json!("1990-01-15"));
    }
}
