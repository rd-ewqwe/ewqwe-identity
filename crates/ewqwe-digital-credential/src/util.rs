//! Shared low-level helpers used across modules.

use base64::Engine as _;
use ciborium::Value as Cbor;

use crate::error::CredentialError;

/// Serialise any `ciborium::Value` to a byte vector.
pub(crate) fn cbor_to_vec(value: &Cbor) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).expect("CBOR serialisation");
    buf
}

/// SHA-256 digest over `data`.
pub(crate) fn sha256(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::new().chain_update(data).finalize().to_vec()
}

/// Current Unix epoch in seconds.
pub(crate) fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_secs() as i64
}

/// Convert a Unix timestamp to an RFC 3339 string.
pub(crate) fn unix_to_rfc3339(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .expect("valid timestamp")
        .to_rfc3339()
}

// ============================================================================
// Fallible CBOR serialisation (used by verification code)
// ============================================================================

/// Serialise any `ciborium::Value` to a byte vector, returning an error on failure.
pub(crate) fn cbor_to_vec_fallible(value: &Cbor) -> Result<Vec<u8>, CredentialError> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).map_err(|e| {
        CredentialError::InvalidPresentation(format!("CBOR serialisation failed: {e}"))
    })?;
    Ok(buf)
}

// ============================================================================
// CBOR navigation helpers (used by mdoc_decoder and mdoc_verification)
// ============================================================================

/// Recursively unwrap CBOR tags to the inner value.
pub(crate) fn unwrap_cbor_tags(value: &Cbor) -> &Cbor {
    match value {
        Cbor::Tag(_, inner) => unwrap_cbor_tags(inner),
        _ => value,
    }
}

/// Return the map entries if the value is a CBOR map (after stripping tags).
pub(crate) fn as_cbor_map(value: &Cbor) -> Option<&Vec<(Cbor, Cbor)>> {
    match value {
        Cbor::Map(map) => Some(map),
        _ => None,
    }
}

/// Return the array items if the value is a CBOR array (after stripping tags).
pub(crate) fn as_cbor_array(value: &Cbor) -> Option<&Vec<Cbor>> {
    match value {
        Cbor::Array(items) => Some(items),
        _ => None,
    }
}

/// Look up a text-keyed entry in a CBOR map.
pub(crate) fn cbor_map_get<'a>(map: &'a [(Cbor, Cbor)], key: &str) -> Option<&'a Cbor> {
    map.iter().find_map(|(k, v)| match k {
        Cbor::Text(t) if t == key => Some(v),
        _ => None,
    })
}

/// Look up a text-keyed entry in a CBOR map and unwrap it as a text string.
pub(crate) fn cbor_map_get_text<'a>(map: &'a [(Cbor, Cbor)], key: &str) -> Option<&'a str> {
    cbor_map_get(map, key).and_then(|v| match unwrap_cbor_tags(v) {
        Cbor::Text(t) => Some(t.as_str()),
        _ => None,
    })
}

/// Return the value of an optional CBOR text entry as an owned `String`.
pub(crate) fn cbor_value_to_text(value: Option<&Cbor>) -> Option<String> {
    match value.map(unwrap_cbor_tags) {
        Some(Cbor::Text(t)) => Some(t.clone()),
        _ => None,
    }
}

/// Convert a CBOR integer to `u64`, handling both positive and negative integers.
pub(crate) fn cbor_integer_to_u64(value: &Cbor) -> Option<u64> {
    match unwrap_cbor_tags(value) {
        Cbor::Integer(i) => {
            let v: i128 = (*i).into();
            u64::try_from(v).ok()
        }
        _ => None,
    }
}

/// Convert a CBOR value to a `serde_json::Value` for API responses.
pub(crate) fn cbor_to_json(val: &Cbor) -> serde_json::Value {
    match val {
        Cbor::Bool(b) => serde_json::Value::Bool(*b),
        Cbor::Integer(i) => {
            let n: i128 = (*i).into();
            if let Ok(u) = u64::try_from(n) {
                serde_json::Value::Number(serde_json::Number::from(u))
            } else if let Ok(i64_val) = i64::try_from(n) {
                serde_json::Value::Number(serde_json::Number::from(i64_val))
            } else {
                serde_json::Value::String(n.to_string())
            }
        }
        Cbor::Float(f) => serde_json::Number::from_f64(*f)
            .map(serde_json::Value::Number)
            .unwrap_or(serde_json::Value::Null),
        Cbor::Text(s) => serde_json::Value::String(s.clone()),
        Cbor::Bytes(b) => {
            serde_json::Value::String(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b))
        }
        Cbor::Array(items) => serde_json::Value::Array(items.iter().map(cbor_to_json).collect()),
        Cbor::Map(entries) => {
            let mut obj = serde_json::Map::new();
            for (k, v) in entries {
                let key_str = match k {
                    Cbor::Text(t) => t.clone(),
                    Cbor::Integer(i) => {
                        let n: i128 = (*i).into();
                        n.to_string()
                    }
                    _ => format!("{k:?}"),
                };
                obj.insert(key_str, cbor_to_json(v));
            }
            serde_json::Value::Object(obj)
        }
        Cbor::Tag(_, inner) => cbor_to_json(inner),
        Cbor::Null => serde_json::Value::Null,
        _ => serde_json::Value::Null,
    }
}

/// Human-readable CBOR type name for error messages.
pub(crate) fn cbor_type_name(val: &Cbor) -> &'static str {
    match val {
        Cbor::Integer(_) => "Integer",
        Cbor::Bytes(_) => "Bytes",
        Cbor::Text(_) => "Text",
        Cbor::Array(_) => "Array",
        Cbor::Map(_) => "Map",
        Cbor::Bool(_) => "Bool",
        Cbor::Tag(_, _) => "Tag",
        Cbor::Null => "Null",
        Cbor::Float(_) => "Float",
        _ => "Unknown",
    }
}
