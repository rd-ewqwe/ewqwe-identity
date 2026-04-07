//! Shared low-level helpers used across modules.

use ciborium::Value as Cbor;

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
