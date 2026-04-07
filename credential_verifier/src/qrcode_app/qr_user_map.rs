//! Thread-safe mapping from OpenID4VP transaction IDs to the QR Code APP user
//! that initiated them.
//!
//! Used to:
//!  - enforce ownership when polling status (only the initiating user can poll)
//!  - attribute journal entries to the correct QR Code APP user (Phase E)

use std::{collections::HashMap, sync::Mutex};

use chrono::{DateTime, Utc};

/// Metadata about the user who initiated a QR transaction.
#[derive(Debug, Clone)]
pub struct QrUserEntry {
    pub user_id: String,
    pub user_email: String,
    /// When the underlying OpenID4VP transaction expires (copied from the
    /// `InitTransactionResponse`).  Used to prune stale entries.
    pub expires_at: DateTime<Utc>,
}

/// Thread-safe store mapping `transaction_id → QrUserEntry`.
///
/// Expired entries are pruned lazily on each [`Self::insert`] call so the map
/// never grows without bound.
#[derive(Debug, Default)]
pub struct QrUserMap {
    inner: Mutex<HashMap<String, QrUserEntry>>,
}

impl QrUserMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new transaction/user mapping and prune expired entries.
    pub fn insert(
        &self,
        transaction_id: String,
        user_id: String,
        user_email: String,
        expires_at: DateTime<Utc>,
    ) {
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        // Prune expired entries while we hold the lock.
        let now = Utc::now();
        map.retain(|_, v| v.expires_at > now);
        map.insert(
            transaction_id,
            QrUserEntry { user_id, user_email, expires_at },
        );
    }

    /// Look up the user entry for a transaction ID.  Returns `None` when
    /// the transaction is unknown or has expired.
    pub fn get(&self, transaction_id: &str) -> Option<QrUserEntry> {
        let map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let entry = map.get(transaction_id)?;
        if entry.expires_at <= Utc::now() {
            return None;
        }
        Some(entry.clone())
    }
}
