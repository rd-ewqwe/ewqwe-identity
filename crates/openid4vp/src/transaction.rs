//! In-memory transaction store with TTL-based cleanup.
//!
//! Manages OpenID4VP transaction lifecycle: creation, lookup by ID or state,
//! status updates, expiration, and periodic garbage collection.
//!
//! For production use, this could be backed by Redis (already available
//! in the credential verifier) or another persistent store.

use crate::types::{OpenID4VPTransaction, TransactionStatus};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tracing::{debug, info};

/// Thread-safe transaction store with automatic TTL cleanup.
#[derive(Clone)]
pub struct TransactionStore {
    inner: Arc<Mutex<HashMap<String, OpenID4VPTransaction>>>,
    cleanup_handle: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

impl TransactionStore {
    /// Create a new empty transaction store.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            cleanup_handle: Arc::new(Mutex::new(None)),
        }
    }

    /// Start periodic cleanup of expired transactions.
    ///
    /// Spawns a background Tokio task that runs every `interval_sec` seconds.
    pub fn start_cleanup(&self, interval_secs: u64) {
        let store = self.inner.clone();
        let handle = tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(tokio::time::Duration::from_secs(interval_secs));
            loop {
                interval.tick().await;
                let now = chrono::Utc::now().timestamp_millis();
                let mut store = store.lock().expect("transaction store lock poisoned");
                let expired: Vec<String> = store
                    .iter()
                    .filter(|(_, tx)| tx.expires_at < now)
                    .map(|(id, _)| id.clone())
                    .collect();
                for id in &expired {
                    store.remove(id);
                    debug!(
                        "Transaction {}... expired and removed",
                        &id[..8.min(id.len())]
                    );
                }
                if !expired.is_empty() {
                    info!("Cleaned up {} expired transaction(s)", expired.len());
                }
            }
        });

        if let Ok(mut h) = self.cleanup_handle.lock() {
            *h = Some(handle);
        }
    }

    /// Stop the background cleanup task.
    pub fn stop_cleanup(&self) {
        if let Ok(mut h) = self.cleanup_handle.lock() {
            if let Some(handle) = h.take() {
                handle.abort();
            }
        }
    }

    /// Store a new transaction.
    pub fn set(&self, transaction: OpenID4VPTransaction) {
        let id = transaction.id.clone();
        let mut store = self.inner.lock().expect("transaction store lock poisoned");
        store.insert(id, transaction);
    }

    /// Retrieve a transaction by ID. Returns `None` if not found.
    pub fn get(&self, id: &str) -> Option<OpenID4VPTransaction> {
        let store = self.inner.lock().expect("transaction store lock poisoned");
        store.get(id).cloned()
    }

    /// Get a mutable reference to a transaction for in-place updates.
    ///
    /// The closure `f` is called with a mutable reference to the transaction
    /// while the store lock is held.
    pub fn update<F, R>(&self, id: &str, f: F) -> Option<R>
    where
        F: FnOnce(&mut OpenID4VPTransaction) -> R,
    {
        let mut store = self.inner.lock().expect("transaction store lock poisoned");
        store.get_mut(id).map(f)
    }

    /// Find a transaction by its `state` parameter.
    pub fn find_by_state(&self, state: &str) -> Option<OpenID4VPTransaction> {
        let store = self.inner.lock().expect("transaction store lock poisoned");
        store.values().find(|tx| tx.state == state).cloned()
    }

    /// Update a transaction found by `state`, applying closure `f`.
    pub fn update_by_state<F, R>(&self, state: &str, f: F) -> Option<R>
    where
        F: FnOnce(&mut OpenID4VPTransaction) -> R,
    {
        let mut store = self.inner.lock().expect("transaction store lock poisoned");
        store.values_mut().find(|tx| tx.state == state).map(f)
    }

    /// Delete a transaction by ID. Returns `true` if it existed.
    pub fn delete(&self, id: &str) -> bool {
        let mut store = self.inner.lock().expect("transaction store lock poisoned");
        store.remove(id).is_some()
    }

    /// Update the status of a transaction.
    pub fn update_status(&self, id: &str, status: TransactionStatus) {
        self.update(id, |tx| {
            tx.status = status;
        });
    }

    /// Check if a transaction has expired. Removes it if so.
    pub fn is_expired(&self, id: &str) -> bool {
        let now = chrono::Utc::now().timestamp_millis();
        let mut store = self.inner.lock().expect("transaction store lock poisoned");
        if let Some(tx) = store.get(id) {
            if tx.expires_at < now {
                store.remove(id);
                return true;
            }
            false
        } else {
            true // Not found = treated as expired
        }
    }

    /// Get the number of active transactions.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        let store = self.inner.lock().expect("transaction store lock poisoned");
        store.len()
    }
}

impl Default for TransactionStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ClientIdScheme, DCQLQuery, ProfileId, ResponseMode, TransactionStatus};

    fn make_test_transaction(id: &str, state: &str, ttl_ms: i64) -> OpenID4VPTransaction {
        let now = chrono::Utc::now().timestamp_millis();
        OpenID4VPTransaction {
            id: id.to_string(),
            state: state.to_string(),
            nonce: "test-nonce".to_string(),
            created_at: now,
            expires_at: now + ttl_ms,
            status: TransactionStatus::Pending,
            dcql_query: DCQLQuery {
                credentials: vec![],
                credential_sets: None,
            },
            client_id: "test-client".to_string(),
            client_id_scheme: ClientIdScheme::RedirectUri,
            response_uri: "https://example.com/callback".to_string(),
            response_mode: ResponseMode::DirectPost,
            profile: ProfileId::AnnexA,
            wallet_response: None,
            wallet_error: None,
            verification_result: None,
            error_message: None,
            client_metadata: None,
            transaction_data: None,
        }
    }

    #[test]
    fn test_set_and_get() {
        let store = TransactionStore::new();
        let tx = make_test_transaction("tx-1", "state-1", 60_000);
        store.set(tx);

        let retrieved = store.get("tx-1").unwrap();
        assert_eq!(retrieved.state, "state-1");
        assert_eq!(retrieved.status, TransactionStatus::Pending);
    }

    #[test]
    fn test_find_by_state() {
        let store = TransactionStore::new();
        store.set(make_test_transaction("tx-1", "state-abc", 60_000));
        store.set(make_test_transaction("tx-2", "state-def", 60_000));

        let found = store.find_by_state("state-abc").unwrap();
        assert_eq!(found.id, "tx-1");

        assert!(store.find_by_state("state-missing").is_none());
    }

    #[test]
    fn test_update() {
        let store = TransactionStore::new();
        store.set(make_test_transaction("tx-1", "state-1", 60_000));

        store.update("tx-1", |tx| {
            tx.status = TransactionStatus::Received;
        });

        let tx = store.get("tx-1").unwrap();
        assert_eq!(tx.status, TransactionStatus::Received);
    }

    #[test]
    fn test_update_status() {
        let store = TransactionStore::new();
        store.set(make_test_transaction("tx-1", "state-1", 60_000));

        store.update_status("tx-1", TransactionStatus::Verified);

        let tx = store.get("tx-1").unwrap();
        assert_eq!(tx.status, TransactionStatus::Verified);
    }

    #[test]
    fn test_is_expired() {
        let store = TransactionStore::new();
        // Already expired (negative TTL)
        store.set(make_test_transaction("tx-expired", "state-1", -1000));
        // Not expired
        store.set(make_test_transaction("tx-valid", "state-2", 60_000));

        assert!(store.is_expired("tx-expired"));
        assert!(!store.is_expired("tx-valid"));
        assert!(store.is_expired("tx-nonexistent"));

        // Expired transaction should be removed
        assert!(store.get("tx-expired").is_none());
    }

    #[test]
    fn test_delete() {
        let store = TransactionStore::new();
        store.set(make_test_transaction("tx-1", "state-1", 60_000));
        assert_eq!(store.len(), 1);

        assert!(store.delete("tx-1"));
        assert_eq!(store.len(), 0);
        assert!(!store.delete("tx-1")); // Already deleted
    }
}
