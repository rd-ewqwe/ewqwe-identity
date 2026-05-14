//! Transaction store — pluggable backend for OpenID4VP transaction lifecycle.
//!
//! The [`TransactionStore`] trait defines the async contract for storing,
//! retrieving and updating [`OpenID4VPTransaction`] values.  Concrete
//! implementations live in [`crate::stores`]:
//!
//! | Store                   | Backend                                          |
//! |-------------------------|--------------------------------------------------|
//! | `InMemoryTransactionStore` | In-process `HashMap` (default)               |
//! | `SqliteTransactionStore`   | SQLite in-memory or file                     |
//! | `PostgresTransactionStore` | PostgreSQL via `sqlx`                        |
//! | `RedisTransactionStore`    | Redis (TTL-native expiry, no cleanup thread) |
//!
//! The enum [`DynTransactionStore`] wraps whichever backend is active and
//! implements [`TransactionStore`] by dispatching to the inner value.  Use
//! [`DynTransactionStore::new`] to build one from [`TransactionStoreParams`].

use crate::error::OpenID4VPResult;
use crate::stores::{
    InMemoryTransactionStore, PostgresTransactionStore, RedisTransactionStore,
    SqliteTransactionStore,
};
use crate::types::{OpenID4VPTransaction, TransactionStatus};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

// ============================================================================
// Configuration
// ============================================================================

/// Which storage backend to use for OpenID4VP transactions.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(tag = "backend", rename_all = "snake_case")]
pub enum TransactionStoreBackend {
    /// SQLite — uses an in-memory database (default).  No file is created.
    #[default]
    SqliteMemory,

    /// SQLite — persists to the given file path.
    #[serde(rename = "sqlite_file")]
    SqliteFile {
        /// Filesystem path to the SQLite database file.
        path: String,
    },

    /// PostgreSQL — connect via a `postgres://` connection URL.
    Postgres {
        /// `postgres://user:password@host/db` style URL.
        url: String,
    },

    /// Redis — connect via a `redis://` connection URL.
    /// Transactions are stored with a TTL so Redis handles expiry automatically.
    Redis {
        /// `redis://[password@]host[:port][/db]` style URL.
        url: String,
    },
}

/// Configuration for the transaction store.
///
/// Embed this in [`crate::service::OpenID4VPServiceConfig`] under the TOML key
/// `transaction_store`.
///
/// ```toml
/// [openid4vp_config.transaction_store]
/// backend = "sqlite_memory"   # default — no further keys required
///
/// # SQLite file:
/// # backend = "sqlite_file"
/// # path    = "/var/lib/ewqwe/transactions.db"
///
/// # PostgreSQL:
/// # backend = "postgres"
/// # url     = "postgres://user:pass@localhost/ewqwe"
///
/// # Redis (TTL-native expiry — no cleanup thread):
/// # backend = "redis"
/// # url     = "redis://127.0.0.1:6379"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TransactionStoreParams {
    #[serde(flatten)]
    pub backend: TransactionStoreBackend,
}

// ============================================================================
// Trait
// ============================================================================

/// Async interface for the transaction store.
///
/// All methods are `async` so that network-backed implementations (Postgres,
/// Redis) do not need to block a thread.
///
/// The `state` field is treated as a unique lookup key for the OpenID4VP
/// authorization response lifecycle. Implementations must not allow two
/// distinct transactions to exist with the same `state`, otherwise
/// `find_by_state` and `update_by_state` become ambiguous.
#[async_trait]
pub trait TransactionStore: Send + Sync {
    /// Persist a new (or updated) transaction.
    async fn set(&self, transaction: OpenID4VPTransaction) -> OpenID4VPResult<()>;

    /// Retrieve a transaction by its primary ID.
    async fn get(&self, id: &str) -> OpenID4VPResult<Option<OpenID4VPTransaction>>;

    /// Find a transaction whose `state` field matches `state`.
    async fn find_by_state(&self, state: &str) -> OpenID4VPResult<Option<OpenID4VPTransaction>>;

    /// Delete a transaction by ID.  Returns `true` if a row was removed.
    async fn delete(&self, id: &str) -> OpenID4VPResult<bool>;

    /// Convenience — update the status of a transaction.
    async fn update_status(&self, id: &str, status: TransactionStatus) -> OpenID4VPResult<()>;

    /// Apply `f` to the transaction with the given ID and persist the result.
    /// Returns `None` when the transaction does not exist.
    async fn update<F>(&self, id: &str, f: F) -> OpenID4VPResult<Option<()>>
    where
        F: FnOnce(&mut OpenID4VPTransaction) + Send;

    /// Apply `f` to the transaction whose `state` matches and persist the result.
    /// Returns `None` when no matching transaction is found.
    async fn update_by_state<F>(&self, state: &str, f: F) -> OpenID4VPResult<Option<()>>
    where
        F: FnOnce(&mut OpenID4VPTransaction) + Send;

    /// Return `true` when the transaction has passed its `expires_at` timestamp
    /// (or does not exist).  Expired transactions are removed from the store.
    async fn is_expired(&self, id: &str) -> OpenID4VPResult<bool>;
}

// ============================================================================
// Dynamic dispatch wrapper
// ============================================================================

/// Wraps any supported backend behind a single concrete type.
///
/// Build with [`DynTransactionStore::new`].
pub enum DynTransactionStore {
    Sqlite(SqliteTransactionStore),
    Postgres(PostgresTransactionStore),
    Redis(RedisTransactionStore),
    InMemory(InMemoryTransactionStore),
}

impl DynTransactionStore {
    /// Create a new store from the supplied parameters.
    ///
    /// Connects or migrates as needed.  Call this once during server startup.
    pub async fn new(params: &TransactionStoreParams, ttl_secs: i64) -> OpenID4VPResult<Self> {
        match &params.backend {
            TransactionStoreBackend::SqliteMemory => {
                let store = SqliteTransactionStore::new_memory(ttl_secs).await?;
                Ok(Self::Sqlite(store))
            }
            TransactionStoreBackend::SqliteFile { path } => {
                let store = SqliteTransactionStore::new_file(path, ttl_secs).await?;
                Ok(Self::Sqlite(store))
            }
            TransactionStoreBackend::Postgres { url } => {
                let store = PostgresTransactionStore::new(url, ttl_secs).await?;
                Ok(Self::Postgres(store))
            }
            TransactionStoreBackend::Redis { url } => {
                let store = RedisTransactionStore::new(url, ttl_secs).await?;
                Ok(Self::Redis(store))
            }
        }
    }
}

// ---- Delegate trait impl to the active inner backend ----

#[async_trait]
impl TransactionStore for DynTransactionStore {
    async fn set(&self, transaction: OpenID4VPTransaction) -> OpenID4VPResult<()> {
        match self {
            Self::Sqlite(s) => s.set(transaction).await,
            Self::Postgres(s) => s.set(transaction).await,
            Self::Redis(s) => s.set(transaction).await,
            Self::InMemory(s) => s.set(transaction).await,
        }
    }

    async fn get(&self, id: &str) -> OpenID4VPResult<Option<OpenID4VPTransaction>> {
        match self {
            Self::Sqlite(s) => s.get(id).await,
            Self::Postgres(s) => s.get(id).await,
            Self::Redis(s) => s.get(id).await,
            Self::InMemory(s) => s.get(id).await,
        }
    }

    async fn find_by_state(&self, state: &str) -> OpenID4VPResult<Option<OpenID4VPTransaction>> {
        match self {
            Self::Sqlite(s) => s.find_by_state(state).await,
            Self::Postgres(s) => s.find_by_state(state).await,
            Self::Redis(s) => s.find_by_state(state).await,
            Self::InMemory(s) => s.find_by_state(state).await,
        }
    }

    async fn delete(&self, id: &str) -> OpenID4VPResult<bool> {
        match self {
            Self::Sqlite(s) => s.delete(id).await,
            Self::Postgres(s) => s.delete(id).await,
            Self::Redis(s) => s.delete(id).await,
            Self::InMemory(s) => s.delete(id).await,
        }
    }

    async fn update_status(&self, id: &str, status: TransactionStatus) -> OpenID4VPResult<()> {
        match self {
            Self::Sqlite(s) => s.update_status(id, status).await,
            Self::Postgres(s) => s.update_status(id, status).await,
            Self::Redis(s) => s.update_status(id, status).await,
            Self::InMemory(s) => s.update_status(id, status).await,
        }
    }

    async fn update<F>(&self, id: &str, f: F) -> OpenID4VPResult<Option<()>>
    where
        F: FnOnce(&mut OpenID4VPTransaction) + Send,
    {
        match self {
            Self::Sqlite(s) => s.update(id, f).await,
            Self::Postgres(s) => s.update(id, f).await,
            Self::Redis(s) => s.update(id, f).await,
            Self::InMemory(s) => s.update(id, f).await,
        }
    }

    async fn update_by_state<F>(&self, state: &str, f: F) -> OpenID4VPResult<Option<()>>
    where
        F: FnOnce(&mut OpenID4VPTransaction) + Send,
    {
        match self {
            Self::Sqlite(s) => s.update_by_state(state, f).await,
            Self::Postgres(s) => s.update_by_state(state, f).await,
            Self::Redis(s) => s.update_by_state(state, f).await,
            Self::InMemory(s) => s.update_by_state(state, f).await,
        }
    }

    async fn is_expired(&self, id: &str) -> OpenID4VPResult<bool> {
        match self {
            Self::Sqlite(s) => s.is_expired(id).await,
            Self::Postgres(s) => s.is_expired(id).await,
            Self::Redis(s) => s.is_expired(id).await,
            Self::InMemory(s) => s.is_expired(id).await,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stores::InMemoryTransactionStore;
    use crate::types::{ClientIdScheme, DCQLQuery, ProfileId, ResponseMode, TransactionStatus};

    /// Build a fresh isolated in-memory store for each test.
    /// Using InMemoryTransactionStore directly avoids SQLite shared-cache
    /// state leaking between concurrently-running tests.
    fn make_store() -> DynTransactionStore {
        DynTransactionStore::InMemory(InMemoryTransactionStore::new(300))
    }

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

    #[tokio::test]
    async fn test_set_and_get() {
        let store = make_store();
        let tx = make_test_transaction("tx-1", "state-1", 60_000);
        store.set(tx).await.unwrap();

        let retrieved = store.get("tx-1").await.unwrap().unwrap();
        assert_eq!(retrieved.state, "state-1");
        assert_eq!(retrieved.status, TransactionStatus::Pending);
    }

    #[tokio::test]
    async fn test_find_by_state() {
        let store = make_store();
        store
            .set(make_test_transaction("tx-1", "state-abc", 60_000))
            .await
            .unwrap();
        store
            .set(make_test_transaction("tx-2", "state-def", 60_000))
            .await
            .unwrap();

        let found = store.find_by_state("state-abc").await.unwrap().unwrap();
        assert_eq!(found.id, "tx-1");

        assert!(
            store
                .find_by_state("state-missing")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_reject_duplicate_state_for_different_transaction() {
        let store = make_store();
        store
            .set(make_test_transaction("tx-1", "state-dup", 60_000))
            .await
            .unwrap();

        let err = store
            .set(make_test_transaction("tx-2", "state-dup", 60_000))
            .await
            .unwrap_err();

        assert!(err.to_string().contains("duplicate state"));
    }

    #[tokio::test]
    async fn test_update() {
        let store = make_store();
        store
            .set(make_test_transaction("tx-1", "state-1", 60_000))
            .await
            .unwrap();

        store
            .update("tx-1", |tx| tx.status = TransactionStatus::Received)
            .await
            .unwrap();

        let tx = store.get("tx-1").await.unwrap().unwrap();
        assert_eq!(tx.status, TransactionStatus::Received);
    }

    #[tokio::test]
    async fn test_update_status() {
        let store = make_store();
        store
            .set(make_test_transaction("tx-1", "state-1", 60_000))
            .await
            .unwrap();

        store
            .update_status("tx-1", TransactionStatus::Verified)
            .await
            .unwrap();

        let tx = store.get("tx-1").await.unwrap().unwrap();
        assert_eq!(tx.status, TransactionStatus::Verified);
    }

    #[tokio::test]
    async fn test_is_expired() {
        let store = make_store();
        store
            .set(make_test_transaction("tx-expired", "state-1", -1_000))
            .await
            .unwrap();
        store
            .set(make_test_transaction("tx-valid", "state-2", 60_000))
            .await
            .unwrap();

        assert!(store.is_expired("tx-expired").await.unwrap());
        assert!(!store.is_expired("tx-valid").await.unwrap());
        assert!(store.is_expired("tx-nonexistent").await.unwrap());

        // Expired transaction should have been removed.
        assert!(store.get("tx-expired").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_delete() {
        let store = make_store();
        store
            .set(make_test_transaction("tx-1", "state-1", 60_000))
            .await
            .unwrap();

        assert!(store.delete("tx-1").await.unwrap());
        assert!(!store.delete("tx-1").await.unwrap()); // already deleted
        assert!(store.get("tx-1").await.unwrap().is_none());
    }
}
