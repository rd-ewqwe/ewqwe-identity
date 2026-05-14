//! SQLite-backed transaction store (in-memory or file).

use async_trait::async_trait;

use crate::error::{OpenID4VPError, OpenID4VPResult};
use crate::transaction::TransactionStore;
use crate::types::{OpenID4VPTransaction, TransactionStatus};

pub struct SqliteTransactionStore {
    pool: sqlx::SqlitePool,
    _ttl_secs: i64,
}

impl SqliteTransactionStore {
    /// Open an in-memory SQLite database shared across all pool connections.
    pub(crate) async fn new_memory(ttl_secs: i64) -> OpenID4VPResult<Self> {
        use sqlx::sqlite::SqliteConnectOptions;
        use std::str::FromStr as _;
        // Use a named shared-cache URI so all pool connections see the same data.
        // Plain `:memory:` gives each connection its own isolated database.
        let url = "sqlite:file::memory:?cache=shared&mode=memory";
        let options = SqliteConnectOptions::from_str(url)
            .map_err(|e| OpenID4VPError::Config(format!("SQLite URL parse error: {e}")))?
            .shared_cache(true);
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .min_connections(1)
            .connect_with(options)
            .await
            .map_err(|e| {
                OpenID4VPError::Config(format!("Cannot open SQLite in-memory store: {e}"))
            })?;
        let store = Self {
            pool,
            _ttl_secs: ttl_secs,
        };
        store.migrate().await?;
        Ok(store)
    }

    /// Open (or create) a SQLite database at the given filesystem path.
    pub(crate) async fn new_file(path: &str, ttl_secs: i64) -> OpenID4VPResult<Self> {
        use sqlx::sqlite::SqliteConnectOptions;
        use std::str::FromStr as _;
        let options = SqliteConnectOptions::from_str(&format!("sqlite:{path}"))
            .map_err(|e| OpenID4VPError::Config(format!("SQLite URL parse error: {e}")))?
            .create_if_missing(true);
        let pool = sqlx::SqlitePool::connect_with(options).await.map_err(|e| {
            OpenID4VPError::Config(format!("Cannot open SQLite file store at {path}: {e}"))
        })?;
        let store = Self {
            pool,
            _ttl_secs: ttl_secs,
        };
        store.migrate().await?;
        Ok(store)
    }

    async fn migrate(&self) -> OpenID4VPResult<()> {
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS transactions (
                id          TEXT    PRIMARY KEY NOT NULL,
                state       TEXT    NOT NULL,
                expires_at  INTEGER NOT NULL,
                data        TEXT    NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_transactions_state_unique
                ON transactions (state);"#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| OpenID4VPError::Internal(format!("SQLite migration failed: {e}")))?;
        Ok(())
    }

    fn serialize(tx: &OpenID4VPTransaction) -> OpenID4VPResult<String> {
        serde_json::to_string(tx)
            .map_err(|e| OpenID4VPError::Internal(format!("Transaction serialization: {e}")))
    }

    fn deserialize(data: &str) -> OpenID4VPResult<OpenID4VPTransaction> {
        serde_json::from_str(data)
            .map_err(|e| OpenID4VPError::Internal(format!("Transaction deserialization: {e}")))
    }
}

#[async_trait]
impl TransactionStore for SqliteTransactionStore {
    async fn set(&self, transaction: OpenID4VPTransaction) -> OpenID4VPResult<()> {
        let data = Self::serialize(&transaction)?;
        sqlx::query(
            "INSERT INTO transactions (id, state, expires_at, data) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(id) DO UPDATE SET state=excluded.state,
                                           expires_at=excluded.expires_at,
                                           data=excluded.data",
        )
        .bind(&transaction.id)
        .bind(&transaction.state)
        .bind(transaction.expires_at)
        .bind(data)
        .execute(&self.pool)
        .await
        .map_err(|e| OpenID4VPError::Internal(format!("SQLite set: {e}")))?;
        Ok(())
    }

    async fn get(&self, id: &str) -> OpenID4VPResult<Option<OpenID4VPTransaction>> {
        let row: Option<(String,)> = sqlx::query_as("SELECT data FROM transactions WHERE id = ?1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| OpenID4VPError::Internal(format!("SQLite get: {e}")))?;
        row.map(|(data,)| Self::deserialize(&data)).transpose()
    }

    async fn find_by_state(&self, state: &str) -> OpenID4VPResult<Option<OpenID4VPTransaction>> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT data FROM transactions WHERE state = ?1 LIMIT 1")
                .bind(state)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| OpenID4VPError::Internal(format!("SQLite find_by_state: {e}")))?;
        row.map(|(data,)| Self::deserialize(&data)).transpose()
    }

    async fn delete(&self, id: &str) -> OpenID4VPResult<bool> {
        let result = sqlx::query("DELETE FROM transactions WHERE id = ?1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| OpenID4VPError::Internal(format!("SQLite delete: {e}")))?;
        Ok(result.rows_affected() > 0)
    }

    async fn update_status(&self, id: &str, status: TransactionStatus) -> OpenID4VPResult<()> {
        self.update(id, |tx| tx.status = status).await?;
        Ok(())
    }

    async fn update<F>(&self, id: &str, f: F) -> OpenID4VPResult<Option<()>>
    where
        F: FnOnce(&mut OpenID4VPTransaction) + Send,
    {
        let mut tx = match self.get(id).await? {
            Some(t) => t,
            None => return Ok(None),
        };
        f(&mut tx);
        self.set(tx).await?;
        Ok(Some(()))
    }

    async fn update_by_state<F>(&self, state: &str, f: F) -> OpenID4VPResult<Option<()>>
    where
        F: FnOnce(&mut OpenID4VPTransaction) + Send,
    {
        let mut tx = match self.find_by_state(state).await? {
            Some(t) => t,
            None => return Ok(None),
        };
        f(&mut tx);
        self.set(tx).await?;
        Ok(Some(()))
    }

    async fn is_expired(&self, id: &str) -> OpenID4VPResult<bool> {
        let now = chrono::Utc::now().timestamp_millis();
        let row: Option<(i64,)> =
            sqlx::query_as("SELECT expires_at FROM transactions WHERE id = ?1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| OpenID4VPError::Internal(format!("SQLite is_expired: {e}")))?;
        match row {
            None => Ok(true), // not found → treat as expired
            Some((expires_at,)) => {
                if expires_at < now {
                    let _ = self.delete(id).await;
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
        }
    }
}
