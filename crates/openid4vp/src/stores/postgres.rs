//! PostgreSQL-backed transaction store.

use async_trait::async_trait;

use crate::error::{OpenID4VPError, OpenID4VPResult};
use crate::transaction::TransactionStore;
use crate::types::{OpenID4VPTransaction, TransactionStatus};

pub struct PostgresTransactionStore {
    pool: sqlx::PgPool,
    _ttl_secs: i64,
}

impl PostgresTransactionStore {
    pub(crate) async fn new(url: &str, ttl_secs: i64) -> OpenID4VPResult<Self> {
        let pool = sqlx::PgPool::connect(url)
            .await
            .map_err(|e| OpenID4VPError::Config(format!("Cannot connect to Postgres: {e}")))?;
        let store = Self {
            pool,
            _ttl_secs: ttl_secs,
        };
        store.migrate().await?;
        Ok(store)
    }

    async fn migrate(&self) -> OpenID4VPResult<()> {
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS openid4vp_transactions (
                id          TEXT        PRIMARY KEY NOT NULL,
                state       TEXT        NOT NULL,
                expires_at  BIGINT      NOT NULL,
                data        JSONB       NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_openid4vp_transactions_state
                ON openid4vp_transactions (state);"#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| OpenID4VPError::Internal(format!("Postgres migration failed: {e}")))?;
        Ok(())
    }
}

#[async_trait]
impl TransactionStore for PostgresTransactionStore {
    async fn set(&self, transaction: OpenID4VPTransaction) -> OpenID4VPResult<()> {
        let data = serde_json::to_value(&transaction)
            .map_err(|e| OpenID4VPError::Internal(format!("Transaction serialization: {e}")))?;
        sqlx::query(
            "INSERT INTO openid4vp_transactions (id, state, expires_at, data) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT(id) DO UPDATE SET state=EXCLUDED.state, \
                                           expires_at=EXCLUDED.expires_at, \
                                           data=EXCLUDED.data",
        )
        .bind(&transaction.id)
        .bind(&transaction.state)
        .bind(transaction.expires_at)
        .bind(data)
        .execute(&self.pool)
        .await
        .map_err(|e| OpenID4VPError::Internal(format!("Postgres set: {e}")))?;
        Ok(())
    }

    async fn get(&self, id: &str) -> OpenID4VPResult<Option<OpenID4VPTransaction>> {
        let row: Option<(serde_json::Value,)> =
            sqlx::query_as("SELECT data FROM openid4vp_transactions WHERE id = $1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| OpenID4VPError::Internal(format!("Postgres get: {e}")))?;
        row.map(|(v,)| {
            serde_json::from_value(v)
                .map_err(|e| OpenID4VPError::Internal(format!("Transaction deserialization: {e}")))
        })
        .transpose()
    }

    async fn find_by_state(&self, state: &str) -> OpenID4VPResult<Option<OpenID4VPTransaction>> {
        let row: Option<(serde_json::Value,)> =
            sqlx::query_as("SELECT data FROM openid4vp_transactions WHERE state = $1 LIMIT 1")
                .bind(state)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| OpenID4VPError::Internal(format!("Postgres find_by_state: {e}")))?;
        row.map(|(v,)| {
            serde_json::from_value(v)
                .map_err(|e| OpenID4VPError::Internal(format!("Transaction deserialization: {e}")))
        })
        .transpose()
    }

    async fn delete(&self, id: &str) -> OpenID4VPResult<bool> {
        let result = sqlx::query("DELETE FROM openid4vp_transactions WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| OpenID4VPError::Internal(format!("Postgres delete: {e}")))?;
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
            sqlx::query_as("SELECT expires_at FROM openid4vp_transactions WHERE id = $1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| OpenID4VPError::Internal(format!("Postgres is_expired: {e}")))?;
        match row {
            None => Ok(true),
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
