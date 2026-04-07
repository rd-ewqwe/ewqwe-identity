//! Redis-backed transaction store (TTL-native expiry — no cleanup thread needed).

use async_trait::async_trait;

use crate::error::{OpenID4VPError, OpenID4VPResult};
use crate::transaction::TransactionStore;
use crate::types::{OpenID4VPTransaction, TransactionStatus};

pub struct RedisTransactionStore {
    client: redis::Client,
    _ttl_secs: i64,
}

impl RedisTransactionStore {
    pub(crate) async fn new(url: &str, ttl_secs: i64) -> OpenID4VPResult<Self> {
        let client = redis::Client::open(url)
            .map_err(|e| OpenID4VPError::Config(format!("Invalid Redis URL: {e}")))?;
        // Verify connectivity.
        let mut conn = client
            .get_multiplexed_tokio_connection()
            .await
            .map_err(|e| OpenID4VPError::Config(format!("Cannot connect to Redis: {e}")))?;
        redis::cmd("PING")
            .query_async::<()>(&mut conn)
            .await
            .map_err(|e| OpenID4VPError::Config(format!("Redis PING failed: {e}")))?;
        Ok(Self { client, _ttl_secs: ttl_secs })
    }

    async fn conn(&self) -> OpenID4VPResult<redis::aio::MultiplexedConnection> {
        self.client
            .get_multiplexed_tokio_connection()
            .await
            .map_err(|e| OpenID4VPError::Internal(format!("Redis connection: {e}")))
    }

    fn id_key(id: &str) -> String {
        format!("openid4vp:tx:{id}")
    }

    fn state_key(state: &str) -> String {
        format!("openid4vp:state:{state}")
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
impl TransactionStore for RedisTransactionStore {
    async fn set(&self, transaction: OpenID4VPTransaction) -> OpenID4VPResult<()> {
        use redis::AsyncCommands as _;

        let data = Self::serialize(&transaction)?;
        let mut conn = self.conn().await?;

        // Derive TTL from the absolute expires_at timestamp so that refreshed
        // transactions always honour the original expiry.
        let now = chrono::Utc::now().timestamp_millis();
        let remaining_secs = ((transaction.expires_at - now) / 1000).max(1) as u64;

        conn.set_ex::<_, _, ()>(Self::id_key(&transaction.id), &data, remaining_secs)
            .await
            .map_err(|e| OpenID4VPError::Internal(format!("Redis SET: {e}")))?;

        conn.set_ex::<_, _, ()>(
            Self::state_key(&transaction.state),
            &transaction.id,
            remaining_secs,
        )
        .await
        .map_err(|e| OpenID4VPError::Internal(format!("Redis SET state index: {e}")))?;

        Ok(())
    }

    async fn get(&self, id: &str) -> OpenID4VPResult<Option<OpenID4VPTransaction>> {
        use redis::AsyncCommands as _;
        let mut conn = self.conn().await?;
        let data: Option<String> = conn
            .get(Self::id_key(id))
            .await
            .map_err(|e| OpenID4VPError::Internal(format!("Redis GET: {e}")))?;
        data.map(|d| Self::deserialize(&d)).transpose()
    }

    async fn find_by_state(&self, state: &str) -> OpenID4VPResult<Option<OpenID4VPTransaction>> {
        use redis::AsyncCommands as _;
        let mut conn = self.conn().await?;
        let id: Option<String> = conn
            .get(Self::state_key(state))
            .await
            .map_err(|e| OpenID4VPError::Internal(format!("Redis GET state key: {e}")))?;
        match id {
            None => Ok(None),
            Some(id) => self.get(&id).await,
        }
    }

    async fn delete(&self, id: &str) -> OpenID4VPResult<bool> {
        use redis::AsyncCommands as _;

        // Fetch the state before deleting so we can clean up the secondary index.
        let tx = self.get(id).await?;
        let mut conn = self.conn().await?;

        let deleted: i64 = conn
            .del(Self::id_key(id))
            .await
            .map_err(|e| OpenID4VPError::Internal(format!("Redis DEL: {e}")))?;

        if let Some(t) = &tx {
            let _: i64 = conn
                .del(Self::state_key(&t.state))
                .await
                .map_err(|e| OpenID4VPError::Internal(format!("Redis DEL state index: {e}")))?;
        }

        Ok(deleted > 0)
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

    /// The key either exists (not expired) or has been evicted by Redis TTL.
    async fn is_expired(&self, id: &str) -> OpenID4VPResult<bool> {
        use redis::AsyncCommands as _;
        let mut conn = self.conn().await?;
        let exists: bool = conn
            .exists(Self::id_key(id))
            .await
            .map_err(|e| OpenID4VPError::Internal(format!("Redis EXISTS: {e}")))?;
        Ok(!exists)
    }
}
