//! Pure in-memory transaction store backed by a `HashMap` behind a `RwLock`.
//!
//! Suitable for single-node deployments or testing. Transactions are held
//! in process memory; expiry is checked lazily on access.

use async_trait::async_trait;
use std::collections::HashMap;
use tokio::sync::RwLock;

use crate::error::OpenID4VPResult;
use crate::transaction::TransactionStore;
use crate::types::{OpenID4VPTransaction, TransactionStatus};

pub struct InMemoryTransactionStore {
    inner: RwLock<HashMap<String, OpenID4VPTransaction>>,
    _ttl_secs: i64,
}

impl InMemoryTransactionStore {
    pub fn new(ttl_secs: i64) -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
            _ttl_secs: ttl_secs,
        }
    }
}

#[async_trait]
impl TransactionStore for InMemoryTransactionStore {
    async fn set(&self, transaction: OpenID4VPTransaction) -> OpenID4VPResult<()> {
        self.inner
            .write()
            .await
            .insert(transaction.id.clone(), transaction);
        Ok(())
    }

    async fn get(&self, id: &str) -> OpenID4VPResult<Option<OpenID4VPTransaction>> {
        Ok(self.inner.read().await.get(id).cloned())
    }

    async fn find_by_state(&self, state: &str) -> OpenID4VPResult<Option<OpenID4VPTransaction>> {
        Ok(self
            .inner
            .read()
            .await
            .values()
            .find(|tx| tx.state == state)
            .cloned())
    }

    async fn delete(&self, id: &str) -> OpenID4VPResult<bool> {
        Ok(self.inner.write().await.remove(id).is_some())
    }

    async fn update_status(&self, id: &str, status: TransactionStatus) -> OpenID4VPResult<()> {
        self.update(id, |tx| tx.status = status).await?;
        Ok(())
    }

    async fn update<F>(&self, id: &str, f: F) -> OpenID4VPResult<Option<()>>
    where
        F: FnOnce(&mut OpenID4VPTransaction) + Send,
    {
        let mut map = self.inner.write().await;
        match map.get_mut(id) {
            Some(tx) => {
                f(tx);
                Ok(Some(()))
            }
            None => Ok(None),
        }
    }

    async fn update_by_state<F>(&self, state: &str, f: F) -> OpenID4VPResult<Option<()>>
    where
        F: FnOnce(&mut OpenID4VPTransaction) + Send,
    {
        let mut map = self.inner.write().await;
        match map.values_mut().find(|tx| tx.state == state) {
            Some(tx) => {
                f(tx);
                Ok(Some(()))
            }
            None => Ok(None),
        }
    }

    async fn is_expired(&self, id: &str) -> OpenID4VPResult<bool> {
        let now = chrono::Utc::now().timestamp_millis();
        let mut map = self.inner.write().await;
        match map.get(id) {
            None => Ok(true),
            Some(tx) => {
                if tx.expires_at < now {
                    map.remove(id);
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
        }
    }
}
