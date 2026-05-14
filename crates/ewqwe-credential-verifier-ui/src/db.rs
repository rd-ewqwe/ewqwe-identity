//! Verifier App store trait and dynamic dispatch wrapper.

use async_trait::async_trait;

use crate::{
    config::{VerifierAppDbBackend, VerifierUiConfig},
    error::VerifierAppResult,
    models::{NewUserRecord, UserChanges, VerifierAppUser},
    stores::{MysqlVerifierAppStore, PostgresVerifierAppStore, SqliteVerifierAppStore},
};

// ============================================================================
// Store trait
// ============================================================================

/// Async interface for the Verifier App user store.
#[async_trait]
pub trait VerifierAppStore: Send + Sync {
    /// Return the total number of users in the database.
    ///
    /// Used to gate the bootstrap endpoint — it only succeeds when this is 0.
    async fn user_count(&self) -> VerifierAppResult<u64>;

    /// Create a new user and return the persisted record.
    async fn create_user(&self, record: &NewUserRecord) -> VerifierAppResult<VerifierAppUser>;

    /// Look up a user by their email address.
    async fn get_user_by_email(&self, email: &str) -> VerifierAppResult<Option<VerifierAppUser>>;

    /// Look up a user by their UUID.
    async fn get_user_by_id(&self, id: &str) -> VerifierAppResult<Option<VerifierAppUser>>;

    /// List all users. When `active_only` is `true`, only active users are returned.
    async fn list_users(&self, active_only: bool) -> VerifierAppResult<Vec<VerifierAppUser>>;

    /// Apply partial changes to a user and return the updated record.
    async fn update_user(
        &self,
        id: &str,
        changes: &UserChanges,
    ) -> VerifierAppResult<VerifierAppUser>;

    /// Permanently remove a user from the database.
    ///
    /// Returns [`VerifierAppError::Conflict`] if the user is the superadmin.
    async fn delete_user(&self, id: &str) -> VerifierAppResult<()>;

    /// Get a setting value by key.
    async fn get_setting(&self, key: &str) -> VerifierAppResult<Option<String>>;

    /// Upsert a setting value by key.
    async fn set_setting(&self, key: &str, value: &str) -> VerifierAppResult<()>;
}

// ============================================================================
// Dynamic dispatch wrapper
// ============================================================================

/// Wraps any supported backend behind a single concrete type.
pub enum DynVerifierUiStore {
    Sqlite(SqliteVerifierAppStore),
    Postgres(PostgresVerifierAppStore),
    Mysql(MysqlVerifierAppStore),
}

impl DynVerifierUiStore {
    /// Construct a new store from the provided configuration.
    ///
    /// Runs schema migrations automatically.  Call once during server startup.
    pub async fn new(config: &VerifierUiConfig) -> VerifierAppResult<Self> {
        match &config.db {
            VerifierAppDbBackend::SqliteMemory => {
                let store = SqliteVerifierAppStore::new_memory().await?;
                Ok(Self::Sqlite(store))
            }
            VerifierAppDbBackend::SqliteFile { path } => {
                let store = SqliteVerifierAppStore::new_file(path).await?;
                Ok(Self::Sqlite(store))
            }
            VerifierAppDbBackend::Postgres { url } => {
                let store = PostgresVerifierAppStore::new(url).await?;
                Ok(Self::Postgres(store))
            }
            VerifierAppDbBackend::Mysql { url } => {
                let store = MysqlVerifierAppStore::new(url).await?;
                Ok(Self::Mysql(store))
            }
        }
    }
}

// ============================================================================
// Trait delegation
// ============================================================================

#[async_trait]
impl VerifierAppStore for DynVerifierUiStore {
    async fn user_count(&self) -> VerifierAppResult<u64> {
        match self {
            Self::Sqlite(s) => s.user_count().await,
            Self::Postgres(s) => s.user_count().await,
            Self::Mysql(s) => s.user_count().await,
        }
    }

    async fn create_user(&self, record: &NewUserRecord) -> VerifierAppResult<VerifierAppUser> {
        match self {
            Self::Sqlite(s) => s.create_user(record).await,
            Self::Postgres(s) => s.create_user(record).await,
            Self::Mysql(s) => s.create_user(record).await,
        }
    }

    async fn get_user_by_email(&self, email: &str) -> VerifierAppResult<Option<VerifierAppUser>> {
        match self {
            Self::Sqlite(s) => s.get_user_by_email(email).await,
            Self::Postgres(s) => s.get_user_by_email(email).await,
            Self::Mysql(s) => s.get_user_by_email(email).await,
        }
    }

    async fn get_user_by_id(&self, id: &str) -> VerifierAppResult<Option<VerifierAppUser>> {
        match self {
            Self::Sqlite(s) => s.get_user_by_id(id).await,
            Self::Postgres(s) => s.get_user_by_id(id).await,
            Self::Mysql(s) => s.get_user_by_id(id).await,
        }
    }

    async fn list_users(&self, active_only: bool) -> VerifierAppResult<Vec<VerifierAppUser>> {
        match self {
            Self::Sqlite(s) => s.list_users(active_only).await,
            Self::Postgres(s) => s.list_users(active_only).await,
            Self::Mysql(s) => s.list_users(active_only).await,
        }
    }

    async fn update_user(
        &self,
        id: &str,
        changes: &UserChanges,
    ) -> VerifierAppResult<VerifierAppUser> {
        match self {
            Self::Sqlite(s) => s.update_user(id, changes).await,
            Self::Postgres(s) => s.update_user(id, changes).await,
            Self::Mysql(s) => s.update_user(id, changes).await,
        }
    }

    async fn delete_user(&self, id: &str) -> VerifierAppResult<()> {
        match self {
            Self::Sqlite(s) => s.delete_user(id).await,
            Self::Postgres(s) => s.delete_user(id).await,
            Self::Mysql(s) => s.delete_user(id).await,
        }
    }

    async fn get_setting(&self, key: &str) -> VerifierAppResult<Option<String>> {
        match self {
            Self::Sqlite(s) => s.get_setting(key).await,
            Self::Postgres(s) => s.get_setting(key).await,
            Self::Mysql(s) => s.get_setting(key).await,
        }
    }

    async fn set_setting(&self, key: &str, value: &str) -> VerifierAppResult<()> {
        match self {
            Self::Sqlite(s) => s.set_setting(key, value).await,
            Self::Postgres(s) => s.set_setting(key, value).await,
            Self::Mysql(s) => s.set_setting(key, value).await,
        }
    }
}
