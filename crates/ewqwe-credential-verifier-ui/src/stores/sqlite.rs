//! Verifier App — SQLite-backed user store.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::str::FromStr as _;

use crate::{
    db::VerifierAppStore,
    error::{VerifierAppError, VerifierAppResult},
    models::{NewUserRecord, UserChanges, VerifierAppRole, VerifierAppUser},
};

// ============================================================================
// Store struct
// ============================================================================

pub struct SqliteVerifierAppStore {
    pool: sqlx::SqlitePool,
}

// ============================================================================
// Construction & migration
// ============================================================================

impl SqliteVerifierAppStore {
    /// Open an isolated in-memory SQLite Verifier App store.
    pub async fn new_memory() -> VerifierAppResult<Self> {
        let options = SqliteConnectOptions::from_str("sqlite::memory:")
            .map_err(|e| VerifierAppError::Config(format!("SQLite URL parse: {e}")))?;

        // Single connection so all operations share the same in-memory database.
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .map_err(|e| VerifierAppError::Config(format!("SQLite in-memory open: {e}")))?;

        let store = Self { pool };
        store.migrate().await?;
        Ok(store)
    }

    /// Open (or create) a SQLite Verifier App store at the given filesystem path.
    pub async fn new_file(path: &str) -> VerifierAppResult<Self> {
        let options = SqliteConnectOptions::from_str(&format!("sqlite:{path}"))
            .map_err(|e| VerifierAppError::Config(format!("SQLite URL parse: {e}")))?
            .create_if_missing(true);

        let pool = sqlx::SqlitePool::connect_with(options)
            .await
            .map_err(|e| VerifierAppError::Config(format!("SQLite open {path}: {e}")))?;

        let store = Self { pool };
        store.migrate().await?;
        Ok(store)
    }

    /// Create tables and indexes if they do not already exist.
    async fn migrate(&self) -> VerifierAppResult<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS qrcode_app_users (
                id             TEXT PRIMARY KEY NOT NULL,
                email          TEXT UNIQUE NOT NULL,
                password_hash  TEXT,
                first_name     TEXT,
                last_name      TEXT,
                role           TEXT NOT NULL DEFAULT 'verifier',
                is_active      INTEGER NOT NULL DEFAULT 1,
                is_superadmin  INTEGER NOT NULL DEFAULT 0,
                allowed_credential_types TEXT,
                created_at     TEXT NOT NULL,
                updated_at     TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_qrca_users_email
                ON qrcode_app_users (email);
            CREATE INDEX IF NOT EXISTS idx_qrca_users_role
                ON qrcode_app_users (role);
            CREATE TABLE IF NOT EXISTS qrcode_app_oidc_providers (
                id            TEXT PRIMARY KEY NOT NULL,
                name          TEXT NOT NULL,
                issuer        TEXT NOT NULL,
                client_id     TEXT NOT NULL,
                client_secret TEXT NOT NULL,
                scope         TEXT NOT NULL DEFAULT 'openid email profile',
                enabled       INTEGER NOT NULL DEFAULT 1,
                created_by    TEXT REFERENCES qrcode_app_users(id),
                created_at    TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS verifier_app_settings (
                key   TEXT PRIMARY KEY NOT NULL,
                value TEXT NOT NULL
            );
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| VerifierAppError::Storage(format!("SQLite migration: {e}")))?;
        Ok(())
    }

    /// Parse a raw database row into a [`VerifierAppUser`].
    #[allow(clippy::too_many_arguments)]
    fn parse_row(
        id: String,
        email: String,
        password_hash: Option<String>,
        first_name: Option<String>,
        last_name: Option<String>,
        role: String,
        is_active: i32,
        is_superadmin: i32,
        allowed_credential_types: Option<String>,
        created_at: String,
        updated_at: String,
    ) -> VerifierAppResult<VerifierAppUser> {
        let role = VerifierAppRole::from_str(&role)
            .map_err(|e| VerifierAppError::Storage(format!("invalid role in db: {e}")))?;
        let created_at: DateTime<Utc> = created_at
            .parse()
            .map_err(|e| VerifierAppError::Storage(format!("invalid created_at: {e}")))?;
        let updated_at: DateTime<Utc> = updated_at
            .parse()
            .map_err(|e| VerifierAppError::Storage(format!("invalid updated_at: {e}")))?;

        let allowed_credential_types = allowed_credential_types
            .filter(|s| !s.is_empty())
            .map(|s| {
                s.split(',')
                    .map(|t| t.trim().to_string())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        Ok(VerifierAppUser {
            id,
            email,
            password_hash,
            first_name,
            last_name,
            role,
            is_active: is_active != 0,
            is_superadmin: is_superadmin != 0,
            allowed_credential_types,
            created_at,
            updated_at,
        })
    }
}

// ============================================================================
// VerifierAppStore implementation
// ============================================================================

type UserRow = (
    String,         // id
    String,         // email
    Option<String>, // password_hash
    Option<String>, // first_name
    Option<String>, // last_name
    String,         // role
    i32,            // is_active
    i32,            // is_superadmin
    Option<String>, // allowed_credential_types
    String,         // created_at
    String,         // updated_at
);

const SELECT_COLS: &str = "id, email, password_hash, first_name, last_name, \
    role, is_active, is_superadmin, allowed_credential_types, created_at, updated_at";

#[async_trait]
impl VerifierAppStore for SqliteVerifierAppStore {
    async fn user_count(&self) -> VerifierAppResult<u64> {
        let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM qrcode_app_users")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| VerifierAppError::Storage(format!("user_count: {e}")))?;
        Ok(count as u64)
    }

    async fn create_user(&self, record: &NewUserRecord) -> VerifierAppResult<VerifierAppUser> {
        let now = Utc::now().to_rfc3339();
        let allowed = if record.allowed_credential_types.is_empty() {
            None
        } else {
            Some(record.allowed_credential_types.join(","))
        };
        sqlx::query(
            "INSERT INTO qrcode_app_users \
             (id, email, password_hash, first_name, last_name, role, \
              is_active, is_superadmin, allowed_credential_types, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7, ?8, ?9, ?9)",
        )
        .bind(&record.id)
        .bind(&record.email)
        .bind(&record.password_hash)
        .bind(&record.first_name)
        .bind(&record.last_name)
        .bind(record.role.as_str())
        .bind(record.is_superadmin as i32)
        .bind(&allowed)
        .bind(&now)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            if e.to_string().contains("UNIQUE") {
                VerifierAppError::Conflict(format!(
                    "a user with email {} already exists",
                    record.email
                ))
            } else {
                VerifierAppError::Storage(format!("create_user: {e}"))
            }
        })?;

        self.get_user_by_id(&record.id)
            .await?
            .ok_or(VerifierAppError::NotFound)
    }

    async fn get_user_by_email(&self, email: &str) -> VerifierAppResult<Option<VerifierAppUser>> {
        let row: Option<UserRow> = sqlx::query_as(&format!(
            "SELECT {SELECT_COLS} FROM qrcode_app_users WHERE email = ?1"
        ))
        .bind(email)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| VerifierAppError::Storage(format!("get_user_by_email: {e}")))?;

        row.map(|(id, email, ph, fn_, ln, role, ia, isa, act, ca, ua)| {
            Self::parse_row(id, email, ph, fn_, ln, role, ia, isa, act, ca, ua)
        })
        .transpose()
    }

    async fn get_user_by_id(&self, id: &str) -> VerifierAppResult<Option<VerifierAppUser>> {
        let row: Option<UserRow> = sqlx::query_as(&format!(
            "SELECT {SELECT_COLS} FROM qrcode_app_users WHERE id = ?1"
        ))
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| VerifierAppError::Storage(format!("get_user_by_id: {e}")))?;

        row.map(|(id, email, ph, fn_, ln, role, ia, isa, act, ca, ua)| {
            Self::parse_row(id, email, ph, fn_, ln, role, ia, isa, act, ca, ua)
        })
        .transpose()
    }

    async fn list_users(&self, active_only: bool) -> VerifierAppResult<Vec<VerifierAppUser>> {
        let sql = if active_only {
            format!("SELECT {SELECT_COLS} FROM qrcode_app_users WHERE is_active = 1 ORDER BY email")
        } else {
            format!("SELECT {SELECT_COLS} FROM qrcode_app_users ORDER BY email")
        };

        let rows: Vec<UserRow> = sqlx::query_as(&sql)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| VerifierAppError::Storage(format!("list_users: {e}")))?;

        rows.into_iter()
            .map(|(id, email, ph, fn_, ln, role, ia, isa, act, ca, ua)| {
                Self::parse_row(id, email, ph, fn_, ln, role, ia, isa, act, ca, ua)
            })
            .collect()
    }

    async fn update_user(
        &self,
        id: &str,
        changes: &UserChanges,
    ) -> VerifierAppResult<VerifierAppUser> {
        let current = self
            .get_user_by_id(id)
            .await?
            .ok_or(VerifierAppError::NotFound)?;

        let first_name = changes
            .first_name
            .as_deref()
            .or(current.first_name.as_deref());
        let last_name = changes
            .last_name
            .as_deref()
            .or(current.last_name.as_deref());
        let role = changes.role.as_ref().unwrap_or(&current.role);
        let is_active = changes.is_active.unwrap_or(current.is_active);
        let password_hash = changes
            .password_hash
            .as_deref()
            .or(current.password_hash.as_deref());
        let allowed = changes
            .allowed_credential_types
            .as_ref()
            .unwrap_or(&current.allowed_credential_types);
        let allowed_str = if allowed.is_empty() {
            None
        } else {
            Some(allowed.join(","))
        };
        let now = Utc::now().to_rfc3339();

        sqlx::query(
            "UPDATE qrcode_app_users SET \
             first_name=?1, last_name=?2, role=?3, is_active=?4, \
             password_hash=?5, allowed_credential_types=?6, updated_at=?7 \
             WHERE id=?8",
        )
        .bind(first_name)
        .bind(last_name)
        .bind(role.as_str())
        .bind(is_active as i32)
        .bind(password_hash)
        .bind(&allowed_str)
        .bind(&now)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(|e| VerifierAppError::Storage(format!("update_user: {e}")))?;

        self.get_user_by_id(id)
            .await?
            .ok_or(VerifierAppError::NotFound)
    }

    async fn delete_user(&self, id: &str) -> VerifierAppResult<()> {
        // Refuse to delete the superadmin account.
        let user = self
            .get_user_by_id(id)
            .await?
            .ok_or(VerifierAppError::NotFound)?;
        if user.is_superadmin {
            return Err(VerifierAppError::Conflict(
                "the superadmin account cannot be deleted".to_string(),
            ));
        }

        sqlx::query("DELETE FROM qrcode_app_users WHERE id = ?1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| VerifierAppError::Storage(format!("delete_user: {e}")))?;
        Ok(())
    }

    async fn get_setting(&self, key: &str) -> VerifierAppResult<Option<String>> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT value FROM verifier_app_settings WHERE key = ?1")
                .bind(key)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| VerifierAppError::Storage(format!("get_setting: {e}")))?;
        Ok(row.map(|(v,)| v))
    }

    async fn set_setting(&self, key: &str, value: &str) -> VerifierAppResult<()> {
        sqlx::query(
            "INSERT INTO verifier_app_settings (key, value) VALUES (?1, ?2) \
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        )
        .bind(key)
        .bind(value)
        .execute(&self.pool)
        .await
        .map_err(|e| VerifierAppError::Storage(format!("set_setting: {e}")))?;
        Ok(())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::NewUserRecord;

    async fn test_store() -> SqliteVerifierAppStore {
        SqliteVerifierAppStore::new_memory().await.unwrap()
    }

    fn sample_user() -> NewUserRecord {
        NewUserRecord {
            id: uuid::Uuid::new_v4().to_string(),
            email: "alice@example.com".into(),
            password_hash: Some("hash123".into()),
            first_name: Some("Alice".into()),
            last_name: Some("Smith".into()),
            role: VerifierAppRole::Verifier,
            is_superadmin: false,
            allowed_credential_types: vec!["proof-of-age".into(), "mdl".into()],
        }
    }

    #[tokio::test]
    async fn test_create_and_get_user() {
        let store = test_store().await;
        let rec = sample_user();
        let user = store.create_user(&rec).await.unwrap();
        assert_eq!(user.email, "alice@example.com");
        assert_eq!(user.allowed_credential_types, vec!["proof-of-age", "mdl"]);
        assert_eq!(user.role, VerifierAppRole::Verifier);

        let fetched = store
            .get_user_by_email("alice@example.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fetched.id, user.id);
        assert_eq!(
            fetched.allowed_credential_types,
            vec!["proof-of-age", "mdl"]
        );
    }

    #[tokio::test]
    async fn test_empty_allowed_credential_types() {
        let store = test_store().await;
        let mut rec = sample_user();
        rec.allowed_credential_types = vec![];
        let user = store.create_user(&rec).await.unwrap();
        assert!(user.allowed_credential_types.is_empty());
    }

    #[tokio::test]
    async fn test_update_allowed_credential_types() {
        let store = test_store().await;
        let rec = sample_user();
        let user = store.create_user(&rec).await.unwrap();

        let changes = UserChanges {
            allowed_credential_types: Some(vec!["national-id".into()]),
            ..Default::default()
        };
        let updated = store.update_user(&user.id, &changes).await.unwrap();
        assert_eq!(updated.allowed_credential_types, vec!["national-id"]);
    }

    #[tokio::test]
    async fn test_list_users() {
        let store = test_store().await;
        let rec1 = sample_user();
        store.create_user(&rec1).await.unwrap();
        let mut rec2 = sample_user();
        rec2.email = "bob@example.com".into();
        rec2.allowed_credential_types = vec![];
        store.create_user(&rec2).await.unwrap();

        let users = store.list_users(false).await.unwrap();
        assert_eq!(users.len(), 2);
    }

    #[tokio::test]
    async fn test_duplicate_email_returns_conflict() {
        let store = test_store().await;
        let rec1 = sample_user();
        let email = rec1.email.clone();
        store.create_user(&rec1).await.unwrap();
        let mut rec2 = sample_user();
        rec2.email = email;
        let result = store.create_user(&rec2).await;
        assert!(matches!(result, Err(VerifierAppError::Conflict(_))));
    }

    #[tokio::test]
    async fn test_settings_roundtrip() {
        let store = test_store().await;
        store.set_setting("app_name", "Test App").await.unwrap();
        let val = store.get_setting("app_name").await.unwrap();
        assert_eq!(val.as_deref(), Some("Test App"));

        let missing = store.get_setting("nonexistent").await.unwrap();
        assert!(missing.is_none());
    }

    #[tokio::test]
    async fn test_delete_user() {
        let store = test_store().await;
        let rec = sample_user();
        let user = store.create_user(&rec).await.unwrap();
        store.delete_user(&user.id).await.unwrap();
        let result = store.get_user_by_email("alice@example.com").await.unwrap();
        assert!(result.is_none());
    }
}
