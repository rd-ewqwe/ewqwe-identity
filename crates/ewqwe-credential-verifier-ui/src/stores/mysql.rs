//! Verifier App — MySQL/MariaDB-backed user store.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::str::FromStr as _;

use crate::{
    db::VerifierAppStore,
    error::{VerifierAppError, VerifierAppResult},
    models::{NewUserRecord, UserChanges, VerifierAppRole, VerifierAppUser},
};

// ============================================================================
// Store struct
// ============================================================================

pub struct MysqlVerifierAppStore {
    pool: sqlx::MySqlPool,
}

// ============================================================================
// Construction & migration
// ============================================================================

impl MysqlVerifierAppStore {
    /// Connect to MySQL/MariaDB and initialise the schema.
    pub async fn new(url: &str) -> VerifierAppResult<Self> {
        let pool = sqlx::MySqlPool::connect(url)
            .await
            .map_err(|e| VerifierAppError::Config(format!("MySQL connect: {e}")))?;
        let store = Self { pool };
        store.migrate().await?;
        Ok(store)
    }

    /// Create tables and indexes if they do not already exist.
    async fn migrate(&self) -> VerifierAppResult<()> {
        // MySQL requires separate statements — cannot batch DDL in one query.
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS qrcode_app_users (
                id             VARCHAR(255) PRIMARY KEY,
                email          VARCHAR(255) UNIQUE NOT NULL,
                password_hash  TEXT,
                first_name     VARCHAR(255),
                last_name      VARCHAR(255),
                role           VARCHAR(32)  NOT NULL DEFAULT 'verifier',
                is_active      BOOLEAN      NOT NULL DEFAULT TRUE,
                is_superadmin  BOOLEAN      NOT NULL DEFAULT FALSE,
                allowed_credential_types TEXT,
                created_at     DATETIME(3)  NOT NULL,
                updated_at     DATETIME(3)  NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| VerifierAppError::Storage(format!("MySQL migration (users): {e}")))?;

        // Indexes — MySQL uses IF NOT EXISTS since 8.0; for compatibility we
        // silently ignore "index already exists" errors.
        for stmt in [
            "CREATE INDEX idx_qrca_users_email ON qrcode_app_users (email)",
            "CREATE INDEX idx_qrca_users_role  ON qrcode_app_users (role)",
        ] {
            let result = sqlx::query(stmt).execute(&self.pool).await;
            if let Err(e) = result {
                let msg = e.to_string();
                // "Duplicate key name" is the MySQL error for index-already-exists.
                if !msg.contains("Duplicate key name") && !msg.contains("already exists") {
                    return Err(VerifierAppError::Storage(format!(
                        "MySQL migration (index): {e}"
                    )));
                }
            }
        }

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS qrcode_app_oidc_providers (
                id            VARCHAR(255) PRIMARY KEY,
                name          VARCHAR(255) NOT NULL,
                issuer        TEXT NOT NULL,
                client_id     TEXT NOT NULL,
                client_secret TEXT NOT NULL,
                scope         VARCHAR(255) NOT NULL DEFAULT 'openid email profile',
                enabled       BOOLEAN NOT NULL DEFAULT TRUE,
                created_by    VARCHAR(255),
                created_at    DATETIME(3) NOT NULL,
                FOREIGN KEY (created_by) REFERENCES qrcode_app_users(id)
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| VerifierAppError::Storage(format!("MySQL migration (oidc): {e}")))?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS verifier_ui_settings (
                `key`   VARCHAR(255) PRIMARY KEY,
                value   TEXT NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| VerifierAppError::Storage(format!("MySQL migration (settings): {e}")))?;

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
        is_active: bool,
        is_superadmin: bool,
        allowed_credential_types: Option<String>,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
    ) -> VerifierAppResult<VerifierAppUser> {
        let role = VerifierAppRole::from_str(&role)
            .map_err(|e| VerifierAppError::Storage(format!("invalid role in db: {e}")))?;

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
            is_active,
            is_superadmin,
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
    bool,           // is_active
    bool,           // is_superadmin
    Option<String>, // allowed_credential_types
    DateTime<Utc>,  // created_at
    DateTime<Utc>,  // updated_at
);

const SELECT_COLS: &str = "id, email, password_hash, first_name, last_name, \
    role, is_active, is_superadmin, allowed_credential_types, created_at, updated_at";

#[async_trait]
impl VerifierAppStore for MysqlVerifierAppStore {
    async fn user_count(&self) -> VerifierAppResult<u64> {
        let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM qrcode_app_users")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| VerifierAppError::Storage(format!("user_count: {e}")))?;
        Ok(count as u64)
    }

    async fn create_user(&self, record: &NewUserRecord) -> VerifierAppResult<VerifierAppUser> {
        let now = Utc::now();
        let allowed = if record.allowed_credential_types.is_empty() {
            None
        } else {
            Some(record.allowed_credential_types.join(","))
        };

        sqlx::query(
            "INSERT INTO qrcode_app_users \
             (id, email, password_hash, first_name, last_name, role, \
              is_active, is_superadmin, allowed_credential_types, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, TRUE, ?, ?, ?, ?)",
        )
        .bind(&record.id)
        .bind(&record.email)
        .bind(&record.password_hash)
        .bind(&record.first_name)
        .bind(&record.last_name)
        .bind(record.role.as_str())
        .bind(record.is_superadmin)
        .bind(&allowed)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("Duplicate entry") || msg.contains("unique") {
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
            "SELECT {SELECT_COLS} FROM qrcode_app_users WHERE email = ?"
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
            "SELECT {SELECT_COLS} FROM qrcode_app_users WHERE id = ?"
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
            format!(
                "SELECT {SELECT_COLS} FROM qrcode_app_users \
                 WHERE is_active = TRUE ORDER BY email"
            )
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
        let now = Utc::now();

        sqlx::query(
            "UPDATE qrcode_app_users SET \
             first_name=?, last_name=?, role=?, is_active=?, \
             password_hash=?, allowed_credential_types=?, updated_at=? \
             WHERE id=?",
        )
        .bind(first_name)
        .bind(last_name)
        .bind(role.as_str())
        .bind(is_active)
        .bind(password_hash)
        .bind(&allowed_str)
        .bind(now)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(|e| VerifierAppError::Storage(format!("update_user: {e}")))?;

        self.get_user_by_id(id)
            .await?
            .ok_or(VerifierAppError::NotFound)
    }

    async fn delete_user(&self, id: &str) -> VerifierAppResult<()> {
        let user = self
            .get_user_by_id(id)
            .await?
            .ok_or(VerifierAppError::NotFound)?;
        if user.is_superadmin {
            return Err(VerifierAppError::Conflict(
                "the superadmin account cannot be deleted".to_string(),
            ));
        }

        sqlx::query("DELETE FROM qrcode_app_users WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| VerifierAppError::Storage(format!("delete_user: {e}")))?;
        Ok(())
    }

    async fn get_setting(&self, key: &str) -> VerifierAppResult<Option<String>> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT value FROM verifier_ui_settings WHERE `key` = ?")
                .bind(key)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| VerifierAppError::Storage(format!("get_setting: {e}")))?;
        Ok(row.map(|(v,)| v))
    }

    async fn set_setting(&self, key: &str, value: &str) -> VerifierAppResult<()> {
        // MySQL upsert: INSERT ... ON DUPLICATE KEY UPDATE.
        sqlx::query(
            "INSERT INTO verifier_ui_settings (`key`, value) VALUES (?, ?) \
             ON DUPLICATE KEY UPDATE value = VALUES(value)",
        )
        .bind(key)
        .bind(value)
        .execute(&self.pool)
        .await
        .map_err(|e| VerifierAppError::Storage(format!("set_setting: {e}")))?;
        Ok(())
    }
}
