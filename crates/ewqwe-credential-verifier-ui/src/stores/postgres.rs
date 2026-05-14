//! Verifier App — PostgreSQL-backed user store.

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

pub struct PostgresVerifierAppStore {
    pool: sqlx::PgPool,
}

// ============================================================================
// Construction & migration
// ============================================================================

impl PostgresVerifierAppStore {
    /// Connect to PostgreSQL and initialise the schema.
    pub async fn new(url: &str) -> VerifierAppResult<Self> {
        let pool = sqlx::PgPool::connect(url)
            .await
            .map_err(|e| VerifierAppError::Config(format!("PostgreSQL connect: {e}")))?;
        let store = Self { pool };
        store.migrate().await?;
        Ok(store)
    }

    /// Create tables and indexes if they do not already exist.
    async fn migrate(&self) -> VerifierAppResult<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS qrcode_app_users (
                id             TEXT PRIMARY KEY,
                email          TEXT UNIQUE NOT NULL,
                password_hash  TEXT,
                first_name     TEXT,
                last_name      TEXT,
                role           TEXT NOT NULL DEFAULT 'verifier',
                is_active      BOOLEAN NOT NULL DEFAULT TRUE,
                is_superadmin  BOOLEAN NOT NULL DEFAULT FALSE,
                allowed_credential_types TEXT,
                created_at     TIMESTAMPTZ NOT NULL,
                updated_at     TIMESTAMPTZ NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_qrca_users_email
                ON qrcode_app_users (email);
            CREATE INDEX IF NOT EXISTS idx_qrca_users_role
                ON qrcode_app_users (role);
            CREATE TABLE IF NOT EXISTS qrcode_app_oidc_providers (
                id            TEXT PRIMARY KEY,
                name          TEXT NOT NULL,
                issuer        TEXT NOT NULL,
                client_id     TEXT NOT NULL,
                client_secret TEXT NOT NULL,
                scope         TEXT NOT NULL DEFAULT 'openid email profile',
                enabled       BOOLEAN NOT NULL DEFAULT TRUE,
                created_by    TEXT REFERENCES qrcode_app_users(id),
                created_at    TIMESTAMPTZ NOT NULL
            );
            CREATE TABLE IF NOT EXISTS verifier_ui_settings (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| VerifierAppError::Storage(format!("Postgres migration: {e}")))?;
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
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    String,
    bool,
    bool,
    Option<String>,
    DateTime<Utc>,
    DateTime<Utc>,
);

const SELECT_COLS: &str = "id, email, password_hash, first_name, last_name, \
    role, is_active, is_superadmin, allowed_credential_types, created_at, updated_at";

#[async_trait]
impl VerifierAppStore for PostgresVerifierAppStore {
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
             VALUES ($1, $2, $3, $4, $5, $6, TRUE, $7, $8, $9, $9)",
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
        .execute(&self.pool)
        .await
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("unique") || msg.contains("duplicate") {
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
            "SELECT {SELECT_COLS} FROM qrcode_app_users WHERE email = $1"
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
            "SELECT {SELECT_COLS} FROM qrcode_app_users WHERE id = $1"
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
             first_name=$1, last_name=$2, role=$3, is_active=$4, \
             password_hash=$5, allowed_credential_types=$6, updated_at=$7 \
             WHERE id=$8",
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

        sqlx::query("DELETE FROM qrcode_app_users WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| VerifierAppError::Storage(format!("delete_user: {e}")))?;
        Ok(())
    }

    async fn get_setting(&self, key: &str) -> VerifierAppResult<Option<String>> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT value FROM verifier_ui_settings WHERE key = $1")
                .bind(key)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| VerifierAppError::Storage(format!("get_setting: {e}")))?;
        Ok(row.map(|(v,)| v))
    }

    async fn set_setting(&self, key: &str, value: &str) -> VerifierAppResult<()> {
        sqlx::query(
            "INSERT INTO verifier_ui_settings (key, value) VALUES ($1, $2) \
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
