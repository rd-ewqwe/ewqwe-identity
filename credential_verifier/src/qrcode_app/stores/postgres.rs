//! QR Code APP — PostgreSQL-backed user store.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::str::FromStr as _;

use crate::qrcode_app::{
    db::QrcodeAppStore,
    error::{QrcodeAppError, QrcodeAppResult},
    models::{NewUserRecord, QrcodeAppRole, QrcodeAppUser, UserChanges},
};

// ============================================================================
// Store struct
// ============================================================================

pub struct PostgresQrcodeAppStore {
    pool: sqlx::PgPool,
}

// ============================================================================
// Construction & migration
// ============================================================================

impl PostgresQrcodeAppStore {
    /// Connect to PostgreSQL and initialise the schema.
    pub async fn new(url: &str) -> QrcodeAppResult<Self> {
        let pool = sqlx::PgPool::connect(url)
            .await
            .map_err(|e| QrcodeAppError::Config(format!("PostgreSQL connect: {e}")))?;
        let store = Self { pool };
        store.migrate().await?;
        Ok(store)
    }

    /// Create tables and indexes if they do not already exist.
    async fn migrate(&self) -> QrcodeAppResult<()> {
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
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| QrcodeAppError::Storage(format!("Postgres migration: {e}")))?;
        Ok(())
    }

    /// Parse a raw database row into a [`QrcodeAppUser`].
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
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
    ) -> QrcodeAppResult<QrcodeAppUser> {
        let role = QrcodeAppRole::from_str(&role)
            .map_err(|e| QrcodeAppError::Storage(format!("invalid role in db: {e}")))?;
        Ok(QrcodeAppUser {
            id,
            email,
            password_hash,
            first_name,
            last_name,
            role,
            is_active,
            is_superadmin,
            created_at,
            updated_at,
        })
    }
}

// ============================================================================
// QrcodeAppStore implementation
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
    DateTime<Utc>,
    DateTime<Utc>,
);

const SELECT_COLS: &str = "id, email, password_hash, first_name, last_name, \
    role, is_active, is_superadmin, created_at, updated_at";

#[async_trait]
impl QrcodeAppStore for PostgresQrcodeAppStore {
    async fn user_count(&self) -> QrcodeAppResult<u64> {
        let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM qrcode_app_users")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| QrcodeAppError::Storage(format!("user_count: {e}")))?;
        Ok(count as u64)
    }

    async fn create_user(&self, record: &NewUserRecord) -> QrcodeAppResult<QrcodeAppUser> {
        let now = Utc::now();
        sqlx::query(
            "INSERT INTO qrcode_app_users \
             (id, email, password_hash, first_name, last_name, role, \
              is_active, is_superadmin, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, TRUE, $7, $8, $8)",
        )
        .bind(&record.id)
        .bind(&record.email)
        .bind(&record.password_hash)
        .bind(&record.first_name)
        .bind(&record.last_name)
        .bind(record.role.as_str())
        .bind(record.is_superadmin)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("unique") || msg.contains("duplicate") {
                QrcodeAppError::Conflict(format!(
                    "a user with email {} already exists",
                    record.email
                ))
            } else {
                QrcodeAppError::Storage(format!("create_user: {e}"))
            }
        })?;

        self.get_user_by_id(&record.id)
            .await?
            .ok_or(QrcodeAppError::NotFound)
    }

    async fn get_user_by_email(&self, email: &str) -> QrcodeAppResult<Option<QrcodeAppUser>> {
        let row: Option<UserRow> = sqlx::query_as(&format!(
            "SELECT {SELECT_COLS} FROM qrcode_app_users WHERE email = $1"
        ))
        .bind(email)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| QrcodeAppError::Storage(format!("get_user_by_email: {e}")))?;

        row.map(|(id, email, ph, fn_, ln, role, ia, isa, ca, ua)| {
            Self::parse_row(id, email, ph, fn_, ln, role, ia, isa, ca, ua)
        })
        .transpose()
    }

    async fn get_user_by_id(&self, id: &str) -> QrcodeAppResult<Option<QrcodeAppUser>> {
        let row: Option<UserRow> = sqlx::query_as(&format!(
            "SELECT {SELECT_COLS} FROM qrcode_app_users WHERE id = $1"
        ))
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| QrcodeAppError::Storage(format!("get_user_by_id: {e}")))?;

        row.map(|(id, email, ph, fn_, ln, role, ia, isa, ca, ua)| {
            Self::parse_row(id, email, ph, fn_, ln, role, ia, isa, ca, ua)
        })
        .transpose()
    }

    async fn list_users(&self, active_only: bool) -> QrcodeAppResult<Vec<QrcodeAppUser>> {
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
            .map_err(|e| QrcodeAppError::Storage(format!("list_users: {e}")))?;

        rows.into_iter()
            .map(|(id, email, ph, fn_, ln, role, ia, isa, ca, ua)| {
                Self::parse_row(id, email, ph, fn_, ln, role, ia, isa, ca, ua)
            })
            .collect()
    }

    async fn update_user(&self, id: &str, changes: &UserChanges) -> QrcodeAppResult<QrcodeAppUser> {
        let current = self
            .get_user_by_id(id)
            .await?
            .ok_or(QrcodeAppError::NotFound)?;

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
        let now = Utc::now();

        sqlx::query(
            "UPDATE qrcode_app_users SET \
             first_name=$1, last_name=$2, role=$3, is_active=$4, \
             password_hash=$5, updated_at=$6 \
             WHERE id=$7",
        )
        .bind(first_name)
        .bind(last_name)
        .bind(role.as_str())
        .bind(is_active)
        .bind(password_hash)
        .bind(now)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(|e| QrcodeAppError::Storage(format!("update_user: {e}")))?;

        self.get_user_by_id(id)
            .await?
            .ok_or(QrcodeAppError::NotFound)
    }

    async fn delete_user(&self, id: &str) -> QrcodeAppResult<()> {
        let user = self
            .get_user_by_id(id)
            .await?
            .ok_or(QrcodeAppError::NotFound)?;
        if user.is_superadmin {
            return Err(QrcodeAppError::Conflict(
                "the superadmin account cannot be deleted".to_string(),
            ));
        }

        sqlx::query("DELETE FROM qrcode_app_users WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| QrcodeAppError::Storage(format!("delete_user: {e}")))?;
        Ok(())
    }
}
