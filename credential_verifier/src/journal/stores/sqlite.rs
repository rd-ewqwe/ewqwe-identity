//! SQLite-backed verification journal store.
//!
//! Supports both in-memory (`:memory:`) and file-based databases.
//! A `Mutex`-guarded exclusive transaction serialises concurrent CAS
//! appends at the Rust level, which is cheaper than hitting SQLite's own
//! BUSY_TIMEOUT in the connection pool.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use tokio::sync::Mutex;

use crate::journal::{
    ChainVerificationResult, JournalEntry, JournalError, JournalQuery, JournalResult, JournalStore,
    compute_entry_hash,
};

// ============================================================================
// Store struct
// ============================================================================

pub struct SqliteJournalStore {
    pool: sqlx::SqlitePool,
    /// Serialises CAS append operations so that concurrent tokio tasks do not
    /// race with each other on a shared SQLite file / in-memory database.
    append_lock: Mutex<()>,
}

// ============================================================================
// Construction & migration
// ============================================================================

impl SqliteJournalStore {
    /// Open an isolated in-memory SQLite journal.
    ///
    /// Uses a single-connection pool with `sqlite::memory:` so that each call
    /// produces a completely isolated database — safe for concurrent tests.
    /// For production use with persistence, call [`new_file`] instead.
    pub async fn new_memory() -> JournalResult<Self> {
        use sqlx::sqlite::SqliteConnectOptions;
        use sqlx::sqlite::SqlitePoolOptions;
        use std::str::FromStr as _;

        let options = SqliteConnectOptions::from_str("sqlite::memory:")
            .map_err(|e| JournalError::Config(format!("SQLite URL parse: {e}")))?;

        // max_connections(1) keeps all queries on the same connection, which is
        // mandatory for `:memory:` databases (each connection gets its own DB).
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .map_err(|e| {
                JournalError::Config(format!("Cannot open SQLite in-memory journal: {e}"))
            })?;

        let store = Self {
            pool,
            append_lock: Mutex::new(()),
        };
        store.migrate().await?;
        Ok(store)
    }

    /// Open (or create) a SQLite journal at the given filesystem path.
    pub async fn new_file(path: &str) -> JournalResult<Self> {
        use sqlx::sqlite::SqliteConnectOptions;
        use std::str::FromStr as _;

        let options = SqliteConnectOptions::from_str(&format!("sqlite:{path}"))
            .map_err(|e| JournalError::Config(format!("SQLite URL parse: {e}")))?
            .create_if_missing(true);

        let pool = sqlx::SqlitePool::connect_with(options).await.map_err(|e| {
            JournalError::Config(format!("Cannot open SQLite journal at {path}: {e}"))
        })?;

        let store = Self {
            pool,
            append_lock: Mutex::new(()),
        };
        store.migrate().await?;
        Ok(store)
    }

    /// Create the journal tables and indexes if they do not already exist.
    async fn migrate(&self) -> JournalResult<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS journal_entries (
                id                         TEXT PRIMARY KEY NOT NULL,
                username                   TEXT NOT NULL,
                previous_hash              TEXT,
                entry_hash                 TEXT NOT NULL,
                attestation_signature_hash TEXT NOT NULL,
                attestation_jti            TEXT,
                client_id                  TEXT,
                doc_type                   TEXT,
                namespace                  TEXT,
                qrcode_app_user_id         TEXT,
                qrcode_app_user_email      TEXT,
                verification_summary       TEXT NOT NULL,
                created_at                 TEXT NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_journal_entry_hash
                ON journal_entries (entry_hash);
            CREATE INDEX IF NOT EXISTS idx_journal_username_created
                ON journal_entries (username, created_at);
            CREATE INDEX IF NOT EXISTS idx_journal_qrcode_app_user
                ON journal_entries (qrcode_app_user_id);
            CREATE TABLE IF NOT EXISTS journal_heads (
                username   TEXT PRIMARY KEY NOT NULL,
                head_hash  TEXT,
                updated_at TEXT NOT NULL
            );
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| JournalError::Storage(format!("SQLite journal migration: {e}")))?;

        // Additive migration: add new columns to existing tables that were
        // created before this version.  SQLite does not support IF NOT EXISTS
        // for ALTER TABLE; we ignore errors ("duplicate column name").
        for col in &[
            "ALTER TABLE journal_entries ADD COLUMN qrcode_app_user_id TEXT",
            "ALTER TABLE journal_entries ADD COLUMN qrcode_app_user_email TEXT",
        ] {
            let _ = sqlx::query(col).execute(&self.pool).await;
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn parse_row(
        id: String,
        username: String,
        previous_hash: Option<String>,
        entry_hash: String,
        attestation_signature_hash: String,
        attestation_jti: Option<String>,
        client_id: Option<String>,
        doc_type: Option<String>,
        namespace: Option<String>,
        qrcode_app_user_id: Option<String>,
        qrcode_app_user_email: Option<String>,
        verification_summary: String,
        created_at: String,
    ) -> JournalResult<JournalEntry> {
        let verification_summary: serde_json::Value =
            serde_json::from_str(&verification_summary)
                .map_err(|e| JournalError::Storage(format!("journal deserialization: {e}")))?;

        let created_at: DateTime<Utc> = created_at
            .parse()
            .map_err(|e| JournalError::Storage(format!("journal timestamp parse: {e}")))?;

        Ok(JournalEntry {
            id,
            username,
            previous_hash,
            entry_hash,
            attestation_signature_hash,
            attestation_jti,
            client_id,
            doc_type,
            namespace,
            qrcode_app_user_id,
            qrcode_app_user_email,
            verification_summary,
            created_at,
        })
    }
}

// ============================================================================
// JournalStore implementation
// ============================================================================

type RowTuple = (
    String,
    String,
    Option<String>,
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    String,
    String,
);

const SELECT_COLS: &str = "id, username, previous_hash, entry_hash, \
    attestation_signature_hash, attestation_jti, client_id, doc_type, \
    namespace, qrcode_app_user_id, qrcode_app_user_email, verification_summary, created_at";

#[async_trait]
impl JournalStore for SqliteJournalStore {
    async fn get_head(&self, username: &str) -> JournalResult<Option<String>> {
        let row: Option<(Option<String>,)> =
            sqlx::query_as("SELECT head_hash FROM journal_heads WHERE username = ?1")
                .bind(username)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| JournalError::Storage(format!("SQLite get_head: {e}")))?;

        Ok(row.and_then(|(h,)| h))
    }

    async fn append_entry(
        &self,
        entry: &JournalEntry,
        expected_previous_hash: Option<&str>,
    ) -> JournalResult<()> {
        // Hold the Mutex for the entire duration of this operation so that
        // concurrent async tasks cannot interleave their read-check-write.
        let _guard = self.append_lock.lock().await;

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| JournalError::Storage(format!("SQLite begin: {e}")))?;

        // Read the current head inside the transaction.
        let current: Option<(Option<String>,)> =
            sqlx::query_as("SELECT head_hash FROM journal_heads WHERE username = ?1")
                .bind(&entry.username)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| JournalError::Storage(format!("SQLite head read: {e}")))?;

        let actual_head = current.and_then(|(h,)| h);

        // CAS check.
        if actual_head.as_deref() != expected_previous_hash {
            tx.rollback().await.ok();
            return Err(JournalError::StaleHead);
        }

        // Insert the journal entry.
        let summary_str = serde_json::to_string(&entry.verification_summary)
            .map_err(|e| JournalError::Storage(format!("journal serialization: {e}")))?;
        let created_at_str = entry.created_at.to_rfc3339();

        sqlx::query(
            "INSERT INTO journal_entries \
             (id, username, previous_hash, entry_hash, attestation_signature_hash, \
              attestation_jti, client_id, doc_type, namespace, \
              qrcode_app_user_id, qrcode_app_user_email, \
              verification_summary, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        )
        .bind(&entry.id)
        .bind(&entry.username)
        .bind(&entry.previous_hash)
        .bind(&entry.entry_hash)
        .bind(&entry.attestation_signature_hash)
        .bind(&entry.attestation_jti)
        .bind(&entry.client_id)
        .bind(&entry.doc_type)
        .bind(&entry.namespace)
        .bind(&entry.qrcode_app_user_id)
        .bind(&entry.qrcode_app_user_email)
        .bind(&summary_str)
        .bind(&created_at_str)
        .execute(&mut *tx)
        .await
        .map_err(|e| JournalError::Storage(format!("SQLite insert entry: {e}")))?;

        // Upsert the head row.
        let updated_at_str = Utc::now().to_rfc3339();
        sqlx::query(
            "INSERT INTO journal_heads (username, head_hash, updated_at) \
             VALUES (?1, ?2, ?3) \
             ON CONFLICT(username) DO UPDATE \
             SET head_hash = excluded.head_hash, updated_at = excluded.updated_at",
        )
        .bind(&entry.username)
        .bind(&entry.entry_hash)
        .bind(&updated_at_str)
        .execute(&mut *tx)
        .await
        .map_err(|e| JournalError::Storage(format!("SQLite upsert head: {e}")))?;

        tx.commit()
            .await
            .map_err(|e| JournalError::Storage(format!("SQLite commit: {e}")))?;

        Ok(())
    }

    async fn list_entries(&self, query: &JournalQuery) -> JournalResult<Vec<JournalEntry>> {
        let limit = i64::from(query.limit.unwrap_or(100));
        let before = query.before.map(|dt| dt.to_rfc3339());
        let after = query.after.map(|dt| dt.to_rfc3339());

        let rows: Vec<RowTuple> = match (&before, &after) {
            (Some(b), Some(a)) => sqlx::query_as(&format!(
                "SELECT {SELECT_COLS} FROM journal_entries \
                 WHERE username = ?1 AND created_at < ?2 AND created_at > ?3 \
                 ORDER BY created_at DESC LIMIT ?4"
            ))
            .bind(&query.username)
            .bind(b)
            .bind(a)
            .bind(limit)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| JournalError::Storage(format!("SQLite list_entries: {e}")))?,

            (Some(b), None) => sqlx::query_as(&format!(
                "SELECT {SELECT_COLS} FROM journal_entries \
                 WHERE username = ?1 AND created_at < ?2 \
                 ORDER BY created_at DESC LIMIT ?3"
            ))
            .bind(&query.username)
            .bind(b)
            .bind(limit)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| JournalError::Storage(format!("SQLite list_entries: {e}")))?,

            (None, Some(a)) => sqlx::query_as(&format!(
                "SELECT {SELECT_COLS} FROM journal_entries \
                 WHERE username = ?1 AND created_at > ?2 \
                 ORDER BY created_at DESC LIMIT ?3"
            ))
            .bind(&query.username)
            .bind(a)
            .bind(limit)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| JournalError::Storage(format!("SQLite list_entries: {e}")))?,

            (None, None) => sqlx::query_as(&format!(
                "SELECT {SELECT_COLS} FROM journal_entries \
                 WHERE username = ?1 \
                 ORDER BY created_at DESC LIMIT ?2"
            ))
            .bind(&query.username)
            .bind(limit)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| JournalError::Storage(format!("SQLite list_entries: {e}")))?,
        };

        rows.into_iter()
            .map(
                |(id, username, prev, eh, ash, jti, cid, dt, ns, quid, quem, vs, ca)| {
                    Self::parse_row(
                        id, username, prev, eh, ash, jti, cid, dt, ns, quid, quem, vs, ca,
                    )
                },
            )
            .collect()
    }

    async fn list_qrcode_app_entries(
        &self,
        qrcode_app_user_id: Option<&str>,
        date_from: Option<DateTime<Utc>>,
        date_to: Option<DateTime<Utc>>,
        limit: u32,
        offset: u32,
    ) -> JournalResult<Vec<JournalEntry>> {
        let limit = i64::from(limit);
        let offset = i64::from(offset);
        // Convert optional dates to RFC 3339 strings for TEXT comparison with stored values.
        let date_from_str = date_from.map(|dt| dt.to_rfc3339());
        let date_to_str = date_to.map(|dt| dt.to_rfc3339());
        let rows: Vec<RowTuple> = sqlx::query_as(&format!(
            "SELECT {SELECT_COLS} FROM journal_entries \
             WHERE (qrcode_app_user_id IS NOT NULL OR qrcode_app_user_email IS NOT NULL) \
               AND (?1 IS NULL OR qrcode_app_user_id = ?1 OR qrcode_app_user_email = ?1) \
               AND (?2 IS NULL OR created_at >= ?2) \
               AND (?3 IS NULL OR created_at <= ?3) \
             ORDER BY created_at DESC LIMIT ?4 OFFSET ?5"
        ))
        .bind(qrcode_app_user_id)
        .bind(date_from_str.as_deref())
        .bind(date_to_str.as_deref())
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| JournalError::Storage(format!("SQLite list_qrcode_app_entries: {e}")))?;

        rows.into_iter()
            .map(
                |(id, username, prev, eh, ash, jti, cid, dt, ns, quid, quem, vs, ca)| {
                    Self::parse_row(
                        id, username, prev, eh, ash, jti, cid, dt, ns, quid, quem, vs, ca,
                    )
                },
            )
            .collect()
    }

    async fn verify_chain(&self, username: &str) -> JournalResult<ChainVerificationResult> {
        // Fetch all entries ordered from oldest to newest.
        let rows: Vec<(String, Option<String>, String, String)> = sqlx::query_as(
            "SELECT id, previous_hash, entry_hash, attestation_signature_hash \
             FROM journal_entries WHERE username = ?1 \
             ORDER BY created_at ASC",
        )
        .bind(username)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| JournalError::Storage(format!("SQLite verify_chain: {e}")))?;

        if rows.is_empty() {
            return Ok(ChainVerificationResult {
                username: username.to_string(),
                valid: true,
                entries_verified: 0,
                first_entry_hash: None,
                last_entry_hash: None,
                error: None,
            });
        }

        let first_entry_hash = rows.first().map(|(_, _, h, _)| h.clone());
        let mut expected_previous: Option<String> = None;
        let mut last_hash: Option<String> = None;

        for (i, (id, stored_previous, stored_hash, att_sig_hash)) in rows.iter().enumerate() {
            if stored_previous.as_deref() != expected_previous.as_deref() {
                return Ok(ChainVerificationResult {
                    username: username.to_string(),
                    valid: false,
                    entries_verified: i as u64,
                    first_entry_hash,
                    last_entry_hash: last_hash,
                    error: Some(format!(
                        "entry {id}: previous_hash pointer mismatch at position {i}"
                    )),
                });
            }

            let recomputed =
                compute_entry_hash(username, expected_previous.as_deref(), att_sig_hash);
            if &recomputed != stored_hash {
                return Ok(ChainVerificationResult {
                    username: username.to_string(),
                    valid: false,
                    entries_verified: i as u64,
                    first_entry_hash,
                    last_entry_hash: last_hash,
                    error: Some(format!(
                        "entry {id}: recomputed entry_hash does not match stored value at position {i}"
                    )),
                });
            }

            expected_previous = Some(stored_hash.clone());
            last_hash = Some(stored_hash.clone());
        }

        // Verify the head row matches the last computed hash.
        let head: Option<(Option<String>,)> =
            sqlx::query_as("SELECT head_hash FROM journal_heads WHERE username = ?1")
                .bind(username)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| JournalError::Storage(format!("SQLite get_head in verify: {e}")))?;

        let stored_head = head.and_then(|(h,)| h);
        if stored_head.as_deref() != last_hash.as_deref() {
            return Ok(ChainVerificationResult {
                username: username.to_string(),
                valid: false,
                entries_verified: rows.len() as u64,
                first_entry_hash,
                last_entry_hash: last_hash,
                error: Some("head hash does not match the last entry hash".to_string()),
            });
        }

        Ok(ChainVerificationResult {
            username: username.to_string(),
            valid: true,
            entries_verified: rows.len() as u64,
            first_entry_hash,
            last_entry_hash: last_hash,
            error: None,
        })
    }
}

// ============================================================================
// Test helpers (not compiled into release builds)
// ============================================================================

#[cfg(test)]
impl SqliteJournalStore {
    /// Expose the underlying connection pool for test-only inspection / tampering.
    pub fn pool_for_test(&self) -> sqlx::SqlitePool {
        self.pool.clone()
    }
}
