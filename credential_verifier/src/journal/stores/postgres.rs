//! PostgreSQL-backed verification journal store.
//!
//! Recommended for multi-instance / high-availability deployments.
//!
//! A test Postgres instance can be started with:
//! ```shell
//! docker run --name postgres_ewqwe \
//!   -e POSTGRES_USER=ewqwe -e POSTGRES_PASSWORD=ewqwe -e POSTGRES_DB=ewqwe \
//!   -p 5432:5432 -d postgres
//! ```
//!
//! ## Concurrency safety
//!
//! The CAS append uses `SELECT ... FOR UPDATE` inside a DB transaction to
//! prevent lost updates when multiple server instances append to the same
//! user's journal simultaneously.

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::journal::{
    ChainVerificationResult, JournalEntry, JournalError, JournalQuery, JournalResult, JournalStore,
    compute_entry_hash,
};

// ============================================================================
// Store struct
// ============================================================================

pub struct PostgresJournalStore {
    pool: sqlx::PgPool,
}

// ============================================================================
// Construction & migration
// ============================================================================

impl PostgresJournalStore {
    pub(crate) async fn new(url: &str) -> JournalResult<Self> {
        let pool = sqlx::PgPool::connect(url)
            .await
            .map_err(|e| JournalError::Config(format!("Cannot connect to Postgres: {e}")))?;

        let store = Self { pool };
        store.migrate().await?;
        Ok(store)
    }

    async fn migrate(&self) -> JournalResult<()> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS journal_entries (
                id                         TEXT        PRIMARY KEY NOT NULL,
                username                   TEXT        NOT NULL,
                previous_hash              TEXT,
                entry_hash                 TEXT        NOT NULL,
                attestation_signature_hash TEXT        NOT NULL,
                attestation_jti            TEXT,
                client_id                  TEXT,
                doc_type                   TEXT,
                namespace                  TEXT,
                verification_summary       JSONB       NOT NULL,
                created_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| JournalError::Storage(format!("Postgres journal migration: {e}")))?;

        sqlx::query(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_journal_entry_hash \
             ON journal_entries (entry_hash)",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| JournalError::Storage(format!("Postgres journal migration: {e}")))?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_journal_username_created \
             ON journal_entries (username, created_at)",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| JournalError::Storage(format!("Postgres journal migration: {e}")))?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS journal_heads (
                username   TEXT        PRIMARY KEY NOT NULL,
                head_hash  TEXT,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| JournalError::Storage(format!("Postgres journal migration: {e}")))?;

        Ok(())
    }
}

// ============================================================================
// JournalStore implementation
// ============================================================================

type PgRowTuple = (
    String,
    String,
    Option<String>,
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    serde_json::Value,
    DateTime<Utc>,
);

const SELECT_COLS: &str = "id, username, previous_hash, entry_hash, \
    attestation_signature_hash, attestation_jti, client_id, doc_type, \
    namespace, verification_summary, created_at";

#[async_trait]
impl JournalStore for PostgresJournalStore {
    async fn get_head(&self, username: &str) -> JournalResult<Option<String>> {
        let row: Option<(Option<String>,)> =
            sqlx::query_as("SELECT head_hash FROM journal_heads WHERE username = $1")
                .bind(username)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| JournalError::Storage(format!("Postgres get_head: {e}")))?;

        Ok(row.and_then(|(h,)| h))
    }

    async fn append_entry(
        &self,
        entry: &JournalEntry,
        expected_previous_hash: Option<&str>,
    ) -> JournalResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| JournalError::Storage(format!("Postgres begin: {e}")))?;

        // Ensure the head row exists (idempotent for concurrent first-time inserts).
        sqlx::query(
            "INSERT INTO journal_heads (username, head_hash, updated_at) \
             VALUES ($1, NULL, NOW()) \
             ON CONFLICT(username) DO NOTHING",
        )
        .bind(&entry.username)
        .execute(&mut *tx)
        .await
        .map_err(|e| JournalError::Storage(format!("Postgres ensure head row: {e}")))?;

        // Lock the head row for the duration of this transaction.
        let (actual_head,): (Option<String>,) =
            sqlx::query_as("SELECT head_hash FROM journal_heads WHERE username = $1 FOR UPDATE")
                .bind(&entry.username)
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| JournalError::Storage(format!("Postgres lock head: {e}")))?;

        // CAS check.
        if actual_head.as_deref() != expected_previous_hash {
            tx.rollback().await.ok();
            return Err(JournalError::StaleHead);
        }

        // Insert the journal entry.
        let summary_value = serde_json::to_value(&entry.verification_summary)
            .map_err(|e| JournalError::Storage(format!("journal serialization: {e}")))?;

        sqlx::query(
            "INSERT INTO journal_entries \
             (id, username, previous_hash, entry_hash, attestation_signature_hash, \
              attestation_jti, client_id, doc_type, namespace, verification_summary, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
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
        .bind(summary_value)
        .bind(entry.created_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| JournalError::Storage(format!("Postgres insert entry: {e}")))?;

        // Update the head row (row is already locked by FOR UPDATE above).
        sqlx::query(
            "UPDATE journal_heads SET head_hash = $1, updated_at = NOW() WHERE username = $2",
        )
        .bind(&entry.entry_hash)
        .bind(&entry.username)
        .execute(&mut *tx)
        .await
        .map_err(|e| JournalError::Storage(format!("Postgres update head: {e}")))?;

        tx.commit()
            .await
            .map_err(|e| JournalError::Storage(format!("Postgres commit: {e}")))?;

        Ok(())
    }

    async fn list_entries(&self, query: &JournalQuery) -> JournalResult<Vec<JournalEntry>> {
        let limit = i64::from(query.limit.unwrap_or(100));

        let rows: Vec<PgRowTuple> = match (&query.before, &query.after) {
            (Some(b), Some(a)) => sqlx::query_as(&format!(
                "SELECT {SELECT_COLS} FROM journal_entries \
                 WHERE username = $1 AND created_at < $2 AND created_at > $3 \
                 ORDER BY created_at DESC LIMIT $4"
            ))
            .bind(&query.username)
            .bind(b)
            .bind(a)
            .bind(limit)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| JournalError::Storage(format!("Postgres list_entries: {e}")))?,

            (Some(b), None) => sqlx::query_as(&format!(
                "SELECT {SELECT_COLS} FROM journal_entries \
                 WHERE username = $1 AND created_at < $2 \
                 ORDER BY created_at DESC LIMIT $3"
            ))
            .bind(&query.username)
            .bind(b)
            .bind(limit)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| JournalError::Storage(format!("Postgres list_entries: {e}")))?,

            (None, Some(a)) => sqlx::query_as(&format!(
                "SELECT {SELECT_COLS} FROM journal_entries \
                 WHERE username = $1 AND created_at > $2 \
                 ORDER BY created_at DESC LIMIT $3"
            ))
            .bind(&query.username)
            .bind(a)
            .bind(limit)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| JournalError::Storage(format!("Postgres list_entries: {e}")))?,

            (None, None) => sqlx::query_as(&format!(
                "SELECT {SELECT_COLS} FROM journal_entries \
                 WHERE username = $1 \
                 ORDER BY created_at DESC LIMIT $2"
            ))
            .bind(&query.username)
            .bind(limit)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| JournalError::Storage(format!("Postgres list_entries: {e}")))?,
        };

        Ok(rows
            .into_iter()
            .map(
                |(id, un, prev, eh, ash, jti, cid, dt, ns, vs, ca)| JournalEntry {
                    id,
                    username: un,
                    previous_hash: prev,
                    entry_hash: eh,
                    attestation_signature_hash: ash,
                    attestation_jti: jti,
                    client_id: cid,
                    doc_type: dt,
                    namespace: ns,
                    verification_summary: vs,
                    created_at: ca,
                },
            )
            .collect())
    }

    async fn verify_chain(&self, username: &str) -> JournalResult<ChainVerificationResult> {
        let rows: Vec<(String, Option<String>, String, String)> = sqlx::query_as(
            "SELECT id, previous_hash, entry_hash, attestation_signature_hash \
             FROM journal_entries WHERE username = $1 \
             ORDER BY created_at ASC",
        )
        .bind(username)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| JournalError::Storage(format!("Postgres verify_chain: {e}")))?;

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

            let recomputed = compute_entry_hash(expected_previous.as_deref(), att_sig_hash);
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

        // Verify that the head row matches the last computed hash.
        let head: Option<(Option<String>,)> =
            sqlx::query_as("SELECT head_hash FROM journal_heads WHERE username = $1")
                .bind(username)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| JournalError::Storage(format!("Postgres get_head in verify: {e}")))?;

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
