//! Verification journal — append-only, hash-chained record of every verification event.
//!
//! Each entry records:
//! - the `username` (from the mTLS client certificate CN)
//! - the cryptographic hash of the attestation JWT bytes
//! - the chain hash linking it to the previous entry in the user's journal
//!
//! ## Hash chaining formula
//!
//! ```text
//! attestation_signature_hash = SHA-256(attestation_jwt_bytes)
//! entry_hash = SHA-256(previous_hash_bytes || attestation_signature_hash_bytes)
//! ```
//!
//! For the genesis (first) entry `previous_hash` is `None` and an
//! empty byte string is used in place of the previous hash bytes.
//!
//! ## Concurrent append safety
//!
//! Appends are guarded by an optimistic compare-and-swap (CAS) on the
//! per-user journal head:
//! * SQLite backend: serialized via a `Mutex`-guarded exclusive transaction.
//! * PostgreSQL backend: serialized via `SELECT ... FOR UPDATE` inside a
//!   DB transaction.
//!
//! If a concurrent writer wins the CAS, the caller retries up to
//! [`MAX_CAS_RETRIES`] times before returning [`JournalError::CasExhausted`].

pub mod stores;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::AttError;
use stores::{PostgresJournalStore, SqliteJournalStore};

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of CAS retry attempts when a concurrent append is detected.
pub const MAX_CAS_RETRIES: usize = 5;

// ============================================================================
// Errors
// ============================================================================

#[derive(Debug, Error)]
pub enum JournalError {
    #[error("journal storage error: {0}")]
    Storage(String),

    #[error("journal head changed concurrently (stale CAS); retry")]
    StaleHead,

    #[error("journal CAS exhausted after {MAX_CAS_RETRIES} retries")]
    CasExhausted,

    #[error("journal configuration error: {0}")]
    Config(String),
}

pub type JournalResult<T> = Result<T, JournalError>;

impl From<JournalError> for AttError {
    fn from(e: JournalError) -> Self {
        AttError::Generic(e.to_string())
    }
}

// ============================================================================
// Configuration
// ============================================================================

/// Which backend the journal uses.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "backend", rename_all = "snake_case")]
#[derive(Default)]
pub enum JournalBackend {
    /// SQLite in-memory — no persistence, ideal for tests and development.
    #[default]
    SqliteMemory,

    /// SQLite file — single-instance deployments with persistence across restarts.
    SqliteFile {
        /// Filesystem path to the SQLite database file.
        /// Resolved relative to the server configuration file directory.
        path: String,
    },

    /// PostgreSQL — recommended for multi-instance / HA deployments.
    Postgres {
        /// `postgres://user:password@host/db` style connection URL.
        url: String,
    },
}

/// Top-level journal configuration section (embedded in [`ServerParams`]).
///
/// ```toml
/// [journal_config]
/// enabled = true
/// backend = "sqlite_memory"     # default — no persistence
///
/// # SQLite file (single-instance, persistent):
/// # [journal_config]
/// # enabled = true
/// # backend = "sqlite_file"
/// # path    = "/var/lib/ewqwe/journal.db"
///
/// # PostgreSQL (recommended for HA):
/// # [journal_config]
/// # enabled = true
/// # backend = "postgres"
/// # url     = "postgres://user:pass@localhost/ewqwe"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct JournalConfig {
    /// Whether journaling is active.  Defaults to `false` (opt-in).
    #[serde(default)]
    pub enabled: bool,

    #[serde(flatten, default)]
    pub backend: JournalBackend,
}

// ============================================================================
// Data model
// ============================================================================

/// A single immutable entry in a user's verification journal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalEntry {
    /// Surrogate primary key (UUIDv4).
    pub id: String,

    /// Authenticated username (mTLS Subject CN).
    pub username: String,

    /// Hash of the preceding entry (`None` for the genesis entry).
    pub previous_hash: Option<String>,

    /// Chain hash for this entry (hex-encoded SHA-256).
    pub entry_hash: String,

    /// SHA-256 of the raw attestation JWT bytes (hex-encoded).
    pub attestation_signature_hash: String,

    /// `jti` claim from the signed attestation JWT.
    pub attestation_jti: Option<String>,

    /// Relying-party `client_id` bound to this verification.
    pub client_id: Option<String>,

    /// Credential doc type (e.g. `org.iso.18013.5.1.mDL`).
    pub doc_type: Option<String>,

    /// Credential namespace (e.g. `org.iso.18013.5.1`).
    pub namespace: Option<String>,

    /// QR Code APP user ID who initiated this verification (when triggered via the embedded app).
    pub qrcode_app_user_id: Option<String>,

    /// QR Code APP user email for the initiating user.
    pub qrcode_app_user_email: Option<String>,

    /// JSON summary of the verification outcome.
    pub verification_summary: serde_json::Value,

    /// UTC timestamp when the entry was created.
    pub created_at: DateTime<Utc>,
}

/// Query parameters for listing journal entries.
#[derive(Debug, Clone, Default)]
pub struct JournalQuery {
    pub username: String,
    /// Maximum number of entries to return (newest first).  Defaults to 100.
    pub limit: Option<u32>,
    /// Return only entries created strictly before this timestamp.
    pub before: Option<DateTime<Utc>>,
    /// Return only entries created strictly after this timestamp.
    pub after: Option<DateTime<Utc>>,
}

/// Result of a full chain integrity verification for one user.
#[derive(Debug, Clone, Serialize)]
pub struct ChainVerificationResult {
    pub username: String,
    /// `true` when all entries hash-verify from genesis to the current head.
    pub valid: bool,
    pub entries_verified: u64,
    pub first_entry_hash: Option<String>,
    pub last_entry_hash: Option<String>,
    /// Human-readable reason when `valid` is `false`.
    pub error: Option<String>,
}

// ============================================================================
// Trait
// ============================================================================

/// Async interface for the verification journal store.
#[async_trait]
pub trait JournalStore: Send + Sync {
    /// Return the current head hash for a user's journal (`None` = no entries yet).
    async fn get_head(&self, username: &str) -> JournalResult<Option<String>>;

    /// Append a new entry if `expected_previous_hash` matches the persisted head.
    ///
    /// Returns [`JournalError::StaleHead`] when the head has been concurrently
    /// updated by another writer, allowing the caller to re-read and retry.
    async fn append_entry(
        &self,
        entry: &JournalEntry,
        expected_previous_hash: Option<&str>,
    ) -> JournalResult<()>;

    /// List entries for a user, newest first.
    ///
    /// Respects the optional `limit`, `before`, and `after` filters in the query.
    async fn list_entries(&self, query: &JournalQuery) -> JournalResult<Vec<JournalEntry>>;

    /// List all journal entries attributed to a specific QR Code APP user.
    ///
    /// When `qrcode_app_user_id` is `None`, returns all entries that have any
    /// QR Code APP user attribution, newest first.  Optional `date_from` and
    /// `date_to` bound the result to a half-open time range.
    async fn list_qrcode_app_entries(
        &self,
        qrcode_app_user_id: Option<&str>,
        date_from: Option<DateTime<Utc>>,
        date_to: Option<DateTime<Utc>>,
        limit: u32,
        offset: u32,
    ) -> JournalResult<Vec<JournalEntry>>;

    /// Verify the entire chain for a user by recomputing every hash from genesis.
    async fn verify_chain(&self, username: &str) -> JournalResult<ChainVerificationResult>;
}

// ============================================================================
// Dynamic dispatch wrapper
// ============================================================================

/// Wraps any supported backend behind a single concrete type.
pub enum DynJournalStore {
    Sqlite(SqliteJournalStore),
    Postgres(PostgresJournalStore),
}

impl DynJournalStore {
    /// Construct a new store from the provided configuration.
    ///
    /// Runs schema migrations as needed.  Call this once during server startup.
    pub async fn new(config: &JournalConfig) -> JournalResult<Self> {
        match &config.backend {
            JournalBackend::SqliteMemory => {
                let store = SqliteJournalStore::new_memory().await?;
                Ok(Self::Sqlite(store))
            }
            JournalBackend::SqliteFile { path } => {
                let store = SqliteJournalStore::new_file(path).await?;
                Ok(Self::Sqlite(store))
            }
            JournalBackend::Postgres { url } => {
                let store = PostgresJournalStore::new(url).await?;
                Ok(Self::Postgres(store))
            }
        }
    }
}

#[async_trait]
impl JournalStore for DynJournalStore {
    async fn get_head(&self, username: &str) -> JournalResult<Option<String>> {
        match self {
            Self::Sqlite(s) => s.get_head(username).await,
            Self::Postgres(s) => s.get_head(username).await,
        }
    }

    async fn append_entry(
        &self,
        entry: &JournalEntry,
        expected_previous_hash: Option<&str>,
    ) -> JournalResult<()> {
        match self {
            Self::Sqlite(s) => s.append_entry(entry, expected_previous_hash).await,
            Self::Postgres(s) => s.append_entry(entry, expected_previous_hash).await,
        }
    }

    async fn list_entries(&self, query: &JournalQuery) -> JournalResult<Vec<JournalEntry>> {
        match self {
            Self::Sqlite(s) => s.list_entries(query).await,
            Self::Postgres(s) => s.list_entries(query).await,
        }
    }

    async fn list_qrcode_app_entries(
        &self,
        qrcode_app_user_id: Option<&str>,
        date_from: Option<DateTime<Utc>>,
        date_to: Option<DateTime<Utc>>,
        limit: u32,
        offset: u32,
    ) -> JournalResult<Vec<JournalEntry>> {
        match self {
            Self::Sqlite(s) => {
                s.list_qrcode_app_entries(qrcode_app_user_id, date_from, date_to, limit, offset)
                    .await
            }
            Self::Postgres(s) => {
                s.list_qrcode_app_entries(qrcode_app_user_id, date_from, date_to, limit, offset)
                    .await
            }
        }
    }

    async fn verify_chain(&self, username: &str) -> JournalResult<ChainVerificationResult> {
        match self {
            Self::Sqlite(s) => s.verify_chain(username).await,
            Self::Postgres(s) => s.verify_chain(username).await,
        }
    }
}

// ============================================================================
// Hash functions (pub for tests and chain verification)
// ============================================================================

/// Compute the SHA-256 of the raw attestation JWT bytes (compact string form).
///
/// The result is lowercase hex-encoded.
pub fn compute_attestation_signature_hash(attestation_jwt: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(attestation_jwt.as_bytes());
    hex::encode(hasher.finalize())
}

/// Compute the chain hash for a new journal entry.
///
/// ```text
/// entry_hash = SHA-256(username_bytes || previous_hash_utf8_bytes || attestation_signature_hash_utf8_bytes)
/// ```
///
/// Including `username` scopes each entry hash to its owner, preventing a
/// cross-user collision on the global `UNIQUE INDEX` when two genesis entries
/// happen to have the same `attestation_signature_hash` (e.g. both QR entries).
///
/// When `previous_hash` is `None` (genesis entry) an empty byte string is used.
pub fn compute_entry_hash(
    username: &str,
    previous_hash: Option<&str>,
    attestation_signature_hash: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(username.as_bytes());
    hasher.update(previous_hash.unwrap_or("").as_bytes());
    hasher.update(attestation_signature_hash.as_bytes());
    hex::encode(hasher.finalize())
}

// ============================================================================
// High-level CAS append helper
// ============================================================================

/// Append a verification event to the journal with bounded CAS retry.
///
/// Computes the `attestation_signature_hash` and `entry_hash`, then calls
/// [`JournalStore::append_entry`] in a loop until the CAS succeeds or the
/// retry limit is exhausted.  Treats a final CAS exhaustion as a hard error
/// because omitting a journal entry would silently break audit integrity.
#[allow(clippy::too_many_arguments)]
pub async fn append_verification(
    store: &dyn JournalStore,
    username: &str,
    attestation_jwt: &str,
    attestation_jti: Option<&str>,
    client_id: Option<&str>,
    doc_type: Option<&str>,
    namespace: Option<&str>,
    verification_summary: serde_json::Value,
    qrcode_app_user_id: Option<&str>,
    qrcode_app_user_email: Option<&str>,
) -> JournalResult<()> {
    for attempt in 0..MAX_CAS_RETRIES {
        let current_head = store.get_head(username).await?;
        // Generate the entry ID here so it can act as a unique salt for QR entries.
        let entry_id = uuid::Uuid::new_v4().to_string();
        // For QR entries the caller passes an empty JWT because no signed attestation is
        // produced.  Synthesise a unique, user-scoped value so the stored
        // `attestation_signature_hash` is never the constant SHA-256 of the empty string,
        // which would collide across all users who have an empty-JWT genesis entry.
        let att_hash_input: std::borrow::Cow<str> = if attestation_jwt.is_empty() {
            format!("qr:{}:{}", username, entry_id).into()
        } else {
            attestation_jwt.into()
        };
        let attestation_signature_hash = compute_attestation_signature_hash(&att_hash_input);
        let entry_hash = compute_entry_hash(
            username,
            current_head.as_deref(),
            &attestation_signature_hash,
        );

        let entry = JournalEntry {
            id: entry_id,
            username: username.to_string(),
            previous_hash: current_head.clone(),
            entry_hash,
            attestation_signature_hash,
            attestation_jti: attestation_jti.map(str::to_string),
            client_id: client_id.map(str::to_string),
            doc_type: doc_type.map(str::to_string),
            namespace: namespace.map(str::to_string),
            qrcode_app_user_id: qrcode_app_user_id.map(str::to_string),
            qrcode_app_user_email: qrcode_app_user_email.map(str::to_string),
            verification_summary: verification_summary.clone(),
            created_at: Utc::now(),
        };

        match store.append_entry(&entry, current_head.as_deref()).await {
            Ok(()) => return Ok(()),
            Err(JournalError::StaleHead) => {
                tracing::debug!(
                    username,
                    attempt = attempt + 1,
                    "journal CAS stale — retrying"
                );
                continue;
            }
            Err(e) => return Err(e),
        }
    }

    Err(JournalError::CasExhausted)
}
