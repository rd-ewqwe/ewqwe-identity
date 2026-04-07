//! Configuration for the Verifier App embedded web application.

use serde::{Deserialize, Serialize};

/// Database backend for the Verifier App.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(tag = "backend", rename_all = "snake_case")]
pub enum VerifierAppDbBackend {
    /// SQLite in-memory — no persistence, suitable for development/testing.
    #[default]
    SqliteMemory,

    /// SQLite file — single-instance deployments with persistence across restarts.
    SqliteFile {
        /// Filesystem path to the SQLite database file.
        path: String,
    },

    /// PostgreSQL — recommended for multi-instance / HA deployments.
    Postgres {
        /// `postgres://user:password@host/db` style connection URL.
        url: String,
    },
}

/// Top-level configuration section for the Verifier App.
///
/// Embedded in the server configuration file as `[verifier_app]`.
///
/// ```toml
/// [verifier_app]
/// enabled = true
/// app_name = "My Age Verifier"
/// # session_secret_key = "<128 hex chars = 64 bytes>"   # stable sessions across restarts
///
/// # Database backend (default: sqlite_memory):
/// backend = "sqlite_memory"
///
/// # SQLite file (persistent, single-instance):
/// # backend = "sqlite_file"
/// # path    = "/var/lib/ewqwe/verifier_app.db"
///
/// # PostgreSQL (HA / multi-instance):
/// # backend = "postgres"
/// # url     = "postgres://ewqwe:ewqwe@localhost/ewqwe"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VerifierAppConfig {
    /// Whether the Verifier App is enabled. Defaults to `false` (opt-in).
    ///
    /// When `false`, all `/verifier_app/*` routes are disabled and return 404.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Display name shown in the UI header.  Defaults to `"Verifier App"`.
    #[serde(default)]
    pub app_name: Option<String>,

    /// Optional URL for a custom logo shown in the UI header.
    #[serde(default)]
    pub logo_url: Option<String>,

    /// Hex-encoded secret used to sign and encrypt session cookies.
    ///
    /// Must decode to **at least 32 bytes** (64 hex characters).  For
    /// stable sessions across server restarts, set this to a fixed value.
    /// When absent, a random key is generated at startup — all active
    /// sessions are invalidated whenever the server restarts.
    #[serde(default)]
    pub session_secret_key: Option<String>,

    /// Database backend for user accounts and OIDC provider configuration.
    ///
    /// Defaults to `sqlite_memory` when not specified.
    #[serde(default)]
    pub db: VerifierAppDbBackend,
}

fn default_true() -> bool {
    true
}
