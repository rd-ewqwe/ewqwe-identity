//! Configuration for the QR Code APP embedded web application.

use serde::{Deserialize, Serialize};

/// Database backend for the QR Code APP.
///
/// Follows the same pattern as [`crate::journal::JournalBackend`].
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(tag = "backend", rename_all = "snake_case")]
pub enum QrcodeAppDbBackend {
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

/// Top-level configuration section for the QR Code APP.
///
/// Embedded in [`crate::server::ServerParams`] as `[qrcode_app]` in the TOML config.
///
/// ```toml
/// [qrcode_app]
/// enabled = true
/// app_name = "My Age Verifier"
/// # session_secret_key = "<128 hex chars = 64 bytes>"   # stable sessions across restarts
///
/// # Database backend (default: sqlite_memory):
/// backend = "sqlite_memory"
///
/// # SQLite file (persistent, single-instance):
/// # backend = "sqlite_file"
/// # path    = "/var/lib/ewqwe/qrcode_app.db"
///
/// # PostgreSQL (HA / multi-instance):
/// # backend = "postgres"
/// # url     = "postgres://ewqwe:ewqwe@localhost/ewqwe"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct QrcodeAppConfig {
    /// Whether the QR Code APP is enabled. Defaults to `false` (opt-in).
    ///
    /// When `false`, all `/qrcode_app/*` routes are disabled and return 404.
    #[serde(default)]
    pub enabled: bool,

    /// Display name shown in the UI header.  Defaults to `"QR Code APP"`.
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
    #[serde(flatten, default)]
    pub db: QrcodeAppDbBackend,
}

impl QrcodeAppConfig {
    /// Returns the configured `app_name` or the default `"QR Code APP"`.
    pub fn app_name(&self) -> &str {
        self.app_name.as_deref().unwrap_or("QR Code APP")
    }
}
