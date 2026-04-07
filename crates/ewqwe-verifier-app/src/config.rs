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


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_toml_parsing() {
        let toml_str = r#"
            enabled = true
            app_name = "My Verifier App"
            logo_url = "https://example.com/logo.png"
            session_secret_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

            [db]
            backend = "sqlite_file"
            path = "/var/lib/ewqwe/verifier_app.db"
        "#;

        let config: VerifierAppConfig = toml::from_str(toml_str).expect("Failed to parse TOML");
        assert!(config.enabled);
        assert_eq!(config.app_name.as_deref(), Some("My Verifier App"));
        assert_eq!(config.logo_url.as_deref(), Some("https://example.com/logo.png"));
        assert_eq!(
            config.session_secret_key.as_deref(),
            Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        );

        match config.db {
            VerifierAppDbBackend::SqliteFile { path } => {
                assert_eq!(path, "/var/lib/ewqwe/verifier_app.db");
            }
            _ => panic!("Expected SqliteFile backend"),
        }
    }
}