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
}

/// Top-level configuration section for the Verifier UI.
///
/// Embedded in the server configuration file as `[verifier_ui]`.
///
/// ```toml
/// [verifier_ui]
/// enabled = true
/// app_name = "My Age Verifier"
/// # public_url = "https://verifier.example.com:9443"
/// # allowed_credential_types = ["proof-of-age", "mdl", "national-id"]
/// # session_secret = "<128 hex chars = 64 bytes>"   # stable sessions across restarts
///
/// # Database backend (default: sqlite_memory):
/// backend = "sqlite_memory"
///
/// # SQLite file (persistent, single-instance):
/// # backend = "sqlite_file"
/// # path    = "/var/lib/ewqwe/verifier_ui.db"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VerifierUiConfig {
    /// Whether the Verifier App is enabled. Defaults to `false` (opt-in).
    ///
    /// When `false`, all `/verifier_ui/*` routes are disabled and return 404.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Display name shown in the UI header.  Defaults to `"Verifier App"`.
    #[serde(default)]
    pub app_name: Option<String>,

    /// Optional URL for a custom logo shown in the UI header.
    #[serde(default)]
    pub logo_url: Option<String>,

    /// Public URL used as the QR code callback URLs that will be called
    /// by the wallet in order to obtain the authorization request.
    ///
    /// This will default to the `public_root_url` set on the credential
    /// verifier server and there little reason to set it manually.
    #[serde(default)]
    pub qr_code_callback_url: Option<String>,

    /// Credential types that verifier users are allowed to request.
    ///
    /// Valid values: `"proof-of-age"`, `"mdl"`, `"national-id"`, `"france-identite-numerique"`.
    /// When empty or absent, all credential types are allowed.
    #[serde(default)]
    pub allowed_credential_types: Vec<String>,

    /// Hex-encoded secret used to sign and encrypt session cookies.
    ///
    /// Must decode to **at least 32 bytes** (64 hex characters).  For
    /// stable sessions across server restarts, set this to a fixed value.
    /// When absent, a random key is generated at startup — all active
    /// sessions are invalidated whenever the server restarts.
    #[serde(default)]
    pub session_secret: Option<String>,

    /// File-system path to the Vite-built UI assets directory.
    ///
    /// When set, the credential verifier serves the SPA from this directory
    /// at the root URL (`/`).  Build with:
    ///
    /// ```bash
    /// cd crates/ewqwe-credential-verifier-ui/ui && pnpm build
    /// ```
    ///
    /// Example: `"./crates/ewqwe-credential-verifier-ui/ui/dist"`
    #[serde(default)]
    pub ui_dist_path: Option<String>,

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
            session_secret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

            [db]
            backend = "sqlite_file"
            path = "/var/lib/ewqwe/verifier_ui.db"
        "#;

        let config: VerifierUiConfig = toml::from_str(toml_str).expect("Failed to parse TOML");
        assert!(config.enabled);
        assert_eq!(config.app_name.as_deref(), Some("My Verifier App"));
        assert_eq!(
            config.logo_url.as_deref(),
            Some("https://example.com/logo.png")
        );
        assert_eq!(
            config.session_secret.as_deref(),
            Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        );
        assert!(config.qr_code_callback_url.is_none());
        assert!(config.allowed_credential_types.is_empty());

        match config.db {
            VerifierAppDbBackend::SqliteFile { path } => {
                assert_eq!(path, "/var/lib/ewqwe/verifier_ui.db");
            }
            _ => panic!("Expected SqliteFile backend"),
        }
    }

    #[test]
    fn test_toml_public_url_and_credential_types() {
        let toml_str = r#"
            enabled = true
            qr_code_callback_url = "https://verifier.example.com:9443"
            allowed_credential_types = ["proof-of-age", "mdl"]

            [db]
            backend = "sqlite_memory"
        "#;

        let config: VerifierUiConfig = toml::from_str(toml_str).expect("Failed to parse TOML");
        assert_eq!(
            config.qr_code_callback_url.as_deref(),
            Some("https://verifier.example.com:9443")
        );
        assert_eq!(config.allowed_credential_types, vec!["proof-of-age", "mdl"]);
    }
}
