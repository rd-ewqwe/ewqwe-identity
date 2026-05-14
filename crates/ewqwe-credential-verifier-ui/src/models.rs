//! Domain models and request/response DTOs for the Verifier App.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

// ============================================================================
// Role
// ============================================================================

/// User role within the Verifier App.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum VerifierAppRole {
    /// Administrator — can manage users, view the full journal, and configure
    /// OIDC providers.
    Admin,
    /// Verifier — can generate QR codes and view their own verification results.
    #[default]
    Verifier,
}

impl VerifierAppRole {
    /// Returns the lowercase string representation stored in the database.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Verifier => "verifier",
        }
    }
}

impl FromStr for VerifierAppRole {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "admin" => Ok(Self::Admin),
            "verifier" => Ok(Self::Verifier),
            other => Err(format!("unknown Verifier App role: {other}")),
        }
    }
}

// ============================================================================
// User (domain model)
// ============================================================================

/// A Verifier App user account, as stored in the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifierAppUser {
    pub id: String,
    pub email: String,
    /// Argon2id hash of the password.  `None` for OIDC-only accounts.
    pub password_hash: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub role: VerifierAppRole,
    pub is_active: bool,
    /// Marks the first admin created by the bootstrap endpoint.
    /// Superadmin accounts cannot be deleted via the UI.
    pub is_superadmin: bool,
    /// Credential types this user is allowed to request.
    ///
    /// Empty means all types are allowed.
    /// Valid values: `"proof-of-age"`, `"mdl"`, `"national-id"`.
    #[serde(default)]
    pub allowed_credential_types: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ============================================================================
// API response DTO
// ============================================================================

/// Public view of a user — never includes the `password_hash`.
#[derive(Debug, Clone, Serialize)]
pub struct UserResponse {
    pub id: String,
    pub email: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub role: VerifierAppRole,
    pub is_active: bool,
    pub is_superadmin: bool,
    pub allowed_credential_types: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<VerifierAppUser> for UserResponse {
    fn from(u: VerifierAppUser) -> Self {
        Self {
            id: u.id,
            email: u.email,
            first_name: u.first_name,
            last_name: u.last_name,
            role: u.role,
            is_active: u.is_active,
            is_superadmin: u.is_superadmin,
            allowed_credential_types: u.allowed_credential_types,
            created_at: u.created_at,
            updated_at: u.updated_at,
        }
    }
}

// ============================================================================
// Internal store records
// ============================================================================

/// Data passed to [`crate::db::VerifierAppStore::create_user`].
pub struct NewUserRecord {
    /// Pre-generated UUIDv4 string (caller is responsible for uniqueness).
    pub id: String,
    pub email: String,
    pub password_hash: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub role: VerifierAppRole,
    pub is_superadmin: bool,
    /// Credential types this user is allowed to request (empty = all).
    pub allowed_credential_types: Vec<String>,
}

/// Partial update applied by [`crate::db::VerifierAppStore::update_user`].
///
/// `None` fields mean "no change"; `Some` fields are written to the database.
#[derive(Default)]
pub struct UserChanges {
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub role: Option<VerifierAppRole>,
    pub is_active: Option<bool>,
    /// Pre-hashed password (argon2id).  `None` = no password change.
    pub password_hash: Option<String>,
    /// Credential types this user is allowed to request.  `None` = no change.
    pub allowed_credential_types: Option<Vec<String>>,
}

// ============================================================================
// API request DTOs
// ============================================================================

/// Body for `POST /verifier_ui/api/setup/bootstrap`.
#[derive(Debug, Deserialize)]
pub struct BootstrapRequest {
    pub email: String,
    pub password: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
}

/// Body for `POST /verifier_ui/api/auth/login`.
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

/// Body for `POST /verifier_ui/api/admin/users`.
#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub email: String,
    pub password: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub role: Option<VerifierAppRole>,
    /// Credential types this user is allowed to request.  Empty = all.
    pub allowed_credential_types: Option<Vec<String>>,
}

/// Body for `PUT /verifier_ui/api/admin/users/{id}`.
#[derive(Debug, Deserialize, Default)]
pub struct UpdateUserRequest {
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub role: Option<VerifierAppRole>,
    pub is_active: Option<bool>,
    pub new_password: Option<String>,
    /// Credential types this user is allowed to request.  `null` = no change.
    pub allowed_credential_types: Option<Vec<String>>,
}

/// Body for `POST /verifier_ui/api/qr/generate`.
#[derive(Debug, Deserialize, Default)]
pub struct GenerateQrRequest {
    /// Credential type to request: `"proof-of-age"`, `"mdl"`, or `"national-id"`.
    ///
    /// Defaults to `"proof-of-age"` when absent.
    pub credential_type: Option<String>,

    /// Specific claim names to request (e.g. `["age_over_18", "portrait"]`).
    ///
    /// When empty or absent, the default claims for the credential type are used.
    #[serde(default)]
    pub claims: Vec<String>,
}

/// Query parameters for `GET /verifier_ui/api/admin/journal`.
#[derive(Debug, Deserialize, Default)]
pub struct AdminJournalQuery {
    /// Filter to entries attributed to this QR app user ID.
    pub user_id: Option<String>,
    /// Filter to entries on or after this ISO 8601 datetime (e.g. `2024-01-15T00:00:00Z`).
    pub date_from: Option<String>,
    /// Filter to entries on or before this ISO 8601 datetime (e.g. `2024-01-15T23:59:59Z`).
    pub date_to: Option<String>,
    /// Maximum number of entries to return (capped at 200).
    pub limit: Option<u32>,
    /// Pagination offset.
    pub offset: Option<u32>,
}

/// Query parameters for `GET /verifier_ui/api/i18n`.
#[derive(Debug, Deserialize, Default)]
pub struct I18nQuery {
    /// BCP-47 language code (e.g. `en`, `de`, `fr`). Defaults to `en`.
    pub lang: Option<String>,
}
