//! HTTP endpoints for querying, verifying, and downloading the verification journal.
//!
//! All endpoints require mTLS authentication via [`SslAuth`] middleware.
//! A client may only access their own journal: the authenticated username must
//! match the `{username}` path parameter.
//!
//! ## Routes
//!
//! | Method | Path                                     | Description                                 |
//! |--------|------------------------------------------|---------------------------------------------|
//! | GET    | `/ewqwe_api/journal/{username}/entries`        | Query recent entries (with optional filters)|
//! | GET    | `/ewqwe_api/journal/{username}/verify`         | Verify the full chain integrity             |
//! | GET    | `/ewqwe_api/journal/{username}/download`       | Download all (or filtered) entries as JSON  |

use crate::{
    AttError,
    journal::{DynJournalStore, JournalEntry, JournalQuery, JournalStore as _},
    tls::AuthenticatedUser,
};
use actix_web::{HttpMessage, HttpRequest, HttpResponse, web};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

// ============================================================================
// Slim response type for the UI (hides internal chain-hash fields)
// ============================================================================

/// A UI-facing view of a journal entry.
///
/// Contains only the fields relevant for human display. The raw chain-hash
/// internals (`entry_hash`, `previous_hash`, `attestation_signature_hash`, …)
/// are intentionally omitted to avoid leaking audit-internals to the browser.
#[derive(Debug, Serialize)]
pub struct JournalEntryView {
    pub created_at: DateTime<Utc>,
    /// Email of the QR App user who performed the verification.
    pub qrcode_app_user_email: Option<String>,
    /// Whether the age verification was successful.
    pub success: bool,
    /// Flattened credential claims (e.g. `age_over_18`, `family_name`).
    /// mDoc namespace wrappers are removed so all claims appear at the top level.
    pub claims: serde_json::Value,
}

impl From<JournalEntry> for JournalEntryView {
    fn from(e: JournalEntry) -> Self {
        let success = e
            .verification_summary
            .get("success")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        // Extract the raw credential claims stored under "credential_claims",
        // then flatten one level if the top-level values are objects (mDoc
        // namespace pattern, e.g. `{"eu.europa.ec.av.1": {"age_over_18": true}}`).
        let raw = e
            .verification_summary
            .get("credential_claims")
            .cloned()
            .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));

        let claims = flatten_credential_claims(raw);

        JournalEntryView {
            created_at: e.created_at,
            qrcode_app_user_email: e.qrcode_app_user_email,
            success,
            claims,
        }
    }
}

/// Flatten one level of namespace wrappers from mDoc claims.
///
/// If **all** top-level values are JSON objects (mDoc pattern), their children
/// are merged into a single flat map.  Flat SD-JWT claims are returned as-is.
fn flatten_credential_claims(raw: serde_json::Value) -> serde_json::Value {
    let Some(obj) = raw.as_object() else {
        return serde_json::Value::Object(serde_json::Map::new());
    };
    let all_nested = !obj.is_empty() && obj.values().all(|v| v.is_object());
    if all_nested {
        let mut flat = serde_json::Map::new();
        for inner in obj.values() {
            if let Some(inner_obj) = inner.as_object() {
                flat.extend(inner_obj.iter().map(|(k, v)| (k.clone(), v.clone())));
            }
        }
        serde_json::Value::Object(flat)
    } else {
        raw
    }
}

// ============================================================================
// Query parameter structs
// ============================================================================

/// Query parameters for `GET /ewqwe_api/journal/{username}/entries`.
#[derive(Deserialize, Default)]
pub struct EntriesQuery {
    /// Maximum number of entries to return (defaults to 20, capped at 1000).
    pub limit: Option<u32>,
    /// Return only entries created strictly before this RFC 3339 timestamp.
    pub before: Option<DateTime<Utc>>,
    /// Return only entries created strictly after this RFC 3339 timestamp.
    pub after: Option<DateTime<Utc>>,
}

/// Query parameters for `GET /ewqwe_api/journal/{username}/download`.
#[derive(Deserialize, Default)]
pub struct DownloadQuery {
    /// Return only entries created strictly before this RFC 3339 timestamp.
    pub before: Option<DateTime<Utc>>,
    /// Return only entries created strictly after this RFC 3339 timestamp.
    pub after: Option<DateTime<Utc>>,
    /// Maximum entries to include (defaults to all).
    pub limit: Option<u32>,
}

// ============================================================================
// Authorisation helper
// ============================================================================

/// Verify that the authenticated mTLS user matches the requested username.
fn check_username_access(req: &HttpRequest, requested_username: &str) -> Result<(), AttError> {
    let auth_user = req
        .extensions()
        .get::<AuthenticatedUser>()
        .map(|u| u.username.clone())
        .ok_or_else(|| {
            AttError::Authentication(
                "mTLS authentication required: authenticated user not found".to_string(),
            )
        })?;

    if auth_user != requested_username {
        return Err(AttError::Authentication(format!(
            "access denied: authenticated as '{auth_user}' but requested journal for '{requested_username}'"
        )));
    }

    Ok(())
}

// ============================================================================
// Handler: list entries
// ============================================================================

/// Query journal entries for the authenticated user.
///
/// Returns a JSON array of [`JournalEntry`] objects, newest first.
///
/// ## Query parameters
///
/// | Parameter | Type           | Description                              |
/// |-----------|----------------|------------------------------------------|
/// | `limit`   | integer        | Maximum results (1–1000, default 20)     |
/// | `before`  | RFC 3339 date  | Only entries created before this time    |
/// | `after`   | RFC 3339 date  | Only entries created after this time     |
pub async fn list_journal_entries(
    req: HttpRequest,
    path: web::Path<String>,
    query: web::Query<EntriesQuery>,
    journal: web::Data<Arc<DynJournalStore>>,
) -> Result<HttpResponse, AttError> {
    let username = path.into_inner();
    check_username_access(&req, &username)?;

    let limit = query.limit.unwrap_or(20).min(1000);

    let entries: Vec<JournalEntryView> = journal
        .list_entries(&JournalQuery {
            username,
            limit: Some(limit),
            before: query.before,
            after: query.after,
        })
        .await
        .map_err(AttError::from)?
        .into_iter()
        .map(JournalEntryView::from)
        .collect();

    Ok(HttpResponse::Ok().json(entries))
}

// ============================================================================
// Handler: verify chain
// ============================================================================

/// Verify the hash-chain integrity of the authenticated user's journal.
///
/// Recomputes every `entry_hash` from genesis and checks the head pointer.
/// Returns a [`ChainVerificationResult`] JSON object.
pub async fn verify_journal_chain(
    req: HttpRequest,
    path: web::Path<String>,
    journal: web::Data<Arc<DynJournalStore>>,
) -> Result<HttpResponse, AttError> {
    let username = path.into_inner();
    check_username_access(&req, &username)?;

    let result = journal
        .verify_chain(&username)
        .await
        .map_err(AttError::from)?;

    Ok(HttpResponse::Ok().json(result))
}

// ============================================================================
// Handler: download journal
// ============================================================================

/// Download journal entries for the authenticated user as a JSON file.
///
/// Returns all matching entries as a JSON array with a
/// `Content-Disposition: attachment` header so browsers offer a save dialog.
///
/// ## Query parameters
///
/// | Parameter | Type           | Description                              |
/// |-----------|----------------|------------------------------------------|
/// | `before`  | RFC 3339 date  | Only entries created before this time    |
/// | `after`   | RFC 3339 date  | Only entries created after this time     |
/// | `limit`   | integer        | Maximum entries (default: all)           |
pub async fn download_journal(
    req: HttpRequest,
    path: web::Path<String>,
    query: web::Query<DownloadQuery>,
    journal: web::Data<Arc<DynJournalStore>>,
) -> Result<HttpResponse, AttError> {
    let username = path.into_inner();
    check_username_access(&req, &username)?;

    let entries = journal
        .list_entries(&JournalQuery {
            username: username.clone(),
            // For download, default to no limit (all entries) unless caller specifies one.
            limit: query.limit,
            before: query.before,
            after: query.after,
        })
        .await
        .map_err(AttError::from)?;

    let json_bytes = serde_json::to_vec_pretty(&entries)
        .map_err(|e| AttError::Generic(format!("journal serialization: {e}")))?;

    let filename = format!("journal_{username}.json");

    Ok(HttpResponse::Ok()
        .content_type("application/json")
        .insert_header((
            "Content-Disposition",
            format!("attachment; filename=\"{filename}\""),
        ))
        .body(json_bytes))
}
