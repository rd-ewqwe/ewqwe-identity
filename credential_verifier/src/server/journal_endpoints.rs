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
    journal::{DynJournalStore, JournalQuery, JournalStore as _},
    tls::AuthenticatedUser,
};
use actix_web::{HttpMessage, HttpRequest, HttpResponse, web};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::sync::Arc;

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

    let entries = journal
        .list_entries(&JournalQuery {
            username,
            limit: Some(limit),
            before: query.before,
            after: query.after,
        })
        .await
        .map_err(AttError::from)?;

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
