//! Verifier App — embedded age-verification web application.
//!
//! This crate provides the complete Verifier App module that is mounted as a
//! scope under `/api/v1` by `credential_verifier`.
//!
//! ## Routes
//!
//! ```text
//! /api/v1/setup/bootstrap     — one-time admin creation
//! /api/v1/setup/status        — bootstrap status (public)
//! /api/v1/auth/*              — login / logout / me
//! /api/v1/qr/generate         — initiate OpenID4VP transaction + QR
//! /api/v1/qr/{id}/status      — poll verification result
//! /api/v1/admin/users/*       — admin: user management
//! /api/v1/admin/journal       — admin: filterable audit log
//! /api/v1/admin/settings      — admin: update app settings
//! /api/v1/settings            — public: read app settings
//! /api/v1/i18n                — locale JSON files
//! /                           — SPA assets (served by actix-files from ui/dist/)
//! ```

pub mod auth;
pub mod config;
pub mod db;
pub mod error;
pub mod models;
pub mod qr_user_map;
mod routes;
pub mod stores;

pub use config::VerifierAppConfig;

use actix_web::web;
use async_trait::async_trait;

/// Result of an inline credential verification performed by the Verifier App
/// QR polling endpoint.
pub struct QrVerifyResult {
    /// Whether the credential passed all verification checks.
    pub success: bool,
    /// Credential document type (e.g. `"eu.europa.ec.av.1"`).
    pub doc_type: String,
    /// Failures or warnings produced during verification.
    pub errors: Vec<String>,
    /// Value of the `age_over_18` claim from the presented credential, if present.
    pub age_over_18: Option<bool>,
}

/// Pluggable in-process credential verifier for the Verifier App QR flow.
///
/// Implemented by `credential_verifier` via `credential_verifier::server::start`
/// and registered as `web::Data<Arc<dyn VerifierCredentialVerifier>>` on the app.
/// Breaks the dependency cycle between `ewqwe_verifier_app` and `credential_verifier`.
#[async_trait]
pub trait VerifierCredentialVerifier: Send + Sync {
    /// Verify a VP token received from the wallet via the OpenID4VP direct_post.
    ///
    /// * `vp_token` – raw VP token string (DCQL mDoc or SD-JWT VC).
    /// * `state`    – OpenID4VP state parameter used to look up the server nonce.
    /// * `username` – email of the Verifier App user who initiated the QR, used for
    ///   journal attribution.
    async fn verify_qr_presentation(
        &self,
        vp_token: &str,
        state: &str,
        username: &str,
    ) -> Result<QrVerifyResult, String>;
}

/// Minimal journal access interface for the [`routes::admin_journal`] handler.
///
/// Implemented by `credential_verifier::journal::DynJournalStore` via a thin
/// adapter in `credential_verifier`.  This trait breaks the dependency cycle
/// between `ewqwe_verifier_app` and `credential_verifier`.
#[async_trait]
pub trait VerifierJournalProvider: Send + Sync {
    /// List journal entries attributed to a Verifier App user.
    ///
    /// Returns pre-serialised [`serde_json::Value`] rows so the HTTP handler
    /// can forward them directly without knowing the concrete entry type.
    async fn list_verifier_entries(
        &self,
        user_id: Option<&str>,
        date_from: Option<chrono::DateTime<chrono::Utc>>,
        date_to: Option<chrono::DateTime<chrono::Utc>>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<serde_json::Value>, String>;
}

/// Register all Verifier App routes on the given [`web::ServiceConfig`].
///
/// Called from `credential_verifier::server::start` when
/// `verifier_app_config.enabled = true`.  The `/api/v1` scope prefix is
/// applied by the caller.
///
/// ## Required `web::Data` registrations (on the enclosing scope or App)
///
/// | Type | Description |
/// |------|-------------|
/// | `Arc<db::DynVerifierAppStore>` | user store |
/// | `Arc<ewqwe_openid4vp::OpenID4VPService>` | QR / OpenID4VP service |
/// | `Arc<qr_user_map::QrUserMap>` | in-memory ownership tracker |
/// | `Arc<VerifierAppConfig>` | config defaults for public settings |
/// | `Option<Arc<dyn VerifierJournalProvider>>` | optional audit journal |
pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg
        // ── Setup (no auth) ────────────────────────────────────────────────
        .route("/setup/bootstrap", web::post().to(routes::bootstrap))
        .route("/setup/status", web::get().to(routes::setup_status))
        // ── Authentication ─────────────────────────────────────────────────
        .route("/auth/login", web::post().to(routes::login))
        .route("/auth/logout", web::post().to(routes::logout))
        .route("/auth/me", web::get().to(routes::me))
        // ── Public settings ────────────────────────────────────────────────
        .route("/settings", web::get().to(routes::get_settings))
        // ── QR Code generation & status polling ────────────────────────────
        .route("/qr/generate", web::post().to(routes::generate_qr))
        .route("/qr/{id}/status", web::get().to(routes::qr_status))
        // ── Admin: user management ─────────────────────────────────────────
        .route("/admin/users", web::get().to(routes::list_users))
        .route("/admin/users", web::post().to(routes::create_user))
        .route("/admin/users/{id}", web::put().to(routes::update_user))
        .route("/admin/users/{id}", web::delete().to(routes::delete_user))
        // ── Admin: journal ─────────────────────────────────────────────────
        .route("/admin/journal", web::get().to(routes::admin_journal))
        // ── Admin: settings ───────────────────────────────────────────────
        .route("/admin/settings", web::put().to(routes::update_settings))
        // ── Internationalisation ────────────────────────────────────────────
        .route("/i18n", web::get().to(routes::get_i18n));
}
