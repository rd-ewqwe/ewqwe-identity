//! Verifier App — embedded age-verification web application.
//!
//! This crate provides the complete Verifier App module that is mounted as a
//! scope under `/verifier_app` by `credential_verifier`.
//!
//! ## Routes
//!
//! ```text
//! /verifier_app/api/setup/bootstrap     — one-time admin creation
//! /verifier_app/api/setup/status        — bootstrap status (public)
//! /verifier_app/api/auth/*              — login / logout / me
//! /verifier_app/api/qr/generate         — initiate OpenID4VP transaction + QR
//! /verifier_app/api/qr/{id}/status      — poll verification result
//! /verifier_app/api/admin/users/*       — admin: user management
//! /verifier_app/api/admin/journal       — admin: filterable audit log
//! /verifier_app/api/admin/settings      — admin: update app settings
//! /verifier_app/api/settings            — public: read app settings
//! /verifier_app/api/i18n                — locale JSON files
//! /verifier_app/*                       — static SPA assets
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
/// `verifier_app_config.enabled = true`.  The `/verifier_app` scope prefix is
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
        // ── Static assets ───────────────────────────────────────────────────
        .route("", web::get().to(routes::ui_index))
        .route("/", web::get().to(routes::ui_index))
        .route("/ui", web::get().to(routes::ui_index))
        .route("/ui/", web::get().to(routes::ui_index))
        .route("/logo.png", web::get().to(routes::logo_png))
        // ── Setup (no auth) ────────────────────────────────────────────────
        .route("/api/setup/bootstrap", web::post().to(routes::bootstrap))
        .route("/api/setup/status", web::get().to(routes::setup_status))
        // ── Authentication ─────────────────────────────────────────────────
        .route("/api/auth/login", web::post().to(routes::login))
        .route("/api/auth/logout", web::post().to(routes::logout))
        .route("/api/auth/me", web::get().to(routes::me))
        // ── Public settings ────────────────────────────────────────────────
        .route("/api/settings", web::get().to(routes::get_settings))
        // ── QR Code generation & status polling ────────────────────────────
        .route("/api/qr/generate", web::post().to(routes::generate_qr))
        .route("/api/qr/{id}/status", web::get().to(routes::qr_status))
        // ── Admin: user management ─────────────────────────────────────────
        .route("/api/admin/users", web::get().to(routes::list_users))
        .route("/api/admin/users", web::post().to(routes::create_user))
        .route("/api/admin/users/{id}", web::put().to(routes::update_user))
        .route(
            "/api/admin/users/{id}",
            web::delete().to(routes::delete_user),
        )
        // ── Admin: journal ─────────────────────────────────────────────────
        .route("/api/admin/journal", web::get().to(routes::admin_journal))
        // ── Admin: settings ───────────────────────────────────────────────
        .route(
            "/api/admin/settings",
            web::put().to(routes::update_settings),
        )
        // ── Internationalisation ────────────────────────────────────────────
        .route("/api/i18n", web::get().to(routes::get_i18n));
}
