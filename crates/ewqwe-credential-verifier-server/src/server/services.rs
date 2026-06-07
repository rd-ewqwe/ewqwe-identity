//! Pluggable server configuration — the `configure_services` function.
//!
//! This module follows the **Open Core architecture** pattern described in
//! `documentation/src/notes/open_core.md`:
//!
//! - The open-core crate exposes `configure_services()`, which registers
//!   all routes on an actix-web `ServiceConfig` **without** authentication
//!   or session middleware.
//! - The enterprise binary (or any downstream consumer) is responsible for
//!   constructing the `App`, adding its own middleware, and calling
//!   `configure_services()`.
//!
//! # Example (open-core binary)
//!
//! ```ignore
//! let components = ServerComponents::create(&params).await?;
//! let app = App::new()
//!     .app_data(Data::new(parameters.clone()))
//!     .configure(|cfg| configure_services(cfg, &components));
//! ```
//!
//! # Example (enterprise binary)
//!
//! ```ignore
//! let components = enterprise_prepare_components(&params).await?;
//! let app = App::new()
//!     .wrap(EnterpriseAuthMiddleware)
//!     .wrap(SessionMiddleware::builder(...).build())
//!     .app_data(Data::new(parameters.clone()))
//!     .configure(|cfg| ewqwe_credential_verifier_server::configure_services(cfg, &components));
//! ```

use crate::{
    AttResult,
    journal::{DynJournalStore, JournalStore},
    parameters::ServerParams,
    server::{
        journal_endpoints::{self, JournalEntryView},
        openid4vp_endpoints,
        verify_endpoint::{self, verify_credential_endpoint, version_endpoint},
    },
};
use actix_web::web::{self, Data, JsonConfig, PayloadConfig};
use ewqwe_credential_verifier_ui::{
    VerifierCredentialVerifier, VerifierJournalProvider, db::DynVerifierUiStore,
    qr_user_map::QrUserMap,
};
use ewqwe_openid4vp::OpenID4VPService;
use std::sync::Arc;

use crate::server::qr_verifier::QrCredentialVerifierImpl;
use crate::server::verify_endpoint::load_credential_issuer_cas;
use tracing::info;

/// Adapter bridging [`DynJournalStore`] to the [`VerifierJournalProvider`] trait.
struct JournalProviderForVerifier(Arc<DynJournalStore>);

#[async_trait::async_trait]
impl VerifierJournalProvider for JournalProviderForVerifier {
    async fn list_verifier_entries(
        &self,
        user_id: Option<&str>,
        date_from: Option<chrono::DateTime<chrono::Utc>>,
        date_to: Option<chrono::DateTime<chrono::Utc>>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<serde_json::Value>, String> {
        self.0
            .list_qrcode_app_entries(user_id, date_from, date_to, limit, offset)
            .await
            .map(|entries| {
                entries
                    .into_iter()
                    .map(|e| serde_json::to_value(JournalEntryView::from(e)).unwrap_or_default())
                    .collect()
            })
            .map_err(|e| e.to_string())
    }
}

// ============================================================================
// ServerComponents — shared application state
// ============================================================================

/// All shared application state required by the credential verifier routes.
///
/// Construct via [`ServerComponents::create`], then pass to
/// [`configure_services`] to register routes on an actix-web `ServiceConfig`.
///
/// Downstream consumers (e.g. the enterprise binary) can provide their own
/// implementations by constructing this struct with different store backends
/// (PostgreSQL, Redis, etc.) or authentication components.
pub struct ServerComponents {
    /// OpenID4VP transaction service.
    pub openid4vp_service: Arc<OpenID4VPService>,

    /// Cached credential-issuer CA certificates for verifying incoming
    /// credentials.
    pub trusted_cas: Arc<Vec<openssl::x509::X509>>,

    /// Verification journal store (enabled or `None`).
    pub journal_store: Option<Arc<DynJournalStore>>,

    /// Verifier App user store (when the UI is enabled).
    pub verifier_ui_store: Option<Arc<DynVerifierUiStore>>,

    /// QR code → user ownership tracker.
    pub qr_user_map: Arc<QrUserMap>,

    /// Verifier App configuration snapshot.
    pub verifier_ui_config: Arc<ewqwe_credential_verifier_ui::config::VerifierUiConfig>,

    /// Journal provider for the Verifier App (or `None`).
    pub journal_provider_for_va: Option<Arc<dyn VerifierJournalProvider>>,

    /// In-process credential verifier for the QR polling flow (or `None`).
    pub qr_credential_verifier: Option<Arc<dyn VerifierCredentialVerifier>>,

    /// Verifier App session cookie signing key (generated when UI is enabled).
    pub verifier_ui_session_key: Option<actix_web::cookie::Key>,
}

impl ServerComponents {
    /// Initialise all shared application state from server parameters.
    ///
    /// This is the canonical way to create the components needed by
    /// [`configure_services`].  Call once during server startup.
    pub async fn create(params: &ServerParams) -> AttResult<Self> {
        let openid4vp_service: Arc<OpenID4VPService> = Arc::new(
            OpenID4VPService::create(params.openid4vp_config.clone())
                .await
                .map_err(|e| {
                    crate::AttError::Config(format!("Failed to initialize OpenID4VP service: {e}"))
                })?,
        );

        let journal_store: Option<Arc<DynJournalStore>> = if params.journal_config.enabled {
            let store = DynJournalStore::new(&params.journal_config)
                .await
                .map_err(|e| {
                    crate::AttError::Config(format!("Failed to initialise journal store: {e}"))
                })?;
            info!(
                "Verification journal enabled (backend: {:?})",
                params.journal_config.backend
            );
            Some(Arc::new(store))
        } else {
            info!("Verification journal disabled");
            None
        };

        let verifier_ui_store: Option<Arc<DynVerifierUiStore>> = if params
            .verifier_ui_config
            .enabled
        {
            let store = DynVerifierUiStore::new(&params.verifier_ui_config)
                .await
                .map_err(|e| {
                    crate::AttError::Config(format!("Failed to initialise Verifier App store: {e}"))
                })?;
            info!(
                "Verifier App store enabled (backend: {:?})",
                params.verifier_ui_config.db
            );
            Some(Arc::new(store))
        } else {
            info!("Verifier App disabled");
            None
        };

        let trusted_cas_vec = load_credential_issuer_cas(params.credential_issuer_ca_dir())?;
        let trusted_cas: Arc<Vec<openssl::x509::X509>> = Arc::new(trusted_cas_vec);
        info!(
            dir = %params.credential_issuer_ca_dir(),
            count = trusted_cas.len(),
            "Loaded credential issuer CAs at startup"
        );

        let verifier_ui_session_key: Option<actix_web::cookie::Key> =
            if params.verifier_ui_config.enabled {
                let key = build_session_key(&params.verifier_ui_config.session_secret)?;
                Some(key)
            } else {
                None
            };

        let qr_user_map: Arc<QrUserMap> = Arc::new(QrUserMap::new());

        let journal_provider_for_va: Option<Arc<dyn VerifierJournalProvider>> =
            journal_store.as_ref().map(|j| {
                Arc::new(JournalProviderForVerifier(j.clone())) as Arc<dyn VerifierJournalProvider>
            });

        let verifier_ui_config = Arc::new(params.verifier_ui_config.clone());

        let qr_credential_verifier: Option<Arc<dyn VerifierCredentialVerifier>> =
            if params.verifier_ui_config.enabled {
                Some(Arc::new(QrCredentialVerifierImpl {
                    service: openid4vp_service.clone(),
                    trusted_cas: trusted_cas.clone(),
                    journal: journal_store.clone(),
                }) as Arc<dyn VerifierCredentialVerifier>)
            } else {
                None
            };

        Ok(Self {
            openid4vp_service,
            trusted_cas,
            journal_store,
            verifier_ui_store,
            qr_user_map,
            verifier_ui_config,
            journal_provider_for_va,
            qr_credential_verifier,
            verifier_ui_session_key,
        })
    }
}

// ============================================================================
// configure_services — route registration (no middleware)
// ============================================================================

/// Register all credential verifier routes on an actix-web [`web::ServiceConfig`].
///
/// This function registers **route handlers only** — it does NOT apply
/// authentication, session, or mTLS middleware.  That is the responsibility
/// of the binary crate that owns the `App` construction.
///
/// The caller must ensure that all required [`web::Data`] items from
/// [`ServerComponents`] have been registered on the app (or enclosing scope)
/// before this function is called.
///
/// # Required `web::Data` registrations
///
/// | Type | Source |
/// |------|--------|
/// | `Arc<ServerParams>` | Caller's parameters |
/// | `Arc<OpenID4VPService>` | `components.openid4vp_service` |
/// | `Arc<Vec<openssl::x509::X509>>` | `components.trusted_cas` |
/// | `Option<Arc<DynJournalStore>>` | `components.journal_store` |
/// | `Option<Arc<DynVerifierUiStore>>` | `components.verifier_ui_store` |
/// | `Arc<QrUserMap>` | `components.qr_user_map` |
/// | `Arc<VerifierUiConfig>` | `components.verifier_ui_config` |
/// | `Option<Arc<dyn VerifierJournalProvider>>` | `components.journal_provider_for_va` |
/// | `Option<Arc<dyn VerifierCredentialVerifier>>` | `components.qr_credential_verifier` |
#[allow(dead_code)] // Used by enterprise binary
pub fn configure_services(cfg: &mut web::ServiceConfig, components: &ServerComponents) {
    // ── Shared application data ──────────────────────────────────────────
    cfg.app_data(PayloadConfig::new(1_000_000))
        .app_data(JsonConfig::default().limit(1_000_000))
        .app_data(Data::new(components.openid4vp_service.clone()))
        .app_data(Data::new(components.trusted_cas.clone()))
        .app_data(Data::new(components.qr_user_map.clone()))
        .app_data(Data::new(components.verifier_ui_config.clone()));

    if let Some(ref store) = components.journal_store {
        cfg.app_data(Data::new(store.clone()));
    }
    if let Some(ref store) = components.verifier_ui_store {
        cfg.app_data(Data::new(store.clone()));
    }
    if let Some(ref jp) = components.journal_provider_for_va {
        cfg.app_data(Data::new(jp.clone()));
    }
    if let Some(ref v) = components.qr_credential_verifier {
        cfg.app_data(Data::new(v.clone()));
    }

    // ── Wallet-facing routes (no authentication required) ────────────────
    cfg.route(
        "/ewqwe_api/openid4vp/direct_post",
        web::post().to(openid4vp_endpoints::handle_direct_post),
    )
    .route(
        "/ewqwe_api/openid4vp/request/{id}",
        web::get().to(openid4vp_endpoints::get_authorization_request),
    )
    .route(
        "/ewqwe_api/openid4vp/request/{id}",
        web::post().to(openid4vp_endpoints::get_authorization_request),
    )
    .route(
        "/ewqwe_api/openid4vp/.well-known/jwks.json",
        web::get().to(openid4vp_endpoints::get_jwks),
    )
    .route(
        "/ewqwe_api/dc_api/verify",
        web::post().to(super::dc_api_endpoint::verify_dc_api),
    )
    .route(
        "/ewqwe_api/dc_api/nonce",
        web::get().to(super::dc_api_endpoint::generate_nonce),
    );

    // ── RP-facing routes ─────────────────────────────────────────────────
    // NOTE: No EnsureAuth or SslAuth middleware is applied here.
    // The enterprise binary (or any downstream consumer) adds auth
    // middleware via actix-web's `.wrap()` before calling this function.
    cfg.route(
        "/ewqwe_api/verify",
        web::post().to(verify_credential_endpoint),
    )
    .route(
        "/ewqwe_api/.well-known/issuer_certs",
        web::get().to(verify_endpoint::issuer_certs_endpoint),
    )
    .route(
        "/ewqwe_api/openid4vp/init",
        web::post().to(openid4vp_endpoints::init_transaction),
    )
    .route(
        "/ewqwe_api/openid4vp/status/{id}",
        web::get().to(openid4vp_endpoints::get_transaction_status),
    )
    .route(
        "/ewqwe_api/journal/{username}/entries",
        web::get().to(journal_endpoints::list_journal_entries),
    )
    .route(
        "/ewqwe_api/journal/{username}/verify",
        web::get().to(journal_endpoints::verify_journal_chain),
    )
    .route(
        "/ewqwe_api/journal/{username}/download",
        web::get().to(journal_endpoints::download_journal),
    );

    // ── Version endpoint ─────────────────────────────────────────────────
    cfg.route("/version", web::get().to(version_endpoint));

    // ── Verifier App UI (only when a session key is available) ───────────
    if let Some(ref _session_key) = components.verifier_ui_session_key {
        // Session middleware must be applied by the caller (binary crate).
        // Here we only wire up the route module so that the endpoints exist.
        cfg.service(
            web::scope("/api/v1").configure(ewqwe_credential_verifier_ui::configure_routes),
        );
    }
}

// ============================================================================
// Internal helpers
// ============================================================================

/// Build an actix-web session cookie signing key from an optional secret.
fn build_session_key(secret: &Option<String>) -> AttResult<actix_web::cookie::Key> {
    use actix_web::cookie::Key as CookieKey;
    use argon2::Argon2;

    if let Some(session_secret) = secret {
        if session_secret.len() < 8 {
            return Err(crate::AttError::Config(
                "verifier_ui.session_secret must be at least 8 characters".to_string(),
            ));
        }
        let mut derived_key = [0u8; 64];
        let salt = concat!("ewQwe Credential Verifier::", env!("CARGO_PKG_VERSION")).as_bytes();
        Argon2::default()
            .hash_password_into(session_secret.as_bytes(), salt, &mut derived_key)
            .map_err(|e| {
                crate::AttError::Config(format!(
                    "failed to derive session secret into a session key: {e}"
                ))
            })?;
        Ok(CookieKey::derive_from(&derived_key))
    } else {
        tracing::warn!(
            "verifier_ui.session_secret not set — sessions will be invalidated on \
             server restart; configure a stable secret for production"
        );
        Ok(CookieKey::generate())
    }
}
