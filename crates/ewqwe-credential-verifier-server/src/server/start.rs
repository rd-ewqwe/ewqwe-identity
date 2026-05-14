use crate::{
    AttError, AttResult, AttResultHelper,
    journal::{DynJournalStore, JournalStore},
    parameters::ServerParams,
    server::{
        EnsureAuth,
        journal_endpoints::{self, JournalEntryView},
        openid4vp_endpoints,
        qr_verifier::QrCredentialVerifierImpl,
        verify_endpoint::{self, verify_credential_endpoint, version_endpoint},
    },
    tls::SslAuth,
};
use actix_identity::IdentityMiddleware;
use actix_session::{SessionMiddleware, storage::CookieSessionStore};
use actix_web::{
    App, HttpServer,
    cookie::Key as CookieKey,
    dev::ServerHandle,
    web::{self, Data, JsonConfig, PayloadConfig},
};
use argon2::Argon2;
use ewqwe_credential_verifier_ui::{
    VerifierCredentialVerifier, VerifierJournalProvider, db::DynVerifierUiStore,
    qr_user_map::QrUserMap,
};
use ewqwe_openid4vp::OpenID4VPService;
use std::{
    io,
    sync::{Arc, mpsc},
};
use tracing::info;

use crate::server::verify_endpoint::load_credential_issuer_cas;
use crate::tls::{create_openssl_acceptor, extract_openssl_peer_certificate};

/// Adapts [`DynJournalStore`] to the [`VerifierJournalProvider`] interface required
/// by `ewqwe_credential_verifier_ui`.  This breaks the dependency cycle between the two crates.
struct JournalProviderForVerifier(std::sync::Arc<DynJournalStore>);

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

/// Inner function to start the attestation server asynchronously.
pub async fn start_server(
    server_params: Arc<ServerParams>,
    server_handle_tx: Option<mpsc::Sender<ServerHandle>>,
) -> AttResult<()> {
    // Log the server configuration
    info!("Server configuration: {server_params:#?}");
    // Instantiate and prepare the  server
    let server = prepare_server(server_params.clone()).await?;
    info!(
        "Attestation Provider server listening on {}:{}",
        server_params.host_name, server_params.host_port
    );

    // send the server handle to the caller
    if let Some(tx) = &server_handle_tx {
        tx.send(server.handle())
            .context("failed to send server handle")?;
    }

    // Run the server and return the result
    server
        .await
        .map_err(|e: io::Error| crate::AttError::Unexpected(format!("{e}")))
}

/// Prepares the attestation server with the given parameters and returns the server instance.
async fn prepare_server(params: Arc<ServerParams>) -> AttResult<actix_web::dev::Server> {
    // Determine the address to bind the server to.
    let address = format!("{}:{}", &params.host_name, params.host_port);

    // Initialize OpenID4VP service if configured
    let openid4vp_service: Arc<OpenID4VPService> = Arc::new(
        OpenID4VPService::create(params.openid4vp_config.clone())
            .await
            .map_err(|e| {
                crate::AttError::Config(format!("Failed to initialize OpenID4VP service: {e}"))
            })?,
    );

    // Initialise the verification journal store (when journaling is enabled).
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

    // Initialise the Verifier App user store (when the app is enabled).
    let verifier_ui_store: Option<Arc<DynVerifierUiStore>> = if params.verifier_ui_config.enabled {
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

    // Load and cache credential issuer CAs for verifying incoming credentials.
    let trusted_cas_vec = load_credential_issuer_cas(params.credential_issuer_ca_dir())?;
    let trusted_cas: Arc<Vec<openssl::x509::X509>> = Arc::new(trusted_cas_vec);
    info!(
        dir = %params.credential_issuer_ca_dir(),
        count = trusted_cas.len(),
        "Loaded credential issuer CAs at startup; restart required to reload"
    );

    // Build session cookie key for the Verifier App (only when enabled).
    let verifier_ui_session_key: Option<CookieKey> = if params.verifier_ui_config.enabled {
        let key = if let Some(session_secret) = &params.verifier_ui_config.session_secret {
            if session_secret.len() < 8 {
                return Err(crate::AttError::Config(
                    "verifier_ui.session_secret must be at least 8 characters".to_string(),
                ));
            }
            // derive 64 bytes using argon 2
            let mut derived_key = [0u8; 64];
            // set salt to cargo package version
            let salt = concat!("ewQwe Credential Verifier::", env!("CARGO_PKG_VERSION")).as_bytes();
            Argon2::default()
                .hash_password_into(session_secret.as_bytes(), salt, &mut derived_key)
                .map_err(|e| {
                    AttError::Config(format!(
                        "failed to derive session secret into a session key: {e}"
                    ))
                })?;
            CookieKey::derive_from(&derived_key)
        } else {
            tracing::warn!(
                "verifier_ui.session_secret not set — sessions will be invalidated on \
                 server restart; configure a stable secret for production"
            );
            CookieKey::generate()
        };
        Some(key)
    } else {
        None
    };

    // Create the QR Code APP transaction→user map (shared across all workers).
    let qr_user_map: Arc<QrUserMap> = Arc::new(QrUserMap::new());

    // Build journal provider adapter for the Verifier App (bridges DynJournalStore
    // to the VerifierJournalProvider trait defined in ewqwe_credential_verifier_ui).
    let journal_provider_for_va: Option<Arc<dyn VerifierJournalProvider>> =
        journal_store.as_ref().map(|j| {
            Arc::new(JournalProviderForVerifier(j.clone())) as Arc<dyn VerifierJournalProvider>
        });
    let verifier_ui_config = Arc::new(params.verifier_ui_config.clone());

    // Build in-process credential verifier for the Verifier App QR polling flow.
    // Only constructed when the Verifier App is enabled; otherwise `qr_status`
    // falls back to returning the raw "received" status.
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

    // Clone attestation server params for HttpServer closure
    let server_params = params.clone();
    let ensure_auth = EnsureAuth::new(
        params.disable_authentication,
        params.disabled_authentication_user().to_string(),
    );

    // let default_username = params.default_username.clone();

    // Create the `HttpServer` instance.
    let server = HttpServer::new(move || {
        // Create an `App` instance and configure the passed data and the various scopes
        let app = App::new()
            .app_data(Data::new(server_params.clone())) // Share the attestation server parameters across the app.
            .app_data(PayloadConfig::new(1_000_000)) // Set the maximum size of the request payload.
            .app_data(JsonConfig::default().limit(1_000_000)); // Set the maximum size of the JSON request payload.

        // Optionally share the OpenID4VP service
        let app = app.app_data(Data::new(openid4vp_service.clone()));

        // Share cached credential issuer CAs for verification.
        let app = app.app_data(Data::new(trusted_cas.clone()));

        // Optionally share the journal store
        let app = if let Some(store) = &journal_store {
            app.app_data(Data::new(store.clone()))
        } else {
            app
        };

        // Optionally share the Verifier UI user store
        let app = if let Some(store) = &verifier_ui_store {
            app.app_data(Data::new(store.clone()))
        } else {
            app
        };

        // Share the QR Code APP transaction→user map.
        let app = app.app_data(Data::new(qr_user_map.clone()));

        // Share VerifierApp config for the get_settings endpoint.
        let app = app.app_data(Data::new(verifier_ui_config.clone()));

        // Optionally share the journal provider adapter for the Verifier App.
        let app = if let Some(ref jp) = journal_provider_for_va {
            app.app_data(Data::new(jp.clone()))
        } else {
            app
        };

        // Optionally share the in-process QR credential verifier for the Verifier App.
        let app = if let Some(ref v) = qr_credential_verifier {
            app.app_data(Data::new(v.clone()))
        } else {
            app
        };

        // /version is registered as an explicit resource before actix_files so
        // it is never shadowed by the catch-all Files service.
        let version_route = web::resource("/version").route(web::get().to(version_endpoint));

        let openid4vp_scope = web::scope("/ewqwe_api")
            // ----- Wallet-facing endpoints — no client cert required -----
            .route(
                "/openid4vp/direct_post",
                web::post().to(openid4vp_endpoints::handle_direct_post),
            )
            .route(
                "/openid4vp/request/{id}",
                web::get().to(openid4vp_endpoints::get_authorization_request),
            )
            .route(
                "/openid4vp/request/{id}",
                web::post().to(openid4vp_endpoints::get_authorization_request),
            )
            .route(
                "/openid4vp/.well-known/jwks.json",
                web::get().to(openid4vp_endpoints::get_jwks),
            )
            // ----- RP-facing endpoints — require client cert (SslAuth + EnsureAuth) -----
            .service(
                web::resource("/verify")
                    .wrap(ensure_auth.clone())
                    .wrap(SslAuth)
                    .route(web::post().to(verify_credential_endpoint)),
            )
            .service(
                web::resource("/.well-known/issuer_certs")
                    .wrap(ensure_auth.clone())
                    .wrap(SslAuth)
                    .route(web::get().to(verify_endpoint::issuer_certs_endpoint)),
            )
            .service(
                web::resource("/openid4vp/init")
                    .wrap(ensure_auth.clone())
                    .wrap(SslAuth)
                    .route(web::post().to(openid4vp_endpoints::init_transaction)),
            )
            .service(
                web::resource("/openid4vp/status/{id}")
                    .wrap(ensure_auth.clone())
                    .wrap(SslAuth)
                    .route(web::get().to(openid4vp_endpoints::get_transaction_status)),
            )
            // Journal endpoints — require authentication.
            .service(
                web::resource("/journal/{username}/entries")
                    .wrap(ensure_auth.clone())
                    .wrap(SslAuth)
                    .route(web::get().to(journal_endpoints::list_journal_entries)),
            )
            .service(
                web::resource("/journal/{username}/verify")
                    .wrap(ensure_auth.clone())
                    .wrap(SslAuth)
                    .route(web::get().to(journal_endpoints::verify_journal_chain)),
            )
            .service(
                web::resource("/journal/{username}/download")
                    .wrap(ensure_auth.clone())
                    .wrap(SslAuth)
                    .route(web::get().to(journal_endpoints::download_journal)),
            );

        // Register openid4vp_scope first (most specific prefix /ewqwe_api),
        // then the verifier_ui API scope, then the explicit /version resource,
        // and finally actix_files (catch-all /). Registration order dictates
        // priority — more specific services must come first.
        let app = app.service(openid4vp_scope).service(version_route);

        if let Some(ref session_key) = verifier_ui_session_key {
            let api_scope = web::scope("/api/v1")
                .wrap(IdentityMiddleware::default())
                .wrap(
                    SessionMiddleware::builder(CookieSessionStore::default(), session_key.clone())
                        // Use a unique name to prevent conflicts with any other "id" cookie.
                        .cookie_name("verifier_ui_session".to_string())
                        // Cookie is scoped to "/" so it is sent on every request to
                        // the server (required now that the SPA lives at root).
                        .cookie_path("/".to_string())
                        .build(),
                )
                .configure(ewqwe_credential_verifier_ui::configure_routes);

            let mut app = app.service(api_scope);

            // Serve the Vite-built SPA from the configured dist directory. Must
            // come after all API scopes and the /version resource so it acts as a
            // true catch-all only when nothing more specific matches.
            if let Some(ref dist_path) = server_params.verifier_ui_config.ui_dist_path {
                if std::path::Path::new(dist_path).exists() {
                    app = app
                        .service(actix_files::Files::new("/", dist_path).index_file("index.html"));
                } else {
                    tracing::warn!(
                        path = %dist_path,
                        "Verifier App ui_dist_path not found — SPA will not be served"
                    );
                }
            }

            app
        } else {
            app
        }
    })
    .keep_alive(actix_web::http::KeepAlive::Timeout(
        std::time::Duration::from_secs(120),
    ))
    .client_request_timeout(std::time::Duration::from_secs(10)); // keep 10 seconds timeout for KMIP attestation vectors

    let server = server
        .on_connect(extract_openssl_peer_certificate)
        .bind_openssl(address, create_openssl_acceptor(&params.tls_params)?)
        .map_err(|e| {
            crate::AttError::Config(format!("Failed binding the OpenSSL TLS connector: {e}"))
        })?;

    let server = server.run();

    Ok(server)
}
