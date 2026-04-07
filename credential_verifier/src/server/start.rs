use crate::{
    AttError, AttResult, AttResultHelper,
    journal::{DynJournalStore, JournalStore},
    parameters::ServerParams,
    server::{
        EnsureAuth, journal_endpoints, openid4vp_endpoints,
        verify_endpoint::{self, verify_credential_endpoint, version_endpoint},
    },
    tls::SslAuth,
};
use actix_cors::Cors;
use actix_identity::IdentityMiddleware;
use actix_session::{SessionMiddleware, storage::CookieSessionStore};
use actix_web::{
    App, HttpServer,
    cookie::Key as CookieKey,
    dev::ServerHandle,
    web::{self, Data, JsonConfig, PayloadConfig},
};
use argon2::Argon2;
use ewqwe_openid4vp::OpenID4VPService;
use ewqwe_verifier_app::{
    VerifierJournalProvider, db::DynVerifierAppStore, qr_user_map::QrUserMap,
};
use std::{
    io,
    sync::{Arc, mpsc},
};
use tracing::info;

use crate::server::verify_endpoint::load_credential_issuer_cas;
use crate::tls::{create_openssl_acceptor, extract_openssl_peer_certificate};

/// Adapts [`DynJournalStore`] to the [`VerifierJournalProvider`] interface required
/// by `ewqwe_verifier_app`.  This breaks the dependency cycle between the two crates.
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
                    .iter()
                    .map(|e| serde_json::to_value(e).unwrap_or_default())
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
    let verifier_app_store: Option<Arc<DynVerifierAppStore>> = if params.verifier_app_config.enabled
    {
        let store = DynVerifierAppStore::new(&params.verifier_app_config)
            .await
            .map_err(|e| {
                crate::AttError::Config(format!("Failed to initialise Verifier App store: {e}"))
            })?;
        info!(
            "Verifier App store enabled (backend: {:?})",
            params.verifier_app_config.db
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
    let verifier_app_session_key: Option<CookieKey> = if params.verifier_app_config.enabled {
        let key = if let Some(session_secret) = &params.verifier_app_config.session_secret {
            if session_secret.len() < 8 {
                return Err(crate::AttError::Config(
                    "verifier_app.session_secret must be at least 8 characters".to_string(),
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
                "verifier_app.session_secret not set — sessions will be invalidated on \
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
    // to the VerifierJournalProvider trait defined in ewqwe_verifier_app).
    let journal_provider_for_va: Option<Arc<dyn VerifierJournalProvider>> =
        journal_store.as_ref().map(|j| {
            Arc::new(JournalProviderForVerifier(j.clone())) as Arc<dyn VerifierJournalProvider>
        });
    let verifier_app_config = Arc::new(params.verifier_app_config.clone());

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

        // Optionally share the Verifier App user store
        let app = if let Some(store) = &verifier_app_store {
            app.app_data(Data::new(store.clone()))
        } else {
            app
        };

        // Share the QR Code APP transaction→user map.
        let app = app.app_data(Data::new(qr_user_map.clone()));

        // Share VerifierApp config for the get_settings endpoint.
        let app = app.app_data(Data::new(verifier_app_config.clone()));

        // Optionally share the journal provider adapter for the Verifier App.
        let app = if let Some(ref jp) = journal_provider_for_va {
            app.app_data(Data::new(jp.clone()))
        } else {
            app
        };

        // The default scope serves from the root / the KMIP, permissions, and TEE endpoints
        let default_scope = web::scope("")
            .wrap(
                Cors::default()
                    .allow_any_origin()
                    .allowed_methods(vec!["GET", "POST", "OPTIONS"])
                    .allowed_headers(vec!["Content-Type", "Authorization"])
                    .max_age(3600),
            )
            .route("/version", web::get().to(version_endpoint));

        let openid4vp_scope = web::scope("/ewqwe_api")
            .wrap(ensure_auth.clone())
            .wrap(SslAuth)
            .service(web::resource("/verify").route(web::post().to(verify_credential_endpoint)))
            .route(
                "/.well-known/issuer_certs",
                web::get().to(verify_endpoint::issuer_certs_endpoint),
            )
            .route(
                "/openid4vp/init",
                web::post().to(openid4vp_endpoints::init_transaction),
            )
            .route(
                "/openid4vp/status/{id}",
                web::get().to(openid4vp_endpoints::get_transaction_status),
            )
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
            // Journal endpoints — use shared authentication pipeline.
            .service(
                web::resource("/journal/{username}/entries")
                    .route(web::get().to(journal_endpoints::list_journal_entries)),
            )
            .service(
                web::resource("/journal/{username}/verify")
                    .route(web::get().to(journal_endpoints::verify_journal_chain)),
            )
            .service(
                web::resource("/journal/{username}/download")
                    .route(web::get().to(journal_endpoints::download_journal)),
            );

        // Register openid4vp_scope first (most specific prefix /ewqwe_api).
        // verifier_app_scope must come before default_scope: default_scope uses an
        // empty prefix ("") which actix-web matches for *every* path; if it is
        // registered first, requests to /verifier_app/* are absorbed by default_scope
        // and never reach the verifier_app scope.
        let app = app.service(openid4vp_scope);

        let app = if let Some(ref session_key) = verifier_app_session_key {
            let verifier_app_scope = web::scope("/verifier_app")
                .wrap(IdentityMiddleware::default())
                .wrap(
                    SessionMiddleware::builder(CookieSessionStore::default(), session_key.clone())
                        // Use a unique name to prevent conflicts with any other "id" cookie
                        // that may be stored at Path=/ from a previous run or other middleware.
                        .cookie_name("verifier_app_session".to_string())
                        // Scope the cookie to this sub-path so it is only sent to
                        // /verifier_app/* requests and is never confused with cookies
                        // from other scopes.
                        .cookie_path("/verifier_app".to_string())
                        .build(),
                )
                .configure(ewqwe_verifier_app::configure_routes);
            app.service(verifier_app_scope)
        } else {
            app
        };

        app.service(default_scope)
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
