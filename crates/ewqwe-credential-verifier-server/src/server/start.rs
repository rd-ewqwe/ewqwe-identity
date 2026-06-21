use crate::{
    AttResult, AttResultHelper,
    parameters::ServerParams,
    server::{
        EnsureAuth, journal_endpoints, openid4vp_endpoints,
        services::ServerComponents,
        verify_endpoint::{self, verify_credential_endpoint, version_endpoint},
    },
    tls::SslAuth,
};
use actix_identity::IdentityMiddleware;
use actix_session::{SessionMiddleware, storage::CookieSessionStore};
use actix_web::{
    App, HttpServer,
    dev::ServerHandle,
    web::{self, Data},
};
use std::{
    io,
    sync::{Arc, mpsc},
};
use tracing::info;

use crate::tls::{create_openssl_acceptor, extract_openssl_peer_certificate};

/// Inner function to start the attestation server asynchronously.
pub async fn start_server(
    server_params: Arc<ServerParams>,
    server_handle_tx: Option<mpsc::Sender<ServerHandle>>,
) -> AttResult<()> {
    // Log the server configuration
    info!("Server configuration: {server_params:#?}");

    // Create all shared application state
    let components = ServerComponents::create(&server_params).await?;
    info!("Server components created");

    // Instantiate and prepare the server
    let server = prepare_server(server_params.clone(), components).await?;
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

/// Build the actix-web server from parameters and pre-built components.
async fn prepare_server(
    params: Arc<ServerParams>,
    components: ServerComponents,
) -> AttResult<actix_web::dev::Server> {
    let address = format!("{}:{}", &params.host_name, params.host_port);

    let server_params = params.clone();
    let ensure_auth = EnsureAuth::new(
        params.disable_authentication,
        params.disabled_authentication_user().to_string(),
    );

    let verifier_ui_session_key = components.verifier_ui_session_key.clone();
    let openid4vp_service = components.openid4vp_service.clone();
    let trusted_cas = components.trusted_cas.clone();
    let journal_store = components.journal_store.clone();
    let verifier_ui_store = components.verifier_ui_store.clone();
    let qr_user_map = components.qr_user_map.clone();
    let verifier_ui_config = components.verifier_ui_config.clone();
    let journal_provider_for_va = components.journal_provider_for_va.clone();
    let qr_credential_verifier = components.qr_credential_verifier.clone();

    // Create the `HttpServer` instance.
    let server = HttpServer::new(move || {
        let mut app = App::new()
            .wrap(super::request_tracing_middleware::RequestTracing)
            .app_data(Data::new(server_params.clone()))
            .app_data(Data::new(openid4vp_service.clone()))
            .app_data(Data::new(trusted_cas.clone()));

        if let Some(ref store) = journal_store {
            app = app.app_data(Data::new(store.clone()));
        }
        if let Some(ref store) = verifier_ui_store {
            app = app.app_data(Data::new(store.clone()));
        }

        app = app.app_data(Data::new(qr_user_map.clone()));
        app = app.app_data(Data::new(verifier_ui_config.clone()));

        if let Some(ref jp) = journal_provider_for_va {
            app = app.app_data(Data::new(jp.clone()));
        }
        if let Some(ref v) = qr_credential_verifier {
            app = app.app_data(Data::new(v.clone()));
        }

        // Build the OpenID4VP scope with auth middleware
        let openid4vp_scope = web::scope("/ewqwe_api")
            // Wallet-facing endpoints — no auth required
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
            .route(
                "/dc_api/verify",
                web::post().to(super::dc_api_endpoint::verify_dc_api),
            )
            .route(
                "/dc_api/nonce",
                web::get().to(super::dc_api_endpoint::generate_nonce),
            )
            // RP-facing endpoints — require authentication
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

        let version_route = web::resource("/version").route(web::get().to(version_endpoint));

        let mut app = app.service(openid4vp_scope).service(version_route);

        // Verifier App UI (with session middleware)
        if let Some(ref session_key) = verifier_ui_session_key {
            let api_scope = web::scope("/api/v1")
                .wrap(IdentityMiddleware::default())
                .wrap(
                    SessionMiddleware::builder(CookieSessionStore::default(), session_key.clone())
                        .cookie_name("verifier_ui_session".to_string())
                        .cookie_path("/".to_string())
                        .build(),
                )
                .configure(ewqwe_credential_verifier_ui::configure_routes);

            app = app.service(api_scope);

            if let Some(ref dist_path) = server_params.verifier_ui_config.ui_dist_path {
                if std::path::Path::new(dist_path).exists() {
                    app = app
                        .service(actix_files::Files::new("/", dist_path).index_file("index.html"));
                } else {
                    tracing::trace!(
                        path = %dist_path,
                        "Verifier App ui_dist_path not found — SPA will not be served"
                    );
                }
            }
        }

        app
    })
    .keep_alive(actix_web::http::KeepAlive::Timeout(
        std::time::Duration::from_secs(120),
    ))
    .client_request_timeout(std::time::Duration::from_secs(10));

    Ok(if let Some(tls_params) = &params.tls_params {
        let server = server
            .on_connect(extract_openssl_peer_certificate)
            .bind_openssl(address, create_openssl_acceptor(tls_params)?)
            .map_err(|e| {
                crate::AttError::Config(format!("Failed binding the OpenSSL TLS connector: {e}"))
            })?;
        server.run()
    } else {
        let server = server
            .bind(address)
            .map_err(|e| crate::AttError::Config(format!("Failed binding the server: {e}")))?;
        server.run()
    })
}
