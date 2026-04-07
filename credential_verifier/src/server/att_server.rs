use crate::{
    AttResult, AttResultHelper,
    server::{
        AttServerParams,
        endpoints::{verify_credential_endpoint, version_endpoint},
        openid4vp_endpoints,
    },
};
use actix_cors::Cors;
use actix_web::{
    App, HttpServer,
    dev::ServerHandle,
    web::{self, Data, JsonConfig, PayloadConfig},
};
use ewqwe_openid4vp::OpenID4VPService;
use std::{
    io,
    sync::{Arc, mpsc},
};
use tracing::info;

#[cfg(feature = "openssl")]
use crate::tls::openssl_config::{create_openssl_acceptor, extract_openssl_peer_certificate};

/// Inner function to start the attestation server asynchronously.
pub async fn start_att_server(
    server_params: Arc<AttServerParams>,
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
async fn prepare_server(params: Arc<AttServerParams>) -> AttResult<actix_web::dev::Server> {
    // Determine the address to bind the server to.
    let address = format!("{}:{}", &params.host_name, params.host_port);

    // Initialize OpenID4VP service if configured
    let openid4vp_service: Arc<OpenID4VPService> = Arc::new(
        OpenID4VPService::create(params.openid4vp_config.clone()).map_err(|e| {
            crate::AttError::Config(format!("Failed to initialize OpenID4VP service: {e}"))
        })?,
    );

    // Clone attestation server params for HttpServer closure
    let server_params = params.clone();

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

        // The default scope serves from the root / the KMIP, permissions, and TEE endpoints
        let default_scope = web::scope("")
            .wrap(
                Cors::default()
                    .allow_any_origin()
                    .allowed_methods(vec!["GET", "POST", "OPTIONS"])
                    .allowed_headers(vec!["Content-Type", "Authorization"])
                    .max_age(3600),
            )
            .route("/version", web::get().to(version_endpoint))
            .route("/api/verify", web::post().to(verify_credential_endpoint))
            .route(
                "/api/openid4vp/init",
                web::post().to(openid4vp_endpoints::init_transaction),
            )
            .route(
                "/api/openid4vp/status/{id}",
                web::get().to(openid4vp_endpoints::get_transaction_status),
            )
            .route(
                "/api/openid4vp/direct_post",
                web::post().to(openid4vp_endpoints::handle_direct_post),
            )
            .route(
                "/api/openid4vp/request/{id}",
                web::get().to(openid4vp_endpoints::get_authorization_request),
            )
            .route(
                "/api/openid4vp/request/{id}",
                web::post().to(openid4vp_endpoints::get_authorization_request),
            )
            .route(
                "/api/openid4vp/.well-known/jwks.json",
                web::get().to(openid4vp_endpoints::get_jwks),
            );

        app.service(default_scope)
    })
    .keep_alive(actix_web::http::KeepAlive::Timeout(
        std::time::Duration::from_secs(120),
    ))
    .client_request_timeout(std::time::Duration::from_secs(10)); // keep 10 seconds timeout for KMIP attestation vectors

    #[cfg(feature = "openssl")]
    let server = server
        .on_connect(extract_openssl_peer_certificate)
        .bind_openssl(address, create_openssl_acceptor(&params.tls_params)?)
        .map_err(|e| {
            crate::AttError::Config(format!("Failed binding the OpenSSL TLS connector: {e}"))
        })?;

    #[cfg(feature = "rustls")]
    let server = server
        .on_connect(extract_rustls_peer_certificate)
        .bind_rustls_0_23(address, rustls_server_config(&params.tls_params)?)
        .map_err(|e| {
            crate::AttError::Config(format!("Failed binding the Rustls TLS connector: {e}"))
        })?;

    let server = server.run();

    Ok(server)
}
