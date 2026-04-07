use crate::{
    AttResult, AttResultHelper,
    server::{AttServerParams, endpoints::version_endpoint},
};
use actix_cors::Cors;
use actix_identity::IdentityMiddleware;
use actix_session::{
    SessionMiddleware,
    config::PersistentSession,
    storage::{RedisSessionStore /* RedisSessionStore */},
};
use actix_web::{
    App, HttpServer,
    cookie::{Key, time::Duration},
    dev::ServerHandle,
    web::{self, Data, JsonConfig, PayloadConfig},
};
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

    info!("Starting the HTTPS Attestation Provider server...");

    // Run the server and return the result
    server
        .await
        .map_err(|e: io::Error| crate::AttError::Unexpected(format!("{e}")))
}

/// Prepares the attestation server with the given parameters and returns the server instance.
async fn prepare_server(params: Arc<AttServerParams>) -> AttResult<actix_web::dev::Server> {
    // Determine the address to bind the server to.
    let address = format!("{}:{}", &params.host_name, params.host_port);

    // Generate key for actix session cookie encryption and elements for UI exposure
    let secret_key: Key = Key::generate();

    let storage = RedisSessionStore::new("redis://127.0.0.1:6379")
        .await
        .expect("failed to create Redis session store");

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

        // The default scope serves from the root / the KMIP, permissions, and TEE endpoints
        let default_scope = web::scope("")
            // .app_data(Data::new(privileged_users.clone()))
            .wrap(IdentityMiddleware::default())
            .wrap(
                SessionMiddleware::builder(storage.clone(), secret_key.clone())
                    .session_lifecycle(
                        PersistentSession::default().session_ttl(Duration::hours(24)),
                    )
                    .build(),
            )
            .wrap(Cors::permissive())
            .route("/version", web::get().to(version_endpoint));

        #[cfg(test)]
        let default_scope = default_scope.route(
            "/authenticate",
            web::get().to(crate::tests::mock_authenticate_endpoint),
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
