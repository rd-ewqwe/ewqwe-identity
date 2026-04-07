use crate::{
    AuthResult, AuthResultHelper,
    server::{AuthServerParams, endpoints::version_endpoint},
};
use actix_cors::Cors;
use actix_identity::IdentityMiddleware;
use actix_session::{SessionMiddleware, storage::RedisSessionStore};
use actix_web::{
    App, HttpServer,
    cookie::Key,
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

/// Inner function to start the test server asynchronously.
pub async fn start_auth_server(
    server_params: Arc<AuthServerParams>,
    _server_handle_tx: Option<mpsc::Sender<ServerHandle>>,
) -> AuthResult<()> {
    // Log the server configuration
    info!(" Server configuration: {server_params:#?}");
    // Instantiate and prepare the  server
    let server = prepare_test_server(server_params).await?;

    // send the server handle to the caller
    if let Some(tx) = &_server_handle_tx {
        tx.send(server.handle())
            .context("failed to send server handle")?;
    }

    info!("Starting the HTTPS Velo test server...");

    // Run the server and return the result
    server
        .await
        .map_err(|e: io::Error| crate::AuthError::Unexpected(format!("{e}")))
}

/// Prepares the test server with the given parameters and returns the server instance.
async fn prepare_test_server(params: Arc<AuthServerParams>) -> AuthResult<actix_web::dev::Server> {
    // Determine the address to bind the server to.
    let address = format!("{}:{}", &params.host_name, params.host_port);

    // Generate key for actix session cookie encryption and elements for UI exposure
    let secret_key: Key = Key::generate();

    let storage = RedisSessionStore::new("redis://127.0.0.1:6379")
        .await
        .expect("failed to create Redis session store");

    // Clone test server params for HttpServer closure
    let server_params = params.clone();

    // let default_username = params.default_username.clone();

    // Create the `HttpServer` instance.
    let server = HttpServer::new(move || {
        // Create an `App` instance and configure the passed data and the various scopes
        let app = App::new()
            .app_data(Data::new(server_params.clone())) // Share the test server parameters across the app.
            .app_data(PayloadConfig::new(1_000_000)) // Set the maximum size of the request payload.
            .app_data(JsonConfig::default().limit(1_000_000)); // Set the maximum size of the JSON request payload.

        // The default scope serves from the root / the KMIP, permissions, and TEE endpoints
        let default_scope = web::scope("")
            // .app_data(Data::new(privileged_users.clone()))
            .wrap(IdentityMiddleware::default())
            .wrap(
                SessionMiddleware::builder(storage.clone(), secret_key.clone())
                    // .session_lifecycle(
                    //     PersistentSession::default().session_ttl(Duration::hours(24)),
                    // )
                    .build(),
            )
            .wrap(Cors::permissive())
            .route("/version", web::get().to(version_endpoint));

        app.service(default_scope)
    })
    .keep_alive(actix_web::http::KeepAlive::Timeout(
        std::time::Duration::from_secs(120),
    ))
    .client_request_timeout(std::time::Duration::from_secs(10)); // keep 10 seconds timeout for KMIP test vectors

    #[cfg(feature = "openssl")]
    let server = server
        .on_connect(extract_openssl_peer_certificate)
        .bind_openssl(address, create_openssl_acceptor(&params.tls_params)?)
        .map_err(|e| {
            crate::AuthError::AuthServer(format!("Failed binding the OpenSSL TLS connector: {e}"))
        })?;

    #[cfg(feature = "rustls")]
    let server = server
        .on_connect(extract_rustls_peer_certificate)
        .bind_rustls_0_23(address, rustls_server_config(&params.tls_params)?)
        .map_err(|e| {
            crate::AuthError::AuthServer(format!("Failed binding the Rustls TLS connector: {e}"))
        })?;

    let server = server.run();

    Ok(server)
}
