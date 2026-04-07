use crate::{HeiError, TlsConfig};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use std::sync::Arc;

pub(crate) fn rustls_server_config(tls_config: &TlsConfig) -> Result<ServerConfig, HeiError> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_e| {
            HeiError::Config(
                "Failed to install AWS-LC-Rust as the default crypto provider".to_owned(),
            )
        })?;

    let mut cert_store = RootCertStore::empty();

    // import Clients CA cert
    for der in CertificateDer::pem_file_iter(
        tls_config
            .client_ca_cert_chain
            .clone()
            .unwrap_or_else(|| tls_config.server_ca_chain.to_string()),
    )
    .map_err(|e| {
        HeiError::Config(format!(
            "Failed to read client CA certificate chain from PEM: {e}"
        ))
    })?
    .flatten()
    {
        cert_store.add(der)?;
    }

    // set up client authentication requirements
    let client_auth = WebPkiClientVerifier::builder(Arc::new(cert_store))
        .allow_unknown_revocation_status()
        .build()
        .map_err(|e| HeiError::Config(format!("Failed to create WebPkiClientVerifier: {e}")))?;

    // import server cert and key
    let key_der = PrivateKeyDer::from_pem_file(&tls_config.server_private_key).map_err(|e| {
        HeiError::Config(format!("Failed to read server private key from PEM: {e}"))
    })?;
    let mut cert_chain: Vec<CertificateDer> =
        CertificateDer::pem_file_iter(&tls_config.server_ca_chain)
            .map_err(|e| {
                HeiError::Config(format!(
                    "Failed to read server certificate chain from PEM: {e}"
                ))
            })?
            .flatten()
            .collect();

    let server_cert =
        CertificateDer::from_pem_file(&tls_config.server_certificate).map_err(|e| {
            HeiError::Config(format!("Failed to read server certificate from PEM: {e}"))
        })?;
    cert_chain.insert(0, server_cert);

    let server_config = ServerConfig::builder()
        .with_client_cert_verifier(client_auth)
        .with_single_cert(cert_chain, key_der)?;

    Ok(server_config)
}

/// Extract the peer certificate from the TLS stream and pass it to middleware.
///
/// This function extracts the peer certificate from the TLS stream and passes it to the middleware.
/// The middleware can then use the peer certificate to authenticate the client.
#[cfg(feature = "rustls")]
pub(crate) fn extract_rustls_peer_certificate(cnx: &dyn Any, extensions: &mut Extensions) {
    // Check if the connection is a TLS connection.
    info!("Extracting peer certificate from connection...{:#?}", cnx);
    if let Some(tls_socket) = cnx
        .downcast_ref::<actix_tls::accept::rustls_0_23::TlsStream<actix_web::rt::net::TcpStream>>()
    {
        info!("Extracting peer certificate from TLS connection...");
        let (_socket, tls_session) = tls_socket.get_ref();
        if let Some(certs) = tls_session.peer_certificates() {
            // insert a `rustls::Certificate` into request extensions`
            if let Some(cert) = certs.last() {
                info!("A client certificate was found");
                let Ok(openssl_cert) = X509::from_der(cert.as_ref()).map_err(|_| {
                    HeiError::Authentication("Failed to parse client certificate".to_owned())
                }) else {
                    error!("Failed to parse client certificate");
                    return;
                };
                extensions.insert(PeerCertificate { cert: openssl_cert });
            } else {
                error!("No client certificate found");
            }
        }
    } else if let Some(cnx) = cnx.downcast_ref::<TcpStream>() {
        error!("Not a TLS connection: {:?}", cnx.peer_addr());
    } else {
        error!("Unknown connection type: {:?}", cnx);
    }
}
