use crate::error::AttError;
use crate::error::AttResult;
use crate::parameters::TlsParams;
use openssl::pkey::PKey;
use openssl::{
    ssl::{SslAcceptor, SslAcceptorBuilder, SslMethod, SslVerifyMode, SslVersion},
    x509::{X509, store::X509StoreBuilder},
};
use tracing::{info, trace};
/// The extension struct holding the peer certificate during the connection.
///
/// This struct stores the peer certificate in the request context.
#[derive(Debug, Clone)]
pub struct PeerCertificate {
    /// The peer certificate.
    pub cert: X509,
}

// TLS 1.3 cipher suites as defined in RFC 8446
pub const TLS13_CIPHER_SUITES: &[&str] = &[
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_CCM_SHA256",
    "TLS_AES_128_CCM_8_SHA256",
];

/// Create and configure an OpenSSL `SslAcceptorBuilder` from HEI TLS settings.
///
/// This function:
/// - builds an `SslAcceptorBuilder` with either default or custom cipher
///   suites based on [`TlsParams::tls_cipher_suites`],
/// - loads the server private key, certificate and certificate chain from
///   the configured PEM files,
/// - configures mutual TLS by setting the CA certificates used to verify
///   client certificates,
/// - enables client-certificate verification according to the provided CA
///   chain.
///
/// The resulting acceptor builder is ready to be bound to a TLS listener
/// by the HTTP server.
///
/// Errors indicate invalid TLS configuration, missing or malformed key or
/// certificate files, or OpenSSL configuration failures.
pub fn create_openssl_acceptor(tls_config: &TlsParams) -> AttResult<SslAcceptorBuilder> {
    // Configure cipher suites
    let mut builder = configure_cipher_suites(tls_config.tls_cipher_suites.as_ref())?;

    let server_private_key_pem = std::fs::read_to_string(&tls_config.server_private_key)
        .map_err(|e| AttError::Config(format!("Failed to read server private key file: {e}")))?;
    let server_private_key = PKey::private_key_from_pem(server_private_key_pem.as_bytes())
        .map_err(|e| {
            AttError::Config(format!("Failed to load server private key from PEM: {e}"))
        })?;
    builder.set_private_key(&server_private_key).map_err(|e| {
        AttError::Config(format!(
            "Failed to set server private key in SslAcceptorBuilder: {e}"
        ))
    })?;

    let server_cert_pem = std::fs::read_to_string(&tls_config.server_certificate)
        .map_err(|e| AttError::Config(format!("Failed to read server certificate file: {e}")))?;
    let server_cert = X509::from_pem(server_cert_pem.as_bytes()).map_err(|e| {
        AttError::Config(format!("Failed to load server certificate from PEM: {e}"))
    })?;

    let server_ca_chain_pem = std::fs::read_to_string(&tls_config.server_ca_chain)
        .map_err(|e| AttError::Config(format!("Failed to read server CA chain file: {e}")))?;
    let server_ca_chain = X509::stack_from_pem(server_ca_chain_pem.as_bytes()).map_err(|e| {
        AttError::Config(format!(
            "Failed to load server certificate chain from PEM: {e}"
        ))
    })?;

    builder.set_certificate(&server_cert).map_err(|e| {
        AttError::Config(format!(
            "Failed to set server certificate in SslAcceptorBuilder: {e}"
        ))
    })?;

    // Add CA certificates from the PKCS#12 chain
    for cert in &server_ca_chain {
        builder.add_extra_chain_cert(cert.clone()).map_err(|e| {
            AttError::Config(format!(
                "Failed to add certificate to server CA chain in SslAcceptorBuilder: {e}"
            ))
        })?;
    }

    // Configure client certificate verification if CA certs are provided
    let client_ca_cert_chain = if let Some(ca_cert_chain) = &tls_config.client_ca_cert_chain {
        let ca_cert_chain = std::fs::read(ca_cert_chain).map_err(|e| {
            AttError::Config(format!(
                "Failed to read client CA certificate chain file: {e}"
            ))
        })?;
        X509::stack_from_pem(ca_cert_chain.as_slice()).map_err(|e| {
            AttError::Config(format!(
                "Failed to load client CA certificate chain from PEM: {e}"
            ))
        })?
    } else {
        server_ca_chain
    };
    for c in &client_ca_cert_chain {
        info!("Client CA cert subject: {:?}", c.subject_name());
    }

    configure_client_cert_verification(&mut builder, client_ca_cert_chain.as_slice())?;

    Ok(builder)
}

/// Configure cipher suites and protocol versions for the SSL acceptor.
///
/// Depending on whether a custom cipher string is provided:
/// - with a custom string, it parses TLS 1.2 and TLS 1.3 cipher suites,
///   sets appropriate minimum protocol versions, and applies the selected
///   suites to the builder;
/// - without a custom string, it uses the Mozilla "intermediate" profile
///   and enforces TLS 1.2–1.3 as the supported protocol range.
///
/// The function returns an `SslAcceptorBuilder` with cipher and protocol
/// settings applied, or a configuration error if OpenSSL rejects the
/// requested parameters.
fn configure_cipher_suites(cipher_suites: Option<&String>) -> AttResult<SslAcceptorBuilder> {
    let builder = if let Some(suites) = cipher_suites {
        trace!("configure_cipher_suites: Setting custom cipher string: {suites}");

        // See the doc at: https://wiki.mozilla.org/Security/Server_Side_TLS
        // This forces the use of certificates on the P-256 curve (no RSA)
        let mut builder = SslAcceptor::mozilla_modern_v5(SslMethod::tls()).map_err(|e| {
            AttError::Config(format!(
                "Failed to create SslAcceptorBuilder with mozilla_modern_v5: {e}",
            ))
        })?;

        // Helper function to check if a cipher suite is TLS 1.3
        let is_tls13_cipher = |cipher: &str| -> bool { TLS13_CIPHER_SUITES.contains(&cipher) };

        // Parse and configure cipher suites
        let (tls13_ciphers, tls12_ciphers): (Vec<&str>, Vec<&str>) = suites
            .split(':')
            .filter(|s| !s.trim().is_empty())
            .partition(|&cipher| is_tls13_cipher(cipher));

        if !tls12_ciphers.is_empty() {
            builder
                .set_min_proto_version(Some(SslVersion::TLS1_2))
                .map_err(|e| {
                    AttError::Config(format!(
                        "Failed to set minimum protocol version to TLS 1.2: {e}"
                    ))
                })?;
            builder
                .set_cipher_list(&tls12_ciphers.join(":"))
                .map_err(|e| AttError::Config(format!("Failed to set TLS 1.2 cipher list: {e}")))?;
        }

        if !tls13_ciphers.is_empty() {
            if tls12_ciphers.is_empty() {
                builder
                    .set_min_proto_version(Some(SslVersion::TLS1_3))
                    .map_err(|e| {
                        AttError::Config(format!(
                            "Failed to set minimum protocol version to TLS 1.3: {e}"
                        ))
                    })?;
            }
            builder
                .set_ciphersuites(&tls13_ciphers.join(":"))
                .map_err(|e| {
                    AttError::Config(format!("Failed to set TLS 1.3 cipher suites: {e}"))
                })?;
        }
        builder
    } else {
        let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).map_err(|e| {
            AttError::Config(format!(
                "Failed to create SslAcceptorBuilder with mozilla_intermediate_v5: {e}"
            ))
        })?;
        trace!("configure_cipher_suites: Enable default cipher suites (mozilla_intermediate_v5)");
        builder
            .set_min_proto_version(Some(SslVersion::TLS1_2))
            .map_err(|e| {
                AttError::Config(format!(
                    "Failed to set minimum protocol version to TLS 1.2: {e}"
                ))
            })?;
        builder
            .set_max_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|e| {
                AttError::Config(format!(
                    "Failed to set maximum protocol version to TLS 1.3: {e}"
                ))
            })?;
        builder
    };
    Ok(builder)
}

/// Configure verification of client certificates for mutual TLS.
///
/// This function:
/// - builds an `X509` certificate store from the provided CA certificates,
/// - attaches the store to the `SslAcceptorBuilder`,
/// - enforces verification of peer certificates and rejects connections
///   that do not present a valid client certificate.
///
/// It is used to ensure that only clients with certificates issued by the
/// trusted CAs can establish TLS connections.
pub(crate) fn configure_client_cert_verification(
    builder: &mut SslAcceptorBuilder,
    ca_cert_pem: &[X509],
) -> AttResult<()> {
    // Load the CA certificates for client verification

    let mut store_builder = X509StoreBuilder::new().map_err(|e| {
        AttError::Config(format!(
            "Failed to create X509StoreBuilder for client certificate verification: {e}"
        ))
    })?;

    // Add all CA certificates to the store
    for ca_cert in ca_cert_pem {
        store_builder.add_cert(ca_cert.to_owned()).map_err(|e| {
            AttError::Config(format!(
                "Failed to add CA certificate to X509StoreBuilder: {e}"
            ))
        })?;
    }

    let ca_store = store_builder.build();

    builder.set_verify_cert_store(ca_store).map_err(|e| {
        AttError::Config(format!(
            "Failed to set verify cert store in SslAcceptorBuilder: {e}"
        ))
    })?;
    // Request the client certificates only, do not require them
    builder.set_verify(SslVerifyMode::PEER);

    Ok(())
}
