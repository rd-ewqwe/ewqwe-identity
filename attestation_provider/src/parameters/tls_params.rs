use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct TlsParams {
    /// The file containing the server TLS key in PKCS#8 PEM format
    /// Defaults to "certificates/hei.server.key.pem"
    pub server_private_key: String,

    /// The file containing the server TLS certificate in a PEM format
    /// Defaults to "certificates/hei.server.cert.pem"
    pub server_certificate: String,

    /// The file containing the TLS CA chain of certificates in a PEM format
    /// Defaults to "certificates/hei.server.ca.chain.pem"
    pub server_ca_chain: String,

    /// The server's optional X. 509 certificates chain in PEM format
    /// that validates the client certificate presented for authentication.
    /// If not provided, the TLS CA certificate chain will be used.
    pub client_ca_cert_chain: Option<String>,

    /// Colon-separated list of TLS cipher suites to enable:
    /// Example: --tls-cipher-suites `"TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256"`
    /// If not specified, OpenSSL default cipher suites will be used:
    /// ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:\
    /// ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:\
    /// DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:\
    /// ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA384:\
    /// ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:\
    /// DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-DES-CBC3-SHA:\
    /// EDH-RSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:\
    /// AES256-SHA:DES-CBC3-SHA:!DSS"
    /// Otherwise, ANSSI-recommended cipher suites (RFC 8446 compliant) are:
    /// - For TLS 1.3 (preferred): `TLS_AES_256_GCM_SHA384`, `TLS_AES_128_GCM_SHA256`, `TLS_CHACHA20_POLY1305_SHA256`, `TLS_AES_128_CCM_SHA256`, `TLS_AES_128_CCM_8_SHA256`
    /// - For TLS 1.2 (compatibility): `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`, `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`,
    ///   `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256`, `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`,
    ///   `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`, `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256`
    pub tls_cipher_suites: Option<String>,
}
