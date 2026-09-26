# Install and run the server

This guide builds the credential verifier from source, gives it a minimal configuration, and starts it. When you finish, the server answers requests at `https://127.0.0.1:9443`.

## Prerequisites

- Rust 1.92.0 or later. Check with `rustc --version`.
- A C toolchain, because the OpenSSL dependency is built from source.
- A trusted issuer CA directory. The repository provides one at `certificates/issuers_cas`.

## Steps

1. Build the server. Run the command from the `credential_verifier` directory.

   ```bash
   cd credential_verifier
   cargo build --release
   ```

   The workspace writes the binary to `target/release/credential-verifier` at the repository root.

2. Create the configuration file. Write a file named `credential-server.toml` in the `credential_verifier` directory with the content below. The paths point at the test certificates in this repository, so do not use them in production.

   ```toml
   host_name = "127.0.0.1"
   host_port = 9443
   default_username = "demo-user"
   rust_log = "info"

   credentials_cas_dir = "../certificates/issuers_cas"
   attestation_issuer_certificate = "../certificates/signer/ewqwe.signer.leaf.cert.pem"
   attestation_issuer_key = "../certificates/signer/ewqwe.signer.leaf.key.pem"

   [tls_params]
   server_private_key = "../certificates/tls/ewqwe.server.key.pem"
   server_certificate = "../certificates/tls/ewqwe.server.cert.pem"
   server_ca_chain = "../certificates/tls/ewqwe.ca.pem"
   client_ca_cert_chain = "../certificates/tls/ewqwe.ca.pem"

   [openid4vp_config]
   transaction_ttl_secs = 300

   [openid4vp_config.haip_config]
   x509_cert_path = "../certificates/signer/ewqwe.signer.leaf.fullchain.pem"
   x509_key_path = "../certificates/signer/ewqwe.signer.leaf.key.pem"
   ```

   The table below explains the settings that matter at startup.

| Setting                          | Purpose                                                              |
| :------------------------------- | :------------------------------------------------------------------- |
| `host_name`, `host_port`         | The address and port on which the server listens.                    |
| `credentials_cas_dir`            | The directory of trusted issuer CA certificates. It must exist.      |
| `attestation_issuer_certificate` | The certificate whose common name becomes the `iss` claim.           |
| `attestation_issuer_key`         | The private key that signs the attestations.                         |
| `[tls_params]`                   | The server key, certificate, CA chain, and optional client CA chain. |
| `[openid4vp_config.haip_config]` | The certificate chain and key that sign authorization requests.      |

Most relative paths in the file are resolved against the directory that contains the configuration file, not against the working directory. The SQLite path of the transaction store is the exception, because it is used as given.

3. Start the server. Run the built binary, or use Cargo.

   ```bash
   cargo run --release
   ```

   To use a configuration file at another location, pass its path as the first argument.

   ```bash
   cargo run --release -- /etc/ewqwe/credential-server.toml
   ```

   When you pass no path, the server searches these locations in order and uses the first file that exists.

   1. `./credential-server.toml` in the current directory.
   2. The platform configuration directory: `$HOME/Library/Application Support/ewQwe/Credential Server/config.toml` on macOS, `$XDG_CONFIG_HOME/ewQwe/Credential Server/config.toml` or `$HOME/.config/ewQwe/Credential Server/config.toml` on Linux, and `%APPDATA%\ewQwe\Credential Server\config.toml` on Windows.

4. Read the startup output. The server logs its progress when `rust_log` is set to `info` or higher.

   ```text
   INFO credential_verifier: Starting ewQwe Credential Verifier
   INFO credential_verifier: Loaded configuration from /path/to/credential-server.toml
   INFO credential_verifier: Server will listen on https://127.0.0.1:9443
   INFO ewqwe_openid4vp::service: OpenID4VP service initialized san=<dns-name> ttl_secs=300
   INFO credential_verifier::server::start: Verification journal disabled
   INFO credential_verifier::server::start: Loaded credential issuer CAs at startup; restart required to reload count=<number>
   INFO credential_verifier::server::start: Attestation Provider server listening on 127.0.0.1:9443
   ```

   The server also logs the whole loaded configuration as one structured line at info level. If the log shows a `Credentials issuers CA directory not found` error, the server stops before it binds the port.

5. Check that the server answers. The `/version` endpoint does not require a client certificate.

   ```bash
   curl -sk https://localhost:9443/version
   ```

   Expected output:

   ```json
   { "version": "0.1.0" }
   ```

6. Stop the server with `Ctrl+C`. The server logs `Server shut down gracefully`.

## Troubleshooting

- **The server stops with `No configuration file found. Searched: ...`.** Create `credential-server.toml` in the current directory, or pass an explicit path as the first argument.
- **The server stops with `Credentials issuers CA directory not found`.** Create the directory named by `credentials_cas_dir`, or point the setting at an existing directory. An empty directory is valid, but then no issuer is trusted.
- **The server stops with `Failed to read server private key file` or a PEM parse error.** Check that each path in `[tls_params]` exists relative to the configuration file, and that the key is in PKCS#8 PEM format.
- **The server stops with `Address already in use`.** Another process holds the port. Change `host_port`, or stop the other process.
- **The server stops while it initialises the transaction store or the journal.** Check the database URL and that the database is reachable. See [configure storage](configure-storage.md).
- **The server starts but ignores a setting.** A misspelled key is silently ignored. Compare the key against the [configuration reference](../../reference/credential-verifier/configuration.md).

## Next steps

- Secure the listener with [configure TLS](configure-tls.md).
- Choose the stores with [configure storage](configure-storage.md).
- Send a request with [verify a credential](verify-a-credential.md).
