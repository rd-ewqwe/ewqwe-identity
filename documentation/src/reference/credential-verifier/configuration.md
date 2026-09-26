# Credential verifier configuration

The credential verifier reads one TOML configuration file at startup. This page lists every configuration key, its type, its default, and its effect.

## Configuration file discovery

The server searches for the configuration file in two locations, in this order.

| Search order | Location                                                   |
| :----------- | :--------------------------------------------------------- |
| 1            | `credential-server.toml` in the current working directory. |
| 2            | `config.toml` in the platform configuration directory.     |

The platform configuration directory depends on the operating system:

| Platform | Directory                                                                               |
| :------- | :-------------------------------------------------------------------------------------- |
| Linux    | `$XDG_CONFIG_HOME/ewQwe/Credential Server/` or `$HOME/.config/ewQwe/Credential Server/` |
| macOS    | `$HOME/Library/Application Support/ewQwe/Credential Server/`                            |
| Windows  | `%APPDATA%\ewQwe\Credential Server\`                                                    |

The server reads the first file that exists. The server stops with a configuration error when it finds no file.

## Relative paths

The server resolves every relative path against the directory that contains the configuration file. An absolute path is used as written.

These keys accept a relative path:

- `tls_params.server_private_key`
- `tls_params.server_certificate`
- `tls_params.server_ca_chain`
- `tls_params.client_ca_cert_chain`
- `openid4vp_config.haip_config.x509_cert_path`
- `openid4vp_config.haip_config.x509_key_path`
- `credentials_cas_dir`
- `attestation_issuer_certificate`
- `attestation_issuer_key`
- `journal_config.path` for the `sqlite_file` backend

## Server parameters

The table below lists the top-level keys of the configuration file.

| Key                              | Type    | Required | Default                         | Description                                                                               |
| :------------------------------- | :------ | :------- | :------------------------------ | :---------------------------------------------------------------------------------------- |
| `host_name`                      | string  | Yes      | —                               | IP address or host name to bind.                                                          |
| `host_port`                      | integer | Yes      | —                               | TCP port to bind.                                                                         |
| `tls_params`                     | table   | Yes      | —                               | TLS listener settings. See [TLS and mutual TLS](./tls-authentication.md).                 |
| `openid4vp_config`               | table   | Yes      | —                               | OpenID4VP service settings.                                                               |
| `default_username`               | string  | No       | —                               | Accepted for compatibility. The server does not read this value.                          |
| `public_root_url`                | string  | No       | —                               | Public base URL of the server.                                                            |
| `credentials_cas_dir`            | string  | No       | `credentials_cas`               | Directory of trusted credential issuer CA files.                                          |
| `attestation_issuer_certificate` | string  | No       | `tls_params.server_certificate` | PEM certificate for attestation signing.                                                  |
| `attestation_issuer_key`         | string  | No       | `tls_params.server_private_key` | PEM private key for attestation signing.                                                  |
| `disable_authentication`         | boolean | No       | `false`                         | Bypass client certificate authentication.                                                 |
| `disabled_authentication_user`   | string  | No       | `test`                          | Username inserted when authentication is disabled.                                        |
| `rust_log`                       | string  | No       | —                               | Log filter string.                                                                        |
| `tracing_config`                 | table   | No       | See below                       | Logging and telemetry settings.                                                           |
| `journal_config`                 | table   | No       | Journal disabled                | Verification journal settings. See [Verification journal](./verification-journal.md).     |
| `verifier_app`                   | table   | No       | App disabled                    | Embedded verifier app. See the [Verifier app](../verifier-app/verifier-app.md) reference. |

The key `verifier_app` accepts the alias `qrcode_app`.

### Public root URL

The `public_root_url` value is the public base URL of the server. The server uses it to build the wallet callback URIs `response_uri` and `request_uri`.

The server chooses the base URL in this order:

| Priority | Source                            |
| :------- | :-------------------------------- |
| 1        | `verifier_app.public_url`         |
| 2        | `public_root_url`                 |
| 3        | The URL inferred from the request |

Set `public_root_url` when the server runs behind a reverse proxy or a NAT, or when the bind address is not reachable by wallets.

### Credential issuer CA directory

The `credentials_cas_dir` value is the directory that holds the trusted credential issuer CA files. The server loads every `*.pem` file in the directory at startup and caches the result. The directory is not reloaded while the server runs, so a restart applies changes.

The default directory is `credentials_cas` next to the configuration file. When the directory holds no PEM file, no issuer CA is trusted and every presentation reports `issuer_trusted = false`.

> [!IMPORTANT]
> The server reads the configuration key `credentials_cas_dir`. The development file `credential_verifier/credential-server.toml` in this repository writes `credential_cas_dir`, which is a different key. The server ignores an unknown key, so the shipped file uses the default directory instead of the configured one.

### Attestation issuer

The `attestation_issuer_certificate` value is the PEM certificate whose public key verifies signed attestation JWTs. The Subject Common Name (CN) of the certificate becomes the `iss` claim. The server publishes the public key and its key identifier at the JWKS endpoint.

The `attestation_issuer_key` value is the PEM private key that signs attestation JWTs. The key must match `attestation_issuer_certificate`.

When both keys are omitted, the server uses `tls_params.server_certificate` and `tls_params.server_private_key`.

### Authentication bypass

The `disable_authentication` value controls the local-development authentication bypass. When the value is `true`, the server does not require a client certificate on the relying-party endpoints. The `disabled_authentication_user` value is the username that the server inserts into the request context in that case. The default username is `test`.

See [TLS and mutual TLS](./tls-authentication.md) for the full authentication behaviour.

> [!WARNING]
> Do not set `disable_authentication = true` in production. The value removes the client certificate requirement from every relying-party endpoint.

## TLS parameters

The `[tls_params]` table configures the TLS listener.

| Key                    | Type   | Required | Default                 | Description                                          |
| :--------------------- | :----- | :------- | :---------------------- | :--------------------------------------------------- |
| `server_private_key`   | string | Yes      | —                       | Server private key in PKCS#8 PEM format.             |
| `server_certificate`   | string | Yes      | —                       | Server X.509 certificate in PEM format.              |
| `server_ca_chain`      | string | Yes      | —                       | CA chain in PEM format.                              |
| `client_ca_cert_chain` | string | No       | `server_ca_chain`       | CA chain that validates client certificates.         |
| `tls_cipher_suites`    | string | No       | Mozilla intermediate v5 | Colon-separated list of TLS cipher suites to enable. |

The full field reference is on the [TLS and mutual TLS](./tls-authentication.md) page.

## OpenID4VP configuration

The `[openid4vp_config]` table configures the OpenID4VP service.

| Key                    | Type    | Required | Default         | Description                                |
| :--------------------- | :------ | :------- | :-------------- | :----------------------------------------- |
| `transaction_ttl_secs` | integer | No       | `300`           | Transaction lifetime in seconds.           |
| `haip_config`          | table   | No       | —               | JAR signing settings for the HAIP profile. |
| `transaction_store`    | table   | No       | `sqlite_memory` | Transaction store backend. See below.      |

When `transaction_ttl_secs` is omitted, the server uses 300 seconds.

### HAIP configuration

The `[openid4vp_config.haip_config]` table enables the HAIP profile. The server ignores the table for non-HAIP profiles.

| Key              | Type   | Required | Description                                                             |
| :--------------- | :----- | :------- | :---------------------------------------------------------------------- |
| `x509_cert_path` | string | Yes      | Certificate chain PEM (leaf first) used to sign authorization requests. |
| `x509_key_path`  | string | Yes      | Private key PEM that signs authorization requests.                      |

The leaf certificate of the chain must carry the DNS subject alternative name (SAN) that the server uses in the `x509_san_dns:` client identifier.

### Transaction store

The `[openid4vp_config.transaction_store]` table selects the backend that stores OpenID4VP transactions.

| `backend` value | Required keys | Persistence | Multi-instance | Notes                                               |
| :-------------- | :------------ | :---------- | :------------- | :-------------------------------------------------- |
| `sqlite_memory` | None          | No          | No             | Default. No file is created.                        |
| `sqlite_file`   | `path`        | Yes         | No             | Persists across restarts.                           |
| `postgres`      | `url`         | Yes         | Yes            | Recommended for high-availability deployments.      |
| `redis`         | `url`         | Yes         | Yes            | Native TTL expiry. Recommended for distributed use. |

| Key    | Type   | Required                   | Description                                  |
| :----- | :----- | :------------------------- | :------------------------------------------- |
| `path` | string | For `sqlite_file`          | Filesystem path to the SQLite database file. |
| `url`  | string | For `postgres` and `redis` | Backend connection URL.                      |

The example below shows all four backends. Uncomment the block that matches the deployment.

```toml
# SQLite in-memory — default, no keys required
[openid4vp_config.transaction_store]
backend = "sqlite_memory"

# SQLite file — single instance with persistence
# [openid4vp_config.transaction_store]
# backend = "sqlite_file"
# path    = "/var/lib/ewqwe/transactions.db"

# PostgreSQL — multi-instance / high availability
# [openid4vp_config.transaction_store]
# backend = "postgres"
# url     = "postgres://ewqwe:ewqwe@localhost/ewqwe"

# Redis — distributed, TTL-native expiry
# [openid4vp_config.transaction_store]
# backend = "redis"
# url     = "redis://127.0.0.1:6379"
```

## Verification journal configuration

The `[journal_config]` table configures the verification journal. The journal is disabled by default.

| Key       | Type    | Required          | Default         | Description                                 |
| :-------- | :------ | :---------------- | :-------------- | :------------------------------------------ |
| `enabled` | boolean | No                | `false`         | Turn journaling on or off.                  |
| `backend` | string  | No                | `sqlite_memory` | Journal storage backend.                    |
| `path`    | string  | For `sqlite_file` | —               | Filesystem path to the SQLite journal file. |
| `url`     | string  | For `postgres`    | —               | PostgreSQL connection URL.                  |

| `backend` value | Persistence | Multi-instance |
| :-------------- | :---------- | :------------- |
| `sqlite_memory` | No          | No             |
| `sqlite_file`   | Yes         | No             |
| `postgres`      | Yes         | Yes            |

See the [Verification journal](./verification-journal.md) page for the entry schema and the journal HTTP API.

## Logging and telemetry

The server configures logging from two sources. The top-level `rust_log` key is a shortcut for the `tracing_config.rust_log` key. When both keys are present, `tracing_config.rust_log` wins. When neither key is set, the server uses the `RUST_LOG` environment variable.

The `[tracing_config]` table controls the logging sinks.

| Key                | Type    | Default               | Description                                                           |
| :----------------- | :------ | :-------------------- | :-------------------------------------------------------------------- |
| `service_name`     | string  | `credential_verifier` | Service name reported to OpenTelemetry and syslog.                    |
| `rust_log`         | string  | —                     | Log filter string. Overrides the top-level `rust_log` and `RUST_LOG`. |
| `no_log_to_stdout` | boolean | `false`               | Suppress logging to stdout and stderr.                                |
| `log_to_syslog`    | boolean | `false`               | Send logs to the system syslog daemon. Unix and macOS only.           |
| `log_to_file`      | array   | —                     | Daily rolling file logging as `[directory, base_name]`.               |
| `with_ansi_colors` | boolean | `false`               | Enable ANSI color codes in stdout logs.                               |
| `otlp`             | table   | —                     | OpenTelemetry export settings. See below.                             |

The `log_to_file` value is an array of two strings. The first string is the directory, and the second string is the base file name. The server appends the date to the base name and creates a new file each day.

The `[tracing_config.otlp]` table enables export to an OpenTelemetry Protocol (OTLP) collector over gRPC.

| Key               | Type    | Required | Description                                                        |
| :---------------- | :------ | :------- | :----------------------------------------------------------------- |
| `otlp_url`        | string  | Yes      | OTLP collector gRPC endpoint, for example `http://localhost:4317`. |
| `version`         | string  | No       | Service version attribute.                                         |
| `environment`     | string  | No       | Deployment environment attribute.                                  |
| `enable_metering` | boolean | No       | Enable metrics export in addition to traces.                       |

> [!NOTE]
> The `log_to_syslog` key is not compiled on Windows.

## Full example

The example below enables mutual TLS, a Redis transaction store, the HAIP profile, journaling to PostgreSQL, and OTLP export.

```toml
host_name = "0.0.0.0"
host_port = 9443
public_root_url = "https://verifier.example.com"

credentials_cas_dir = "issuer_cas"
attestation_issuer_certificate = "certs/attestation.cert.pem"
attestation_issuer_key = "certs/attestation.key.pem"

rust_log = "info,credential_verifier=debug"

[tls_params]
server_private_key   = "certs/server.key.pem"
server_certificate   = "certs/server.cert.pem"
server_ca_chain      = "certs/ca.chain.pem"
client_ca_cert_chain = "certs/client-ca.pem"

[openid4vp_config]
transaction_ttl_secs = 300

[openid4vp_config.transaction_store]
backend = "redis"
url     = "redis://127.0.0.1:6379"

[openid4vp_config.haip_config]
x509_cert_path = "certs/server.fullchain.pem"
x509_key_path  = "certs/server.key.pem"

[journal_config]
enabled = true
backend = "postgres"
url     = "postgres://ewqwe:ewqwe@localhost/ewqwe"

[tracing_config]
service_name     = "credential_verifier"
with_ansi_colors = false

[tracing_config.otlp]
otlp_url        = "http://localhost:4317"
environment     = "production"
enable_metering = true
```

## Startup validation

The server validates the configuration at startup. The server stops with a configuration error in these cases:

- The configuration file is missing or cannot be parsed.
- A TLS key or certificate file cannot be read or parsed.
- The OpenID4VP service cannot initialize, for example when a HAIP certificate file is missing.
- The configured transaction store or journal backend cannot be reached.
- `verifier_app.session_secret` is shorter than 8 characters when the verifier app is enabled.
