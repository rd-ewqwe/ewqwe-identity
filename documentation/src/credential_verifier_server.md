# ewQwe Credential Verification Server

The **ewQwe Credential Verification Server** is a production-ready backend service that Relying Parties (RPs) use to verify credentials presented by users' digital wallets. Instead of implementing complex cryptographic verification logic directly in web applications, RPs delegate credential verification to this trusted service, which returns signed attestations confirming successful verification.

> **Technical Note**: While named "Credential Verifier," this service technically verifies **Verifiable Presentations** (VP Tokens) that contain credentials. In the W3C Verifiable Credentials data model, credentials are cryptographically bound into presentations before verification. We use "Credential Verifier" throughout this documentation for clarity, as the business purpose is verifying credential authenticity—non-expert users immediately understand verifying credentials, while "Presentation Verifier" requires explaining the technical distinction between credentials and presentations.

This architecture provides several key benefits:

- **Security**: Cryptographic verification happens on a secure backend, isolated from browser environments
- **Centralization**: A single verification service can support multiple RPs across an organization
- **Standards Compliance**: Implements OpenID4VP, W3C Digital Credentials, and ISO/IEC 18013-5 (mDoc) standards
- **Auditability**: Comprehensive logging and telemetry for compliance and debugging

## Server Architecture

The credential verifier is built using Rust with the Actix-web framework and consists of several key components:

```mermaid
flowchart LR
    RP[Relying Party<br/>webapp]
    Verifier[Credential Verifier Server<br/>Rust/Actix-web]
    TLS[TLS Authentication]
    VP[VP Token Verification]
    Sign[Attestation Signing]
    Store[(Transaction Store<br/>SQLite / PostgreSQL / Redis)]

    RP -->|HTTPS POST<br/>/ewqwe_api/verify| Verifier
    Verifier --> TLS
    Verifier --> VP
    Verifier --> Sign
    Verifier --> Store

    style Verifier fill:#7c3aed
    style Store fill:#dc2626
```

## Verification Process

The server performs the following verification steps:

1. **Parse VP Token**: Deserialize the credential presentation (DCQL-wrapped mDoc CBOR, SD-JWT VC compact serialisation, or direct JSON)
2. **Claim Extraction**: Extract selectively-disclosed claims from SD-JWT disclosures or mDoc namespaced elements
3. **Expiration Check**: Verify `exp` timestamp (SD-JWT payload) or MSO `validUntil` / `validFrom` (mDoc)
4. **Nonce Binding**: The `state` from the request is used to look up the server-stored `OpenID4VPTransaction` nonce, which is compared against the nonce embedded in the KB-JWT (SD-JWT VC) or the reconstructed `SessionTranscript` (mDoc) — this prevents replay attacks since the nonce never travels in the request body
5. **Cryptographic Signature Verification**:
   - **SD-JWT VC issuer JWT**: The `x5c` JWT header (mandatory per HAIP §2 and OpenID4VP §6.1.1) provides the leaf certificate; its public key verifies the issuer JWT via `jsonwebtoken`. Supports ES256, ES384, RS256, RS384, RS512. Presentations without `x5c` are rejected.
   - **SD-JWT VC issuer trust**: The leaf `x5c` certificate is validated against the trusted issuer CA directory using OpenSSL X.509 chain verification.
   - **SD-JWT VC KB-JWT holder signature**: The holder's public key is extracted from the `cnf.jwk` claim in the issuer payload. EC (P-256/P-384/P-521), RSA, and EdDSA key types are supported.
   - **mDoc IssuerAuth COSE_Sign1**: The MSO is verified against the issuer certificate chain from the `x5chain` COSE header using OpenSSL.
   - **mDoc IssuerSigned digests**: Each disclosed `IssuerSignedItem` is verified against the SHA-256 digests in the MSO `valueDigests`.
   - **mDoc DeviceSignature COSE_Sign1**: The device signature is verified with the device public key from `deviceKeyInfo.deviceKey` in the MSO, over `DeviceAuthenticationBytes` bound to the reconstructed OpenID4VP `SessionTranscript`.
6. **Attestation Signing**: Generate an ES256-signed JWT attestation confirming verification

## Installation and Configuration

### Prerequisites

- **Rust** 1.75 or later
- **OpenSSL** 3.0+ or **rustls** (for TLS)
- A **transaction store** backend (see below) — SQLite in-memory is the default and requires no external dependencies

### Building from Source

```bash
cd ewqwe-identity/credential_verifier

# Build with default features (OpenSSL TLS backend)
cargo build --release --features openssl

# Or build with rustls
cargo build --release --features rustls
```

### Transaction Store

The server uses a pluggable transaction store to manage OpenID4VP sessions. Configure it under `[openid4vp_config.transaction_store]` in `credential-server.toml`:

| Backend | TOML `backend` value | Notes |
| :------ | :------------------- | :---- |
| SQLite in-memory | `"sqlite_memory"` (default) | No external dependency; state lost on restart; suitable for single-instance dev/test |
| SQLite file | `"sqlite_file"` | Persists across restarts; suitable for single-instance production |
| PostgreSQL | `"postgres"` | Suitable for multi-instance / HA deployments |
| Redis | `"redis"` | TTL-native expiry; no cleanup thread; recommended for distributed / HA deployments |

```toml
# Default — no configuration block needed
# [openid4vp_config.transaction_store]
# backend = "sqlite_memory"

# Single-instance production
# [openid4vp_config.transaction_store]
# backend = "sqlite_file"
# path    = "/var/lib/ewqwe/transactions.db"

# Distributed / HA — PostgreSQL
# [openid4vp_config.transaction_store]
# backend = "postgres"
# url     = "postgres://user:pass@localhost/ewqwe"

# Distributed / HA — Redis
# [openid4vp_config.transaction_store]
# backend = "redis"
# url     = "redis://127.0.0.1:6379"
```

For resilient multi-instance deployments, use Redis or PostgreSQL so that any server node can look up a session created by another node.

### Trusted Issuer CA Certificates

Place all trusted issuer CA PEM files in a single directory and point `trusted_issuer_certs_dir` at it. All `*.pem` files in the directory are loaded at startup as trusted CA certificates.

```toml
# credential-server.toml
trusted_issuer_certs_dir = "issuer_certificates"   # relative to config file
```

If `trusted_issuer_certs_dir` is omitted, the server looks for a directory named `issuer_certificates/` next to the configuration file. If that directory does not exist, no issuer CAs are trusted and all presentations will have `issuer_trusted = false`.

### TLS Configuration

```toml
[tls_params]
server_private_key  = "certs/server.key.pem"      # PKCS#8 PEM
server_certificate  = "certs/server.cert.pem"     # X.509 PEM
server_ca_chain     = "certs/ca.chain.pem"        # CA chain PEM
# client_ca_cert_chain = "certs/client-ca.pem"   # Uncomment for mTLS
```

All paths are resolved relative to the config file directory.

### HAIP and x509_san_dns Client ID

For the HAIP profile (`x509_san_dns:` `client_id` scheme), configure the server's full certificate chain for use in JAR `x5c` headers:

```toml
[openid4vp_config.haip_config]
x509_cert_path = "certs/server.fullchain.pem"   # leaf + intermediate + root
x509_key_path  = "certs/server.key.pem"
```

### Full Example Configuration

```toml
host_name = "0.0.0.0"
host_port = 9443
default_username = "demo-user"
trusted_issuer_certs_dir = "issuer_certificates"

[tls_params]
server_private_key    = "certs/server.key.pem"
server_certificate    = "certs/server.cert.pem"
server_ca_chain       = "certs/ca.chain.pem"
client_ca_cert_chain  = "certs/client-ca.pem"

[openid4vp_config]
transaction_ttl_secs  = 300

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
```

### Test Certificates

For development and testing, pre-generated certificates are available:

- **EC (P-256)**: `credential_verifier/src/tests/certificates/ec/`
- **RSA (4096-bit)**: `credential_verifier/src/tests/certificates/rsa/`

⚠️ **Never use test certificates in production environments.**

### Systemd Service Example

```ini
[Unit]
Description=ewQwe Credential Verifier Server
After=network.target

[Service]
Type=simple
User=ewqwe
WorkingDirectory=/opt/credential-verifier
Environment=RUST_LOG=info
ExecStart=/opt/credential-verifier/credential-verifier
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

## Logging and Telemetry

The credential verifier uses the `ewqwe_logging` crate for structured observability, supporting:

- **Console Output**: Structured logs with optional ANSI colors
- **File Logging**: Daily rolling file appender
- **Syslog**: Unix/macOS/Linux system logging
- **OpenTelemetry (OTLP)**: Distributed tracing and metrics

Configure log level via the `RUST_LOG` environment variable:

```bash
RUST_LOG=info cargo run                # info and above
RUST_LOG=credential_verifier=debug     # debug for this crate only
```

### Key Log Events

The server emits structured logs for:

- **Request Processing**: VP token receipt, parsing, verification steps
- **Authentication**: Session validation, user identification
- **Verification Results**: Success/failure with detailed reasons
- **Attestation Signing**: Algorithm used, claims embedded
- **Errors**: Detailed error context with stack traces

Example log output:

```
2026-02-01T12:00:00.123Z INFO  credential_verifier::server: Server listening on 0.0.0.0:9443
2026-02-01T12:00:15.456Z INFO  credential_verifier::endpoints: VP Token received length=2048
2026-02-01T12:00:15.460Z DEBUG credential_verifier::endpoints: parsing VP token
2026-02-01T12:00:15.462Z DEBUG credential_verifier::endpoints: mDoc decoded doc_type="org.iso.18013.5.1.mDL" namespaces=1
2026-02-01T12:00:15.465Z INFO  credential_verifier::endpoints: credential verified doc_type=Some("org.iso.18013.5.1.mDL")
2026-02-01T12:00:15.468Z INFO  credential_verifier::attestation: signing attestation algorithm=ES256
```

## TLS Authentication

### Standard TLS (Server Authentication)

Configure with `server_private_key`, `server_certificate`, and `server_ca_chain` in `[tls_params]`. The server presents certificates to clients and validates server certificate chain.

### Mutual TLS (mTLS) - Client Certificate Authentication

Configure with `client_ca_cert_chain` in `[tls_params]` to require client certificates.

**How it works for `/ewqwe_api/verify`**:

1. The TLS listener is configured to validate client certificates against the configured CA chain when a client certificate is presented.
2. The `SslAuth` middleware runs in front of `POST /ewqwe_api/verify` and requires a client certificate for that endpoint.
3. The server extracts the client certificate from the TLS connection.
4. The Common Name (CN) field of the client certificate is extracted and used as the **username**.
5. Wildcard usernames are rejected (`CN` values ending in `*` are denied).
6. This username is used to:
   - Identify the authenticated client
   - Lookup user-specific journal entries (append-only audit logs)
   - Perform per-user authorization checks

**Configuration**:

```toml
[tls_params]
server_private_key    = "certs/server.key.pem"
server_certificate    = "certs/server.cert.pem"
server_ca_chain       = "certs/ca.chain.pem"
client_ca_cert_chain  = "certs/client-ca.pem"  # Required for mTLS
```

**Behavior for `POST /ewqwe_api/verify`**:

- ✅ **Valid client certificate**: Request proceeds with `username` = certificate CN
- ❌ **No client certificate**: Request rejected with `401 Unauthorized`
- ❌ **Invalid certificate chain**: TLS handshake fails or request rejected
- ❌ **Certificate not signed by client CA**: TLS handshake fails
- ❌ **Wildcard CN (for example `CN=test*`)**: Request rejected with `401 Unauthorized`

Other endpoints (such as `/version`) are not protected by `SslAuth` and therefore do not require a client certificate.

**Client certificate requirements**:

- Must be signed by a CA listed in `client_ca_cert_chain`
- Must have a valid Common Name (CN) in the Subject field
- Must be valid (not expired, not before current time)
- CN format: Any UTF-8 string (recommended: `CN=client-name`)

**Example client certificate**:

```
Subject: CN=ewqwe-client-01
Issuer: C=EU, O=ewQwe, CN=ewQwe Client CA
```

### Certificate Formats

All certificates must be in **PEM format**:

- **Private Keys**: PKCS#8 PEM encoding (`-----BEGIN PRIVATE KEY-----`)
- **Certificates**: X.509 PEM encoding (`-----BEGIN CERTIFICATE-----`)
- **CA Chains**: Concatenated PEM certificates (root and intermediates)

**Test certificates** are available in:

- **EC (P-256)**: `credential_verifier/src/tests/certificates/ec/`
- **RSA (4096-bit)**: `credential_verifier/src/tests/certificates/rsa/`

⚠️ **Never use test certificates in production environments.**

## API Endpoints

### `POST /ewqwe_api/verify` — Verify Credential

Verifies a Verifiable Presentation (VP) token from a user's wallet and returns a signed attestation if valid.

**Request Body**:

```json
{
  "vp_token": "{\"proof_of_age\":[\"base64url_mdoc_presentation\"]}",
  "presentation_submission": null,
  "state": "session-state",
  "client_id": "https://example.com"
}
```

> **Note**: `presentation_submission` is **optional** and typically `null` when the wallet uses DCQL queries (OpenID4VP §8.1). With DCQL, the `vp_token` is a JSON object where keys are credential IDs from the query.
>
> The `state` field is **required** for transaction binding: the server looks up the original `OpenID4VPTransaction` by state and compares the stored transaction context against the presentation proof. For SD-JWT VC that means comparing the stored nonce against the KB-JWT nonce. For `mso_mdoc` that means rebuilding the OpenID4VP handover from the stored `client_id`, `nonce`, and `response_uri` before verifying `deviceAuth.deviceSignature`.

**Response** (Success):

```json
{
  "success": true,
  "message": "Credential verified successfully",
  "claims": {
    "age_over_18": true,
    "birth_date": "1990-01-01"
  },
  "verification_details": {
    "signature_valid": true,
    "not_expired": true,
    "issuer_trusted": true,
    "timestamp": "2026-02-01T12:00:00Z",
    "doc_type": "org.iso.18013.5.1.mDL",
    "namespace": "org.iso.18013.5.1"
  },
  "attestation": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response** (Failure):

```json
{
  "success": false,
  "message": "Credential verification failed",
  "verification_details": {
    "signature_valid": false,
    "not_expired": true,
    "issuer_trusted": false,
    "timestamp": "2026-02-01T12:00:00Z",
    "doc_type": "org.iso.18013.5.1.mDL",
    "namespace": "org.iso.18013.5.1"
  },
  "errors": [
    "Invalid signature",
    "Untrusted issuer"
  ]
}
```

### `GET /version` — Server Version

Returns the server version information.

**Response**:

```json
{
  "version": "0.1.0"
}
```

## Security Considerations

### Nonce Replay Prevention ✅

The nonce used for replay prevention is looked up **server-side** from the `OpenID4VPTransaction` store. The `verify_credential_endpoint` receives the `state` field from the request, loads the stored transaction, and compares the stored nonce against the holder-binding proof in the presentation. The nonce is never taken from the HTTP request body.

**Flow**:

1. `init_transaction()` stores a fresh nonce in the `OpenID4VPTransaction`
2. The wallet binds this nonce into the holder-binding proof (KB-JWT nonce for SD-JWT VC; `SessionTranscript` for mDoc)
3. `verify_credential_endpoint` looks up the transaction by `state` and retrieves the stored nonce plus the original OpenID4VP request context
4. The verifier compares that stored context against the presentation proof — mismatch leads to verification failure
5. After a successful verification, the transaction is consumed so the VP token is single-use

### Cryptographic Signature Verification

| Signature | Algorithm | Key Source | Crate | Status |
| :-------- | :-------- | :--------- | :---- | :----- |
| SD-JWT VC issuer JWT | ES256/ES384/RS256/RS384/RS512 | `x5c` leaf certificate (required) | `jsonwebtoken` v9 | ✅ |
| KB-JWT holder binding | ES256/RS256/EdDSA | `cnf.jwk` claim in issuer payload | `jsonwebtoken` v9 | ✅ |
| mDoc `issuerAuth` COSE_Sign1 | ES256/ES384/ES512/RS256 | X.509 chain in `x5chain` COSE header | `coset` + `openssl` | ✅ |
| mDoc `deviceSignature` COSE_Sign1 | ES256/ES384/ES512/RS256 | Device public key in MSO `deviceKeyInfo.deviceKey` | `coset` + `openssl` | ✅ |

**SD-JWT VC**: The JWT header **must** contain `x5c` (required by HAIP §2 and OpenID4VP §6.1.1). Presentations without `x5c` are rejected — the issuer key cannot be obtained by any other means in this profile. The `cnf.jwk` claim provides the holder's public key for KB-JWT verification.

**mDoc**: Full verification is performed:

- `issuerAuth` COSE_Sign1 signature verified against the X.509 chain in the `x5chain` COSE header
- All `IssuerSignedItem` SHA-256 digests validated against MSO `valueDigests`
- `SessionTranscript` / `OpenID4VPHandover` reconstructed from `client_id`, `nonce`, `response_uri`, and the response-encryption JWK thumbprint (when `direct_post.jwt` is used)
- `deviceAuth.deviceSignature` COSE_Sign1 verified with the device key from MSO `deviceKeyInfo.deviceKey` over `DeviceAuthenticationBytes = Tag(24, bstr(.cbor DeviceAuthentication))`

Current limitation: `deviceAuth.deviceMac` is rejected; only `deviceSignature`-based holder binding is supported.

### Trusted-Issuer CA Directory

The `trusted_issuer_certs_dir` configuration parameter specifies a directory of PEM files. All `*.pem` files are loaded as trusted CA certificates at request time using OpenSSL X.509 chain verification with the `PARTIAL_CHAIN` flag (allows validation against intermediate CAs, not only root CAs).

OpenID4VP 1.0 §6.1.1 defines three trust mechanisms:

| Mechanism | Type | Description |
| :-------- | :--- | :---------- |
| `aki` | X.509 Authority Key Identifier | Match issuer cert chain against known AKIs |
| `etsi_tl` | ETSI Trusted List (TS 119 612) | EU Member State official trust lists (LOTL) |
| `openid_federation` | OpenID Federation Entity | Federation-based trust chains |

The type definitions for these mechanisms already exist in `crates/openid4vp/src/types.rs` (`TrustedAuthority`, `TrustedAuthorityType`). Production deployments should integrate with dynamic trust sources (ETSI Trusted Lists, OpenID Federation) rather than relying solely on the static certificate directory.

**Note**: No central Age Verification issuer registry exists yet. The EU LOTL covers eIDAS services but not AV-specific credential issuers. The Age Verification Profile uses the `redirect_uri` `client_id` scheme precisely because no issuer trust framework is established yet.

## Verification Journal

The credential verifier maintains an **append-only, hash-chained audit log** of every successful age verification event per user. The journal provides:

- **Non-repudiation**: An immutable record of every credential the verifier accepted
- **Tamper detection**: Any modification to any historical entry breaks the chain
- **Per-user scoping**: Each client (identified by its mTLS certificate CN) has an independent chain
- **mTLS-protected API**: Only the owner of a journal can read or download it

### Hash-Chaining Formula

```
attestation_signature_hash = SHA-256(attestation_jwt_bytes)
entry_hash = SHA-256(previous_hash_bytes || attestation_signature_hash_bytes)
```

For the genesis (first) entry, `previous_hash` is treated as an empty byte string.

### Configuration

Add a `[journal_config]` section to `credential-server.toml`:

```toml
# SQLite in-memory — no persistence, useful for development / smoke tests
[journal_config]
enabled = true
backend = "sqlite_memory"

# SQLite file — single-instance deployments with persistence across restarts
# [journal_config]
# enabled  = true
# backend  = "sqlite_file"
# path     = "/var/lib/ewqwe/journal.db"

# PostgreSQL — recommended for multi-instance / HA deployments
# [journal_config]
# enabled  = true
# backend  = "postgres"
# url      = "postgres://ewqwe:ewqwe@localhost/ewqwe"
```

The journal is **disabled by default** (`enabled = false`) to preserve backward compatibility.

### Journal HTTP API

All journal endpoints are under `/ewqwe_api/journal/{username}/` and require mTLS authentication. A client may only access its **own** journal (the authenticated CN must match the `{username}` path parameter).

#### List Entries

```
GET /ewqwe_api/journal/{username}/entries
```

| Query Param | Type         | Default | Description                           |
| :---------- | :----------- | :------ | :------------------------------------ |
| `limit`     | integer      | 20      | Maximum results (1–1000)              |
| `before`    | RFC 3339     | —       | Only entries created before this time |
| `after`     | RFC 3339     | —       | Only entries created after this time  |

Returns a JSON array of journal entries (newest first):

```json
[
  {
    "id": "018f…",
    "username": "alice@example.com",
    "previous_hash": "3a7b…",
    "entry_hash": "c2d9…",
    "attestation_signature_hash": "e1f8…",
    "attestation_jti": "550e8400-e29b-41d4-a716-446655440000",
    "client_id": "redirect_uri:https://rp.example.com/cb",
    "doc_type": "org.iso.18013.5.1.mDL",
    "namespace": "org.iso.18013.5.1",
    "verification_summary": { "age_over_18": true },
    "created_at": "2025-03-20T14:32:01Z"
  }
]
```

#### Verify Chain Integrity

```
GET /ewqwe_api/journal/{username}/verify
```

Recomputes every `entry_hash` from genesis and checks the head pointer. Returns:

```json
{
  "username": "alice@example.com",
  "valid": true,
  "entries_verified": 42,
  "first_entry_hash": "0000…",
  "last_entry_hash": "c2d9…",
  "error": null
}
```

If any entry has been tampered with, `valid` is `false` and `error` contains a description.

#### Download Journal

```
GET /ewqwe_api/journal/{username}/download?before=&after=&limit=
```

Returns the same filtered entries as `list_entries` as a `Content-Disposition: attachment` JSON file named `journal_{username}.json`.

### Backend Comparison

| Backend         | Persistence | Multi-instance | Use case                       |
| :-------------- | :---------- | :------------- | :----------------------------- |
| `sqlite_memory` | ✗           | ✗              | Tests and development          |
| `sqlite_file`   | ✓           | ✗              | Single-instance with audit log |
| `postgres`      | ✓           | ✓              | HA / multi-instance production |

### Concurrent Append Safety

Journal appends use an **optimistic compare-and-swap (CAS)** strategy:

- **SQLite**: A `tokio::sync::Mutex` serializes appends within the process + an exclusive transaction for atomic read-check-write.
- **PostgreSQL**: `SELECT … FOR UPDATE` inside a DB transaction ensures atomicity across multiple server instances.

If the head changes concurrently (e.g., another request completed first), the append retries up to 5 times. Exhausting retries returns an error to the caller (verification was still successful; the journal write failed).

- [x] ~~Nonce replay prevention: server-stored nonce, not client-supplied~~
- [x] ~~SD-JWT VC issuer JWT signature verification~~
- [x] ~~KB-JWT holder signature verification~~
- [x] ~~Trusted-issuer CA certificate configuration~~
- [x] ~~mDoc IssuerAuth COSE_Sign1 signature verification~~
- [x] ~~mDoc IssuerSigned digest verification~~
- [x] ~~mDoc DeviceSignature verification bound to OpenID4VPHandover~~
- [x] ~~Consume verified transactions (single-use VP tokens)~~
- [x] ~~mTLS client certificate authentication (CN as username)~~
- [x] ~~Append-only journaling with hash chaining (SQLite / PostgreSQL backends)~~
- [x] ~~Optimistic locking for journal integrity (Mutex + CAS / SELECT FOR UPDATE)~~
- [ ] Replace test certificates with production certificates from trusted CA
- [ ] Configure production Redis or PostgreSQL for HA transaction storage
- [ ] Enable `deviceAuth.deviceMac` verification when that proof mode is needed
- [ ] Integrate with dynamic trust sources (ETSI Trusted Lists, OpenID Federation)
- [ ] Implement credential revocation checking (CRLs or OCSP)
- [ ] Set up centralized logging/monitoring (ELK, Datadog, etc.)
- [ ] Configure firewall rules to restrict access
- [ ] Implement rate limiting to prevent abuse
- [ ] Use proper secret management (HashiCorp Vault, etc.) for private keys
- [ ] Regular security audits and dependency updates
- [ ] Disaster recovery and backup procedures

## Related Documentation

- [User Journey - Sequence Diagram](./user-journey.md) - Complete credential flow
- [Credential Specifications](./credential_specifications.md) - Credential format reference
- [DCQL Age Verification](./dcql_age_verification.md) - Query language for credential requests
- [Digital Credential Browser Storage](./digital_credentials_browser_storage.md) - Browser credential storage
