# AI Agent Instructions for ewqwe-auth

## Project Overview

This is an **EU Age Verification** system implementing the [EU Age Verification Profile](https://ageverification.dev/Technical%20Specification/annexes/annex-A/annex-A-av-profile) using W3C Digital Credentials:

- **Wallet** (`wallet/`) - TypeScript/Deno **Age Verification App Instance (AVI)** - stores Proof of Age attestations
- **Webapp** (`webapp/`) - TypeScript/Deno **Relying Party (RP)** - requests age verification from the wallet
- **Credential Verifier** (`credential_verifier/`) - Rust actix-web server - verifies proofs on behalf of RPs

Standards: W3C Digital Credentials API, ISO/IEC 18013-5 (mDL/mDoc), OpenID4VP 1.0, EU Age Verification Profile.

## Architecture

The RP **delegates verification** to the credential_verifier, which returns a signed attestation:

```
┌─────────────────┐  (1) Request   ┌─────────────────┐  (2) VP Token    ┌─────────────────┐
│   Relying       │  Proof of Age  │     Wallet      │  (Presentation)  │   Credential    │
│   Party (RP)    │ ──────────────>│     (AVI)       │                  │    Verifier     │
│   webapp/       │                │    wallet/      │                  │credential_verif/│
└────────┬────────┘                └────────┬────────┘                  └────────┬────────┘
         │                                  │                                    │
         │  (3) Send VP Token for verification                                   │
         └───────────────────────────────────────────────────────────────────────>
                                                                                 │
         <─────────────────────────────────────────────────────────────────────────
                              (4) Return signed attestation (proof is valid)
```

## OpenID4VP Flows

This project implements [OpenID4VP 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html):

### Same-Device Flow (Section 3.1)

- RP and Wallet on same device
- Uses redirects with `response_mode=fragment`
- Authorization Request → Wallet → Authorization Response (VP Token)

### Cross-Device Flow (Section 3.2)

- RP on different device than Wallet (e.g., QR code scanning)
- Uses `response_mode=direct_post` with `response_uri`
- Wallet POSTs VP Token directly to RP's endpoint

Key parameters:

- `response_type=vp_token` - Request Verifiable Presentations
- `dcql_query` - Digital Credentials Query Language for specifying required claims
- `nonce` - Binds presentation to transaction (replay prevention)
- `client_id` with prefixes like `redirect_uri:` or `x509_san_dns:`

## Rust Workspace Conventions

### Cargo Workspace Structure

- **Root workspace** (`Cargo.toml`): Defines shared dependencies via `[workspace.dependencies]`
- **Members**: `credential_verifier`, `crates/logging`
- All members use `workspace = true` for version, edition, rust-version, authors, license

### Error Handling Pattern

**Critical**: Use the project's error handling system, not anyhow/eyre directly.

```rust
use crate::{AttError, AttResult, AttResultHelper};

// Type alias for Results
pub type AttResult<R> = Result<R, AttError>;

// Error context helper trait (custom, extends Result and Option)
fn example() -> AttResult<String> {
    some_operation()
        .context("failed to do operation")?;  // AttResultHelper trait
    Ok("success".to_string())
}

// Error construction macros (in credential_verifier/src/error/)
auth_error!("something went wrong");           // Create error
auth_bail!("early return with error");         // Return early
auth_ensure!(condition, "must be true");       // Guard clause
```

### TLS Configuration

Server supports both OpenSSL and rustls via Cargo features (default: `openssl`). TLS parameters in `TlsParams` struct require:

- `server_private_key`: PKCS#8 PEM format
- `server_certificate`: PEM format
- `server_ca_chain`: CA chain in PEM
- Optional `client_ca_cert_chain` for mTLS

### Logging

Use the `ewqwe_logging` crate ([crates/logging/](crates/logging/)):

```rust
use ewqwe_logging::{TracingConfig, tracing_init};

// Initialize at app start (NOT in #[tokio::test])
let _guard = tracing_init(&config);

// Use tracing macros
tracing::info!("server started");
tracing::debug!(user_id = %id, "processing request");
```

**Important**: In `#[tokio::test]`, use `log_init(Some("debug"))` instead of `tracing_init()` due to OTLP gRPC limitations.

### Testing

- Unit tests: `#[test]` in `tests.rs` modules within feature modules
- Integration tests: `credential_verifier/src/tests/` with `#[actix_web::test]` or `#[tokio::test]`
- Test utilities: `credential_verifier/src/tests/test_client/` and `test_server/`

## TypeScript/Deno Conventions

### Project Structure

Both `wallet/` and `webapp/` follow the same pattern:

- `deno.json`: Tasks and imports configuration
- `vite.config.ts`: Vite bundler config
- `tailwind.config.js` + `postcss.config.js`: Tailwind CSS
- `src/`: TypeScript sources (no framework - vanilla TS)

### Development Commands

```bash
cd wallet/    # or webapp/
deno task dev      # Start dev server (wallet: 5173, webapp: 5174)
deno task build    # Production build
deno task preview  # Preview production build
```

### Code Patterns

**No React/Vue** - Uses vanilla TypeScript with class-based architecture:

```typescript
// Main app controller pattern (wallet.ts, rp.ts)
export class WalletApp {
  private store: CredentialStore;
  private logger: DebugLogger;

  initialize(): void {
    this.setupEventListeners();
    this.renderUI();
  }
}
```

Type definitions centralized in `types.ts`:

- `StoredCredential`, `OpenID4VPRequest`, `OpenID4VPResponse`
- ISO 18013-5 structures: `MobileDriverLicense`, `MDLNamespace`

Credential configurations in `config.ts` (webapp) define ISO namespace mappings:

```typescript
export const CREDENTIAL_TYPES: Record<string, CredentialTypeConfig> = {
  mdl: {
    docType: "org.iso.18013.5.1.mDL",
    namespace: "org.iso.18013.5.1",
    claims: [
      /* ISO claim definitions */
    ],
  },
};
```

## Common Tasks

### Running the Full Stack

```bash
# Terminal 1: Wallet
cd wallet && deno task dev

# Terminal 2: Webapp (RP)
cd webapp && deno task dev

# Terminal 3 (future): Rust credential verifier
cd credential_verifier
cargo run --features openssl
```

### Adding Rust Dependencies

Edit root `Cargo.toml` `[workspace.dependencies]`, then reference in member crate:

```toml
# In credential_verifier/Cargo.toml
my_crate = { workspace = true }
```

### Rust Feature Flags

- `openssl` (default) or `rustls`: TLS backend
- `no_jwt_validation`: **TEST ONLY** - disables JWT verification

## Runtime Dependencies

### Redis

The credential verifier requires a **Redis server** for session storage. The server connects to Redis at startup:

```rust
// From credential_verifier/src/server/att_server.rs
let storage = RedisSessionStore::new("redis://127.0.0.1:6379")
    .await
    .expect("failed to create Redis session store");
```

**Start Redis before running the server:**

```bash
# macOS (Homebrew)
brew services start redis

# Linux (systemd)
sudo systemctl start redis

# Docker
docker run -d -p 6379:6379 redis:alpine
```

Sessions are configured with a 24-hour TTL using `actix-session` with `redis-session` feature.

## Test Certificates

Test certificates for TLS connections and attestation signing are located in:

- **EC (P-256)**: `credential_verifier/src/tests/certificates/ec/`
- **RSA (4096-bit)**: `credential_verifier/src/tests/certificates/rsa/`

| File                    | Purpose                              |
| ----------------------- | ------------------------------------ |
| `ewqwe.chain.pem`       | Full CA certificate chain            |
| `ewqwe.root.key.pem`    | Root CA private key                  |
| `ewqwe.server.cert.pem` | Server TLS certificate               |
| `ewqwe.server.key.pem`  | Server private key (for TLS/signing) |
| `ewqwe.user1.cert.pem`  | Client certificate for mTLS testing  |
| `ewqwe.user1.key.pem`   | Client private key                   |
| `ewqwe.user1.p12`       | PKCS#12 bundle for browser testing   |

**⚠️ These are TEST CERTIFICATES ONLY** - never use in production.

Generate new certificates using the provided scripts:

```bash
cd credential_verifier/src/tests/certificates/ec
./generate_certs_p256.sh

cd ../rsa
./generate_certs_rsa4096.sh
```

## Attestation Signing

The credential verifier signs attestations confirming successful age verification. Supported formats and algorithms:

### JWT Attestations (RS256/ES256)

```rust
use credential_verifier::attestation::{
    AttestationClaims, JwtSigner, SigningAlgorithm
};

// Create claims
let claims = AttestationClaims::new(
    "verifier.example.com",  // issuer
    "rp.example.com",        // audience (relying party)
    "session-123",           // subject (session ID)
    true,                    // age_verified
)
.with_age_over(18)
.with_namespace("eu.europa.ec.av.1")
.with_nonce("request-nonce");

// Sign with ES256 (P-256 ECDSA)
let signer = JwtSigner::from_pem(SigningAlgorithm::ES256, &private_key_pem)?;
let jwt = signer.sign_to_string(&claims)?;

// Or RS256 (RSA)
let signer = JwtSigner::from_pem(SigningAlgorithm::RS256, &rsa_key_pem)?;
```

### COSE/CBOR Attestations (ES256/RS256)

For mDoc-compatible attestations using COSE_Sign1 (RFC 8152):

```rust
use credential_verifier::attestation::{
    AttestationClaims, CoseSigner, CoseSigningAlgorithm, verify_cose_attestation
};

// Sign
let signer = CoseSigner::from_pem(CoseSigningAlgorithm::ES256, &private_key_pem)?
    .with_key_id(b"key-2024-01");
let cose_bytes = signer.sign_to_bytes(&claims)?;

// Verify
let verified = verify_cose_attestation(&cose_bytes, &public_key_pem, CoseSigningAlgorithm::ES256)?;
```

### Attestation Claims Structure

| Claim          | Type    | Description                           |
| -------------- | ------- | ------------------------------------- |
| `iss`          | String  | Credential verifier identifier        |
| `aud`          | String  | Relying party identifier              |
| `sub`          | String  | Session/transaction ID                |
| `exp/iat/nbf`  | i64     | Standard JWT timestamps               |
| `jti`          | String  | Unique attestation ID (UUID)          |
| `age_verified` | bool    | Whether age requirement was met       |
| `age_over`     | u8?     | Age threshold verified (e.g., 18, 21) |
| `av_namespace` | String? | Namespace used (eu.europa.ec.av.1)    |
| `nonce`        | String? | Nonce from OpenID4VP request          |

## Key Files Reference

| Purpose                 | Location                                                                                           |
| ----------------------- | -------------------------------------------------------------------------------------------------- |
| Error types & macros    | [credential_verifier/src/error/](credential_verifier/src/error/)                                   |
| Attestation signing     | [credential_verifier/src/attestation/](credential_verifier/src/attestation/)                       |
| Server entry point      | [credential_verifier/src/server/att_server.rs](credential_verifier/src/server/att_server.rs)       |
| Logging configuration   | [crates/logging/src/lib.rs](crates/logging/src/lib.rs)                                             |
| Test certificates (EC)  | [credential_verifier/src/tests/certificates/ec/](credential_verifier/src/tests/certificates/ec/)   |
| Test certificates (RSA) | [credential_verifier/src/tests/certificates/rsa/](credential_verifier/src/tests/certificates/rsa/) |
| DCQL query examples     | [documentation/dcql_age_verification.md](documentation/dcql_age_verification.md)                   |
| Wallet main logic       | [wallet/src/wallet.ts](wallet/src/wallet.ts)                                                       |
| RP credential handling  | [webapp/src/credentials.ts](webapp/src/credentials.ts)                                             |
| ISO credential configs  | [webapp/src/config.ts](webapp/src/config.ts)                                                       |
| Standards documentation | [documentation/](documentation/)                                                                   |

## Standards Compliance

When working with credentials, consult:

- [documentation/digital_credential_format.md](documentation/digital_credential_format.md) - Format specs
- ISO 18013-5 namespace: `org.iso.18013.5.1` for mDL claims
- OpenID4VP protocol for presentation exchanges
- W3C Digital Credentials API: `navigator.credentials.get()`/`.create()`
