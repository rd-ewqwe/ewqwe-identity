# Demo Architecture

## Overview

This demonstration system showcases a complete credential verification flow using three main components:

1. **Relying Party Demo Webapp** - A reference implementation of a Relying Party (RP) web application that requests and verifies credentials from users.
2. **ewQwe Credential Verifier Server** - A production-ready backend service that performs cryptographic verification on behalf of Relying Parties.
3. **Demo Wallets**:

   1. Age Verification Mobile App - A mobile application that acts as a wallet on Android devices, allowing users to manage and present age verification credentials on . Emulator for testing and development purposes.
   2. EUDI Wallet - A reference implementation of a mobile wallet based on the EU Digital Identity (EUDI) specifications and HAIP profile. The wallet runs in the Android Studio Emulator for testing and development purposes.
The demo wallets and webapp work together to demonstrate the complete end-to-end flow of credential presentation and verification. The webapp serves as both a functional demonstration and a **starting point for Relying Parties** who want to implement credential verification in their own web applications.

> **Source Code**: The wallets and relying party webapp source codes are available on GitHub for developers to use as a reference implementation. (GitHub repository details to be provided)

## System Architecture

The following diagram shows how the components interact in a complete credential verification flow:

```mermaid
flowchart TB
subgraph Browser["Browser Environment"]
    subgraph WebappUI["Demo Webapp Frontend"]
        RP[Relying Party UI<br/>- Credential Type Selection<br/>- Claims Configuration<br/>- Protocol Selection<br/>- Results Display]
    end
end
    
    subgraph WebappBackend["Webapp Backend<br/>Deno Server"]
        API[API Server<br/>- /api/verify endpoint<br/>- TLS client config<br/>- Proxied via Vite]
    end
    
    subgraph CredVerifier["ewQwe Credential Verifier"]
        Endpoints[REST API<br/>POST /api/verify<br/>GET /version]
        Attestation[Attestation Engine<br/>- Parse VP Token<br/>- Verify Signatures<br/>- Sign JWT Attestation]
        
        Endpoints --> Attestation
    end
    
    subgraph Infrastructure["Infrastructure"]
        Redis[(Redis<br/>Session Storage<br/>Port 6379)]
    end
    
    RP -->|fetch /api/verify| API
    API -->|HTTPS POST| Endpoints
    Attestation -->|Store Sessions| Redis
    API -->|Return signed<br/>attestation| RP
    
    style Browser fill:#6d28d9
    style WebappUI fill:##7c3aed
    style WebappBackend fill:#6d28d9
    style CredVerifier fill:#6d28d9
    style Infrastructure fill:#6d28d9
```

## Setting Up the Demo Environment

### Verification Checklist

- ✅ Redis responding to `redis-cli ping`
- ✅ Credential Verifier listening on <https://127.0.0.1:9443>
- ✅ Webapp frontend accessible at <https://localhost:5174>
- ✅ Webapp backend API proxied through Vite

### Test the Complete Flow

1. **Open the Demo Webapp**: Navigate to [https://localhost:5174](https://localhost:5174)

2. **Configure a Request**:
   - Select credential type (e.g., "Proof of Age")
   - Choose required claims (e.g., "age_over_18")
   - Select protocol (appropriate for your wallet setup)

3. **Initiate Verification**:
   - Click "Request Credentials"
   - The webapp sends the credential request to the credential verifier via the backend

4. **Verification**:
   - The credential verifier processes the request
   - Verifier validates and returns a signed attestation
   - Webapp displays verification results and extracted claims

**Expected Result**: You should see verified claims displayed in the webapp UI with a success message and the signed attestation JWT.

## Port Assignments

| Component                  | Port  | Protocol | Description                                      |
|----------------------------|-------|----------|--------------------------------------------------|
| Webapp Frontend (Vite)     | 5174  | HTTPS    | Demo RP web interface + proxy to backend API     |
| Webapp Backend (Deno)      | 5175  | HTTP     | API server (proxied via Vite)                    |
| Credential Verifier (Rust) | 9443  | HTTPS    | Verification server with TLS                     |
| Redis                      | 6379  | TCP      | Session storage for Credential Verifier          |

## Troubleshooting

### Common Issues

**Issue**: Webapp can't connect to credential verifier

**Solution**:

- Check verifier is running: `curl -k https://127.0.0.1:9443/version`
- Verify Redis is running: `redis-cli ping`
- Check backend logs for TLS certificate errors
- Ensure CA certificate is correctly configured in `webapp/server.ts`

---

**Issue**: Verification fails with "Invalid signature"

**Solution**:

- This is expected in demo mode - signature verification is simulated
- For production, ensure proper issuer certificates are configured
- Check that credential was signed by a trusted issuer
- Verify the credential hasn't expired

---

**Issue**: Redis connection errors

**Solution**:

- Ensure Redis is running: `redis-server`
- Check Redis is accessible: `redis-cli ping`
- Verify connection string in verifier configuration
- Check firewall rules if Redis is on a different host

## Next Steps

- Review the [User Journey](./user-journey.md) for detailed protocol flow
- Learn about [Credential Verifier Server](./credential_verifier_server.md) configuration
- Explore [DCQL Age Verification](./dcql_age_verification.md) for credential queries
- Study [Credential Format Specifications](./digital_credential_format.md)

## Startup Commands Summary

For quick reference, here are the commands to start all components:

```bash
# Terminal 1: Redis (required by Credential Verifier)
redis-server

# Terminal 2: Credential Verifier (Rust)
cd credential_verifier
RUST_LOG=info \
X509_CERT_PATH=src/tests/certificates/ec/ewqwe.server.fullchain.pem \
X509_KEY_PATH=src/tests/certificates/ec/ewqwe.server.key.pem \
cargo run --features openssl

# Terminal 3 — Webapp API server (port 5175)
cd webapp
deno task api

# Terminal 4 — Webapp Vite dev server (port 5174, HTTPS)
cd webapp
deno task vite

# Open: https://localhost:5174
```

**Alternative**: Use the provided shell script or tmux session for one-command startup.
