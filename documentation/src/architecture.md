# EU Age Verification - Architecture Flow

## System Components

```text
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              BROWSER                                            │
│  ┌──────────────────────────────────────────────────────────────────────────┐   │
│  │                        WALLET EXTENSION                                  │   │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────────┐   │   │
│  │  │  Background     │  │    Popup UI     │  │    Content Script       │   │   │
│  │  │  Service Worker │  │  (Credential    │  │  (Injected into pages)  │   │   │
│  │  │                 │  │   Management)   │  │                         │   │   │
│  │  │  - Storage      │  │                 │  │  - Message listener     │   │   │
│  │  │  - Matching     │  │  - View creds   │  │  - Credential selector  │   │   │
│  │  │  - Credentials  │  │  - Reset wallet │  │  - VP response builder  │   │   │
│  │  └────────┬────────┘  └─────────────────┘  └───────────┬─────────────┘   │   │
│  │           │                                            │                 │   │
│  │           └──────────── runtime.sendMessage ───────────┘                 │   │
│  └──────────────────────────────────────────────────────────────────────────┘   │
│                                      │                                          │
│                                      │ window.postMessage                       │
│                                      │ (EU_AV_WALLET_REQUEST/RESPONSE)          │
│                                      ▼                                          │
│  ┌──────────────────────────────────────────────────────────────────────────┐   │
│  │                         WEBAPP UI (Frontend)                             │   │
│  │                         http://localhost:5174                            │   │
│  │                                                                          │   │
│  │  ┌─────────────────────────────────────────────────────────────────────┐ │   │
│  │  │  RelyingPartyApp                                                    │ │   │
│  │  │  - Credential type selection (mDL, PID, Proof of Age)               │ │   │
│  │  │  - Claims selection                                                 │ │   │
│  │  │  - Protocol selection (W3C DC API, OpenID4VP)                       │ │   │
│  │  │  - Request credentials → Display verification results               │ │   │
│  │  └─────────────────────────────────────────────────────────────────────┘ │   │
│  └──────────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       │ fetch("/api/verify")
                                       │ POST { vp_token, presentation_submission, nonce }
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         WEBAPP BACKEND (Deno)                                   │
│                         http://localhost:5175 (proxied via Vite)                │
│                                                                                 │
│  ┌───────────────────────────────────────────────────────────────────────────┐  │
│  │  API Server (server.ts)                                                   │  │
│  │  - /api/verify  → Forward to Credential Verifier                          │  │
│  │  - /api/health  → Health check                                            │  │
│  │  - TLS client with CA certificate for mTLS                                │  │
│  └───────────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       │ fetch("https://127.0.0.1:9443/api/verify")
                                       │ POST { vp_token, presentation_submission, nonce, client_id }
                                       │ (with CA certificate for TLS)
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                      CREDENTIAL VERIFIER (Rust/Actix-web)                       │
│                      https://127.0.0.1:9443                                     │
│                                                                                 │
│  ┌───────────────────────────────────────────────────────────────────────────┐  │
│  │  Endpoints                                                                │  │
│  │  - POST /api/verify  → Verify VP token, return signed attestation         │  │
│  │  - GET  /version     → Server version                                     │  │
│  └───────────────────────────────────────────────────────────────────────────┘  │
│                                                                                 │
│  ┌───────────────────────────────────────────────────────────────────────────┐  │
│  │  Attestation Module                                                       │  │
│  │  - Parse VP token (JSON)                                                  │  │
│  │  - Verify credential (issuer, expiration, signature*)                     │  │
│  │  - Create signed JWT attestation (ES256)                                  │  │
│  └───────────────────────────────────────────────────────────────────────────┘  │
│                                                                                 │
│  * Signature verification is simulated in demo mode                             │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## Port Assignments

| Component              | Port  | Protocol | Description                          |
|------------------------|-------|----------|--------------------------------------|
| Webapp UI (Vite)       | 5174  | HTTP     | Frontend + proxy to backend API      |
| Webapp Backend (Deno)  | 5175  | HTTP     | API server (proxied via Vite)        |
| Credential Verifier    | 9443  | HTTPS    | Rust server with TLS                 |
| Redis                  | 6379  | TCP      | Session storage for Credential Verifier |

## Message Types

### Browser Extension Messages (postMessage)

| Message Type            | Direction        | Payload                                    |
|-------------------------|------------------|--------------------------------------------|
| EU_AV_WALLET_REQUEST    | Page → Extension | {protocol, data: OpenID4VPRequest}         |
| EU_AV_WALLET_RESPONSE   | Extension → Page | {response: OpenID4VPResponse} or {error}   |

### Extension Internal Messages (runtime.sendMessage)

| Message Type      | Direction                  | Payload                          |
|-------------------|----------------------------|----------------------------------|
| GET_CREDENTIALS   | Popup/Content → Background | -                                |
| DC_API_REQUEST    | Content → Background       | {request: {protocol, data}}      |
| RESET_CREDENTIALS | Popup → Background         | -                                |

## Startup Commands

```bash
# Terminal 1: Redis (required by Credential Verifier)
redis-server

# Terminal 2: Credential Verifier (Rust)
cd credential_verifier && cargo run --features openssl

# Terminal 3: Webapp Backend (Deno)
cd webapp && deno task api

# Terminal 4: Webapp Frontend (Vite)
cd webapp && deno task vite

# Browser: Load extension from wallet-extension/dist/
# Open: http://localhost:5174
```
