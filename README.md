# Digital Credentials Authentication Project

This project contains two web applications for demonstrating W3C Digital Credentials:

1. **Wallet** (`/wallet`) - A digital wallet application that manages verifiable credentials
2. **Webapp** (`/webapp`) - A Relying Party demo that requests and verifies credentials

## Quick Start

### Prerequisites

- [Deno](https://deno.land/) v1.40 or later

### Running Both Applications

Open two terminal windows:

**Terminal 1 - Wallet (port 5173):**
```bash
cd wallet
deno task dev
```

**Terminal 2 - Webapp (port 5174):**
```bash
cd webapp
deno task dev
```

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Attestation   │     │     Wallet      │     │   Relying       │
│    Provider     │────▶│   Application   │◀────│     Party       │
│      (AP)       │     │    (Holder)     │     │     (RP)        │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                              │                         │
                              │    W3C Digital          │
                              │  Credentials API        │
                              ▼                         ▼
                        ┌─────────────────────────────────┐
                        │        Browser / User Agent      │
                        └─────────────────────────────────┘
                                        │
                                        ▼
                        ┌─────────────────────────────────┐
                        │      Backend Verification       │
                        │         (Rust - TBD)            │
                        └─────────────────────────────────┘
```

## Technology Stack

- **Runtime**: Deno
- **Build Tool**: Vite
- **Language**: TypeScript
- **Styling**: Tailwind CSS
- **Backend**: Rust (to be developed)

## Standards Implemented

- [W3C Digital Credentials API](https://www.w3.org/TR/digital-credentials/)
- [W3C Verifiable Credentials Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/)
- [OpenID for Verifiable Presentations (OpenID4VP)](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
- [ISO/IEC 18013-5 (Mobile Driving License)](https://www.iso.org/standard/69084.html)

## Project Structure

```
ewqwe-auth/
├── opus.md              # Project requirements
├── README.md            # This file
├── wallet/              # Digital Wallet application
│   ├── deno.json
│   ├── vite.config.ts
│   ├── index.html
│   ├── README.md
│   └── src/
│       ├── main.ts
│       ├── wallet.ts
│       ├── store.ts
│       ├── types.ts
│       ├── debug.ts
│       └── styles.css
└── webapp/              # Relying Party demo application
    ├── deno.json
    ├── vite.config.ts
    ├── index.html
    ├── README.md
    └── src/
        ├── main.ts
        ├── rp.ts
        ├── credentials.ts
        ├── config.ts
        ├── types.ts
        ├── debug.ts
        └── styles.css
```

## Future Work

### Rust Backend

A Rust backend server will be developed to:
- Verify cryptographic signatures on credentials
- Validate credential issuers against trusted lists
- Check credential revocation status
- Provide secure nonce generation and validation

### Additional Features

- Cross-device credential presentation
- Credential issuance flow
- Multiple wallet provider support
- Enhanced security features
