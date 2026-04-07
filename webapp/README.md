# Relying Party Demo Application

A demo Relying Party (RP) application that requests and verifies W3C Digital Credentials.

## Overview

This web application demonstrates how a Relying Party can:

1. **Request credentials from digital wallets** - Using the W3C Digital Credentials API and OpenID4VP
2. **Verify received credentials** - Send credentials to a backend for verification
3. **Display verification results** - Show the verified claims and debug information

Based on [demo.digitalcredentials.dev](https://demo.digitalcredentials.dev).

The wallet is now a browser extension. See [wallet-extension/README.md](wallet-extension/README.md) for build and installation steps.

## Technology Stack

- **Runtime**: Deno
- **Build Tool**: Vite
- **Language**: TypeScript
- **Styling**: Tailwind CSS
- **No JavaScript Framework** (vanilla TypeScript)

The shared credential/query utilities are resolved from [../js-lib/ewqwe-npm/src/lib.ts](/Users/bgrieder/projects/ewqwe-identity/js-lib/ewqwe-npm/src/lib.ts) during local development.

## Getting Started

### Prerequisites

- [Deno](https://deno.land/) installed (v1.40+)

### Running the Application

```bash
# Navigate to the webapp directory
cd webapp

# Start the backend API server (Terminal 1)
deno task api

# Start the Vite dev server (Terminal 2)
deno task vite
```

The application will be available at `http://localhost:5174`

Note: `deno task dev` only prints a reminder to run the `api` and `vite` tasks.

### Building for Production

```bash
deno task build
```

### Preview Production Build

```bash
deno task preview
```

## Project Structure

```
webapp/
├── deno.json           # Deno configuration and tasks
├── vite.config.ts      # Vite configuration
├── tailwind.config.js  # Tailwind CSS configuration
├── postcss.config.js   # PostCSS configuration
├── index.html          # Main HTML entry point
└── src/
    ├── main.ts         # Application entry point
    ├── rp.ts           # Relying Party application logic
    ├── credentials.ts  # Credential request/verification logic
    ├── config.ts       # Credential type configurations
    ├── types.ts        # TypeScript type definitions
    ├── debug.ts        # Debug logging utilities
    └── styles.css      # Tailwind CSS styles
```

## Features

### Credential Request Configuration

- Select credential type (mDL, National ID)
- Choose specific claims to request
- Select protocol (OpenID4VP 1.0, Preview/Legacy)
- View the generated request JSON

### Supported Credential Types

#### Mobile Driver's License (mDL)

ISO 18013-5 compliant mobile driver's license with claims:

- Family Name, Given Names
- Birth Date, Portrait
- Age Over 18/21
- Document Number, Issue/Expiry Date
- Issuing Authority/Country
- Driving Privileges

#### National ID

Government-issued national ID with claims:

- Family Name, Given Names
- Birth Date, Portrait
- Age Verification
- Nationality, Gender
- Resident Address

### Verification Flow

1. Configure the credential request
2. Click "Request Credentials"
3. (When Digital Credentials API is available) Browser shows credential chooser
4. User selects and authorizes credential sharing
5. Credential is sent to backend for verification
6. Results are displayed with verified claims

### Debug Information

- Raw credential response
- Verification details
- Request/response logs

## Backend Integration

The application is designed to send received credentials to a Rust backend server for verification. Currently, the backend is simulated client-side.

### Backend API Endpoint

```http
POST /ewqwe_api/verify
Content-Type: application/json

{
  "vp_token": "<base64-encoded VP token>",
  "presentation_submission": { ... }
}
```

Expected response:

```json
{
  "success": true,
  "message": "Credential verified successfully",
  "claims": { ... },
  "verificationDetails": {
    "signatureValid": true,
    "notExpired": true,
    "issuerTrusted": true,
    "timestamp": "2024-01-01T00:00:00.000Z"
  }
}
```

## W3C Digital Credentials API

This application uses the [W3C Digital Credentials API](https://www.w3.org/TR/digital-credentials/):

```typescript
const credential = await navigator.credentials.get({
  digital: {
    requests: [{
      protocol: "openid4vp",
      data: { /* OpenID4VP request */ }
    }]
  }
});
```

### API Support Status

The application checks for:

- Digital Credentials API support
- Credential Management API
- Secure Context (HTTPS)
- Web Crypto API

If the Digital Credentials API is not available, the application falls back to a simulation mode for demonstration purposes.

## Related Standards

- [W3C Digital Credentials](https://www.w3.org/TR/digital-credentials/)
- [OpenID4VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
- [ISO/IEC 18013-5 (mDL)](https://www.iso.org/standard/69084.html)
- [W3C Verifiable Credentials Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/)

## Security Considerations

⚠️ **This is a demo application**

In production:

- All communication must use HTTPS
- Backend verification must validate cryptographic signatures
- Nonce must be validated to prevent replay attacks
- Trusted issuer lists should be maintained
- Rate limiting and abuse prevention should be implemented
