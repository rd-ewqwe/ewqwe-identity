# Digital Wallet Application

A W3C Digital Credentials wallet application for managing verifiable credentials.

## Overview

This wallet application simulates a mobile digital wallet that:

1. **Gets credentials from Attestation Providers (APs)** - Authenticates with credential issuers and receives digital credentials
2. **Stores credentials securely** - Uses local storage (in production, would use the device's secure element)
3. **Presents credentials to Relying Parties (RPs)** - Responds to credential requests using W3C Verifiable Credentials and OpenID4VP

## Technology Stack

- **Runtime**: Deno
- **Build Tool**: Vite
- **Language**: TypeScript
- **Styling**: Tailwind CSS
- **No JavaScript Framework** (vanilla TypeScript)

## Getting Started

### Prerequisites

- [Deno](https://deno.land/) installed (v1.40+)

### Running the Application

```bash
# Navigate to the wallet directory
cd wallet

# Start the development server
deno task dev
```

The application will be available at `http://localhost:5173`

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
wallet/
├── deno.json           # Deno configuration and tasks
├── vite.config.ts      # Vite configuration
├── tailwind.config.js  # Tailwind CSS configuration
├── postcss.config.js   # PostCSS configuration
├── index.html          # Main HTML entry point
└── src/
    ├── main.ts         # Application entry point
    ├── wallet.ts       # Main wallet application logic
    ├── store.ts        # Credential storage management
    ├── types.ts        # TypeScript type definitions
    ├── debug.ts        # Debug logging utilities
    └── styles.css      # Tailwind CSS styles
```

## Features

### Credential Management
- View all stored credentials
- Add new credentials from demo Attestation Providers
- Delete credentials
- View credential details

### Credential Types Supported
- **Mobile Driver's License (mDL)** - ISO 18013-5 compliant
- **National ID Card**
- **Education Credentials**
- **Employment Credentials**

### Presentation Flow
- Receive presentation requests from Relying Parties
- Select which credential to present
- Review requested claims before sharing
- Authorize or deny the presentation

## W3C Digital Credentials API

This application implements the [W3C Digital Credentials API](https://www.w3.org/TR/digital-credentials/) specification, including:

- `navigator.credentials.get()` for presentation requests
- `navigator.credentials.create()` for issuance requests
- OpenID4VP protocol support

## Security Notes

⚠️ **This is a demo application**

In a production wallet:
- Credentials would be stored in the device's secure element (TEE/SE)
- All cryptographic operations would be performed in the secure enclave
- User authentication (biometrics, PIN) would be required
- The wallet would be properly certified and audited

## Related Standards

- [W3C Digital Credentials](https://www.w3.org/TR/digital-credentials/)
- [W3C Verifiable Credentials Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/)
- [ISO/IEC 18013-5 (mDL)](https://www.iso.org/standard/69084.html)
- [OpenID4VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
