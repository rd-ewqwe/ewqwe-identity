# Relying Party Demo Webapp

A demo Relying Party (RP) application that requests and verifies W3C Digital Credentials
via OpenID4VP.

## Technology Stack

- **Runtime**: Node.js
- **Build Tool**: Vite
- **Language**: TypeScript
- **Styling**: Tailwind CSS
- **No JavaScript Framework** (vanilla TypeScript)

## Getting Started

### Prerequisites

- [Node.js](https://nodejs.org/) v18+
- The **credential verifier** Rust server must be running (see root README)

### Running

```bash
# Install dependencies (first time only)
npm install

# Start Vite dev server (starts both the frontend dev server and API proxy)
npm run dev
```

The application will be available at `https://localhost:5174`

The Vite dev server proxies `/ewqwe_api/*` requests directly to the credential
verifier (`https://127.0.0.1:9443` by default). The proxy uses `secure: false`
to accept the self-signed dev certificate. No separate proxy process is needed.

### Building for Production

```bash
npm run build
```

### Preview Production Build

```bash
npm run preview
```

## Project Structure

```
webapp/
├── package.json         # Node.js dependencies and scripts
├── tsconfig.json        # TypeScript configuration
├── vite.config.ts       # Vite configuration (includes API proxy)
├── tailwind.config.js   # Tailwind CSS configuration
├── postcss.config.js    # PostCSS configuration
├── index.html           # Main HTML entry point
└── src/
    ├── main.ts         # Application entry point
    ├── relying_party_app.ts  # Relying Party application logic
    ├── credentials.ts  # Credential request/verification logic
    ├── dc_api_service.ts  # W3C Digital Credentials API service
    ├── hpke.ts         # HPKE crypto utilities
    ├── debug.ts        # Debug logging utilities
    └── styles.css      # Tailwind CSS styles
```

## How It Works

The webapp is served by Vite at `https://localhost:5174`. All `/ewqwe_api/*`
requests are transparently proxied to the credential verifier Rust server.
This means:

- **No separate proxy process needed** — Vite's built-in `http-proxy` handles
  forwarding, with `secure: false` to accept the local self-signed TLS cert.
- **HTTPS in dev** — `vite-plugin-mkcert` generates a trusted local CA and
  certificate on first run so the browser accepts the dev server's HTTPS.
- **Error logging** — proxy errors and upstream response bodies are logged
  directly in the Vite terminal output.

The shared `@ewqwe/digital-identity` library is resolved via a Vite alias to
`../js-lib/ewqwe-digital-identity/src/lib.ts` for live TypeScript transpilation.

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `CREDENTIAL_VERIFIER_URL` | `https://127.0.0.1:9443` | URL of the Rust credential verifier |
