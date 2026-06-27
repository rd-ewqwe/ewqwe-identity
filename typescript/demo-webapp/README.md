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
- [pnpm](https://pnpm.io/) >= 9
- The **credential verifier** Rust server must be running (see root README)

### Running (inside the workspace)

From the workspace root (`typescript/`):

```bash
# Install all dependencies and link workspace packages
pnpm install

# Build the shared library first (this package depends on it)
pnpm --filter @ewqwe/digital-identity build

# Start the demo-webapp dev server
pnpm --filter @ewqwe/demo-webapp dev
```

Or run everything in parallel watch mode:

```bash
pnpm dev
```

The application will be available at `https://localhost:5174`

### Running standalone (not recommended)

```bash
cd typescript/demo-webapp
pnpm install
pnpm dev
```

> **Note**: Standalone usage requires the `@ewqwe/digital-identity` library to be
> built first. Prefer running from the workspace root with `pnpm dev` which handles
> the build order automatically.

## Building for Production

```bash
pnpm build
```

### Preview Production Build

```bash
pnpm preview
```

## How It Works

The webapp is served by Vite at `https://localhost:5174`. All `/ewqwe_api/*`
requests are transparently proxied to the credential verifier Rust server.
This means:

- **No separate proxy process needed** — Vite's built-in `http-proxy` handles
  forwarding, with `secure: false` to accept the local self-signed TLS cert.
- **HTTPS in dev** — `@vitejs/plugin-basic-ssl` generates a certificate on first run
  so the browser accepts the dev server's HTTPS.
- **Error logging** — proxy errors and upstream response bodies are logged
  directly in the Vite terminal output.

The `@ewqwe/digital-identity` library is resolved via the pnpm workspace
protocol (`workspace:*` in `package.json`). pnpm symlinks it directly into
`node_modules`, so no manual path alias is needed.

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `CREDENTIAL_VERIFIER_URL` | `https://127.0.0.1:9443` | URL of the Rust credential verifier |

## License

MIT — see [LICENSE](LICENSE).
