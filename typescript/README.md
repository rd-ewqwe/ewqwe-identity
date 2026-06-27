# ewQwe TypeScript Workspace

pnpm workspace monorepo for ewQwe's TypeScript packages — a shared identity library and a
Relying Party (RP) demo webapp for EU Age Verification using W3C Digital Credentials.

## Packages

| Package | Description |
|---|---|
| [`@ewqwe/digital-identity`](./ewqwe-digital-identity/) | Shared library: types, DCQL query builders, protocol profiles, attestation verification, and `EwqweApiClient` for OpenID4VP. Published to npm. |
| [`@ewqwe/demo-webapp`](./demo-webapp/) | Vanilla TypeScript RP demo webapp with Vite, Tailwind CSS, and an API proxy to the credential verifier. Private, not published. |

## Prerequisites

- **Node.js** >= 18
- **pnpm** >= 9

```bash
# Install pnpm if you don't have it
npm install -g pnpm
```

## Getting Started

```bash
# Install all dependencies and link workspace packages
pnpm install

# Build the shared library first (demo-webapp depends on it)
pnpm --filter @ewqwe/digital-identity build

# Start both packages in parallel dev/watch mode
pnpm dev
```

> **Note**: The demo-webapp depends on `@ewqwe/digital-identity` via the pnpm workspace
> protocol (`workspace:*`). The library must be built before the webapp can resolve its
> module exports. In dev mode, `pnpm dev` runs the library's `vite build --watch` and the
> webapp's `vite` dev server concurrently.

## Commands

All commands run from the workspace root (`typescript/`):

| Command | Action |
|---|---|
| `pnpm install` | Install dependencies for all packages |
| `pnpm build` | Build all packages (`pnpm --recursive build`) |
| `pnpm dev` | Run all packages in parallel watch mode |
| `pnpm test` | Run tests across all packages |
| `pnpm typecheck` | Run `tsc --noEmit` across all packages |
| `pnpm --filter <name> <cmd>` | Run a command in a specific package |

### Targeting a single package

```bash
# Build only the identity library
pnpm --filter @ewqwe/digital-identity build

# Run tests only in the identity library
pnpm --filter @ewqwe/digital-identity test

# Start only the demo-webapp dev server
pnpm --filter @ewqwe/demo-webapp dev
```

## Dependency Graph

```mermaid
graph LR
    WEBAPP["@ewqwe/demo-webapp"] -->|workspace:*| LIB["@ewqwe/digital-identity"]
```

The demo-webapp imports types and utilities from `@ewqwe/digital-identity` via the
pnpm workspace protocol. The library is symlinked into the demo-webapp's `node_modules`
by pnpm, so no manual path aliases are needed.

## Package Details

### `@ewqwe/digital-identity`

A framework-agnostic TypeScript library providing:

- **DCQL query builders** — `buildAgeVerificationQuery`, `buildInitTransactionRequest`, etc.
- **Credential type configurations** — mDL, PID, Proof of Age profiles with ISO namespace mappings
- **Protocol profiles** — HAIP and Annex A support for OpenID4VP
- **Attestation verification** — JWT signature verification via Web Crypto API
- **API client** — `EwqweApiClient` for interacting with the credential verifier's REST endpoints

Built with Vite (library mode) and tested with Vitest.

### `@ewqwe/demo-webapp`

A demo Relying Party application (vanilla TypeScript, no framework) that:

- Requests W3C Digital Credentials via OpenID4VP
- Proxies `/ewqwe_api/*` requests to a Rust credential verifier backend
- Uses Tailwind CSS for styling
- Runs on HTTPS in development (via `@vitejs/plugin-basic-ssl`)

**Configurable environment variable:**

| Variable | Default | Description |
|---|---|---|
| `CREDENTIAL_VERIFIER_URL` | `https://127.0.0.1:9443` | URL of the Rust credential verifier |

## Workspace Structure

```mermaid
graph TD
    ROOT["typescript/"] --> PKG_JSON["package.json — workspace config"]
    ROOT --> YAML["pnpm-workspace.yaml — package declarations"]
    ROOT --> LOCK["pnpm-lock.yaml — lockfile"]
    ROOT --> NPMRC[".npmrc — pnpm config"]
    ROOT --> IDENTITY["ewqwe-digital-identity/<br/>@ewqwe/digital-identity"]
    ROOT --> WEBAPP["demo-webapp/<br/>@ewqwe/demo-webapp"]

## License

All packages in this workspace are licensed under **MIT**. See individual package LICENSE files for details.
```
