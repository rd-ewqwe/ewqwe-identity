# Verifier App

The Verifier App is an embedded, session-authenticated web application served directly by the credential verifier under the `/verifier_app` path. It provides a self-contained UI for credential verification operators — no separate deployment is required.

## Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                  Credential Verifier  (:9443)                            │
│                                                                          │
│   GET  /verifier_app/                     → embedded SPA (index.html)   │
│   GET  /verifier_app/ui                   → same SPA (alias)            │
│   POST /verifier_app/api/setup/bootstrap  → one-time admin creation     │
│   GET  /verifier_app/api/setup/status     → bootstrap status (public)   │
│   POST /verifier_app/api/auth/login                                      │
│   POST /verifier_app/api/qr/generate      → OpenID4VP QR transaction    │
│   GET  /verifier_app/api/qr/{id}/status                                 │
│   GET  /verifier_app/api/settings         → public app settings         │
│   GET  /verifier_app/api/admin/users      → (admin role only)           │
│   PUT  /verifier_app/api/admin/settings   → (admin role only)           │
│   GET  /verifier_app/api/admin/journal    → (admin role only)           │
└─────────────────────────────────────────────────────────────────────────┘
```

All assets are embedded in the server binary at compile time — there are no separate static file deployments.

---

## Enabling the Verifier App

Add the following section to `credential-server.toml`:

```toml
[verifier_app]
enabled = true
app_name = "My Age Verifier"          # optional display name
# logo_url = "https://example.com/logo.png"   # optional logo
# session_secret_key = "<128 hex chars>"       # recommended for production
```

When `enabled = false` (the default if the section is absent), all `/verifier_app/*` routes return 404.

### Session Secret Key

Session cookies are signed and encrypted with a key derived from `session_secret_key`. When the key is not set, the server generates a random key at startup — all active sessions are invalidated on restart.

For production, generate a stable key once:

```bash
openssl rand -hex 64
```

Paste the output as the value of `session_secret_key`.

### Public URL

When the server is behind a reverse proxy or NAT, the auto-detected URL from the incoming request may not match the externally reachable address. Set `public_url` to the canonical HTTPS URL that wallets will use for the OpenID4VP redirect:

```toml
[verifier_app]
public_url = "https://demo.ewqwe.local:9443"
```

When omitted, the URL is derived from the `Host` header of the incoming request.

### Allowed Credential Types

Restrict which credential types can be requested from this server instance:

```toml
[verifier_app]
allowed_credential_types = ["proof-of-age", "mdl"]
```

Valid values: `"proof-of-age"`, `"mdl"`, `"national-id"`. An empty list (or omitting the key) allows all types.

This setting controls what appears in the dashboard's credential type dropdown. Per-user restrictions can further narrow the selection (see [Per-User Credential Permissions](#per-user-credential-permissions)).

---

## Database Backend

The Verifier App manages user accounts in a separate database from the main credential store. Four backends are supported:

| Backend | Use-case | Config |
|---------|----------|--------|
| `sqlite_memory` (default) | Development / testing | _(no extra config needed)_ |
| `sqlite_file` | Single-instance with persistence | `path = "/var/lib/ewqwe/verifier_app.db"` |
| `postgres` | Multi-instance / HA | `url = "postgres://user:pw@host/db"` |
| `mysql` | MySQL / MariaDB environments | `url = "mysql://user:pw@host/db"` |

```toml
[verifier_app.db]
backend = "sqlite_file"
path    = "/var/lib/ewqwe/verifier_app.db"
```

```toml
[verifier_app.db]
backend = "postgres"
url     = "postgres://ewqwe:secret@db.internal/ewqwe_verifierapp"
```

```toml
[verifier_app.db]
backend = "mysql"
url     = "mysql://ewqwe:secret@db.internal/ewqwe_verifierapp"
```

### Session Store Tradeoffs

The `actix-session` middleware manages HTTP sessions (authentication cookies). The credential verifier currently uses **cookie-based** session storage.

| Approach | Pros | Cons |
|----------|------|------|
| **Cookie** (current) | Zero infrastructure — all session data travels in the encrypted cookie. No server-side store needed. | 4 KB size limit per cookie; no server-side revocation (session lives until expiry); every request carries full state. |
| **Redis** | TTL-native expiry; instant server-side revocation; suitable for distributed / multi-instance deployments. | Requires a running Redis instance; additional network hop per request. |
| **SQL (SQLite/Postgres)** | Reuses the same database already available; unlimited session size; server-side revocation. | No native TTL — requires a periodic cleanup job or trigger; extra write per request. |

For most single-instance deployments the cookie store is sufficient. For multi-instance or high-availability setups, consider adding Redis as a session backend (requires implementing the `actix-session` `SessionStore` trait for the chosen store).

---

## First-Time Setup

On the first visit, navigate to `https://<server>/verifier_app/`.

Because no users exist yet, click **"Create admin account"** (or navigate directly to `/verifier_app/ui` then follow the on-screen link) to reach the bootstrap form. Fill in the admin email and a password of at least 12 characters.

This `POST /verifier_app/api/setup/bootstrap` endpoint is automatically locked after the first admin is created — subsequent calls return `409 Conflict`.

---

## Roles

| Role | Permissions |
|------|-------------|
| `admin` | Full access: user management, journal, QR generation |
| `verifier` | QR generation and status polling only |

The first account created via bootstrap is always an admin with `is_superadmin = true` and cannot be deleted through the UI.

---

## Generating a QR Code

1. Sign in at `https://<server>/verifier_app/`.
2. Select the **Credential Type** from the dropdown (Proof of Age, mDL, or National ID).
3. Click **Generate QR Code**.
4. A QR code is displayed for the selected credential type. The holder scans it with their digital wallet; the status badge updates automatically every 2 seconds:

| Status | Meaning |
|--------|---------|
| `pending` | Waiting for the wallet to scan |
| `scanned` | Wallet received the request |
| `verified` | Credential verified — presentation accepted |
| `failed` | Presentation was rejected |
| `expired` | Transaction timed out (default TTL: 300 s) |

1. Once `verified`, click **New QR Code** to start another session.

The credential type determines the OpenID4VP profile used:

| Credential Type | Profile | Namespace |
|----------------|---------|----------|
| `proof-of-age` | Annex A (EU AV) | `eu.europa.ec.av.1` |
| `mdl` | HAIP | `org.iso.18013.5.1.mDL` |
| `national-id` | HAIP | `eu.europa.ec.eudi.pid.1` |

---

## Admin: User Management

Navigate to **Users** (admin only) to:

- View all accounts, their role and active status.
- **Add User** — creates a new `verifier` or `admin` account.
- **Edit** — update name, role, active status, password, and **allowed credential types**.
- **Delete** — removes the account (superadmin is protected).

Password requirements: minimum 12 characters.

### Per-User Credential Permissions

Each user can be restricted to specific credential types via the **Allowed Credential Types** checkboxes in the user modal. When all checkboxes are unchecked, the user inherits the server-level `allowed_credential_types` setting. When one or more are checked, QR generation is limited to those types only.

This allows an admin to, for example, let one operator verify only proof-of-age while another can also verify mDL and national IDs.

---

## Admin: Journal

Navigate to **Journal** (admin only) to browse the verification audit log. Each entry is attributed to the Verifier App user who initiated the transaction.

Available filter:

- **User ID** — show entries belonging to a specific operator.

Entries are paginated (20 per page). The journal backend must be enabled in the credential-server configuration (see `[journal]` section).

---

## Internationalisation (i18n)

The UI fetches locale strings from:

```
GET /verifier_app/api/i18n?lang=<code>
```

Supported language codes:

| Code | Language |
|------|----------|
| `en` | English (default) |
| `de` | German |
| `fr` | French |

Locale files are embedded in the binary at compile time from  
`credential_verifier/src/verifier_app/static/i18n/`.

---

## API Reference

All API endpoints are under `/verifier_app/api/` and require `Content-Type: application/json` for POST/PUT requests. Sessions are managed via `HttpOnly` cookies.

### Setup

| Method | Path | Body | Description |
|--------|------|------|-------------|
| `POST` | `/api/setup/bootstrap` | `{email, password, first_name, last_name?}` | One-time admin creation |
| `GET`  | `/api/setup/status`    | — | `{"bootstrapped": bool}` — public endpoint |

### Auth

| Method | Path | Body | Description |
|--------|------|------|-------------|
| `POST` | `/api/auth/login`  | `{email, password}` | Sign in, sets session cookie |
| `POST` | `/api/auth/logout` | — | Invalidate session |
| `GET`  | `/api/auth/me`     | — | Current user profile |

### QR Code

| Method | Path | Body | Description |
|--------|------|------|-------------|
| `POST` | `/api/qr/generate`    | `{credential_type?}` | Start a new OpenID4VP transaction. `credential_type`: `"proof-of-age"` (default), `"mdl"`, or `"national-id"`. |
| `GET`  | `/api/qr/{id}/status` | — | Poll transaction status |

`generate` response:

```json
{
  "transaction_id": "...",
  "qr_code_data_url": "data:image/png;base64,...",
  "authorization_request_uri": "openid4vp://...",
  "expires_in": 300
}
```

### Settings (public)

| Method | Path | Body | Description |
|--------|------|------|-------------|
| `GET`  | `/api/settings` | — | `{"app_name": "...", "logo_url": "...\|null", "allowed_credential_types": [...]}` |

### Admin: Settings

| Method | Path | Body | Description |
|--------|------|------|-------------|
| `PUT`  | `/api/admin/settings` | `{app_name?, logo_url?}` | Persist display settings |

`status` response:

```json
{
  "status": "pending | scanned | verified | failed | expired",
  "expires_in": 287
}
```

### Admin: Users

| Method | Path | Body | Description |
|--------|------|------|-------------|
| `GET`    | `/api/admin/users`      | — | List all users |
| `POST`   | `/api/admin/users`      | `{email, password, first_name, last_name?, role?, allowed_credential_types?}` | Create user |
| `PUT`    | `/api/admin/users/{id}` | `{first_name?, last_name?, role?, is_active?, new_password?, allowed_credential_types?}` | Update user |
| `DELETE` | `/api/admin/users/{id}` | — | Delete user |

### Admin: Journal

| Method | Path | Query | Description |
|--------|------|-------|-------------|
| `GET` | `/api/admin/journal` | `user_id`, `limit` (≤200), `offset` | List journal entries attributed to QR app users |

### i18n

| Method | Path | Query | Description |
|--------|------|-------|-------------|
| `GET` | `/api/i18n` | `lang` | Get locale strings JSON |

---

## Source Layout

```
crates/ewqwe-verifier-app/src/
├── lib.rs            — module root + route registration
├── config.rs         — VerifierAppConfig struct
├── auth.rs           — argon2id password hashing/verification
├── db.rs             — VerifierAppStore trait + DynVerifierAppStore dispatch
├── error.rs          — VerifierAppError, VerifierAppResult
├── models.rs         — DTOs: UserResponse, LoginRequest, …
├── qr_user_map.rs    — in-memory transaction→user attribution map
├── routes.rs         — all HTTP handlers (static + API)
├── stores/
│   ├── sqlite.rs     — SQLite backend (in-memory or file)
│   ├── postgres.rs   — PostgreSQL backend
│   └── mysql.rs      — MySQL / MariaDB backend
└── static/
    ├── index.html    — embedded SPA (compiled into binary)
    └── i18n/
        ├── en.json
        ├── de.json
        └── fr.json
```
