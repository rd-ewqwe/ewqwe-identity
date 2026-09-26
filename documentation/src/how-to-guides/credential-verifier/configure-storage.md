# Configure storage

The credential verifier uses two independent stores. The transaction store holds the short-lived state of each OpenID4VP request. The verification journal is an append-only audit log of successful verifications. This guide shows how to configure both stores for your deployment.

The choice of backend depends on the deployment shape. A single server instance can use a file or an in-memory store. Several server instances that share traffic must use a shared backend, so that any instance can serve any request.

## Prerequisites

- A running server. See [install and run the server](install-and-run.md).
- For a PostgreSQL backend, a reachable PostgreSQL database and a connection URL.
- For a Redis backend, a reachable Redis server and a connection URL.

## Configure the transaction store

The transaction store keeps the nonce and the request context between the moment the relying party creates a transaction and the moment the wallet responds. Configure it under `[openid4vp_config.transaction_store]`.

| Backend          | `backend` value | Persistence          | Multi-instance | Use it for                   |
| :--------------- | :-------------- | :------------------- | :------------- | :--------------------------- |
| SQLite in memory | `sqlite_memory` | No, lost on restart  | No             | Development and tests        |
| SQLite file      | `sqlite_file`   | Yes                  | No             | A single production instance |
| PostgreSQL       | `postgres`      | Yes                  | Yes            | Multi-instance deployments   |
| Redis            | `redis`         | Yes, with native TTL | Yes            | Distributed deployments      |

1. Add the backend section. The in-memory backend is the default and needs no section.

   ```toml
   # SQLite in memory: the default, and no section is required.
   # [openid4vp_config.transaction_store]
   # backend = "sqlite_memory"

   # SQLite file: a single instance that must survive a restart.
   [openid4vp_config.transaction_store]
   backend = "sqlite_file"
   path = "transactions.db"

   # PostgreSQL: shared state across several instances.
   # [openid4vp_config.transaction_store]
   # backend = "postgres"
   # url     = "postgres://ewqwe:ewqwe@localhost/ewqwe"

   # Redis: shared state with automatic expiry.
   # [openid4vp_config.transaction_store]
   # backend = "redis"
   # url     = "redis://127.0.0.1:6379"
   ```

   The journal resolves a relative SQLite `path` against the directory of the configuration file, but the transaction store does not. Give the transaction store an absolute path, or start the server from the directory that holds the database file.

2. Set the transaction lifetime. A transaction expires after this many seconds, and an expired transaction can no longer be verified. The default is 300 seconds.

   ```toml
   [openid4vp_config]
   transaction_ttl_secs = 300
   ```

   Set the value high enough for the user to complete the wallet interaction, and low enough to limit the value of a stolen VP Token. Restart the server after you change the value.

## Configure the verification journal

The journal records each successful verification in a per-user chain. Every entry holds a SHA-256 hash of the attestation and a link to the previous entry, so a modification to any entry breaks the chain. The journal is disabled by default.

| Backend          | `backend` value | Persistence         | Multi-instance |
| :--------------- | :-------------- | :------------------ | :------------- |
| SQLite in memory | `sqlite_memory` | No, lost on restart | No             |
| SQLite file      | `sqlite_file`   | Yes                 | No             |
| PostgreSQL       | `postgres`      | Yes                 | Yes            |

1. Add a `[journal_config]` section and set `enabled = true`.

   ```toml
   [journal_config]
   enabled = true
   backend = "sqlite_file"
   path = "journal.db"
   ```

   The commented alternatives below select the other backends.

   ```toml
   # SQLite in memory: development and smoke tests.
   # [journal_config]
   # enabled = true
   # backend = "sqlite_memory"

   # PostgreSQL: multi-instance deployments.
   # [journal_config]
   # enabled = true
   # backend = "postgres"
   # url     = "postgres://ewqwe:ewqwe@localhost/ewqwe"
   ```

   As with the transaction store, a relative `path` is resolved against the directory that contains the configuration file.

2. Restart the server and check the startup output.

   ```text
   INFO credential_verifier::server::start: Verification journal enabled (backend: SqliteFile { path: "/path/to/journal.db" })
   ```

   The server prints `Verification journal disabled` in place of that line when the journal is not enabled.

## Read the journal through the API

The journal endpoints require mutual TLS, and a client can read only its own journal. The `{username}` path segment must equal the Common Name of the client certificate.

1. List the newest entries.

   ```bash
   curl -sk \
     --cert certificates/tls/ewqwe.user1.cert.pem \
     --key certificates/tls/ewqwe.user1.key.pem \
     "https://localhost:9443/ewqwe_api/journal/user1.acme.com/entries?limit=20"
   ```

2. Check the chain integrity.

   ```bash
   curl -sk \
     --cert certificates/tls/ewqwe.user1.cert.pem \
     --key certificates/tls/ewqwe.user1.key.pem \
     https://localhost:9443/ewqwe_api/journal/user1.acme.com/verify
   ```

   Expected output for an intact chain:

   ```json
   {
     "username": "user1.acme.com",
     "valid": true,
     "entries_verified": 1,
     "first_entry_hash": "0000...",
     "last_entry_hash": "c2d9...",
     "error": null
   }
   ```

3. Download the entries as a file.

   ```bash
   curl -sk \
     --cert certificates/tls/ewqwe.user1.cert.pem \
     --key certificates/tls/ewqwe.user1.key.pem \
     -o "journal_user1.acme.com.json" \
     "https://localhost:9443/ewqwe_api/journal/user1.acme.com/download"
   ```

For the entry fields and the chain formula, see [the verification journal](../../reference/credential-verifier/verification-journal.md).

## Troubleshooting

- **The server stops while it initialises a store.** The database URL is wrong or the database is unreachable. Check the URL, the credentials, and the network path.
- **The server stops with a journal storage error on a SQLite file.** The directory of `path` does not exist or is not writable. Create the directory, or use an absolute path.
- **A verification succeeds but the journal write fails.** The response reports an error even though the checks passed. A concurrent append changed the chain head and the retries were exhausted. Retry the request, or move the journal to a backend suited to the load.
- **The journal endpoints return `401 Unauthorized`.** The request carried no client certificate, or the Common Name of the certificate does not match the `{username}` in the path.
- **The journal is empty after a restart.** The `sqlite_memory` backend does not persist. Use `sqlite_file` or `postgres` to keep entries across restarts.
- **Several instances do not see each other's transactions.** SQLite does not share state. Use `postgres` or `redis` for the transaction store on a multi-instance deployment.
