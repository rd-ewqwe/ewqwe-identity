# Verification journal

The verification journal is an append-only record of every successful verification. This page documents its purpose, its hash chain, its storage backends, its configuration, and its HTTP API.

## Purpose

The journal gives each authenticated user a tamper-evident audit log of the credentials that the verifier accepted. The journal has these properties:

- Non-repudiation: the journal records every accepted verification.
- Tamper detection: a change to any entry breaks the hash chain.
- Per-user scoping: each username has an independent chain.
- Access control: a user can read only the user's own journal over mutual TLS.

The server records an entry after a successful verification. A failed verification does not produce an entry.

## Hash chaining

Each entry stores a hash that links it to the previous entry in the same user chain. The server computes two hashes.

```text
attestation_signature_hash = hex(SHA-256(attestation_jwt_bytes))
entry_hash                 = hex(SHA-256(username_bytes || previous_hash_bytes || attestation_signature_hash_bytes))
```

The definitions of the two values are:

| Value                        | Input                                                                              |
| :--------------------------- | :--------------------------------------------------------------------------------- |
| `attestation_signature_hash` | The raw bytes of the attestation JWT.                                              |
| `entry_hash`                 | The username bytes, then the previous hash bytes, then the attestation hash bytes. |

The server includes the username in the `entry_hash` input, so the hash of an entry is bound to its owner. This binding prevents a hash collision between two different users.

For the first entry of a chain, the `previous_hash` value is absent and the server substitutes an empty byte sequence.

When an entry has no signed attestation, for example a verifier app entry, the server substitutes the string `qr:<username>:<entry_id>` for the JWT bytes. This substitution keeps the `attestation_signature_hash` unique across users.

All hashes use SHA-256 and are stored as lowercase hexadecimal strings.

## Storage backends

The `backend` key of the `[journal_config]` table selects the backend.

| Backend         | Persistence | Multi-instance | Notes                                          |
| :-------------- | :---------- | :------------- | :--------------------------------------------- |
| `sqlite_memory` | No          | No             | Default. Useful for development and tests.     |
| `sqlite_file`   | Yes         | No             | Single instance with persistence.              |
| `postgres`      | Yes         | Yes            | Recommended for high-availability deployments. |

The SQLite backend creates the tables `journal_entries` and `journal_heads`. The tables include a unique index on `entry_hash` and an index on `(username, created_at)`.

## Concurrent append behaviour

The server appends with an optimistic compare-and-swap (CAS) on the per-user chain head. An append performs these operations in order.

| Order | Operation                                                                                    |
| :---- | :------------------------------------------------------------------------------------------- |
| 1     | Read the current head hash for the username.                                                 |
| 2     | Compute the entry hash from that head.                                                       |
| 3     | Append the entry, but only when the stored head still matches the value read in operation 1. |

Each backend serializes the read-check-write section.

| Backend    | Serialization                                                         |
| :--------- | :-------------------------------------------------------------------- |
| SQLite     | A process-level mutex, held across an exclusive database transaction. |
| PostgreSQL | A `SELECT ... FOR UPDATE` row lock inside a database transaction.     |

When a concurrent writer changes the head first, the append detects a stale head and retries. The server retries up to 5 times. When the retries are exhausted, the append fails with a hard error and the server reports the failure. The server does not silently drop an entry, because a missing entry would break the audit chain.

## Configuration

The `[journal_config]` table configures the journal. The journal is disabled by default.

| Key       | Type    | Required          | Default         | Description                                 |
| :-------- | :------ | :---------------- | :-------------- | :------------------------------------------ |
| `enabled` | boolean | No                | `false`         | Turn journaling on or off.                  |
| `backend` | string  | No                | `sqlite_memory` | Storage backend.                            |
| `path`    | string  | For `sqlite_file` | —               | Filesystem path to the SQLite journal file. |
| `url`     | string  | For `postgres`    | —               | PostgreSQL connection URL.                  |

The example below enables journaling with the SQLite file backend.

```toml
[journal_config]
enabled = true
backend = "sqlite_file"
path    = "/var/lib/ewqwe/journal.db"
```

The example below enables journaling with the PostgreSQL backend.

```toml
[journal_config]
enabled = true
backend = "postgres"
url     = "postgres://ewqwe:ewqwe@localhost/ewqwe"
```

The `path` value is relative to the configuration file directory. See [Configuration](./configuration.md) for the path resolution rule.

## Entry schema

The table below documents a full journal entry. The `/download` endpoint returns this shape.

| Field                        | Type   | Description                                                                   |
| :--------------------------- | :----- | :---------------------------------------------------------------------------- |
| `id`                         | string | Surrogate primary key in UUIDv4 format.                                       |
| `username`                   | string | Authenticated username. The Common Name of the client certificate.            |
| `previous_hash`              | string | Hash of the preceding entry. Absent for the first entry.                      |
| `entry_hash`                 | string | Chain hash of this entry, hex-encoded SHA-256.                                |
| `attestation_signature_hash` | string | SHA-256 of the raw attestation JWT bytes, hex-encoded.                        |
| `attestation_jti`            | string | The `jti` claim of the signed attestation.                                    |
| `client_id`                  | string | The relying-party `client_id` bound to the verification.                      |
| `doc_type`                   | string | Credential document type, for example `org.iso.18013.5.1.mDL`.                |
| `namespace`                  | string | Credential namespace, for example `org.iso.18013.5.1`.                        |
| `qrcode_app_user_id`         | string | Verifier app user identifier, when the verifier app started the verification. |
| `qrcode_app_user_email`      | string | Verifier app user email, when the verifier app started the verification.      |
| `verification_summary`       | object | JSON summary of the verification outcome.                                     |
| `created_at`                 | string | Creation time in RFC 3339 format, in UTC.                                     |

The `verification_summary` object holds the `success` boolean and the `credential_claims` object.

The `/entries` endpoint returns a smaller, human-readable view instead of the full entry. See the [HTTP API](./http-api.md) page for the view fields and the query parameters.

## Journal HTTP API

All journal endpoints start with `/ewqwe_api/journal/{username}`. Each endpoint requires a client certificate, and the authenticated username must equal the `{username}` path parameter.

| Method | Path                                     | Description                        |
| :----- | :--------------------------------------- | :--------------------------------- |
| GET    | `/ewqwe_api/journal/{username}/entries`  | List recent entries, newest first. |
| GET    | `/ewqwe_api/journal/{username}/verify`   | Verify the full chain integrity.   |
| GET    | `/ewqwe_api/journal/{username}/download` | Download entries as a JSON file.   |

The [HTTP API](./http-api.md) page documents the query parameters, the response bodies, and the status codes of each endpoint.

When the journal is disabled, the journal store is absent and a request to these paths returns an internal server error.

## Chain verification

The `/verify` endpoint recomputes every `entry_hash` from the first entry and compares the result with the stored values. The response holds these fields.

| Field              | Type    | Description                                                        |
| :----------------- | :------ | :----------------------------------------------------------------- |
| `username`         | string  | The journal owner.                                                 |
| `valid`            | boolean | `true` when every entry verifies from the first entry to the head. |
| `entries_verified` | integer | Number of entries that the server checked.                         |
| `first_entry_hash` | string  | Hash of the first entry, when present.                             |
| `last_entry_hash`  | string  | Hash of the current head, when present.                            |
| `error`            | string  | Human-readable reason when `valid` is `false`.                     |
