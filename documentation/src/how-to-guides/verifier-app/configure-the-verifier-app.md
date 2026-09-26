# Configure the verifier app

This guide shows how to configure the verifier app after it runs. It covers the display settings, the allowed credential types, the session, the user database, and the user accounts.

## Goal

Configure the verifier app for a deployment: set the display name and logo, restrict the credential types, keep sessions across restarts, choose the user database, and manage the accounts.

## Prerequisites

- A running verifier app. See [Run the verifier app](../../tutorials/verifier-app/run-the-verifier-app.md).
- A signed-in administrator account.

## Configure the display

Set the display keys in the `[verifier_ui]` section of the server configuration file:

```toml
[verifier_ui]
enabled = true
app_name = "City of Example Age Check"
logo_url = "https://example.com/logo.svg"
ui_dist_path = "../crates/ewqwe-credential-verifier-ui/ui/dist"
```

- `app_name` sets the text in the header.
- `logo_url` accepts an HTTPS URL or a `data:` URL.
- `public_url` sets the base URL for the wallet callback. When the value is absent, the app derives the base URL from the incoming request.

An administrator can also change the display name and the logo on the Settings page. A value in the configuration file sets the start value; a value on the Settings page overrides it and is stored in the user database.

## Restrict the credential types

The `allowed_credential_types` key limits the types that any user can request:

```toml
[verifier_ui]
allowed_credential_types = ["proof-of-age", "mdl"]
```

The accepted values are `proof-of-age`, `mdl`, and `national-id`. An empty list allows every type. A per-user list narrows the server setting for one user; it never widens it.

To restrict one user, open the Users page as an administrator, edit the user, and select the allowed types.

## Keep sessions across restarts

The app signs the session cookie with `session_secret`. When the value is absent, the server generates a random key at startup, and every restart ends all sessions. To keep sessions, generate a secret and set it:

```bash
openssl rand -hex 64
```

```toml
[verifier_ui]
session_secret = "<the generated value>"
```

The value must contain at least 8 characters.

## Choose the user database

The app stores the user accounts in the backend named by the `[verifier_ui.db]` table.

```toml
[verifier_ui.db]
backend = "sqlite_file"
path = "/var/lib/ewqwe/verifier_ui.db"
```

| Backend         | Persistence | Extra keys | Use                                       |
| :-------------- | :---------- | :--------- | :---------------------------------------- |
| `sqlite_memory` | none        | none       | Development and testing.                  |
| `sqlite_file`   | file        | `path`     | A single instance with persistence.       |
| `postgres`      | server      | `url`      | Multiple instances and high availability. |
| `mysql`         | server      | `url`      | MySQL and MariaDB installations.          |

The `path` value resolves relative to the directory that holds the configuration file. The default backend is `sqlite_memory`.

## Manage users and roles

Open the Users page as an administrator to create, update, and delete accounts. Each account has one role:

| Role       | Permissions                                       |
| :--------- | :------------------------------------------------ |
| `admin`    | User management, settings, journal, and QR codes. |
| `verifier` | QR code generation and status polling.            |

The first account that the bootstrap route creates is an administrator with `is_superadmin = true`. A superadmin cannot be deleted through the interface. A password must contain at least 12 characters.

## Troubleshooting

| Symptom                              | Cause                                   | Action                                                          |
| :----------------------------------- | :-------------------------------------- | :-------------------------------------------------------------- |
| The config key has no effect         | The app reads the value at startup.     | Restart the server after a change to the configuration file.   |
| Every `/verifier_ui/api` route returns 404    | The app is disabled.                    | Keep the `[verifier_ui]` section with `enabled = true`.        |
| Accounts disappear after a restart   | The database is `sqlite_memory`.        | Configure `sqlite_file`, `postgres`, or `mysql`.                |
| Sessions end after a restart         | `session_secret` is not set.            | Set a stable `session_secret` value.                            |
| A user cannot request a type         | The type is not allowed for that user.  | Widen the per-user list or the `allowed_credential_types` list. |

## Related pages

- [The verifier app](../../reference/verifier-app/verifier-app.md)
- [Run the verifier app](../../tutorials/verifier-app/run-the-verifier-app.md)
- [Credential verifier configuration](../../reference/credential-verifier/configuration.md)
