# Credential verifier HTTP API

The credential verifier exposes an HTTP API over TLS. This page documents every endpoint, the request body, the response body, the status codes, and the error cases.

## Base path and authentication

Every endpoint starts with `/ewqwe_api`. The server serves two further paths outside that prefix: `GET /version` and the verifier app single-page application at `/`.

The endpoints fall into three authentication classes.

| Class         | Endpoints                                                                                                                                           | Client certificate |
| :------------ | :-------------------------------------------------------------------------------------------------------------------------------------------------- | :----------------- |
| Relying party | `/ewqwe_api/verify`, `/ewqwe_api/openid4vp/init`, `/ewqwe_api/openid4vp/status/{id}`, `/ewqwe_api/journal/*`, `/ewqwe_api/.well-known/issuer_certs` | Required           |
| Wallet        | `/ewqwe_api/openid4vp/direct_post`, `/ewqwe_api/openid4vp/request/{id}`, `/ewqwe_api/openid4vp/.well-known/jwks.json`                               | Not required       |
| Public        | `/version`                                                                                                                                          | Not required       |

A relying-party endpoint requires a verified client certificate. The server uses the certificate Common Name (CN) as the authenticated username. See [TLS and mutual TLS](./tls-authentication.md) for the certificate requirements.

## Request limits

| Setting                 | Value           |
| :---------------------- | :-------------- |
| Maximum request payload | 1,000,000 bytes |
| Maximum JSON payload    | 1,000,000 bytes |
| Keep-alive timeout      | 120 seconds     |
| Client request timeout  | 10 seconds      |

## Error responses

The server returns two error-body shapes.

The credential verifier core returns the error message as a JSON string with these status codes.

| Condition                        | Status | Body                      |
| :------------------------------- | :----- | :------------------------ |
| Invalid request parameter        | `400`  | JSON string error message |
| Missing or failed authentication | `401`  | JSON string error message |
| Any other failure                | `500`  | JSON string error message |

The OpenID4VP endpoints return a JSON object with an `error` field and these status codes.

| Condition             | Status | Body                                                          |
| :-------------------- | :----- | :------------------------------------------------------------ |
| Unknown transaction   | `404`  | `{ "error": "<message>" }`                                    |
| Expired transaction   | `410`  | `{ "error": "<message>", "status": "expired" }`               |
| Invalid request       | `400`  | `{ "error": "<message>" }`                                    |
| Cryptographic failure | `500`  | `{ "error": "Internal crypto error" }`                        |
| Configuration failure | `500`  | `{ "error": "credential verifier configuration: <message>" }` |
| Internal failure      | `500`  | `{ "error": "Internal server error" }`                        |

## POST /ewqwe_api/verify

Verifies a verifiable presentation (VP) token and returns a signed attestation. This endpoint requires a client certificate.

### Request body

The request body is a JSON object.

| Field                     | Type   | Required | Description                                                             |
| :------------------------ | :----- | :------- | :---------------------------------------------------------------------- |
| `vp_token`                | string | Yes      | The VP token from the wallet.                                           |
| `state`                   | string | No       | Transaction state used to look up the stored nonce and request context. |
| `client_id`               | string | No       | Relying-party identifier used as the attestation audience.              |
| `presentation_submission` | object | No       | Presentation submission. Usually absent for DCQL-based responses.       |

The `vp_token` value is a JSON string. The server accepts three presentation shapes:

- A DCQL object whose keys are credential query identifiers and whose values are arrays of presentations.
- An SD-JWT VC compact serialization, which contains the `~` separator.
- A base64url-encoded mDoc `DeviceResponse` (CBOR).

The `state` field locates a stored OpenID4VP transaction. The server reads the nonce and the request context from that transaction and never from the request body. For mDoc verification the `state` field is required, because the server rebuilds the OpenID4VP handover from the stored context.

The `client_id` field is required when no stored transaction exists, for example in the same-device Digital Credentials API flow. When a stored transaction exists, the server rejects a `client_id` value that differs from the transaction value.

### Response body

The response body is a JSON object. The server returns this shape with status `200` for both a successful and a failed verification.

| Field                  | Type    | Present    | Description                                                    |
| :--------------------- | :------ | :--------- | :------------------------------------------------------------- |
| `success`              | boolean | Always     | The verification result.                                       |
| `message`              | string  | Always     | Human-readable result message.                                 |
| `attestation`          | string  | Always     | Signed attestation JWT. See [Attestations](./attestations.md). |
| `verification_details` | object  | Always     | Verification breakdown. See below.                             |
| `errors`               | array   | On failure | Human-readable failure reasons.                                |

The `verification_details` object holds three boolean fields.

| Field             | Type    | Description                                   |
| :---------------- | :------ | :-------------------------------------------- |
| `signature_valid` | boolean | The presentation signature is valid.          |
| `not_expired`     | boolean | The credential is within its validity period. |
| `issuer_trusted`  | boolean | The issuer chain terminates at a trusted CA.  |

### Status codes

| Status | Condition                                                                                                                         |
| :----- | :-------------------------------------------------------------------------------------------------------------------------------- |
| `200`  | The server processed the presentation. Check `success` for the result.                                                            |
| `400`  | The `vp_token` is malformed, the `client_id` disagrees with the transaction, the mDoc `state` is missing, or an mDoc check fails. |
| `401`  | No authenticated user is present.                                                                                                 |
| `500`  | An internal failure occurred, for example a journal append failure.                                                               |

### Example

```json
{
  "vp_token": "{\"proof_of_age\":[\"o2d2ZXJzaW9u...\"]}",
  "state": "f7c1a2e0-5b3d-4a9c-9f21-8d2e6b0a1c34",
  "client_id": "x509_san_dns:rp.example.com"
}
```

```json
{
  "success": true,
  "message": "Credential verified successfully",
  "verification_details": {
    "signature_valid": true,
    "not_expired": true,
    "issuer_trusted": true
  },
  "attestation": "eyJhbGciOiJFUzI1NiIsImtpZCI6..."
}
```

## POST /ewqwe_api/openid4vp/init

Starts a new OpenID4VP transaction. This endpoint requires a client certificate.

### Request body

The request body is a JSON object.

| Field              | Type   | Required | Description                                                                                 |
| :----------------- | :----- | :------- | :------------------------------------------------------------------------------------------ |
| `dcql_query`       | object | No       | Digital Credentials Query Language query. A default age query is used when omitted.         |
| `nonce`            | string | No       | Request nonce. The server generates one when omitted.                                       |
| `state`            | string | No       | Client state value. The server generates one when omitted.                                  |
| `profile`          | string | No       | Protocol profile, `haip` or `annex-a`.                                                      |
| `credential_type`  | string | No       | Credential shorthand: `mdl`, `national-id`, `proof-of-age`, or `france-identite-numerique`. |
| `client_metadata`  | object | No       | Relying-party metadata shown by the wallet.                                                 |
| `transaction_data` | array  | No       | Base64url-encoded transaction data entries.                                                 |

The server builds the `response_uri` and the `request_uri` from `public_root_url`, or from the incoming request when `public_root_url` is not set. See [Credential verifier configuration](./configuration.md).

### Response body

| Field                       | Type    | Present      | Description                                                |
| :-------------------------- | :------ | :----------- | :--------------------------------------------------------- |
| `transaction_id`            | string  | Always       | Identifier used for later status polling.                  |
| `client_id`                 | string  | Always       | Constructed client identifier.                             |
| `client_id_scheme`          | string  | Always       | Client identifier scheme, for example `x509_san_dns`.      |
| `request_uri`               | string  | Always       | URI where the wallet fetches the authorization request.    |
| `authorization_request_uri` | string  | Always       | Full authorization request URI for a QR code or deep link. |
| `expires_in`                | integer | Always       | Seconds until the transaction expires.                     |
| `profile`                   | string  | Always       | Selected protocol profile.                                 |
| `qr_code_data_url`          | string  | Cross-device | QR code as an `image/svg+xml` data URL.                    |

### Status codes

| Status | Condition                                     |
| :----- | :-------------------------------------------- |
| `200`  | The transaction was created.                  |
| `400`  | The request body is invalid.                  |
| `401`  | No authenticated user is present.             |
| `500`  | A configuration or internal failure occurred. |

## POST /ewqwe_api/openid4vp/direct_post

Receives the wallet authorization response. This endpoint does not require a client certificate.

### Request body

The server accepts two content types.

For `application/x-www-form-urlencoded`, the server reads these form parameters.

| Parameter                 | Required                               | Description                             |
| :------------------------ | :------------------------------------- | :-------------------------------------- |
| `vp_token`                | For a plain response                   | The VP token.                           |
| `state`                   | For a plain response                   | Transaction state echoed by the wallet. |
| `presentation_submission` | No                                     | Presentation submission string.         |
| `response`                | For a JWE response (`direct_post.jwt`) | Encrypted authorization response.       |
| `error`                   | For a wallet error response            | OpenID4VP error code.                   |
| `error_description`       | No                                     | Human-readable error description.       |

For `application/json`, the server reads the same fields as a JSON object.

When the wallet sends an `error` parameter, the server records a wallet error and does not expect a VP token.

### Response body

On success the server returns status `200`, the content type `application/json`, and an empty JSON object `{}`.

### Status codes

| Status | Condition                                                     |
| :----- | :------------------------------------------------------------ |
| `200`  | The response was stored.                                      |
| `400`  | The body is malformed or the state is unknown.                |
| `404`  | No transaction matches the state.                             |
| `410`  | The transaction has expired.                                  |
| `500`  | A cryptographic, configuration, or internal failure occurred. |

## GET and POST /ewqwe_api/openid4vp/request/{id}

Returns the authorization request for a transaction. The wallet fetches this URI from the `request_uri` value. This endpoint does not require a client certificate.

### Path parameter

| Parameter | Type   | Description                 |
| :-------- | :----- | :-------------------------- |
| `id`      | string | The transaction identifier. |

### Response body

The response body is either a signed JAR (JWT-secured authorization request) or a plain JSON object, depending on the profile.

| Profile | Content type                      | Body                              |
| :------ | :-------------------------------- | :-------------------------------- |
| HAIP    | `application/oauth-authz-req+jwt` | Signed JAR JWT.                   |
| Annex A | `application/json`                | Plain authorization request JSON. |

### Status codes

| Status | Condition                     |
| :----- | :---------------------------- |
| `200`  | The request is returned.      |
| `404`  | The transaction is unknown.   |
| `410`  | The transaction has expired.  |
| `500`  | An internal failure occurred. |

## GET /ewqwe_api/openid4vp/status/{id}

Returns the status of a transaction. This endpoint requires a client certificate.

### Path parameter

| Parameter | Type   | Description                 |
| :-------- | :----- | :-------------------------- |
| `id`      | string | The transaction identifier. |

### Response body

| Field                    | Type    | Present                           | Description                                                   |
| :----------------------- | :------ | :-------------------------------- | :------------------------------------------------------------ |
| `status`                 | string  | Always                            | One of `pending`, `received`, `verified`, `error`, `expired`. |
| `expires_in`             | integer | When `pending`                    | Seconds until expiry.                                         |
| `authorization_response` | object  | When `received`                   | The wallet authorization response.                            |
| `nonce`                  | string  | When `received`                   | Nonce from the original authorization request.                |
| `transaction_data`       | array   | When `received`                   | Transaction data from the original request.                   |
| `wallet_error`           | object  | When the wallet returned an error | Wallet error code and description.                            |
| `error_message`          | string  | On a server error                 | Server error description.                                     |

The `authorization_response` object holds `vp_token`, `state`, and an optional `presentation_submission`.

The `status` value has the meanings below.

| Value      | Meaning                                     |
| :--------- | :------------------------------------------ |
| `pending`  | Waiting for the wallet response.            |
| `received` | Wallet response received, not yet verified. |
| `verified` | Credential verified successfully.           |
| `error`    | Verification or processing failed.          |
| `expired`  | Transaction TTL exceeded.                   |

### Status codes

| Status | Condition                     |
| :----- | :---------------------------- |
| `200`  | The status is returned.       |
| `404`  | The transaction is unknown.   |
| `410`  | The transaction has expired.  |
| `500`  | An internal failure occurred. |

## GET /ewqwe_api/openid4vp/.well-known/jwks.json

Returns the public JSON Web Key Set (JWKS). This endpoint does not require a client certificate.

### Response body

The response content type is `application/jwk-set+json`. The body holds a `keys` array with up to two groups of keys.

| Key                          | Present      | Purpose                                                  |
| :--------------------------- | :----------- | :------------------------------------------------------- |
| JAR signing key              | HAIP profile | Lets the wallet verify the signed authorization request. |
| Attestation verification key | Always       | Lets the relying party verify a signed attestation JWT.  |

The attestation verification key is an EC P-256 key with `alg` set to `ES256`. The key carries the fields `kty`, `crv`, `use`, `alg`, `kid`, `x`, `y`, and `x5c`. The `kid` value is the base64url (no padding) SHA-256 fingerprint of the certificate. The same `kid` appears in the header of every attestation JWT.

### Status codes

| Status | Condition                |
| :----- | :----------------------- |
| `200`  | The key set is returned. |

## GET /ewqwe_api/.well-known/issuer_certs

Returns the trusted credential issuer CA certificates. This endpoint requires a client certificate.

### Query parameters

| Parameter  | Type    | Default | Description                                   |
| :--------- | :------ | :------ | :-------------------------------------------- |
| `cert_pem` | boolean | `false` | Include the PEM encoding of each certificate. |

### Response body

| Field    | Type    | Description                        |
| :------- | :------ | :--------------------------------- |
| `loaded` | boolean | The server loaded at least one CA. |
| `count`  | integer | Number of trusted CA certificates. |
| `certs`  | array   | One object per CA certificate.     |

Each entry in `certs` holds these fields.

| Field        | Type   | Present              | Description                      |
| :----------- | :----- | :------------------- | :------------------------------- |
| `subject`    | string | Always               | Certificate Subject Common Name. |
| `issuer`     | string | Always               | Certificate Issuer Common Name.  |
| `not_before` | string | Always               | Validity start.                  |
| `not_after`  | string | Always               | Validity end.                    |
| `cert_pem`   | string | When `cert_pem=true` | Certificate in PEM encoding.     |

### Status codes

| Status | Condition                         |
| :----- | :-------------------------------- |
| `200`  | The certificate list is returned. |
| `401`  | No authenticated user is present. |

## Journal endpoints

The journal endpoints return the append-only verification journal of the authenticated user. Each endpoint requires a client certificate, and the authenticated username must match the `{username}` path parameter. When the journal is disabled, the journal store is absent and a request to these paths returns an internal server error.

See the [Verification journal](./verification-journal.md) page for the entry schema.

### GET /ewqwe_api/journal/{username}/entries

Returns the recent journal entries of the user, newest first, as human-readable views.

| Query parameter | Type    | Default | Description                                                     |
| :-------------- | :------ | :------ | :-------------------------------------------------------------- |
| `limit`         | integer | `20`    | Maximum entries. The server caps the value at 1000.             |
| `before`        | string  | —       | Return entries created strictly before this RFC 3339 timestamp. |
| `after`         | string  | —       | Return entries created strictly after this RFC 3339 timestamp.  |

Each entry holds these fields.

| Field                   | Type    | Description                                   |
| :---------------------- | :------ | :-------------------------------------------- |
| `created_at`            | string  | Entry creation time in RFC 3339 format.       |
| `qrcode_app_user_email` | string  | Email of the verifier app user, when present. |
| `success`               | boolean | Whether the verification succeeded.           |
| `claims`                | object  | Flattened credential claims.                  |

### GET /ewqwe_api/journal/{username}/verify

Recomputes every entry hash from the first entry and checks the chain.

| Field              | Type    | Description                             |
| :----------------- | :------ | :-------------------------------------- |
| `username`         | string  | The journal owner.                      |
| `valid`            | boolean | `true` when every hash matches.         |
| `entries_verified` | integer | Number of entries checked.              |
| `first_entry_hash` | string  | Hash of the first entry, when present.  |
| `last_entry_hash`  | string  | Hash of the current head, when present. |
| `error`            | string  | Reason when `valid` is `false`.         |

### GET /ewqwe_api/journal/{username}/download

Returns the matching journal entries as a JSON file. The server sets the header `Content-Disposition: attachment` with the file name `journal_{username}.json`.

| Query parameter | Type    | Default | Description                                                     |
| :-------------- | :------ | :------ | :-------------------------------------------------------------- |
| `before`        | string  | —       | Return entries created strictly before this RFC 3339 timestamp. |
| `after`         | string  | —       | Return entries created strictly after this RFC 3339 timestamp.  |
| `limit`         | integer | All     | Maximum entries.                                                |

Unlike the `/entries` endpoint, the download returns the full journal entry, including the chain hash fields.

### Journal status codes

| Status | Condition                                                         |
| :----- | :---------------------------------------------------------------- |
| `200`  | The result is returned.                                           |
| `401`  | No authenticated user is present, or the username does not match. |
| `500`  | The journal is disabled, or a storage failure occurred.           |

## GET /version

Returns the server version. This endpoint does not require a client certificate.

### Response body

| Field     | Type   | Description                               |
| :-------- | :----- | :---------------------------------------- |
| `version` | string | The compiled credential verifier version. |

```json
{
  "version": "0.1.0"
}
```

### Status codes

| Status | Condition                |
| :----- | :----------------------- |
| `200`  | The version is returned. |
