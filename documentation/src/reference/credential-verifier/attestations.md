# Attestations

The credential verifier returns a signed attestation after it processes a presentation. This page documents the attestation format, the signing algorithms, and every claim.

## Purpose

An attestation is the verifier's signed statement about a verification event. It records the verification result, the credential metadata, and the verified credential claims. The relying party verifies the attestation signature and then reads the claims it needs.

## JWT format

The `POST /ewqwe_api/verify` endpoint returns the attestation in the `attestation` field of its response. See the [HTTP API](./http-api.md) page for the full response.

The attestation is a JSON Web Token (JWT) in compact serialization. It has three dot-separated parts: a header, a payload, and a signature.

### Header

| Header parameter | Value                                                                      |
| :--------------- | :------------------------------------------------------------------------- |
| `alg`            | `ES256`                                                                    |
| `kid`            | Base64url (no padding) SHA-256 fingerprint of the signing certificate DER. |

The `kid` value matches the `kid` of the attestation verification key in the published JSON Web Key Set (JWKS). The relying party uses this value to select the correct key.

### Claims

| Claim             | Type    | Present  | Description                                                                 |
| :---------------- | :------ | :------- | :-------------------------------------------------------------------------- |
| `iss`             | string  | Always   | Issuer. The Subject Common Name (CN) of the attestation issuer certificate. |
| `sub`             | string  | Always   | Subject. The transaction identifier that triggered the attestation.         |
| `aud`             | string  | Always   | Audience. The relying-party `client_id`.                                    |
| `iat`             | integer | Always   | Issued-at time as a Unix timestamp.                                         |
| `exp`             | integer | Always   | Expiration time as a Unix timestamp.                                        |
| `nbf`             | integer | Always   | Not-before time as a Unix timestamp.                                        |
| `jti`             | string  | Always   | Unique attestation identifier in UUIDv4 format.                             |
| `verified`        | boolean | Always   | The verification outcome.                                                   |
| `nonce`           | string  | Optional | The nonce from the request.                                                 |
| `doc_type`        | string  | Optional | The credential document type, for example `org.iso.18013.5.1.mDL`.          |
| `namespace`       | string  | Optional | The credential namespace, for example `org.iso.18013.5.1`.                  |
| credential claims | varies  | Optional | The verified credential claims, flattened into the payload.                 |

The credential claims are not fixed fields. The server flattens the verified claims of the presentation into the top level of the payload. A relying party reads a claim such as `age_over_18` or `given_name` directly from the payload.

When the request carries no transaction, the server generates a fresh UUID for the `sub` claim. The `nonce` claim is present when the presentation or the stored transaction provides a nonce.

> [!NOTE]
> The server returns an attestation in both the success and the failure response of `POST /ewqwe_api/verify`. Treat the `success` field of the response as the authoritative verification result.

### Validity

| Claim | Value                                      |
| :---- | :----------------------------------------- |
| `iat` | The time the server signs the attestation. |
| `exp` | `iat` plus 300 seconds.                    |
| `nbf` | `iat` minus 5 seconds.                     |

The 5-second allowance before `iat` absorbs clock skew between the server and the relying party.

### Example payload

```json
{
  "iss": "ewqwe.acme.com",
  "sub": "f7c1a2e0-5b3d-4a9c-9f21-8d2e6b0a1c34",
  "aud": "x509_san_dns:rp.example.com",
  "exp": 1770000300,
  "iat": 1770000000,
  "nbf": 1769999995,
  "jti": "550e8400-e29b-41d4-a716-446655440000",
  "verified": true,
  "nonce": "8f14e45fceea167a5a36dedd4bea2543",
  "doc_type": "eu.europa.ec.av.1",
  "namespace": "eu.europa.ec.av.1",
  "age_over_18": true
}
```

## COSE and CBOR format

The library also supports a CBOR-based attestation that has the same claim set. The format is a COSE_Sign1 structure as defined by RFC 8152.

| Part             | Content                                                             |
| :--------------- | :------------------------------------------------------------------ |
| Protected header | The `alg` identifier and an optional key identifier.                |
| Payload          | The CBOR serialization of the attestation claims.                   |
| Signature        | The signature over the `Sig_structure` of the COSE_Sign1 structure. |

The ECDSA signature uses the fixed-length format of COSE: the `r` and `s` values, each 32 bytes for the P-256 curve. The RSA signature uses PKCS#1 v1.5 with SHA-256.

A verifier parses the CBOR bytes, rebuilds the `Sig_structure`, checks the signature with the public key, and then deserializes the payload into the claim set.

## Signing algorithms

The table below lists the algorithms of the two signer types.

| Format | Algorithm | Identifier | Description                             |
| :----- | :-------- | :--------- | :-------------------------------------- |
| JWT    | ES256     | `ES256`    | ECDSA with the P-256 curve and SHA-256. |
| JWT    | RS256     | `RS256`    | RSA PKCS#1 v1.5 with SHA-256.           |
| COSE   | ES256     | `-7`       | ECDSA with the P-256 curve and SHA-256. |
| COSE   | RS256     | `-257`     | RSA PKCS#1 v1.5 with SHA-256.           |

The `POST /ewqwe_api/verify` endpoint signs the attestation with ES256.

## Signing keys

| Setting                          | Role                                                                                    |
| :------------------------------- | :-------------------------------------------------------------------------------------- |
| `attestation_issuer_certificate` | The PEM certificate. Its CN becomes `iss`, and its public key verifies the attestation. |
| `attestation_issuer_key`         | The PEM private key that signs the attestation.                                         |

When both settings are omitted, the server uses `tls_params.server_certificate` and `tls_params.server_private_key`. See [Configuration](./configuration.md) for the defaults.

The server reads the private key from disk for each signature operation.

## Verification by the relying party

The relying party verifies an attestation against these checks.

| Check            | Action                                                                            |
| :--------------- | :-------------------------------------------------------------------------------- |
| Key retrieval    | Fetch the JSON Web Key Set from `GET /ewqwe_api/openid4vp/.well-known/jwks.json`. |
| Key selection    | Select the key whose `kid` matches the `kid` of the JWT header.                   |
| Signature        | Verify the JWT signature with the public key of that key.                         |
| Audience         | Compare the `aud` claim with the relying-party identifier.                        |
| Validity window  | Compare the `exp` and `nbf` claims with the current time.                         |
| Claim extraction | Read the credential claims from the payload.                                      |

The JWKS endpoint returns the attestation key as an EC P-256 key with `alg` set to `ES256`. The key includes the `x5c` certificate chain, so a relying party can also verify the key against a trusted certificate.
