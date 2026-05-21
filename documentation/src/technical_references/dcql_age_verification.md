# DCQL Age Verification Queries

This document defines the Digital Credentials Query Language (DCQL) queries used in the EU Age Verification system, implementing the [EU Age Verification Profile](https://ageverification.dev/Technical%20Specification/annexes/annex-A/annex-A-av-profile).

**Related Documentation**:

- For complete credential attribute specifications and authoritative references, see [Credential Type Specifications](./credential_type_specifications.md)
- For how these queries are used in the demo webapp and wallet communication, see [Webapp -> Wallet Communication Protocol](./webapp_wallet_communication.md)

## Overview

DCQL (Digital Credentials Query Language) is defined in [OpenID4VP Section 6](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6). It allows Relying Parties to specify which credentials and claims they require from the Wallet.

For age verification, we primarily request the `age_over_18` claim from the EU Age Verification namespace.

## Credential Namespaces

DCQL queries reference credential attributes using namespace paths. The primary namespaces for age verification are:

| Namespace           | Description                                  | Specification |
|---------------------|----------------------------------------------|---------------|
| `eu.europa.ec.av.1` | EU Age Verification namespace (Proof of Age) | [EU Age Verification Profile](https://ageverification.dev/Technical%20Specification/annexes/annex-A/annex-A-av-profile) |
| `org.iso.18013.5.1` | ISO mDL namespace (Mobile Driver License)    | [ISO/IEC 18013-5:2021](https://www.iso.org/standard/69084.html) |

For complete attribute listings and encoding formats, see [Credential Type Specifications](./credential_type_specifications.md).

## Age Verification DCQL Query

### Minimal Age Verification Request

The simplest age verification request asks only for `age_over_18`:

```json
{
  "credentials": [
    {
      "id": "proof_of_age",
      "format": "mso_mdoc",
      "meta": {
        "doctype_value": "eu.europa.ec.av.1"
      },
      "claims": [
        {
          "path": ["eu.europa.ec.av.1", "age_over_18"]
        }
      ]
    }
  ]
}
```

### Age Verification with Age Over 21

For jurisdictions requiring age 21+:

```json
{
  "credentials": [
    {
      "id": "proof_of_age",
      "format": "mso_mdoc",
      "meta": {
        "doctype_value": "eu.europa.ec.av.1"
      },
      "claims": [
        {
          "path": ["eu.europa.ec.av.1", "age_over_21"]
        }
      ]
    }
  ]
}
```

### Age Verification with Value Matching

Request age verification only if the claim value is `true`:

```json
{
  "credentials": [
    {
      "id": "proof_of_age",
      "format": "mso_mdoc",
      "meta": {
        "doctype_value": "eu.europa.ec.av.1"
      },
      "claims": [
        {
          "path": ["eu.europa.ec.av.1", "age_over_18"],
          "values": [true]
        }
      ]
    }
  ]
}
```

### Fallback: mDL Age Verification

If the user doesn't have an EU Proof of Age but has an mDL:

```json
{
  "credentials": [
    {
      "id": "age_from_mdl",
      "format": "mso_mdoc",
      "meta": {
        "doctype_value": "org.iso.18013.5.1.mDL"
      },
      "claims": [
        {
          "path": ["org.iso.18013.5.1", "age_over_18"]
        }
      ]
    }
  ]
}
```

### Multiple Credential Options

Request age proof from either EU AV or mDL (Wallet chooses one):

```json
{
  "credentials": [
    {
      "id": "eu_age_proof",
      "format": "mso_mdoc",
      "meta": {
        "doctype_value": "eu.europa.ec.av.1"
      },
      "claims": [
        {
          "path": ["eu.europa.ec.av.1", "age_over_18"]
        }
      ]
    },
    {
      "id": "mdl_age_proof",
      "format": "mso_mdoc",
      "meta": {
        "doctype_value": "org.iso.18013.5.1.mDL"
      },
      "claims": [
        {
          "path": ["org.iso.18013.5.1", "age_over_18"]
        }
      ]
    }
  ],
  "credential_sets": [
    {
      "options": [
        ["eu_age_proof"],
        ["mdl_age_proof"]
      ]
    }
  ]
}
```

## Complete OpenID4VP Authorization Request

### Same-Device Flow

```
GET /authorize?
  response_type=vp_token
  &response_mode=fragment
  &client_id=redirect_uri%3Ahttps%3A%2F%2Frp.example.com%2Fcallback
  &redirect_uri=https%3A%2F%2Frp.example.com%2Fcallback
  &nonce=n-0S6_WzA2Mj
  &dcql_query=%7B%22credentials%22%3A%5B%7B%22id%22%3A%22proof_of_age%22%2C%22format%22%3A%22mso_mdoc%22%2C%22meta%22%3A%7B%22doctype_value%22%3A%22eu.europa.ec.av.1%22%7D%2C%22claims%22%3A%5B%7B%22path%22%3A%5B%22eu.europa.ec.av.1%22%2C%22age_over_18%22%5D%7D%5D%7D%5D%7D
```

Decoded `dcql_query`:

```json
{
  "credentials": [
    {
      "id": "proof_of_age",
      "format": "mso_mdoc",
      "meta": {
        "doctype_value": "eu.europa.ec.av.1"
      },
      "claims": [
        {
          "path": ["eu.europa.ec.av.1", "age_over_18"]
        }
      ]
    }
  ]
}
```

### Cross-Device Flow

```
GET /authorize?
  response_type=vp_token
  &response_mode=direct_post
  &client_id=redirect_uri%3Ahttps%3A%2F%2Frp.example.com%2Fpost
  &response_uri=https%3A%2F%2Frp.example.com%2Fpost
  &nonce=n-0S6_WzA2Mj
  &state=eyJhb...6-sVA
  &dcql_query=...
```

Key differences from same-device:

- `response_mode=direct_post` instead of `fragment`
- `response_uri` instead of `redirect_uri`
- `state` parameter for session correlation

## VP Token Response

The Wallet returns a VP Token containing the presentation:

```json
{
  "proof_of_age": ["<base64url-encoded DeviceResponse>"]
}
```

The DeviceResponse is a CBOR-encoded structure as defined in ISO/IEC 18013-5.

## TypeScript Implementation Example

```typescript
// Build DCQL query for age verification
function buildAgeVerificationQuery(minAge: 18 | 21 = 18): DCQLQuery {
  return {
    credentials: [
      {
        id: "proof_of_age",
        format: "mso_mdoc",
        meta: {
          doctype_value: "eu.europa.ec.av.1"
        },
        claims: [
          {
            path: ["eu.europa.ec.av.1", `age_over_${minAge}`]
          }
        ]
      }
    ]
  };
}

// Build complete authorization request
function buildAuthorizationRequest(
  flow: "same-device" | "cross-device",
  callbackUrl: string,
  minAge: 18 | 21 = 18
): OpenID4VPRequest {
  const nonce = crypto.randomUUID();
  const dcqlQuery = buildAgeVerificationQuery(minAge);
  
  if (flow === "same-device") {
    return {
      response_type: "vp_token",
      response_mode: "fragment",
      client_id: `redirect_uri:${callbackUrl}`,
      redirect_uri: callbackUrl,
      nonce,
      dcql_query: dcqlQuery
    };
  } else {
    return {
      response_type: "vp_token",
      response_mode: "direct_post",
      client_id: `redirect_uri:${callbackUrl}`,
      response_uri: callbackUrl,
      nonce,
      state: crypto.randomUUID(),
      dcql_query: dcqlQuery
    };
  }
}
```

## References

- [EU Age Verification Profile - Annex A](https://ageverification.dev/Technical%20Specification/annexes/annex-A/annex-A-av-profile)
- [OpenID4VP 1.0 - DCQL](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6)
- [ISO/IEC 18013-5 - mDL](https://www.iso.org/standard/69084.html)
