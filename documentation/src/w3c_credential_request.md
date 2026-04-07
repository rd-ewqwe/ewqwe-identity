# W3C Digital Credentials API - Integration Guide

## Overview

This document describes how the EU Age Verification web app requests credentials from the wallet extension using the **W3C Digital Credentials API**. This is the primary protocol for same-device credential presentation as specified in the [EU Age Verification Profile](https://ageverification.dev/Technical%20Specification/annexes/annex-A/annex-A-av-profile).

## Normative References

| Specification | URL | Description |
|---------------|-----|-------------|
| W3C Digital Credentials API | <https://wicg.github.io/digital-credentials/> | Browser API for requesting digital credentials |
| W3C Credential Management Level 1 | <https://www.w3.org/TR/credential-management-1/> | Base credential management API |
| OpenID for Verifiable Presentations (OpenID4VP) 1.0 | <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html> | Protocol for requesting and presenting VPs |
| ISO/IEC 18013-5:2021 | <https://www.iso.org/standard/69084.html> | Mobile driving licence (mDL) standard |
| EU Age Verification Profile | <https://ageverification.dev> | EU-specific age verification profile |

## W3C Digital Credentials API

### Browser Support

The Digital Credentials API is a new web standard currently in development. It extends the Credential Management API (`navigator.credentials`) with support for digital identity credentials.

```typescript
// Feature detection
if (typeof globalThis.DigitalCredential !== "undefined") {
  // Native Digital Credentials API is available
}
```

### API

The Digital Credentials API adds the `digital` option to `navigator.credentials.get()`:

```typescript
interface CredentialRequestOptions {
  digital?: DigitalCredentialRequestOptions;
}

interface DigitalCredentialRequestOptions {
  requests: DigitalCredentialRequest[];
}

interface DigitalCredentialRequest {
  protocol: string;           // e.g., "openid4vp", "org-iso-mdoc"
  data: object;               // Protocol-specific request data
}
```

## Request Flow

### 1. Building the Presentation Request

The web app constructs an OpenID4VP-compatible presentation request:

```typescript
// From web app/src/credentials.ts

const request: OpenID4VPRequest = {
  // Client identification
  client_id: window.location.origin,        // "http://localhost:5174"
  client_id_scheme: "redirect_uri",         // How client_id should be validated
  
  // Response configuration  
  response_type: "vp_token",                // Request a Verifiable Presentation
  response_mode: "direct_post",             // VP will be POSTed back
  
  // Security
  nonce: crypto.randomUUID(),               // Prevents replay attacks
  state: crypto.randomUUID(),               // Correlates request/response
  
  // What credentials are requested
  presentation_definition: {
    id: crypto.randomUUID(),
    name: "Proof of Age Verification",
    purpose: "Verify identity using Proof of Age",
    input_descriptors: [{
      id: "proof-of-age_credential",
      name: "Proof of Age (EU AV)",
      purpose: "We need to verify your proof of age",
      format: {
        mso_mdoc: {
          alg: ["ES256", "ES384", "ES512", "EdDSA"]
        }
      },
      constraints: {
        limit_disclosure: "required",       // Only disclose requested claims
        fields: [{
          path: ["$['eu.europa.ec.av.1']['age_over_18']"],
          id: "age_over_18",
          name: "Age Over 18",
          intent_to_retain: false           // Will not store the claim
        }]
      }
    }]
  },
  
  // RP metadata
  client_metadata: {
    client_name: "Digital Credentials Demo",
    client_purpose: "Identity verification for demo purposes",
    vp_formats: {
      mso_mdoc: { alg: ["ES256", "ES384", "ES512", "EdDSA"] },
      jwt_vp: { alg: ["ES256", "ES384", "ES512", "EdDSA"] }
    }
  }
};
```

### 2. Requesting Credentials via Native API

When the native Digital Credentials API is available:

```typescript
// From web app/src/credentials.ts

const credential = await navigator.credentials.get({
  digital: {
    requests: [{
      protocol: "openid4vp",
      data: request
    }]
  }
});

// Result is a DigitalCredential
const digitalCredential = credential as {
  protocol: string;           // "openid4vp"
  data: OpenID4VPResponse;    // The VP token and submission
};
```

### 3. Fallback: Extension Communication via postMessage

When the native API is unavailable, web appbapp communicates with the wallet extension via `postMessage`:

```typescript
// From web app/src/credentials.ts

// Send request to extension's content script
window.postMessage({
  type: "EU_AV_WALLET_REQUEST",
  requestId: crypto.randomUUID(),
  payload: {
    protocol: "openid4vp",
    data: request
  }
}, "*");

// Listen for response
window.addEventListener("message", (event) => {
  if (event.data?.type === "EU_AV_WALLET_RESPONSE" &&
      event.data?.requestId === requestId) {
    const { response, error, cancelled } = event.data.payload;
    // Handle response...
  }
});
```

### 4. Extension Content Script Handling

The wallet extension's content script receives and processes requests:

```typescript
// From wallet-extension/content/content-script.ts

window.addEventListener("message", (event) => {
  if (event.source !== window) return;
  
  if (event.data?.type === "EU_AV_WALLET_REQUEST") {
    handleWalletRequest(event.data.payload, event.data.requestId);
  }
});

async function handleWalletRequest(payload, requestId) {
  // Forward to background worker
  const response = await runtime.sendMessage({
    type: "DC_API_REQUEST",
    request: payload
  });
  
  // Get matching credentials
  const matchingCredentials = response.matchingCredentials;
  
  // Show credential selector UI
  const selectedCredential = await showCredentialSelector(matchingCredentials);
  
  // Build and send VP response
  const vpResponse = buildVPResponse(selectedCredential, payload);
  
  window.postMessage({
    type: "EU_AV_WALLET_RESPONSE",
    requestId,
    payload: { response: vpResponse }
  }, "*");
}
```

## Request Parameters

### OpenID4VPRequest

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `client_id` | string | ✓ | Identifier of the Relying Party (e.g., origin URL) |
| `client_id_scheme` | string | ✓ | How to validate client_id: `redirect_uri`, `x509_san_dns`, `verifier_attestation` |
| `response_type` | string | ✓ | Always `vp_token` for VP requests |
| `response_mode` | string | ✓ | `direct_post` (cross-device) or `fragment` (same-device) |
| `nonce` | string | ✓ | Unique value for replay protection, bound to the presentation |
| `state` | string | | Optional state to correlate request/response |
| `presentation_definition` | object | ✓ | Defines what credentials and claims are requested |
| `client_metadata` | object | | RP metadata (name, purpose, supported formats) |

### PresentationDefinition

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `id` | string | ✓ | Unique identifier for this presentation definition |
| `name` | string | | Human-readable name |
| `purpose` | string | | Why the credential is being requested |
| `input_descriptors` | array | ✓ | Array of credential requirements |

### InputDescriptor

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `id` | string | ✓ | Unique identifier (e.g., `proof-of-age_credential`) |
| `name` | string | | Human-readable credential name |
| `purpose` | string | | Why this specific credential is needed |
| `format` | object | ✓ | Acceptable credential formats (`mso_mdoc`, `jwt_vp`) |
| `constraints` | object | ✓ | Constraints on the credential |

### Constraints

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `limit_disclosure` | string | | `required` = only disclose requested claims |
| `fields` | array | ✓ | Specific claims being requested |

### ConstraintField

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `path` | string[] | ✓ | JSONPath to the claim (e.g., `$['namespace']['claim']`) |
| `id` | string | | Identifier for the claim |
| `name` | string | | Human-readable claim name |
| `intent_to_retain` | boolean | | Whether RP will store the claim value |

## Response Format

### OpenID4VPResponse

```typescript
interface OpenID4VPResponse {
  // The Verifiable Presentation token (JSON-stringified)
  vp_token: string;
  
  // Describes how the VP maps to the request
  presentation_submission: {
    id: string;
    definition_id: string;
    descriptor_map: [{
      id: string;           // Matches input_descriptor.id
      format: string;       // e.g., "mso_mdoc"
      path: string;         // JSONPath to the credential in vp_token
    }]
  };
  
  // Echoed from request
  state?: string;
  nonce: string;
}
```

### VP Token Structure (Proof of Age)

```json
{
  "docType": "eu.europa.ec.av.1",
  "namespace": "eu.europa.ec.av.1",
  "claims": {
    "age_over_18": true
  },
  "issuer": "Government ID Authority",
  "issuedAt": "2025-01-01T00:00:00.000Z",
  "expiresAt": "2026-04-01T00:00:00.000Z"
}
```

## Credential Types

### Supported Document Types

| Type | docType | Namespace | Description |
|------|---------|-----------|-------------|
| Mobile Driver's License | `org.iso.18013.5.1.mDL` | `org.iso.18013.5.1` | ISO 18013-5 compliant mDL |
| EU Personal ID | `eu.europa.ec.eudi.pid.1` | `eu.europa.ec.eudi.pid.1` | EU Digital Identity PID |
| Proof of Age | `eu.europa.ec.av.1` | `eu.europa.ec.av.1` | EU Age Verification attestation |

### Available Claims by Type

#### Proof of Age (`eu.europa.ec.av.1`)

| Claim | Type | Description |
|-------|------|-------------|
| `age_over_18` | boolean | Subject is 18 or older |

#### Mobile Driver's License (`org.iso.18013.5.1`)

| Claim | Type | Description |
|-------|------|-------------|
| `family_name` | string | Family name |
| `given_name` | string | Given names |
| `birth_date` | string | Date of birth (full-date) |
| `age_over_18` | boolean | Subject is 18 or older |
| `age_over_21` | boolean | Subject is 21 or older |
| `portrait` | bytes | Photo of the holder |
| `document_number` | string | License number |
| `issuing_authority` | string | Issuing authority name |
| `issuing_country` | string | ISO 3166-1 alpha-2 country code |

## Security Considerations

### Nonce Binding

The `nonce` parameter MUST be:

1. Generated fresh for each request using cryptographically secure randomness
2. Bound to the VP token in the response
3. Verified by the Credential Verifier to prevent replay attacks

```typescript
// Request
const nonce = crypto.randomUUID();  // "f5059300-5812-4e21-a679-f0668f0ff795"

// Response must include same nonce
assert(response.nonce === nonce);
```

### Origin Validation

The wallet extension validates the requesting origin before showing credentials:

```typescript
// Content script validates origin
const siteInfo = window.location.origin;  // Shown to user in credential selector
```

### Selective Disclosure

When `limit_disclosure: "required"` is set:

- Wallet MUST only reveal the specifically requested claims
- Other claims in the credential remain hidden
- Supports privacy-preserving age verification (reveal `age_over_18` without revealing exact birth date)

## Implementation Status

| Feature | Status | Notes |
|---------|--------|-------|
| Native Digital Credentials API | ⏳ Fallback | Uses postMessage when native API unavailable |
| OpenID4VP presentation_definition | ✅ Implemented | Full support |
| mso_mdoc format | ✅ Simulated | Signature verification simulated |
| Selective disclosure | ✅ Implemented | Claims filtering in extension |
| Nonce verification | ✅ Implemented | Bound in response |

## Next Steps

- [ ] Add OpenID4VP cross-device flow documentation
- [ ] Add DCQL (Digital Credentials Query Language) support
- [ ] Add real mDoc signature verification
- [ ] Add issuer trust list management
