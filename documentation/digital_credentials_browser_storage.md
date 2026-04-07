# Digital Credentials: Browser Storage and Querying

This document explains how digital credentials are stored and queried using the W3C Digital Credentials API, and how this applies to the ewqwe-auth project.

---

## Architecture Overview

The W3C Digital Credentials API **does not store credentials in the browser**. Instead, it provides a mediation layer between:

1. **Relying Parties (Verifiers)** - Websites requesting credential presentations
2. **User Agents (Browsers)** - Mediating the request and presenting a credential chooser
3. **Holders (Wallets)** - Applications that store and manage digital credentials

```
┌─────────────────┐     navigator.credentials.get()     ┌─────────────────┐
│   Relying       │ ──────────────────────────────────> │     Browser     │
│   Party (RP)    │                                     │   (User Agent)  │
│   webapp/       │                                     │                 │
└─────────────────┘                                     └────────┬────────┘
                                                                 │
                                                    Credential Chooser UI
                                                                 │
                                                        ┌────────▼────────┐
                                                        │  Wallet App     │
                                                        │  (Holder)       │
                                                        │  wallet/        │
                                                        └─────────────────┘
```

### Key Points

- **Credentials are stored in wallet applications**, not in the browser's `CredentialsContainer`
- `navigator.credentials.store()` is **not used** for digital credentials
- The browser acts as a **mediator**, not a credential store
- Wallet applications register with the OS/browser to handle credential requests

---

## W3C Digital Credentials API

### Requesting Credentials (Presentation)

The RP requests credentials using `navigator.credentials.get()` with the `digital` option:

```typescript
const credential = await navigator.credentials.get({
  digital: {
    requests: [{
      protocol: "openid4vp-v1-unsigned",
      data: {
        // OpenID4VP Authorization Request
        client_id: "https://rp.example.com",
        response_type: "vp_token",
        response_mode: "fragment",
        nonce: crypto.randomUUID(),
        dcql_query: {
          credentials: [{
            id: "proof_of_age",
            format: "mso_mdoc",
            meta: { doctype_value: "eu.europa.ec.av.1" },
            claims: [{ path: ["eu.europa.ec.av.1", "age_over_18"] }]
          }]
        }
      }
    }]
  }
});
```

### Issuing Credentials

The issuer uses `navigator.credentials.create()` with the `digital` option:

```typescript
const credential = await navigator.credentials.create({
  digital: {
    requests: [{
      protocol: "openid4vci-v1",
      data: {
        // OpenID4VCI Credential Offer
        credential_issuer: "https://issuer.example.com",
        credential_configuration_ids: ["proof_of_age"],
        grants: {
          authorization_code: {
            issuer_state: "state-123"
          }
        }
      }
    }]
  }
});
```

### Supported Protocols

The W3C spec defines these presentation protocols:

| Protocol | Identifier | Description |
|:---------|:-----------|:------------|
| OpenID4VP Unsigned | `openid4vp-v1-unsigned` | OpenID4VP 1.0 without signed requests |
| OpenID4VP Signed | `openid4vp-v1-signed` | OpenID4VP 1.0 with signed requests |
| OpenID4VP Multi-signed | `openid4vp-v1-multisigned` | OpenID4VP 1.0 with multiple signers |
| ISO mDoc | `org-iso-mdoc` | ISO/IEC 18013-7 Annex C |

---

## Credential Storage in This Project

Since browsers don't store digital credentials, our **wallet application** (`wallet/`) acts as the credential holder. The wallet stores credentials in:

1. **Browser Storage** (for demo/testing): `localStorage` or `IndexedDB`
2. **Production**: Platform-specific secure storage (Keychain, Keystore, etc.)

### Sample Credentials

The wallet stores credentials in a format compatible with ISO mDoc presentations:

#### Sample Store Structure

```typescript
interface CredentialStore {
  credentials: StoredCredential[];
}

interface StoredCredential {
  id: string;                    // Unique credential ID
  docType: string;               // e.g., "org.iso.18013.5.1.mDL"
  issuedAt: string;              // ISO 8601 timestamp
  expiresAt: string;             // ISO 8601 timestamp
  issuer: string;                // Issuer identifier
  claims: Record<string, any>;   // Namespace -> claims mapping
  rawCredential: string;         // Base64-encoded mDoc or JWT
}
```

---

## Sample Credentials for Testing

### Mobile Driver's License (mDL)

#### Sample 1: Alice Johnson (California)

```json
{
  "id": "mdl-alice-001",
  "docType": "org.iso.18013.5.1.mDL",
  "issuedAt": "2024-01-15T00:00:00Z",
  "expiresAt": "2029-01-15T00:00:00Z",
  "issuer": "California DMV",
  "claims": {
    "org.iso.18013.5.1": {
      "family_name": "Johnson",
      "given_name": "Alice Marie",
      "birth_date": "1990-05-15",
      "issue_date": "2024-01-15",
      "expiry_date": "2029-01-15",
      "issuing_authority": "California Department of Motor Vehicles",
      "issuing_country": "US",
      "document_number": "D1234567",
      "portrait": "data:image/jpeg;base64,...",
      "driving_privileges": [
        {
          "vehicle_category_code": "C",
          "issue_date": "2024-01-15",
          "expiry_date": "2029-01-15"
        }
      ],
      "age_over_18": true,
      "age_over_21": true,
      "resident_address": "123 Main Street",
      "resident_city": "San Francisco",
      "resident_state": "CA",
      "resident_postal_code": "94102",
      "resident_country": "US"
    }
  }
}
```

#### Sample 2: Bob Smith (Germany)

```json
{
  "id": "mdl-bob-002",
  "docType": "org.iso.18013.5.1.mDL",
  "issuedAt": "2023-06-01T00:00:00Z",
  "expiresAt": "2038-06-01T00:00:00Z",
  "issuer": "Kraftfahrt-Bundesamt",
  "claims": {
    "org.iso.18013.5.1": {
      "family_name": "Schmidt",
      "given_name": "Robert",
      "birth_date": "1985-11-22",
      "issue_date": "2023-06-01",
      "expiry_date": "2038-06-01",
      "issuing_authority": "Kraftfahrt-Bundesamt",
      "issuing_country": "DE",
      "document_number": "B9876543",
      "portrait": "data:image/jpeg;base64,...",
      "driving_privileges": [
        {
          "vehicle_category_code": "B",
          "issue_date": "2005-11-22",
          "expiry_date": "2038-06-01"
        },
        {
          "vehicle_category_code": "A",
          "issue_date": "2010-03-15",
          "expiry_date": "2038-06-01"
        }
      ],
      "age_over_18": true,
      "age_over_21": true,
      "resident_city": "Berlin",
      "resident_country": "DE"
    }
  }
}
```

---

### National ID / Person Identification Data (PID)

#### Sample 1: Marie Dubois (France)

```json
{
  "id": "pid-marie-001",
  "docType": "eu.europa.ec.eudi.pid.1",
  "issuedAt": "2024-03-01T00:00:00Z",
  "expiresAt": "2034-03-01T00:00:00Z",
  "issuer": "ANTS France",
  "claims": {
    "eu.europa.ec.eudi.pid.1": {
      "family_name": "Dubois",
      "given_name": "Marie Claire",
      "birth_date": "1992-08-14",
      "place_of_birth": {
        "locality": "Paris",
        "country": "FR"
      },
      "nationality": ["FR"],
      "expiry_date": "2034-03-01",
      "issuing_authority": "Agence Nationale des Titres Sécurisés",
      "issuing_country": "FR",
      "portrait": "data:image/jpeg;base64,...",
      "resident_address": "45 Rue de la République",
      "resident_city": "Lyon",
      "resident_postal_code": "69001",
      "resident_country": "FR",
      "sex": 2
    }
  }
}
```

#### Sample 2: Jan van der Berg (Netherlands)

```json
{
  "id": "pid-jan-002",
  "docType": "eu.europa.ec.eudi.pid.1",
  "issuedAt": "2024-06-15T00:00:00Z",
  "expiresAt": "2034-06-15T00:00:00Z",
  "issuer": "RvIG Netherlands",
  "claims": {
    "eu.europa.ec.eudi.pid.1": {
      "family_name": "van der Berg",
      "given_name": "Jan Willem",
      "birth_date": "1978-02-28",
      "place_of_birth": {
        "locality": "Amsterdam",
        "country": "NL"
      },
      "nationality": ["NL"],
      "expiry_date": "2034-06-15",
      "issuing_authority": "Rijksdienst voor Identiteitsgegevens",
      "issuing_country": "NL",
      "document_number": "SPECI2024",
      "personal_administrative_number": "999999999",
      "portrait": "data:image/jpeg;base64,...",
      "resident_address": "Herengracht 100",
      "resident_city": "Amsterdam",
      "resident_postal_code": "1015 BS",
      "resident_country": "NL",
      "sex": 1
    }
  }
}
```

---

### Proof of Age (EU Age Verification)

#### Sample 1: Young Adult (Age 19)

```json
{
  "id": "poa-young-001",
  "docType": "eu.europa.ec.av.1",
  "issuedAt": "2025-01-01T00:00:00Z",
  "expiresAt": "2025-04-01T00:00:00Z",
  "issuer": "EU Age Verification Authority",
  "claims": {
    "eu.europa.ec.av.1": {
      "age_over_18": true
    }
  }
}
```

#### Sample 2: Minor (Age 16)

```json
{
  "id": "poa-minor-002",
  "docType": "eu.europa.ec.av.1",
  "issuedAt": "2025-01-01T00:00:00Z",
  "expiresAt": "2025-04-01T00:00:00Z",
  "issuer": "EU Age Verification Authority",
  "claims": {
    "eu.europa.ec.av.1": {
      "age_over_18": false
    }
  }
}
```

---

## Querying Credentials

### From Relying Party (webapp/)

The RP requests credentials using DCQL (Digital Credentials Query Language):

```typescript
import { buildPresentationRequest } from "./credentials.ts";

// Request age verification
const request = buildPresentationRequest("proof-of-age", ["age_over_18"], "openid4vp");

// Make the API call
const credential = await navigator.credentials.get({
  digital: {
    requests: [{
      protocol: "openid4vp-v1-unsigned",
      data: request
    }]
  }
});

// The response is encrypted - send to verifier backend
const result = await fetch("/verify", {
  method: "POST",
  body: JSON.stringify(credential)
});
```

### DCQL Query Examples

#### Request Age Over 18 from mDL

```json
{
  "credentials": [{
    "id": "mdl_age",
    "format": "mso_mdoc",
    "meta": { "doctype_value": "org.iso.18013.5.1.mDL" },
    "claims": [
      { "path": ["org.iso.18013.5.1", "age_over_18"] }
    ]
  }]
}
```

#### Request Identity from PID

```json
{
  "credentials": [{
    "id": "pid_identity",
    "format": "mso_mdoc",
    "meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" },
    "claims": [
      { "path": ["eu.europa.ec.eudi.pid.1", "family_name"] },
      { "path": ["eu.europa.ec.eudi.pid.1", "given_name"] },
      { "path": ["eu.europa.ec.eudi.pid.1", "birth_date"] },
      { "path": ["eu.europa.ec.eudi.pid.1", "nationality"] }
    ]
  }]
}
```

#### Request Proof of Age (EU AV)

```json
{
  "credentials": [{
    "id": "proof_of_age",
    "format": "mso_mdoc",
    "meta": { "doctype_value": "eu.europa.ec.av.1" },
    "claims": [
      { "path": ["eu.europa.ec.av.1", "age_over_18"] }
    ]
  }]
}
```

---

## Wallet Implementation (wallet/)

### Storing Credentials

The wallet stores credentials using browser storage for the demo:

```typescript
// wallet/src/store.ts
const STORAGE_KEY = "ewqwe_credentials";

export function storeCredential(credential: StoredCredential): void {
  const store = getStore();
  store.credentials.push(credential);
  localStorage.setItem(STORAGE_KEY, JSON.stringify(store));
}

export function getStore(): CredentialStore {
  const data = localStorage.getItem(STORAGE_KEY);
  return data ? JSON.parse(data) : { credentials: [] };
}
```

### Matching Credentials to Requests

```typescript
export function findMatchingCredentials(
  query: DCQLQuery
): StoredCredential[] {
  const store = getStore();
  
  return store.credentials.filter(credential => {
    // Match docType
    const docTypeMatch = query.credentials.some(
      q => q.meta?.doctype_value === credential.docType
    );
    
    // Match available claims
    const claimsMatch = query.credentials.some(q => 
      q.claims.every(claim => {
        const [namespace, claimName] = claim.path;
        return credential.claims[namespace]?.[claimName] !== undefined;
      })
    );
    
    return docTypeMatch && claimsMatch;
  });
}
```

### Responding to Presentation Requests

```typescript
export async function handlePresentationRequest(
  request: OpenID4VPRequest
): Promise<OpenID4VPResponse> {
  const matching = findMatchingCredentials(request.dcql_query);
  
  if (matching.length === 0) {
    throw new Error("No matching credentials found");
  }
  
  // User selects credential (UI interaction)
  const selected = await promptUserSelection(matching);
  
  // Create VP Token with selective disclosure
  const vpToken = await createVPToken(selected, request);
  
  return {
    vp_token: vpToken,
    presentation_submission: {
      id: crypto.randomUUID(),
      definition_id: request.dcql_query.credentials[0].id
    }
  };
}
```

---

## Security Considerations

### Browser Storage Limitations

For demo purposes, credentials are stored in `localStorage`. This is **NOT secure** for production:

| Storage | Security | Use Case |
|:--------|:---------|:---------|
| `localStorage` | ❌ Accessible to JS | Demo/Testing only |
| `sessionStorage` | ❌ Accessible to JS | Demo/Testing only |
| `IndexedDB` | ❌ Accessible to JS | Demo/Testing only |
| Platform Keychain | ✅ Hardware-backed | Production |
| Secure Enclave | ✅ Hardware-backed | Production |

### Production Requirements

- Credentials MUST be stored in platform-secure storage
- Private keys MUST never be extractable
- mDoc MUST be signed with a device-bound key
- Key attestation SHOULD verify genuine secure hardware

---

## References

- [W3C Digital Credentials API](https://www.w3.org/TR/digital-credentials/)
- [Credential Management Level 1](https://www.w3.org/TR/credential-management-1/)
- [OpenID for Verifiable Presentations 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
- [ISO/IEC 18013-5:2021 Mobile Driving Licence](https://www.iso.org/standard/69084.html)
- [ISO/IEC 18013-7:2025 mDL Add-on Functions](https://www.iso.org/standard/91154.html)
- [EU Age Verification Profile](https://ageverification.dev/Technical%20Specification/annexes/annex-A/annex-A-av-profile)
