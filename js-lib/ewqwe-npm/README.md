# @ewqwe/digital-identity

npm-compatible JavaScript/TypeScript library for EU Digital Identity (OpenID4VP, DCQL, mDoc, SD-JWT VC).

## Installation

```bash
npm install @ewqwe/digital-identity
```

## Usage

### CommonJS

```javascript
const { buildAgeVerificationQuery, generateNonce } = require('@ewqwe/digital-identity');

const query = buildAgeVerificationQuery(18);
const nonce = generateNonce();
```

### ES Modules

```javascript
import { buildAgeVerificationQuery, generateNonce } from '@ewqwe/digital-identity';

const query = buildAgeVerificationQuery(18);
const nonce = generateNonce();
```

## Features

- **DCQL Query Builders**: Build Digital Credentials Query Language queries for OpenID4VP
- **Credential Types**: Pre-configured credential types (mDL, PID, Proof of Age, etc.)
- **Protocol Profiles**: HAIP and Annex A profile support
- **Attestation Verification**: JWT signature verification using the Web Crypto API in browsers and Node.js
- **Type Definitions**: Full TypeScript support with comprehensive type safety

## Quick Start

### Generate an age verification query

```javascript
import { buildAgeVerificationQuery } from '@ewqwe/digital-identity';

// Generate query for age 18+
const query = buildAgeVerificationQuery(18);
console.log(JSON.stringify(query, null, 2));

// Generate query for age 21+
const query21 = buildAgeVerificationQuery(21);
```

### Build an Init Transaction Request

```javascript
import { buildInitTransactionRequest } from '@ewqwe/digital-identity';

const request = buildInitTransactionRequest(
  'https://example.com',
  'mdl',
  ['given_name', 'family_name', 'birth_date']
);
```

### Generate a Cryptographic Nonce

```javascript
import { generateNonce } from '@ewqwe/digital-identity';

const nonce = generateNonce();
// Returns a base64url-encoded 32-byte random value
```

### Validate a DCQL Query

```javascript
import { isValidDCQLQuery, buildAgeVerificationQuery } from '@ewqwe/digital-identity';

const query = buildAgeVerificationQuery(18);
const validation = isValidDCQLQuery(query);

if (validation.valid) {
  console.log('Valid DCQL query');
} else {
  console.error('Invalid:', validation.error);
}
```

## API Reference

### DCQL Query Functions

| Function | Description |
|----------|-------------|
| `buildAgeVerificationQuery(ageThreshold)` | Build minimal age verification query |
| `buildAgeVerificationQueryWithFallback(ageThreshold)` | Build query with mDL fallback |
| `buildInitTransactionRequest(publicUrl, credentialType, claims)` | Build init transaction request |
| `getDefaultAgeVerificationDCQL()` | Get default age verification query |
| `determineProfile(credentialType, explicitProfile)` | Determine protocol profile |
| `generateNonce()` | Generate cryptographic nonce |
| `isValidDCQLQuery(query)` | Validate DCQL query structure |
| `parseDCQLQuery(queryString)` | Parse DCQL from JSON string |
| `extractAgeThreshold(query)` | Extract age threshold from query |

### Credential Types

```javascript
import { CREDENTIAL_TYPES, getClaimsForType } from '@ewqwe/digital-identity';

// Get all credential types
const types = Object.keys(CREDENTIAL_TYPES);

// Get claims for a specific type
const mdlClaims = getClaimsForType('mdl');
```

### Protocol Profiles

```javascript
import { PROTOCOL_PROFILES, determineProfile } from '@ewqwe/digital-identity';

// Get HAIP profile
const haip = PROTOCOL_PROFILES.haip;

// Determine profile for credential type
const profile = determineProfile('mdl'); // 'haip'
```

### Attestation Verification

```javascript
import { parseAttestation, verifyAttestation } from '@ewqwe/digital-identity';

// Parse and verify attestation from backend response
const attestation = await parseAttestation(jwtToken, '/ewqwe_api/jwks');

// Or verify with pre-imported public key
const publicKey = await importVerifierPublicKey(pemOrSpki);
const claims = await verifyAttestation(jwtToken, publicKey);
```

## License

MIT
