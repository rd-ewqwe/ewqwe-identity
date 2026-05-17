# Annex B (ISO 18013-7) Implementation Plan for the Credential Verifier

This document outlines a step-by-step plan to add **ISO/IEC 18013-7 Annex B** support to the ewQwe credential verifier. Annex B defines how **ISO mDoc** credentials are transported via the **W3C Digital Credentials API** (also known as the **DC API**), using ISO DeviceRequest/DeviceResponse rather than OpenID4VP.

## Why This Matters

The France Identité Wallet and several other national mDL wallets support **Annex B** via the DC API. While our system already supports:

- OpenID4VP (Annex A profile — simpler, `redirect_uri` client_id)
- OpenID4VP HAIP profile (high-assurance, JAR signing)
- mDoc verification (already implemented in `ewqwe_digital_credential`)

…the **transport layer** through which mDoc is received is different for Annex B. Currently our verifier receives mDoc via OpenID4VP (`direct_post` or `direct_post.jwt`). Annex B expects a **W3C Digital Credentials API** call where the browser passes an `encryptionInfo` + `deviceRequest` to the wallet, and the wallet returns an **HPKE-encrypted DeviceResponse**.

## Implementation Scope

The plan is organised into **three phases**:

| Phase | Description | Effort |
|-------|-------------|--------|
| **Phase 1** | Annex B endpoint in the verifier (server-side) | Medium |
| **Phase 2** | DC API client in the webapp (browser-side) | Medium |
| **Phase 3** | End-to-end testing with France Identité Wallet | Low |

---

## Current Architecture (as-is)

```
┌─────────────┐  OpenID4VP  ┌──────────────────────┐
│   Wallet    │ ──────────> │  Credential Verifier  │
│ (mDoc only) │             │  (ewqwe-credential-   │
│             │             │   verifier-server)    │
└─────────────┘             └──────────────────────┘
                                   │
                                   │ ewqwe_openid4vp
                                   │ (transaction mgmt)
                                   ▼
                            ┌───────────────┐
                            │ ewqwe_digital │
                            │ _credential   │
                            │ (mDoc verify) │
                            └───────────────┘
```

The wallet sends a VP Token (DCQL-wrapped) via OpenID4VP `direct_post`; the verifier extracts the base64url-encoded mDoc DeviceResponse and verifies it.

## Target Architecture (with Annex B)

```
┌─────────────┐          ┌──────────────┐         ┌──────────────────────┐
│   Wallet    │ DC API   │   Browser    │  POST   │  Credential Verifier │
│ (mDoc only) │ <─────── │ (W3C DC API) │ ──────> │                      │
│             │          │              │         │  Annex B endpoint    │
└─────────────┘          │ webapp / RP  │         │  (new)               │
                         └──────────────┘         │                      │
                                                  │  ewqwe_openid4vp     │
                                                  │  (unchanged)         │
                                                  │                      │
                                                  │  ewqwe_digital_      │
                                                  │  credential (reuse)  │
                                                  └──────────────────────┘
```

Two parallel paths:
1. **OpenID4VP path** (existing): Wallet → RP proxy → `/ewqwe_api/openid4vp/direct_post`
2. **Annex B path** (new): Wallet ↔ Browser (W3C DC API) → RP post-processor → new verifier endpoint

---

## Phase 1: Annex B Endpoint in the Credential Verifier

### Step 1.1: Create an Annex B Module in the Verifier

Create a new Rust module `crates/ewqwe-credential-verifier-server/src/server/annex_b_endpoints.rs` that implements Annex B server-side logic.

**Key responsibilities:**

1. **Receive HPKE-encrypted DeviceResponse** from the RP webapp (which receives it from the browser)
2. **HPKE decrypt** the ciphertext using the verifier's private key
3. **Extract and verify** the mDoc DeviceResponse (reuse `ewqwe_digital_credential`)
4. **Issue attestation** (same as existing `/verify` endpoint)

**New endpoint:**

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/ewqwe_api/dc_api/verify` | Accept decrypted DeviceResponse + metadata |

**Request format:**

```json
{
    "device_response_b64": "...",
    "nonce": "n-0S6_WzA2Mj",
    "client_id": "verifier.example.com",
    "doc_type": "eu.europa.ec.av.1",
    "requested_claims": ["age_over_18"]
}
```

**Response format:**

```json
{
    "success": true,
    "claims": {
        "eu.europa.ec.av.1": {
            "age_over_18": true
        }
    },
    "attestation_jwt": "eyJ..."
}
```

### Step 1.2: Add HPKE Decryption Support

Annex B uses **HPKE** (RFC 9180) for encrypting the DeviceResponse. The verifier's public key is provided in the `encryptionInfo` when the RP constructs the request.

**Where to add:** Use the existing `crates/ewqwe-openid4vp` or add to a new `crates/ewqwe-annex-b` crate.

```rust
// Proposed API in ewqwe_openid4vp::hpke module
pub fn hpke_decrypt(
    recipient_private_key: &[u8], // PEM-encoded private key
    enc: &[u8],            // HPKE sender's ephemeral public key (from EncryptedResponse)
    ciphertext: &[u8],     // HPKE ciphertext
) -> Result<Vec<u8>, HpkeError>;
```

**Cipher suite (as specified in ISO 18013-7 Annex C):**

| Parameter | Value |
|-----------|-------|
| KEM | DHKEM(X25519, HKDF-SHA256) |
| KDF | HKDF-SHA256 |
| AEAD | AES-128-GCM |
| Info | CBOR-encoded "dcapi" tag + `aad` bytes |

### Step 1.3: Implement the Annex C Wrapper Parsing

ISO 18013-7 Annex C defines the CBOR wrapper:

```rust
// EncryptionInfo (received from RP -> wallet):
// ["dcapi", { nonce: bstr, recipientPublicKey: COSE_Key }]

// EncryptedResponse (received back from wallet):
// ["dcapi", { enc: bstr, cipherText: bstr }]

fn parse_encrypted_response(data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), ...> {
    // Decode CBOR: ["dcapi", { enc: bstr, cipherText: bstr }]
    // Return (enc, cipherText)
}
```

### Step 1.4: Register the Verify Endpoint (Server-Side)

The DC API flow is **stateless** — there is no init endpoint or transaction setup on the verifier. The RP generates the HPKE key pair and nonce locally in the browser. The verifier only needs to serve the verify endpoint that accepts decrypted DeviceResponses.

In `crates/ewqwe-credential-verifier-server/src/server/start.rs`:

```rust
mod annex_b_endpoints;

// In prepare_server():
let app = app.service(
    web::scope("/ewqwe_api")
        .route("/dc_api/verify", web::post().to(annex_b_endpoints::verify_dc_api))
);
```

No additional server configuration is required — the verifier receives already-decrypted DeviceResponses and validates them using the same mDoc verification pipeline as the OpenID4VP path.

### Step 1.5: Add mDoc Verification Reuse

The verification logic for the DeviceResponse is already implemented in `ewqwe_digital_credential`:

```rust
// Reuse existing mDoc verification
use ewqwe_digital_credential::{decode_mdoc_presentation, verify_mdoc_presentation};

// After HPKE decryption:
let presentation = decode_mdoc_presentation(&device_response_b64)?;
let result = verify_mdoc_presentation(
    &device_response_b64,
    &client_id,
    &nonce,
    &"",    // Annex B is direct DC API, no response_uri session binding
    false,  // Annex B uses direct, not JWT mode
    None,   // No JWK thumbprint needed for DC API
    &trusted_cas,
)?;
```

### Step 1.6: Add Test Vectors

Add unit tests with known-good Annex B test vectors:

1. CBOR-encoded `encryptionInfo` with known COSE_Key
2. CBOR-encoded `DeviceRequest` for age verification
3. HPKE-encrypted `DeviceResponse` (test vector)
4. Verification of decrypted DeviceResponse

---

## Phase 2: DC API Client in the Webapp (Browser-Side)

The RP webapp (`webapp/`) needs to initiate the W3C Digital Credentials API call.

### Step 2.1: Create an Annex B Service Module

In `webapp/src/`:

```typescript
// webapp/src/annex_b_service.ts

export interface AnnexBRequest {
  encryptionInfo: string;
  deviceRequest: string;
}

export interface AnnexBResponse {
  encryptedResponse: string;
}

export class AnnexBService {
  buildRequest(
    nonce: Uint8Array,
    recipientPublicKey: CoseKey,
    docType: string,
    requestedClaims: string[]
  ): AnnexBRequest {
    // 1. Build encryptionInfo CBOR
    const encryptionInfoCbor = encodeCbor(["dcapi", { nonce, recipientPublicKey }]);
    const encryptionInfo = base64url(encryptionInfoCbor, { pad: false });

    // 2. Build DeviceRequest CBOR (ISO 18013-5 sec 8.3.2.1.2.1)
    const deviceRequestCbor = encodeCbor({
      version: "1.0",
      docRequests: [{
        docType,
        itemsRequest: {
          nameSpaces: Object.fromEntries(
            requestedClaims.map(claim => [claim, true])
          )
        }
      }]
    });
    const deviceRequest = base64url(deviceRequestCbor, { pad: false });

    return { encryptionInfo, deviceRequest };
  }

  /**
   * Parse the wallet's encrypted response.
   */
  parseResponse(encryptedResponseB64: string): { enc: Uint8Array; cipherText: Uint8Array } {
    const decoded = decodeCbor(base64url.parse(encryptedResponseB64));
    // decoded = ["dcapi", { enc: bstr, cipherText: bstr }]
    const [tag, data] = decoded;
    if (tag !== "dcapi") throw new Error("Unexpected response tag");
    return { enc: data.enc, cipherText: data.cipherText };
  }
}
```

### Step 2.2: Implement the DC API Integration

In the webapp's RP controller (`webapp/src/relying_party_app.ts`):

```typescript
async function initiateDcApiVerification(): Promise<void> {
  // The DC API flow is stateless — generate HPKE key pair + nonce locally
  const { privateKey, publicKeyCoseKey } = await generateHpkeKeyPair();
  const nonceBytes = crypto.getRandomValues(new Uint8Array(16));
  const nonce = base64url(nonceBytes, { pad: false });
  const clientId = window.location.origin;

  const annexB = new AnnexBService();
  const request = annexB.buildRequest(
    nonceBytes,
    publicKeyCoseKey,
    "eu.europa.ec.av.1",
    ["age_over_18"]
  );

  try {
    const credential = await navigator.credentials.get({
      digital: {
        requests: [{
          protocol: "org-iso-mdoc",
          encryptionInfo: request.encryptionInfo,
          deviceRequest: request.deviceRequest
        }]
      }
    });

    const rawResponse = credential.data as string;
    const { enc, cipherText } = annexB.parseResponse(rawResponse);

    const deviceResponseBytes = await hpkeOpen({
      recipientPrivateKey: privateKey,
      enc,
      cipherText
    });

    const verifyResp = await fetch("/ewqwe_api/dc_api/verify", {
      method: "POST",
      body: JSON.stringify({
        device_response_b64: base64url(deviceResponseBytes, { pad: false }),
        nonce,
        client_id: clientId,
        doc_type: "eu.europa.ec.av.1",
        requested_claims: ["age_over_18"]
      })
    });

    const result = await verifyResp.json();
  } catch (err) {
    // Handle errors
  }
}
```

### Step 2.3: Add HPKE Library Dependency

The webapp needs an HPKE library. Update `webapp/deno.json`:

```json
{
  "imports": {
    "hpke-js": "npm:hpke-js@^0.16.0"
  }
}
```

Create an HPKE wrapper module:

```typescript
// webapp/src/hpke.ts
import { CipherSuite } from "hpke-js";
import { DhkemX25519HkdfSha256 } from "hpke-js";
import { Aes128Gcm } from "hpke-js";
import { HkdfSha256 } from "hpke-js";

export async function generateHpkeKeyPair() {
  const suite = new CipherSuite({
    kem: new DhkemX25519HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Aes128Gcm()
  });

  const { publicKey, privateKey } = await suite.kem.generateKeyPair();

  const coseKey = {
    kty: 2,
    crv: 4,
    x: new Uint8Array(publicKey)
  };

  return { privateKey, publicKeyCoseKey: coseKey };
}

export async function hpkeOpen(params: {
  recipientPrivateKey: CryptoKey;
  enc: Uint8Array;
  cipherText: Uint8Array;
}): Promise<Uint8Array> {
  const suite = new CipherSuite({
    kem: new DhkemX25519HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Aes128Gcm()
  });

  const context = await suite.open({
    enc: params.enc,
    recipientPrivateKey: params.recipientPrivateKey
  });

  return context.open(cipherText);
}
```

---

## Phase 3: End-to-End Testing with France Identite Wallet

### Step 3.1: Configure Test Environment

1. Set up the credential verifier with Annex B endpoint enabled
2. Ensure the verifier's CA certificate is installed on the Android device
3. Provision a test mDoc age-over-18 credential to the France Identite Wallet

### Step 3.2: Browser-Based Flow Test

1. Navigate to the webapp on the Android device's Chrome browser
2. Click "Verify Age" (which uses `navigator.credentials.get()`)
3. Verify the France Identite Wallet opens and shows the consent dialog
4. Accept the presentation
5. Verify the device receives the response and the verifier completes verification

### Step 3.3: Test Vectors & Edge Cases

| Test Case | Expected Result |
|-----------|----------------|
| Wallet cancels presentation | Verifier returns error without attestation |
| Nonce mismatch | Verifier rejects with nonce error |
| Expired credential | Verifier returns expired error |
| Missing requested claim | Verifier returns claim not found |
| Wrong document type | Verifier rejects with doc type mismatch |

---

## Dependency Changes

### New Dependencies (Rust)

| Crate | Purpose |
|-------|---------|
| `hpke` (Rust) | HPKE decryption for DeviceResponse |
| `cose` (Rust) | COSE_Key parsing and key extraction |

### New Dependencies (TypeScript)

| Dependency | Purpose |
|------------|---------|
| `hpke-js` | HPKE key generation and decryption |
| `cbor-x` or `cbor` | CBOR encoding/decoding in JavaScript |

---

## Existing Components That Can Be Reused

| Component | Location | How to Reuse |
|-----------|----------|--------------|
| mDoc CBOR decoder | `crates/ewqwe-digital-credential/src/mdoc_decoder.rs` | Already parses DeviceResponse |
| mDoc verification | `crates/ewqwe-digital-credential/src/mdoc_verification.rs` | Already verifies signatures |
| Attestation signing | `crates/ewqwe-credential-verifier-server/src/attestation/` | Reuse `create_attestation()` |
| Trusted CA loading | `crates/ewqwe-credential-verifier-server/src/server/verify_endpoint.rs` | Reuse `load_credential_issuer_cas()` |
| Journal recording | `crates/ewqwe-credential-verifier-server/src/journal/` | Reuse `append_verification()` |

## What's New / Needs to Be Built

| Component | Location | Description |
|-----------|----------|-------------|
| HPKE module | `crates/ewqwe-openid4vp/src/hpke.rs` (new) | HPKE decryption using X25519 + AES-128-GCM |
| Annex C wrapper parser | `crates/ewqwe-openid4vp/src/hpke.rs` (new) | Parse `["dcapi", ...]` CBOR wrapper |
| DC API endpoint | server/src/server/dc_api_endpoints.rs (new) | `POST /ewqwe_api/dc_api/verify` |
| DC API request builder | `webapp/src/annex_b_service.ts` (new) | Build encryptionInfo + deviceRequest CBOR |
| W3C DC API integration | `webapp/src/relying_party_app.ts` (modified) | Call `navigator.credentials.get()` |
| HPKE for webapp | `webapp/src/hpke.ts` (new) | Browser-side HPKE key generation + decryption |
| Server config | `credential-server.toml` (modified) | Add `[annex_b_config]` section |

## Additional Considerations

### Security

- **HPKE key management:** The verifier generates a fresh HPKE key pair per transaction — or reuses one for a configurable window. The private key is ephemeral and never stored long-term.
- **Nonce binding:** The Annex B nonce serves the same purpose as the OpenID4VP nonce — replay prevention.
- **Trust verification:** The mDoc issuer certificate chain must validate against trusted CAs (same as the existing OpenID4VP mDoc flow).

### Protocol Detection / Dual Path

If the verifier needs to support both ISO 18013-7 (Annex B) and OpenID4VP simultaneously:

1. The RP can detect the availability of `navigator.credentials.get()` on page load
2. If available -> use ISO 18013-7 (Annex B) / DC API path with protocol `org-iso-mdoc`
3. If not available -> fall back to OpenID4VP (QR code + direct_post)
4. Both paths converge to the same attestation issuance logic

```typescript
// webapp/src/relying_party_app.ts
async function verifyAge() {
  if ('digital' in navigator.credentials) {
    await initiateDcApiVerification();
  } else {
    await initiateOpenID4VPVerification();
  }
}
```

### Performance

- HPKE decryption is fast (~1ms for X25519 + AES-128-GCM) — no caching needed per transaction
- mDoc verification (COSE signatures) is the same as current flow — already tested
- The Annex B endpoint can share the same thread pool as existing endpoints

## Timeline Estimate

| Phase | Tasks | Estimated Effort |
|-------|-------|------------------|
| Phase 1 | HPKE module, Annex C parser, Annex B endpoint, tests | 3-5 days |
| Phase 2 | Webapp DC API integration, HPKE in browser, type shims | 3-5 days |
| Phase 3 | Configuration, certificate setup, France Identite testing | 1-2 days |
| **Total** | | **7-12 days** (one developer, including testing) |

## Appendix: ISO 18013-7 (Annex B) Data Flow Breakdown

```
RP (Browser)                                                    Wallet (Android)
    |                                                               |
    |  1. Generate HPKE key pair locally                             |
    |     (X25519 + AES-128-GCM)                                    |
    |  2. Generate random 16-byte nonce locally                      |
    |  3. Build encryptionInfo:                                      |
    |     CBOR(["dcapi", {                                           |
    |       nonce: bstr,                                             |
    |       recipientPublicKey: COSE_Key                             |
    |     }])                                                        |
    |  4. Build DeviceRequest:                                       |
    |     CBOR({ docRequests: [{                                    |
    |       docType: "eu.europa.ec.av.1",                            |
    |       itemsRequest: {                                          |
    |         nameSpaces: {                                          |
    |           "eu.europa.ec.av.1": { age_over_18: true }           |
    |         }                                                      |
    |       }                                                        |
    |     }]})                                                       |
    |  5. Base64url-encode both blobs                                 |
    |                                                                 |
    |  ------------------------------------->                         |
    |  navigator.credentials.get({                                    |
    |    digital: { requests: [{                                      |
    |      protocol: "org-iso-mdoc",                                  |
    |      encryptionInfo, deviceRequest                              |
    |    }]}                                                          |
    |  })                                                             |
    |                                                                 |
    |                                                  6. Parse encryptionInfo
    |                                                  7. Parse DeviceRequest
    |                                                  8. Select matching credential
    |                                                  9. Build DeviceResponse (CBOR)
    |                                                 10. HPKE encrypt:
    |                                                     cipherText = HPKE.encrypt(
    |                                                       DeviceResponse CBOR,
    |                                                       recipientPublicKey
    |                                                     )
    |                                                 11. Build EncryptedResponse:
    |                                                     CBOR(["dcapi", {
    |                                                       enc: bstr,
    |                                                       cipherText: bstr
    |                                                     }])
    |                                                 12. Base64url-encode
    |                                                                 |
    |  <-------------------------------------                          |
    |  Promise resolves with { data: base64url(EncryptedResponse) }   |
    |                                                                 |
    | 13. Base64url-decode EncryptedResponse                          |
    | 14. Extract enc and cipherText from CBOR wrapper                |
    | 15. HPKE decrypt: DeviceResponse = HPKE.open(                   |
    |       cipherText,                                               |
    |       recipientPrivateKey,                                      |
    |       enc                                                        |
    |     )                                                           |
    | 16. Send [deviceResponse, nonce, client_id] to verifier         |
    |                                                                 |
    |  ------------------------------------->                         |
    |  POST /ewqwe_api/dc_api/verify                                  |
    |                                                                 |
    |                                                   Verifier      |
    |                                             17. Verify mDoc:
    |                                                 - decode CBOR DeviceResponse
    |                                                 - validate IssuerAuth COSE_Sign1
    |                                                 - check certificate chain
    |                                                 - verify nonce binding
    |                                             18. Sign attestation JWT
    |                                             19. Write to journal
    |                                                                 |
    |  <-------------------------------------                          |
    |  { success: true, claims, attestation_jwt }                      |
```

## References

- [ISO/IEC 18013-5:2023](https://www.iso.org/standard/69084.html) — Mobile Driver Licence - Part 5
- [ISO/IEC 18013-7:2023](https://www.iso.org/standard/69086.html) — Mobile Driver Licence - Part 7, Annex B & C
- [W3C Digital Credentials API](https://www.w3.org/TR/digital-credentials/)
- [HPKE RFC 9180](https://www.rfc-editor.org/rfc/rfc9180)
- [EU Age Verification Profile - DC API](./age_verification_iso_18013_dcapi.md) (existing doc)
- [Annex B vs HAIP Comparison](./annex_b_vs_haip.md)
- [France Identite Wallet Testing Guide](./france_identite_wallet.md)
