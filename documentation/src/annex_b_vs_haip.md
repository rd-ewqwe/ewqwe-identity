# Profile Comparison: ISO 18013-7 Annex B vs HAIP

This chapter explains the architectural and protocol differences between **ISO/IEC 18013-7 Annex B** (used by national mDL systems like France Identité) and **HAIP** (High-Assurance Interoperability Profile), an OpenID4VP-based profile for high-assurance credential verification.

Understanding these differences is essential when:

- Choosing which profiles your verifier should support
- Planning integration with specific wallet implementations (e.g., France Identité, EUDI Wallet)
- Designing credential request/response semantics
- Evaluating interoperability with existing deployments

## Annex Letters Explained

The ISO/IEC 18013-7 standard defines multiple annexes that work together. The France Identité playground uses the following terminology:

| Annex / Term | What It Covers | Playground Convention |
|---|---|---|
| **Annex B** | Online mDoc presentation flow using the W3C Digital Credentials API with the `org-iso-mdoc` protocol. **Umbrella term** for the entire online ISO mDoc verification experience. | `ISO 18013-7 (Annex B)` — the standard name for the online flow |
| **Annex C** | The `["dcapi", ...]` wrapper that encapsulates the ISO DeviceRequest (CBOR) for transport over the W3C DC API. Defines `encryptionInfo` and HPKE parameters. | Referenced as part of `ISO 18013-7 (Annex B)` — not a standalone profile |
| **`org-iso-mdoc`** | The W3C Digital Credentials API protocol identifier for ISO 18013-7 DeviceRequest/Response flows. | The protocol value used in `navigator.credentials.get()` requests |
| **`dc_api.jwt`** | OpenID4VP Authorization Requests transported over the W3C Digital Credentials API with JWT wrapping (rather than native ISO CBOR). | A separate OpenID4VP-based protocol, distinct from Annex B |
| **W3C Digital Credentials API** | The browser API (`navigator.credentials.get()`) that enables communication between RP and Wallet. | The transport layer, not a protocol itself |
| **OpenID4VP** | The OpenID Foundation protocol for verifiable presentations using Authorization Request / VP Token semantics. | A separate protocol family from Annex B |
| **HAIP** | High Assurance Interoperability Profile — an OpenID4VP-based profile with JAR signing, `x509_hash` client_id, and high-assurance cryptographic bindings. | OpenID4VP-based, distinct from Annex B |

> **Key rule:** "ISO 18013-7 (Annex B)" is the umbrella term for the online mDoc flow. Annex C is the encoding wrapper within that flow — it is not a standalone profile. The France Identité playground lists protocols as `ISO 18013-7 (Annex B)` (for the ISO CBOR flow) and `OpenID4VP (dc_api.jwt)` (for the OpenID4VP-over-DC-API flow).

## Quick Comparison Table

| Aspect | ISO 18013-7 Annex B | HAIP |
|--------|-------------------|------|
| **Standards Base** | ISO/IEC 18013-5/7, ETSI | OpenID4VP 1.0, W3C Digital Credentials |
| **Protocol Transport** | ISO DC API (W3C Digital Credentials API) with ISO mDoc semantics | OpenID4VP (HTTP redirects or direct_post) |
| **Request Format** | ISO DeviceRequest (CBOR) wrapped in ISO 18013-7 Annex B envelope (Annex C `["dcapi"]` wrapper) | JWT Authorization Request (optionally JAR-signed) |
| **Response Transport** | ISO mDoc DeviceResponse (HPKE-encrypted CBOR) | VP Token (can be JWT or direct_post.jwt) |
| **Credential Format** | mDoc (ISO/IEC 18013-5) | mDoc or SD-JWT (W3C VC format) |
| **Signature Scheme** | COSE_Sign1 for mDoc, MSO issuer chains | COSE_Sign1 or JWT, X.509 certificate chains |
| **Client Authentication** | Reader authentication in DeviceRequest (optional) | JAR signing, X.509 client_id schemes (x509_hash, x509_san_dns) |
| **Response Mode** | org-iso-mdoc (ISO mDoc protocol via W3C DC API) | direct_post, direct_post.jwt, fragment, form_post |
| **Nonce Binding** | Included in encryptionInfo | Nonce in request, validated in presentation |
| **Trust Model** | ISO/ETSI PKI chains, issuer certificates | X.509 TLS + JAR signing certificates, JWKS endpoints |
| **Use Case** | National mDL systems, proximity flows | Cross-vendor, remote high-assurance verification |
| **Typical Deployment** | Government mDL, EU Member States | Commercial verifiers, bank/corporate onboarding |

## Detailed Comparison

### 1. Standards Foundation & Scope

**ISO 18013-7 Annex B:**

- Built on **ISO/IEC 18013-5** (mDoc/mDL specification) and **ISO/IEC 18013-7** (mobility and remote access extensions).
- Primarily targets **mobile driver license (mDL)** systems and national identity documents.
- Focuses on the **ISO ecosystem** for credential issuance, storage, and verification.
- Transport mechanism: W3C Digital Credentials API (browser integration) with ISO mDoc semantics via the `org-iso-mdoc` protocol (wrapper defined in ISO 18013-7 Annex C).
- Managed by **ISO TC 307** and **ETSI** (European Telecommunications Standards Institute).

**HAIP (High-Assurance Interoperability Profile):**

- Built on **OpenID4VP 1.0** and **OpenID4VC 1.0** standards.
- Extends **OpenID4VP** to provide high-assurance, cryptographically strong bindings between client, request, response, and credential.
- Targets **cross-vendor interoperability** where wallets and verifiers from different providers need to interoperate with assurance guarantees.
- Supports both **mDoc** and **SD-JWT** (Selective Disclosure JWT, W3C Verifiable Credentials format).
- Managed by the **OpenID Foundation** and aligned with W3C Digital Credentials Specification.

**Implication:** If your system targets **national mDL deployments** (France Identité, German ID, etc.), Annex B is the standard path. If you need **interoperable, high-assurance** verification across wallets from different vendors, HAIP is the better choice.

---

### 2. Protocol Transport & Request/Response Flow

**ISO 18013-7 Annex B (W3C Digital Credentials API):**

```
Relying Party                           Wallet
    |                                      |
    |--- navigator.credentials.get() ----->|
    |    (Request contains encryptionInfo  |
    |     + ISO DeviceRequest in CBOR)     |
    |                                      |
    |                                 [User selects credential,
    |                                  consents to release]
    |                                      |
    |<-- Promise resolves with CBOR -------|
    |    HPKE-encrypted DeviceResponse     |
    |                                      |
    |--- Decrypt & verify DeviceResponse --|
    |
    [RP processes credential claims]
```

**Key points:**

- Uses the **W3C Digital Credentials API** (`navigator.credentials.get()`/`.create()`).
- Request is encapsulated as **base64url-encoded CBOR** (opaque to the browser).
- Response is **HPKE-encrypted** CBOR (asymmetric encryption from wallet to RP).
- The **encryption key** is provided by the RP in the request (COSE_Key).
- The **nonce** is part of the encryption metadata (`encryptionInfo`), used to bind request ↔ response.
- **No TLS client certificates** required for basic flows; reader authentication is optional.

**HAIP (OpenID4VP):**

```
Relying Party                           Wallet
    |                                      |
    |--- POST /auth (JAR-signed) -------->|
    |    (Authorization Request, optionally
    |     signed and encrypted)            |
    |                                      |
    |                                 [User selects credential,
    |                                  consents to release]
    |                                      |
    |<-- POST /response_uri (VP Token) ----|
    |    (direct_post or direct_post.jwt)  |
    |    Signed with holder key binding    |
    |                                      |
    |--- Validate signature + nonce -------|
    |
    [RP processes credential claims]
```

**Key points:**

- Uses **HTTP redirects** (OpenID4VP standard) or **direct_post** (POST back to RP endpoint).
- Request is a **JWT** (Authorization Request), optionally **JAR-signed** (JSON Authorization Request).
- Response is a **VP Token** (JWT or signed CBOR), can be wrapped in **direct_post.jwt** for additional integrity.
- The **nonce** is part of the Authorization Request JWT, validated in the VP Token.
- **TLS is always present** for HTTP communication.
- Client authentication via **JAR signing** (proves RP signed the request) or **X.509 client_id** schemes.

**Architectural difference:**

| | Annex B | HAIP |
|---|---------|------|
| Request/Response binding | Encryption context (HPKE, nonce in encryptionInfo) | JWT nonce claim + signature verification |
| Cryptography for flow integrity | Asymmetric encryption (wallet encrypts to RP's public key) | Cryptographic signatures (RP signs JAR, wallet signs VP Token) |
| Session state management | Implicit in encryptionInfo nonce | Explicit state parameter + nonce in JWT |
| Browser involvement | Direct API integration | Browser redirects or form POST |

---

### 3. Request Format

**ISO 18013-7 Annex B (DeviceRequest):**

```cbor
{
  "docType": "org.iso.18013.5.1.mDL",
  "itemsRequest": {
    "org.iso.18013.5.1": {
      "age_over_18": true,
      "age_over_21": false
    }
  },
  "readerAuth": <optional COSE_Sign1>,
  "signatureAlgorithmOID": <optional>
}
```

Encoded as:
- **CBOR** → **base64url** (no padding)
- Wrapped in the ISO 18013-7 Annex B envelope (Annex C `["dcapi"]` wrapper) with `encryptionInfo`
- Sent via W3C Digital Credentials API

**HAIP (Authorization Request JWT):**

```json
{
  "iss": "https://rp.example.com",
  "sub": "https://rp.example.com",
  "aud": "https://wallet.example.com",
  "client_id": "x509_hash:abc123...",
  "response_type": "vp_token",
  "response_mode": "direct_post.jwt",
  "response_uri": "https://rp.example.com/response",
  "nonce": "n-0S6_WzA2Mj",
  "state": "af0ifjsldkj",
  "dcql_query": {
    "credentials": [
      {
        "format": "mdoc",
        "doctype": "org.iso.18013.5.1.mDL",
        "claims": [
          {
            "namespace": "org.iso.18013.5.1",
            "claim_name": "age_over_18",
            "intent_to_retain": false
          }
        ]
      }
    ]
  }
}
```

If **JAR-signed**, this JWT is itself wrapped in another JWT (the "outer" Authorization Request), signed with the RP's private key.

**Key differences:**

| Aspect | Annex B | HAIP |
|--------|---------|------|
| Format | CBOR (binary) | JWT (JSON, signed/encrypted) |
| Expressiveness | ISO DeviceRequest schema | OpenID4VP + DCQL (more flexible) |
| Query language | ISO namespace/claim names | DCQL (Digital Credentials Query Language) |
| Extensibility | Bound to ISO standards | Extensible via JWT claims |
| Signature | Reader authentication (optional) | JAR signing (mandatory for high-assurance) |

---

### 4. Response Format & Verification

**ISO 18013-7 Annex B (DeviceResponse):**

The wallet returns an **HPKE-encrypted** CBOR blob containing:

```cbor
{
  "documents": [
    {
      "docType": "org.iso.18013.5.1.mDL",
      "issuerSigned": {
        "nameSpaces": {
          "org.iso.18013.5.1": [
            {
              "elementIdentifier": "age_over_18",
              "elementValue": true
            }
          ]
        },
        "issuerAuth": <COSE_Sign1 with issuer signature>
      },
      "deviceSigned": {
        "namespaces": {...},
        "deviceAuth": <COSE_Sign1 with device signature>
      }
    }
  ]
}
```

Encrypted via **HPKE** with the RP's public key (provided in the request).

**RP verification steps:**

1. **Decrypt** the HPKE ciphertext using the RP's private key.
2. **Extract** the mDoc DeviceResponse.
3. **Verify issuer signature** (COSE_Sign1) against the issuer's certificate.
4. **Verify device signature** (COSE_Sign1) against the device's public key (embedded in issuer-signed data).
5. **Check nonce binding** in the encryption metadata (`encryptionInfo`).
6. **Extract claims** from the decrypted mDoc.

**HAIP (VP Token):**

The wallet returns a **VP Token** (JWT or CBOR), which can be wrapped in a **direct_post.jwt**:

```json
{
  "vp_token": "eyJhbGciOiJFUzI1NiIsImtpZCI6ImtleS0xIn0.eyJpc3MiOiJodHRwczovL3dhbGxldC5leGFtcGxlLmNvbSIsInN1YiI6InVzZXItMTIzIiwibm9uY2UiOiJuLTBTNl9XekEyTWoiLCJ2cCI6eyJjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZVByZXNlbnRhdGlvbiJdLCJ2ZXJpZmlhYmxlQ3JlZGVudGlhbCI6WyJleUpoYkdjaU9pSlNVekkxTmlaWElpTENKamNtVmZZMnhoYzNObElqcDBjblZ6ZEc5dElpd2laVzUwSWpwMGNuVnpkRzl0In19.signature",
  "presentation_submission": {...}
}
```

If **direct_post.jwt**, the entire response is wrapped in a JWT signed by the wallet.

**RP verification steps:**

1. **Verify VP Token signature** (JWT signature using wallet's public key or certificate chain).
2. **Extract nonce** from the JWT claims.
3. **Validate nonce** matches the Authorization Request.
4. **Verify holder binding** (KB-JWT or proof_type in mDoc).
5. **Extract and verify credential signature(s)** (JWT or COSE_Sign1).
6. **Verify issuer certificate** chain.
7. **Extract claims** from the credential.

**Key differences:**

| Aspect | Annex B | HAIP |
|--------|---------|------|
| Response wrapping | HPKE encryption | JWT signature / direct_post.jwt |
| Integrity mechanism | Encryption (confidentiality + integrity) | Cryptographic signature (integrity + authenticity) |
| Key distribution | RP provides public key in request | Wallet provides signing key via certificate or JWKS |
| Nonce validation | Part of encryption metadata | JWT claim in VP Token |
| Multi-credential support | mDoc only (or mDoc variants) | mDoc + SD-JWT + others |
| Response modes | org-iso-mdoc (ISO mDoc protocol via W3C DC API) | Multiple (fragment, direct_post, direct_post.jwt, form_post) |

---

### 5. Credential Formats

**ISO 18013-7 Annex B:**

- **Primary format:** **ISO/IEC 18013-5 mDoc** (mobile document)
  - Binary CBOR structure
  - Namespaces organize claims (e.g., `org.iso.18013.5.1` for mDL)
  - Issuer signature (COSE_Sign1)
  - Optional device signature (COSE_Sign1) for user consent binding
- **Signature validation:** Issuer certificate chain validation (X.509) + COSE payload verification

**HAIP:**

- **Primary formats:**
  - **ISO/IEC 18013-5 mDoc** (same as Annex B, but with OpenID4VP transport)
  - **SD-JWT VC** (Selective Disclosure JWT) — W3C Verifiable Credential format
    - JSON payload with selectively-disclosable claims
    - JWT signature with issuer key
    - KB-JWT (Key Binding JWT) for holder binding
- **Signature validation:** X.509 certificate chain + JWT verification, or JWT key thumbprint validation

**Implication:** HAIP's flexibility to support both mDoc and SD-JWT makes it easier to integrate with wallets that use different credential storage models.

---

### 6. Client Authentication & Trust

**ISO 18013-7 Annex B:**

- **Optional reader authentication** via `readerAuth` (COSE_Sign1 in DeviceRequest)
- Reader (RP) provides an optional certificate to prove identity to the wallet
- Wallet may validate reader certificate against a trust list (optional)
- **No mandatory client TLS certificate** for the HTTP layer (since W3C API is used)
- **Trust model:** ISO/ETSI PKI chains for issuer certificates + optional reader authentication

**HAIP:**

- **Mandatory JAR signing** (for high-assurance profiles)
  - Authorization Request JWT is signed by the RP's private key
  - Wallet validates RP's signature using the RP's certificate or JWKS endpoint
- **X.509 client_id schemes:**
  - `x509_hash`: client_id is a base64url-encoded SHA-256 hash of the RP's certificate
  - `x509_san_dns`: client_id is derived from certificate SANs (Subject Alternative Names)
- **TLS client certificates:** Often used for mutual TLS (mTLS) authentication
- **Trust model:** X.509 PKI chains + JAR signing verification + optional certificate pinning

**Security implications:**

| Aspect | Annex B | HAIP |
|--------|---------|------|
| **Client authentication** | Optional (reader auth) | Mandatory (JAR signing) |
| **Cryptographic proof of RP identity** | Reader's signature in request | RP's JAR signature |
| **Wallet trust decision** | Based on optional reader cert | Based on JAR signature + client_id validation |
| **Replay protection** | Nonce in encryptionInfo | Nonce in JWT + signature prevents replay |

---

### 7. Use Cases & Deployment Scenarios

**ISO 18013-7 Annex B (France Identité, etc.):**

**Typical use case:** National mDL systems, government-backed identity verification.

**Example flow:**
1. French driver applies for a service requiring identity verification
2. Service (RP) uses the France Identité wallet to request an age-over-18 attestation
3. Wallet presents the mDL credential (stored securely on device)
4. Service verifies the mDoc signature chain against the French government's PKI
5. Service grants access based on age verification

**Characteristics:**
- **Closed ecosystem:** Wallets and verifiers are part of a national system
- **Known participants:** Both RP and wallet are registered with the government scheme
- **mDoc-centric:** Credentials are ISO mDoc format
- **Proximity-friendly:** Designed for same-device flows (W3C API)

**HAIP (Cross-vendor, commercial verifiers):**

**Typical use case:** Bank KYC/AML, corporate onboarding, age verification across wallets.

**Example flow:**
1. Customer tries to open an online bank account
2. Bank (RP) initiates HAIP age verification
3. Bank sends a **JAR-signed** OpenID4VP request to the wallet
4. Wallet validates the bank's JAR signature and client_id
5. Wallet presents credential (mDoc or SD-JWT) with **KB-JWT holder binding**
6. Bank verifies the VP Token signature and holder binding
7. Bank grants account access

**Characteristics:**
- **Open ecosystem:** Wallets and verifiers can be from different vendors
- **Interoperability first:** Strong emphasis on cross-vendor compatibility
- **Flexible credentials:** Supports mDoc, SD-JWT, and other formats
- **High assurance:** JAR signing, holder binding, and certificate validation
- **Remote-friendly:** Supports both same-device and cross-device flows (redirects + direct_post)

**Decision matrix:**

| Scenario | Use Annex B | Use HAIP |
|----------|------------|---------|
| National mDL system | ✓ | – |
| Government identity scheme | ✓ | – |
| Cross-vendor interoperability | – | ✓ |
| Commercial age verification | – | ✓ |
| Bank onboarding | – | ✓ |
| Proximity-only flows | ✓ | – |
| Remote, QR-code-based flows | – | ✓ |
| Single issuer (govt) | ✓ | – |
| Multiple issuers (diverse wallets) | – | ✓ |

---

### 8. Interoperability Implications

**Annex B wallet with HAIP verifier:**

❌ **Not directly compatible** without adaptation layer.

- Annex B wallet expects ISO DeviceRequest via W3C API
- HAIP verifier sends OpenID4VP Authorization Request (JWT)
- Wallet may not understand OpenID4VP protocol

**Workaround:** Verifier could implement both Annex B and HAIP protocols, or wallet could expose an OpenID4VP bridge.

**HAIP wallet with Annex B verifier:**

❌ **Not directly compatible** without adaptation layer.

- HAIP wallet expects OpenID4VP Authorization Request (JAR-signed JWT)
- Annex B verifier sends ISO DeviceRequest (CBOR)
- Wallet may not understand Annex B protocol

**Workaround:** Wallet could support both protocol paths, or verifier could proxy requests.

**Best practice:** If you need to support both ecosystems, implement two protocol paths in your verifier:

```rust
// Pseudo-code
enum VerificationPath {
    AnnexB {
        device_request: DeviceRequest,
        encryption_info: EncryptionInfo,
    },
    HAIP {
        jar: SignedJWT,
        dcql_query: DCQLQuery,
    },
}

fn verify_age(path: VerificationPath) -> AttestationResult {
    match path {
        AnnexB { device_request, encryption_info } => {
            // Handle ISO mDoc DeviceRequest/Response
        }
        HAIP { jar, dcql_query } => {
            // Handle OpenID4VP Authorization Request/VP Token
        }
    }
}
```

---

### 9. Implementation Checklist

**If you want to support Annex B (France Identité, national mDL):**

- [ ] Implement W3C Digital Credentials API request handling (receive CBOR encryptionInfo + deviceRequest)
- [ ] Parse ISO DeviceRequest and build appropriate mDoc query
- [ ] Support HPKE decryption for the wallet's encrypted response
- [ ] Verify COSE_Sign1 signatures (issuer auth + device auth)
- [ ] Validate X.509 issuer certificate chains
- [ ] Validate nonce binding from encryptionInfo
- [ ] Extract and validate age claims from mDoc namespaces

**If you want to support HAIP (cross-vendor high-assurance):**

- [ ] Implement OpenID4VP Authorization Request (JWT) generation
- [ ] Implement JAR (JSON Authorization Request) signing
- [ ] Generate and expose JWKS endpoint for public keys
- [ ] Implement `/response_uri` endpoint for direct_post VP Token submission
- [ ] Verify VP Token signatures (JWT or COSE_Sign1)
- [ ] Validate nonce binding in JWT claims
- [ ] Verify holder binding (KB-JWT or mDoc device signature)
- [ ] Support DCQL query language for flexible credential requests
- [ ] Validate client_id against certificate (x509_hash or x509_san_dns)

**If you want to support both:**

- [ ] Implement both protocol stacks in separate modules
- [ ] Route incoming requests to the appropriate verifier based on protocol detection
- [ ] Share common credential verification logic (COSE_Sign1, X.509 chain validation, etc.)
- [ ] Use a unified attestation output that works for both paths

---

## Summary

| Dimension | Annex B | HAIP |
|-----------|---------|------|
| **Standards** | ISO 18013-7 | OpenID4VP 1.0 |
| **Scope** | National mDL systems | Cross-vendor interoperability |
| **Transport** | W3C Digital Credentials API | HTTP (OpenID4VP) |
| **Request Format** | CBOR DeviceRequest | JWT (optionally JAR-signed) |
| **Response Format** | HPKE-encrypted mDoc | JWT or direct_post.jwt |
| **Credentials** | mDoc only | mDoc + SD-JWT |
| **Client Auth** | Optional reader auth | Mandatory JAR signing |
| **Use Case** | Government identity | Commercial verification |

**Choose Annex B if:** You're integrating with France Identité, German ID, or other national mDL systems.

**Choose HAIP if:** You need cross-vendor wallet support, high-assurance cryptographic bindings, and flexibility in credential formats.

**Choose both if:** You need to support diverse ecosystems (both national schemes and commercial interoperability).

## References

- [ISO/IEC 18013-5:2023](https://www.iso.org/standard/69084.html) — Mobile Driver Licence (mDL) – Part 5: Encoding and transport
- [ISO/IEC 18013-7:2023](https://www.iso.org/standard/69086.html) — Mobile Driver Licence (mDL) – Part 7: Mobility, remote access, and accessibility requirements
- [OpenID4VP 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
- [HAIP Profile](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-E) (Appendix E of OpenID4VP 1.0)
- [W3C Digital Credentials API](https://www.w3.org/TR/digital-credentials-userland/)
- [EU Age Verification Profile](https://ageverification.dev/Technical%20Specification/)
