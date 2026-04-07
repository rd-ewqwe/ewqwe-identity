# The User Journey

This page describes the end-to-end **digital credential verification user journey** in the EU Digital Identity ecosystem and how a Relying Party (RP - you!) can request and validate a **verifiable presentation** from a user’s wallet, such as a proof of age credential.

Because real-world interoperability today is primarily based on **OpenID4VP** (with the **W3C Digital Credentials API** as a browser-native option when available), the journey is presented in two concrete profiles:

- **EU Age Verification Profile (Annex A)** using the **Age Verification App (AVI)** — simpler integration (`redirect_uri`, no signed JAR, `direct_post`).
- **HAIP** using the **EUDI Wallet** — higher assurance integration (certificate-based `x509_*` client IDs, **signed JAR**, `direct_post.jwt`).

Both paths ultimately converge on the same backend pattern: the RP forwards the received VP Token to the **ewQwe Credential Verifier**, which validates the proof and returns a **signed attestation** the RP can use for access control and session establishment.

## W3C Digital Credentials API vs OpenID4VP

The **W3C Digital Credentials API** is a browser-native way for a website (RP) to request a verifiable presentation from a user’s wallet. When it is available, it can provide the simplest user experience because the browser can directly invoke the wallet via `navigator.credentials.get()`. However, it is **still a draft** and is **not consistently supported across browsers and wallets** yet ([W3C Digital Credentials API, Editor’s Draft / TR](https://www.w3.org/TR/digital-credentials/)).

In the **EU Digital Identity** ecosystem, real-world interoperability for presentations is currently based on **OpenID for Verifiable Presentations (OpenID4VP)**. Both the **EU Age Verification Profile (Annex A)** and **HAIP** are OpenID4VP-based profiles and define how wallets and relying parties exchange presentation requests and responses (including same-device redirects and cross-device direct-post) ([OpenID4VP 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html), [EU Age Verification Profile — Annex A](https://ageverification.dev/av-doc-technical-specification/docs/annexes/annex-A/annex-A-av-profile/)).

### Recommended approach

- **Use the W3C Digital Credentials API when available**: use the browser’s credentials interface (`navigator.credentials.get()`) for the smoothest, most “web-native” flow.
- **Fallback to OpenID4VP when the W3C API is not available**: use the standardized OpenID4VP presentation flows (same-device deep link or cross-device QR code, with `direct_post` / `direct_post.jwt`) to stay compatible with EU wallet implementations.

This “use the browser API when possible, otherwise use OpenID4VP” strategy matches the **EU Age Verification Profile (Annex A)** guidance for age-verification presentations and keeps the RP aligned with the European Digital Identity ecosystem as browser support for the W3C API matures (see [EU Age Verification Profile — Annex A](https://ageverification.dev/av-doc-technical-specification/docs/annexes/annex-A/annex-A-av-profile/), and [OpenID4VP 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)).

## Two Wallets, Two Profiles

The European Digital Identity ecosystem defines **two separate profiles** for credential presentation, each with its own wallet implementation:

- The **EU Age Verification Profile (Annex A)**, implemented by the **Age Verification App (AVI)**, focuses on age verification use cases and uses a simpler OpenID4VP flow with `redirect_uri` client IDs and no signed JAR.
- The **High Assurance Interoperability Profile (HAIP)**, implemented by the **EUDI Wallet**, targets high-value credentials like Personal Identity Documents (PID) and mobile driving licenses (mDL), and requires a more complex OpenID4VP flow with certificate-based client IDs, signed JARs, and JWT-wrapped responses.

| Aspect | Age Verification App (Annex A) | EUDI Wallet (HAIP) |
| -------- | --------------------------------- | ------------------- |
| **Profile** | EU Age Verification Profile | High Assurance Interoperability Profile |
| **Use Case** | Age verification (websites, services) | High-value credentials (PID, mDL) |
| **LoA** | Substantial | High |
| **Client ID Scheme** | `redirect_uri` | `x509_san_dns`, `x509_hash` |
| **Request Signing** | Not required (plain query params) | Required (JWT with `x5c` header) |
| **Response Mode** | `direct_post` | `direct_post.jwt` |
| **Trust Model** | RP identified by redirect URI | RP identified by certificate |
| **Root CA Required** | No (any HTTPS certificate) | Yes (must be in wallet trust store) |
| **URL Scheme** | `av://`, `avsp://`, `openid4vp://` | `eudi-openid4vp://`, `openid4vp://` |
| **Credential Formats** | `mso_mdoc` (`eu.europa.ec.av.1`) | `mso_mdoc` (mDL, PID) / `dc+sd-jwt` (PID) |

### Key Differences from HAIP

The Annex A profile was designed to be simpler than HAIP because:

| Feature | Annex A Rationale | HAIP Approach |
| --------- | ------------------- | --------------- |
| **No JAR signing** | Reduces implementation complexity | Required for RP authentication |
| **No trust list** | Trust lists for age verification don't exist yet | Relies on pre-established CA trust |
| **Simple client_id** | `redirect_uri:` prefix + callback URL | Certificate-based identity |
| **Plain response** | Direct POST of VP Token | JWE-encrypted response (ECDH-ES + A256GCM) |
| **Lower LoA** | Appropriate for age verification | Required for identity documents |

> **Source**: [Annex A.9 - Comparison with HAIP](https://ageverification.dev/av-doc-technical-specification/docs/annexes/annex-A/annex-A-av-profile/#a9-comparison-with-haip)

## Architecture Components

All credential verification flows involve these main components:

- **Relying Party (RP) Web App**: A web application requesting credential verification from users
- **Wallet (AVI)**: The user's digital wallet storing credentials — either the Age Verification App (Annex A) or EUDI Wallet (HAIP)
- **ewQwe Credential Verifier**: A trusted backend service that verifies credentials and issues signed attestations

## Flow 1: Age Verification App (Annex A Profile)

This flow implements the [EU Age Verification Profile (Annex A)](https://ageverification.dev/av-doc-technical-specification/docs/annexes/annex-A/annex-A-av-profile/), which uses the `redirect_uri` Client ID Scheme. The Credential Format is `mso_mdoc` with document type `eu.europa.ec.av.1`.

> **Same-device vs Cross-device**: The protocol steps are identical regardless of how the Authorization Request reaches the Wallet. In the **cross-device flow**, the RP displays a QR code that the User scans with their Wallet. In the **same-device flow**, the RP opens the `av://` deep link directly. Both flows use `direct_post` for the Authorization Response.

### Annex A OpenID4VP Flow

```mermaid
sequenceDiagram
    participant User
    participant RP as RP Webapp
    participant AVI as Age Verification<br/>App (Wallet)
    participant CV as ewQwe<br/>Credential Verifier

    User->>RP: Click "Verify Age"

    Note over RP,CV: Transaction Initialization
    RP->>CV: POST /ewqwe_api/openid4vp/init<br/>{profile: "annex-a", dcql_query}
    CV->>CV: Generate transaction_id and nonce<br/>Reuse caller-supplied state or generate request-id state<br/>Build DCQL Credential Query<br/>(format: mso_mdoc, doctype: eu.europa.ec.av.1)
    CV-->>RP: {transaction_id,<br/>authorization_request_uri}

    Note over RP,AVI: Authorization Request (OpenID4VP §5)
    RP->>User: Display QR code / open deep link
    User->>AVI: Scan QR code / tap deep link

    Note over AVI: av://?client_id=redirect_uri:{response_uri}<br/>&response_type=vp_token<br/>&response_mode=direct_post<br/>&response_uri=...&nonce=...&state=...<br/>&dcql_query={...}&client_metadata={...}

    AVI->>AVI: Parse inline Authorization Request<br/>(no signature verification required)
    AVI->>AVI: Evaluate DCQL Credential Query<br/>against stored credentials
    AVI->>User: Present consent dialog
    User->>AVI: Authorize presentation

    Note over AVI,CV: Authorization Response — direct_post (OpenID4VP §8.2)
    AVI->>AVI: Build VP Token (DCQL response map)<br/>{credential_query_id: [base64url(DeviceResponse)]}
    AVI->>CV: POST {response_uri}<br/>vp_token={...}&state={state}
    CV->>CV: Store Authorization Response<br/>Update transaction status → received
    CV-->>AVI: HTTP 200 OK {}

    Note over RP,CV: Transaction Status Polling
    RP->>CV: GET /ewqwe_api/openid4vp/status/{transaction_id}
    CV-->>RP: {status: "received",<br/>authorization_response, nonce}

    Note over RP,CV: Credential Verification
    RP->>CV: POST /ewqwe_api/verify {vp_token, state, client_id}
    CV->>CV: Decode CBOR DeviceResponse (ISO 18013-5)<br/>Verify IssuerAuth (COSE_Sign1)<br/>Validate Issuer certificate chain<br/>Verify DeviceSignature against OpenID4VPHandover<br/>Consume transaction and extract claims
    CV->>CV: Sign Attestation (JWT, ES256)
    CV-->>RP: {success, claims, attestation_jwt}

    RP->>User: Display verification result
```

### Annex A Key Characteristics

- **Inline Authorization Request**: All parameters are passed directly in the `av://` URI — no `request_uri` indirection ([Annex A §A.4](https://ageverification.dev/av-doc-technical-specification/docs/annexes/annex-A/annex-A-av-profile/#a4-authorization-request))
- **No JAR**: The Authorization Request is sent as plain query parameters, not as a JWT-Secured Authorization Request (no RFC 9101)
- **`redirect_uri` Client ID Scheme**: `client_id` = `redirect_uri:{response_uri}` — the Verifier is identified by its callback URL
- **`direct_post` Response Mode** (OpenID4VP §8.2): The Wallet POSTs the plain VP Token directly to `response_uri`
- **Simple trust model**: No certificate chain verification; the Verifier is identified solely by its redirect URI
- **`av://` URL Scheme**: Custom deep link registered by the Age Verification App
- **`client_metadata`**: When provided inline, uses `vp_formats_supported` field with COSE algorithm identifiers

## Flow 2: EUDI Wallet — HAIP Profile, mso_mdoc Credential Format

This flow implements the **High Assurance Interoperability Profile (HAIP)** with `mso_mdoc` credentials (ISO 18013-5). This format is used for mobile driving licenses (`org.iso.18013.5.1.mDL`) and EU PID documents (`eu.europa.ec.eudi.pid.1`).

> **Same-device vs Cross-device**: As with Annex A, the only difference is how the Authorization Request reaches the Wallet. In the **cross-device flow**, the RP displays a QR code. In the **same-device flow**, the RP opens the `eudi-openid4vp://` deep link directly. The JAR fetch, encrypted response, and verification steps are identical.

### HAIP mso_mdoc OpenID4VP Flow

```mermaid
sequenceDiagram
    participant User
    participant RP as RP Webapp
    participant EUDI as EUDI Wallet
    participant CV as ewQwe<br/>Credential Verifier

    User->>RP: Click "Verify Credentials"

    Note over RP,CV: Transaction Initialization
    RP->>CV: POST /ewqwe_api/openid4vp/init<br/>{profile: "haip", dcql_query}
    CV->>CV: Generate transaction_id and nonce<br/>Reuse caller-supplied state or generate request-id state<br/>Build DCQL Credential Query<br/>(format: mso_mdoc, doctype: ...)<br/>Generate ephemeral ECDH key pair for JWE
    CV-->>RP: {transaction_id,<br/>authorization_request_uri}

    Note over RP,EUDI: Authorization Request (OpenID4VP §5)
    RP->>User: Display QR code / open deep link
    User->>EUDI: Scan QR code / tap deep link

    Note over EUDI: eudi-openid4vp://?<br/>client_id=x509_san_dns:{dns_san}<br/>&request_uri={request_uri}

    EUDI->>CV: GET {request_uri}
    CV->>CV: Sign Authorization Request Object<br/>(JAR — RFC 9101, alg: ES256,<br/>typ: oauth-authz-req+jwt, x5c chain)
    CV-->>EUDI: Content-Type: application/oauth-authz-req+jwt

    Note over EUDI: JAR payload: client_id, nonce, state,<br/>response_mode: direct_post.jwt,<br/>response_uri, dcql_query,<br/>client_metadata {jwks, encryption params}

    EUDI->>EUDI: Verify x5c certificate chain<br/>against Reader Trust Store
    EUDI->>EUDI: Verify client_id matches<br/>certificate SAN (DNS name)
    EUDI->>EUDI: Verify JWT signature<br/>with leaf certificate public key
    EUDI->>EUDI: Evaluate DCQL Credential Query<br/>against stored credentials
    EUDI->>User: Present consent dialog<br/>(Verifier identity from certificate)
    User->>EUDI: Authorize presentation

    Note over EUDI,CV: Authorization Response — direct_post.jwt (OpenID4VP §8.3)
    EUDI->>EUDI: Build VP Token (DCQL response map)<br/>{credential_query_id: [base64url(DeviceResponse)]}
    EUDI->>EUDI: Encrypt Authorization Response<br/>as JWE (ECDH-ES + A256GCM)
    EUDI->>CV: POST {response_uri}<br/>response={jwe}&state={state}
    CV->>CV: Decrypt JWE (ECDH-ES key agreement)<br/>Extract VP Token<br/>Update transaction status → received
    CV-->>EUDI: HTTP 200 OK {}

    Note over RP,CV: Transaction Status Polling
    RP->>CV: GET /ewqwe_api/openid4vp/status/{transaction_id}
    CV-->>RP: {status: "received",<br/>authorization_response, nonce}

    Note over RP,CV: Credential Verification
    RP->>CV: POST /ewqwe_api/verify {vp_token, state, client_id}
    CV->>CV: Decode CBOR DeviceResponse (ISO 18013-5)<br/>Verify IssuerAuth (COSE_Sign1)<br/>Validate Issuer certificate chain<br/>Verify DeviceSignature against OpenID4VPHandover<br/>Consume transaction and extract namespaced claims
    CV->>CV: Sign Attestation (JWT, ES256)
    CV-->>RP: {success, claims, attestation_jwt}

    RP->>User: Display verification result
```

## Flow 3: EUDI Wallet — HAIP Profile, SD-JWT VC Credential Format

This flow implements HAIP with `dc+sd-jwt` credentials ([SD-JWT-based Verifiable Credentials](https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-08.html)). This format is used for EU PID documents (`urn:eudi:pid:1`) and other credentials that use selective disclosure with JSON-based claims.

The DCQL Credential Query specifies `format: "dc+sd-jwt"` with `vct_values` (Verifiable Credential Type) instead of the `doctype_value` used by mso_mdoc. Claims Path Pointers use a flat structure (`[claim_name]`) rather than the namespaced `[namespace, element_identifier]` paths of mso_mdoc.

### HAIP SD-JWT VC OpenID4VP Flow

```mermaid
sequenceDiagram
    participant User
    participant RP as RP Webapp
    participant EUDI as EUDI Wallet
    participant CV as ewQwe<br/>Credential Verifier

    User->>RP: Click "Verify Credentials"

    Note over RP,CV: Transaction Initialization
    RP->>CV: POST /ewqwe_api/openid4vp/init<br/>{profile: "haip", dcql_query}
    CV->>CV: Generate transaction_id, nonce, state<br/>Build DCQL Credential Query<br/>(format: dc+sd-jwt, vct_values: [...])<br/>Generate ephemeral ECDH key pair for JWE
    CV-->>RP: {transaction_id,<br/>authorization_request_uri}

    Note over RP,EUDI: Authorization Request (OpenID4VP §5)
    RP->>User: Display QR code / open deep link
    User->>EUDI: Scan QR code / tap deep link

    Note over EUDI: eudi-openid4vp://?<br/>client_id=x509_san_dns:{dns_san}<br/>&request_uri={request_uri}

    EUDI->>CV: GET {request_uri}
    CV->>CV: Sign Authorization Request Object<br/>(JAR — RFC 9101, alg: ES256,<br/>typ: oauth-authz-req+jwt, x5c chain)
    CV-->>EUDI: Content-Type: application/oauth-authz-req+jwt

    Note over EUDI: JAR payload: client_id, nonce, state,<br/>response_mode: direct_post.jwt,<br/>response_uri, dcql_query,<br/>client_metadata {jwks, encryption params}

    EUDI->>EUDI: Verify x5c certificate chain<br/>against Reader Trust Store
    EUDI->>EUDI: Verify client_id matches<br/>certificate SAN (DNS name)
    EUDI->>EUDI: Verify JWT signature<br/>with leaf certificate public key
    EUDI->>EUDI: Evaluate DCQL Credential Query<br/>against stored credentials
    EUDI->>User: Present consent dialog<br/>(Verifier identity from certificate)
    User->>EUDI: Authorize presentation

    Note over EUDI,CV: Authorization Response — direct_post.jwt (OpenID4VP §8.3)
    EUDI->>EUDI: Build VP Token (DCQL response map)<br/>{credential_query_id: [Issuer-signed JWT~Disclosures~KB-JWT]}
    EUDI->>EUDI: Encrypt Authorization Response<br/>as JWE (ECDH-ES + A256GCM)
    EUDI->>CV: POST {response_uri}<br/>response={jwe}&state={state}
    CV->>CV: Decrypt JWE (ECDH-ES key agreement)<br/>Extract VP Token<br/>Update transaction status → received
    CV-->>EUDI: HTTP 200 OK {}

    Note over RP,CV: Transaction Status Polling
    RP->>CV: GET /ewqwe_api/openid4vp/status/{transaction_id}
    CV-->>RP: {status: "received",<br/>authorization_response, nonce}

    Note over RP,CV: Credential Verification
    RP->>CV: POST /ewqwe_api/verify {vp_token, state, client_id}
    CV->>CV: Decode Issuer-signed JWT<br/>Verify SD-JWT Disclosures (SD-JWT VC §6)<br/>Verify Key Binding JWT (if present)<br/>Extract selectively disclosed claims
    CV->>CV: Sign Attestation (JWT, ES256)
    CV-->>RP: {success, claims, attestation_jwt}

    RP->>User: Display verification result
```

### HAIP Key Characteristics

- **JWT-Secured Authorization Request (JAR)**: The Authorization Request Object is a signed JWT (RFC 9101) with `ES256` and an `x5c` header containing the certificate chain (`typ: oauth-authz-req+jwt`)
- **`x509_san_dns` Client ID Scheme**: `client_id` = `x509_san_dns:{dns_san}` — the Verifier is identified by the DNS SAN of its X.509 certificate
- **Certificate chain verification**: The Wallet verifies the `x5c` certificate chain against its Reader Trust Store and confirms the `client_id` matches the leaf certificate's SAN
- **`direct_post.jwt` Response Mode** (OpenID4VP §8.3): The Wallet encrypts the Authorization Response as a JWE (ECDH-ES + A256GCM) before POSTing to `response_uri`
- **JWE Response Encryption**: The JAR's `client_metadata` includes `jwks` with the Verifier's ephemeral public key and `authorization_encrypted_response_alg` / `authorization_encrypted_response_enc` parameters
- **Two Credential Formats**:
  - **`mso_mdoc`** (ISO 18013-5): CBOR-encoded DeviceResponse with COSE_Sign1 IssuerAuth — DCQL uses namespaced Claims Path Pointers `[namespace, element_identifier]`
  - **`dc+sd-jwt`** (SD-JWT VC): Issuer-signed JWT with selectively disclosable claims — DCQL uses flat Claims Path Pointers `[claim_name]` and `vct_values` in credential query metadata
- **`eudi-openid4vp://` URL Scheme**: Custom deep link registered by the EUDI Wallet
- **Root CA required**: The Verifier's root CA must be present in the Wallet's Reader Trust Store

## Wallet Compatibility Matrix

When implementing a Relying Party, choose your approach based on which wallets you need to support:

| If you need to support... | Use this profile | Client ID Scheme | Implementation |
| ------------------------ | ---------------- | ---------------- | -------------- |
| **Age Verification App only** | Annex A | `redirect_uri` | Simpler — no JAR signing |
| **EUDI Wallet only** | HAIP | `x509_san_dns` | Complex — requires JAR + trusted CA |
| **Both wallets** | Dual-mode | Both | Implement both code paths |
| **Browser extension (fallback)** | Annex A + postMessage | `redirect_uri` | Same as Annex A |

## Verification Flow (Common to All)

Regardless of which Wallet and profile is used, the verification flow through the ewQwe Credential Verifier is the same:

1. **RP Webapp receives the Authorization Response** (VP Token) via transaction status polling
2. **RP Webapp calls the Credential Verifier's** `/ewqwe_api/verify` **endpoint** with the VP Token, `state`, and `client_id`
3. **Credential Verifier validates** the Verifiable Presentation:
    - **mso_mdoc**: Decodes CBOR DeviceResponse, verifies IssuerAuth (COSE_Sign1), validates the issuer certificate chain, validates MobileSecurityObject digests, reconstructs the OpenID4VP handover, and verifies `deviceAuth.deviceSignature`
   - **dc+sd-jwt**: Decodes Issuer-signed JWT, verifies Disclosures, verifies Key Binding JWT, extracts selectively disclosed claims
4. **Credential Verifier consumes the stored transaction and returns a signed Attestation JWT** (ES256) confirming successful verification, along with the extracted claims
5. **RP Webapp uses the Attestation** for session establishment or access control

See [The ewQwe Credential Verifier](./credential_verifier_server.md) for detailed API documentation.

## References

- [EU Age Verification Profile (Annex A)](https://ageverification.dev/av-doc-technical-specification/docs/annexes/annex-A/annex-A-av-profile/) — Annex A specification
- [Annex A.9 - Comparison with HAIP](https://ageverification.dev/av-doc-technical-specification/docs/annexes/annex-A/annex-A-av-profile/#a9-comparison-with-haip) — Detailed differences
- [OpenID4VP 1.0 Specification](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) — Protocol standard
- [SD-JWT-based Verifiable Credentials](https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-08.html) — SD-JWT VC specification
- [ISO/IEC 18013-5](https://www.iso.org/standard/69084.html) — Mobile driving licence (mDL) data retrieval
- [RFC 9101 — JWT-Secured Authorization Request (JAR)](https://datatracker.ietf.org/doc/html/rfc9101) — Signed authorization requests
- [Age Verification App Documentation](./av_wallet_android_studio.md) — Installing the AV App
- [EUDI Wallet Documentation](./eudi_wallet_android_studio.md) — Installing the EUDI Wallet
- [Demo Wallet Browser Extension](./demo_wallet_extension.md) — Browser-based fallback
