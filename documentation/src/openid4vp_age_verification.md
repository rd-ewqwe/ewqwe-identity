# Age Verification: OpenID4VP Fallback

This chapter explains the **OpenID for Verifiable Presentations (OpenID4VP)** fallback mechanism used for age verification when the **W3C Digital Credentials API** is not available.

It focuses on the requirements from **EU Age Verification Profile Annex A, Section A.5 (OpenID for Verifiable Presentations profile Requirements)**.

## Why a fallback mechanism?

The W3C Digital Credentials API is the primary method specified in Annex A.5. However:

- Not all browsers support it yet (see browser compatibility notes in the References chapter).
- The API may be disabled by user preference or enterprise policy.
- Browser extensions cannot register as Digital Credentials providers (see Demo Wallet chapter).

When the native API is unavailable, the Relying Party **MUST** fall back to OpenID4VP with specific constraints defined by the Age Verification Profile.

## Normative requirements (what you must do)

The following requirements are **mandatory** when using OpenID4VP for age verification:

### 1) Support the `av://` custom URL scheme

- The Relying Party MUST construct a request URL using the `av://` scheme.
- This triggers the Age Verification App (wallet) if installed on the device.
- Example: `av://authorize?response_type=vp_token&...`

### 2) Use `response_type=vp_token`

- The response MUST be a Verifiable Presentation token.
- This is the standard OpenID4VP response type for presentation exchanges.

### 3) Use `response_mode=direct_post`

- The wallet MUST POST the response directly to the RP's `response_uri`.
- This enables cross-device flows (e.g., QR code scanning).
- No fragment-based or query-based response is permitted.

### 4) Send the request by value (no JAR)

- The RP MUST include all request parameters directly in the `av://` URL.
- Request objects by reference (JAR - JWT-secured Authorization Request) are NOT required.
- This simplifies wallet implementation and reduces round-trips.

### 5) Client identifier scheme: `redirect_uri` + `response_uri`

- The `client_id` MUST use the format: `redirect_uri:<response_uri>`
- Example: `client_id=redirect_uri:https://rp.example.com/callback`
- This binds the client identity to the response endpoint.

### 6) Include a `nonce` parameter

- The `nonce` parameter MUST be present.
- It binds the presentation to the specific transaction and prevents replay attacks.
- The wallet MUST include the `nonce` in the VP token.

### 7) Use DCQL for the query

- The request MUST use the Digital Credentials Query Language (DCQL) as defined in OpenID4VP Section 6.
- See the [DCQL Age Verification](./dcql_age_verification.md) chapter for concrete query examples.

### 8) `state` parameter is optional

- The RP MAY include a `state` parameter per OpenID4VP Section 4.1.1.
- This helps the RP correlate responses with requests.
- However, it is not mandatory for the Age Verification Profile.

### 9) Client authentication is not required

- The wallet does not need to authenticate the RP cryptographically.
- Origin validation and nonce binding provide sufficient security for age verification.
- This is explicitly out of scope for this profile.

## End-to-end flow (sequence)

1. **RP detects W3C Digital Credentials API is unavailable** (feature detection).
2. **RP generates a fresh random `nonce`** and optional `state`.
3. **RP builds the `av://` URL** with all required parameters (including DCQL query).
4. **RP invokes the URL** (via link, redirect, or QR code).
5. **Wallet parses the request** and prompts the user to select/consent to credential presentation.
6. **Wallet builds a VP token** (Verifiable Presentation) containing the requested claims and the `nonce`.
7. **Wallet POSTs the response** to the `response_uri` with `vp_token` and optional `state`.
8. **RP receives the POST**, validates the VP token (signature, nonce, validity), and completes the age verification.

## Implementation: building the request

### TypeScript/JavaScript example (RP side)

```typescript
// 1) Generate nonce and state
const nonce = crypto.randomUUID(); // or a cryptographic random string
const state = crypto.randomUUID(); // optional but recommended for correlation

// 2) Define the response_uri where the wallet will POST back
const responseUri = "https://rp.example.com/api/openid4vp/callback";

// 3) Build the client_id using the redirect_uri scheme
const clientId = `redirect_uri:${responseUri}`;

// 4) Construct the DCQL query for age verification
// (see DCQL Age Verification chapter for detailed examples)
const dcqlQuery = {
  credentials: [
    {
      id: "age_attestation",
      format: "mso_mdoc",
      meta: {
        doctype_value: "eu.europa.ec.av.1",
      },
      claims: [
        {
          namespace: "eu.europa.ec.av.1",
          claim_name: "age_over_18",
        },
      ],
    },
  ],
};

// 5) Encode the DCQL query as a URL parameter
const dcqlQueryParam = encodeURIComponent(JSON.stringify(dcqlQuery));

// 6) Build the av:// URL
const avUrl = new URL("av://authorize");
avUrl.searchParams.set("response_type", "vp_token");
avUrl.searchParams.set("response_mode", "direct_post");
avUrl.searchParams.set("client_id", clientId);
avUrl.searchParams.set("response_uri", responseUri);
avUrl.searchParams.set("nonce", nonce);
avUrl.searchParams.set("dcql_query", dcqlQueryParam);
avUrl.searchParams.set("state", state); // optional

console.log("Age Verification Request URL:", avUrl.toString());

// 7) Invoke the wallet
// Option A: Direct navigation (same device)
// window.location.href = avUrl.toString();

// Option B: QR code (cross-device)
// generateQRCode(avUrl.toString());

// Option C: Deep link (mobile)
// <a href="${avUrl}">Verify your age</a>
```

### Example `av://` URL (formatted for readability)

```
av://authorize?
  response_type=vp_token&
  response_mode=direct_post&
  client_id=redirect_uri%3Ahttps%3A%2F%2Frp.example.com%2Fapi%2Fopenid4vp%2Fcallback&
  response_uri=https%3A%2F%2Frp.example.com%2Fapi%2Fopenid4vp%2Fcallback&
  nonce=550e8400-e29b-41d4-a716-446655440000&
  state=7c9e2d8f-3a1b-4e5f-8d7c-9a1b2c3d4e5f&
  dcql_query=%7B%22credentials%22%3A%5B%7B%22id%22%3A%22age_attestation%22%2C...
```

## Implementation: handling the response

The wallet POSTs a `application/x-www-form-urlencoded` body to the `response_uri` with the following parameters:

| Parameter | Required | Description |
|-----------|----------|-------------|
| `vp_token` | ✓ | The Verifiable Presentation containing the requested claims |
| `presentation_submission` | ✓ | Descriptor mapping the VP token to the DCQL query (OpenID4VP Section 6) |
| `state` | optional | Echoed from the request if provided |

### TypeScript/JavaScript example (RP endpoint)

```typescript
// Express.js / Node.js example
app.post("/api/openid4vp/callback", async (req, res) => {
  const { vp_token, presentation_submission, state } = req.body;

  // 1) Validate state (if used)
  if (state && !validateState(state)) {
    return res.status(400).json({ error: "invalid_state" });
  }

  // 2) Parse the VP token
  // The format depends on the credential type (JWT, mDoc CBOR, etc.)
  // For this example, assume JWT-encoded VP
  let vpPayload;
  try {
    vpPayload = parseAndVerifyVP(vp_token); // verify signature, issuer trust, etc.
  } catch (error) {
    return res.status(400).json({ error: "invalid_vp_token" });
  }

  // 3) Validate the nonce
  const expectedNonce = retrieveNonceForSession(state); // from server-side session
  if (vpPayload.nonce !== expectedNonce) {
    return res.status(400).json({ error: "invalid_nonce" });
  }

  // 4) Extract the age verification claim
  const ageOver18 = extractClaim(vpPayload, "eu.europa.ec.av.1", "age_over_18");
  
  if (ageOver18 !== true) {
    return res.status(403).json({ error: "age_requirement_not_met" });
  }

  // 5) Success - complete the age verification flow
  markSessionAsAgeVerified(state);
  
  // Return success response to wallet
  res.status(200).json({ 
    redirect_uri: "https://rp.example.com/success"
  });
});
```

### Example VP token (JWT format, simplified)

```json
{
  "iss": "https://wallet.example.com",
  "aud": "redirect_uri:https://rp.example.com/api/openid4vp/callback",
  "nonce": "550e8400-e29b-41d4-a716-446655440000",
  "vp": {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    "type": ["VerifiablePresentation"],
    "verifiableCredential": [
      {
        "type": ["VerifiableCredential", "ProofOfAge"],
        "credentialSubject": {
          "eu.europa.ec.av.1": {
            "age_over_18": true
          }
        },
        "issuer": "https://issuer.example.com",
        "issuanceDate": "2025-01-15T00:00:00Z",
        "proof": {
          "type": "JsonWebSignature2020",
          "created": "2025-01-15T00:00:00Z",
          "jws": "eyJhbGciOiJFUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19...."
        }
      }
    ]
  }
}
```

### Example presentation_submission

```json
{
  "id": "submission_1",
  "definition_id": "age_verification",
  "descriptor_map": [
    {
      "id": "age_attestation",
      "format": "jwt_vp",
      "path": "$",
      "path_nested": {
        "format": "jwt_vc",
        "path": "$.vp.verifiableCredential[0]"
      }
    }
  ]
}
```

## Same-device vs. Cross-device flows

### Same-device flow

1. User clicks "Verify Age" button in the RP web app.
2. RP navigates to `av://authorize?...` (or opens in a new window).
3. OS launches the Age Verification App.
4. User approves the presentation.
5. Wallet POSTs to `response_uri`.
6. RP endpoint processes the response and updates the session.
7. User is redirected back to the RP web app (via `redirect_uri` in the response).

### Cross-device flow (QR code)

1. RP displays a QR code encoding the `av://` URL.
2. User scans the QR code with their mobile device.
3. Mobile wallet parses the request and prompts for consent.
4. Wallet POSTs to `response_uri` (cross-device).
5. RP endpoint updates the session.
6. Desktop browser polls the RP session endpoint or uses WebSocket to detect completion.
7. RP redirects the desktop browser to the success page.

## Security considerations (Age Verification)

### Nonce binding

- **CRITICAL**: The RP MUST generate a fresh, cryptographically random `nonce` for each request.
- The RP MUST store the `nonce` server-side (keyed by `state` or session ID).
- The RP MUST reject VP tokens with missing or incorrect `nonce` values.
- This prevents replay attacks and session fixation.

### Origin validation

- The `response_uri` MUST be on the same origin as the RP.
- The RP MUST validate that the `audience` (`aud`) claim in the VP token matches the expected `client_id`.

### HTTPS requirement

- The `response_uri` MUST use HTTPS in production.
- This protects the VP token in transit.

### Data minimization

- Request only the claims needed for age verification (e.g., `age_over_18`).
- Avoid requesting full name, address, portrait, or other identifying attributes unless your privacy policy requires them.

### No client authentication

- While client authentication is out of scope for this profile, RPs SHOULD still validate:
  - VP token signature (issuer trust).
  - VP token validity period.
  - Credential status (revocation, expiration).

## Interop checklist

- [ ] `av://` URL scheme is registered and can launch the wallet.
- [ ] `response_type=vp_token` is set.
- [ ] `response_mode=direct_post` is set.
- [ ] `client_id` uses the `redirect_uri:` prefix.
- [ ] `nonce` is fresh, random, and stored server-side.
- [ ] `dcql_query` is valid JSON and follows the DCQL schema.
- [ ] `response_uri` is HTTPS and handles POST requests.
- [ ] Wallet POSTs `vp_token` + `presentation_submission` + optional `state`.
- [ ] RP validates `nonce`, `aud`, signature, and claim values.
- [ ] RP returns a redirect URI or success indicator to the wallet.

## Comparison with W3C Digital Credentials API

| Aspect | W3C Digital Credentials API | OpenID4VP Fallback |
|--------|----------------------------|-------------------|
| **Invocation** | `navigator.credentials.get()` | `av://` custom URL scheme |
| **Response delivery** | JavaScript Promise (in-page) | HTTP POST to `response_uri` |
| **Cross-device support** | Limited (requires browser extension workaround) | Native (via QR code) |
| **Browser support** | Chrome (flag), limited | Universal (OS handles URL scheme) |
| **Request format** | Base64url CBOR (ISO 18013-7) | Query parameters + DCQL JSON |
| **Response format** | Base64url CBOR (HPKE encrypted) | JWT or CBOR (no encryption required) |
| **Primary use case** | Same-device, browser-native | Cross-device, mobile wallets |

## References

- EU Age Verification Profile – Annex A, A.5 (OpenID4VP Requirements): <https://ageverification.dev/av-doc-technical-specification/docs/annexes/annex-A/annex-A-av-profile/#openid-for-verifiable-presentations-profile-requirements>
- OpenID for Verifiable Presentations 1.0: <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html>
- OpenID4VP Section 6 (DCQL): <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6>
- DCQL Age Verification chapter (this book): [DCQL Age Verification](./dcql_age_verification.md)
- ISO mDoc + DCAPI chapter (this book): [Age Verification: ISO mDoc + DCAPI](./iso_18013_dcapi_age_verification.md)
