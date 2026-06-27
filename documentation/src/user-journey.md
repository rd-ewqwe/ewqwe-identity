# User Journey

This page describes the end-to-end credential verification flow from the perspective of a Relying Party.

## The Two Profiles

The EU Digital Identity ecosystem defines two main profiles:

| Profile | Purpose | Transport | Request Signing | Response |
|---------|---------|-----------|-----------------|----------|
| **EU Age Verification** (Annex A) | Privacy-preserving age checks | `openid4vp://` deep link or QR, `direct_post` | None (`redirect_uri` scheme) | Plain VP Token |
| **HAIP** | High-assurance identity (PID, mDL) | `openid4vp://` deep link or QR, `direct_post.jwt` | JAR with `x5c` certificate chain | JWE-encrypted VP Token |

For a detailed protocol and format reference, see the [Protocols & Formats Summary](./summary_protocols_formats.md).

## OpenID4VP Cross-Device Flow (QR Code)

This is the primary production flow. The user scans a QR code on the Relying Party's screen with their mobile wallet.

```mermaid
sequenceDiagram
    participant User
    participant RP as Relying Party
    participant Verifier as Credential Verifier
    participant Wallet as EUDI Wallet

    User->>RP: Visits website, clicks "Verify Age"
    RP->>Verifier: POST /ewqwe_api/openid4vp/init
    Verifier-->>RP: { transaction_id, qr_code_data_url, request_uri }
    RP->>User: Displays QR code

    User->>Wallet: Scans QR code
    Wallet->>Verifier: GET /ewqwe_api/openid4vp/request/{id}
    Verifier-->>Wallet: Authorization request (JAR or plain JSON)
    Wallet->>User: Consent dialog — "Share proof of age?"
    User->>Wallet: Approves

    Wallet->>Verifier: POST /ewqwe_api/openid4vp/direct_post (VP Token)
    Verifier->>Verifier: Validate signatures, expiry, nonce
    Verifier-->>Wallet: 200 OK

    RP->>Verifier: GET /ewqwe_api/openid4vp/status/{id} (polling)
    Verifier-->>RP: { status: "verified", attestation: "<signed JWT>" }
    RP->>User: Displays verification result
```

## Verification Flow (Common to All)

Regardless of the transport (QR code, deep link, or DC API), the verification steps are the same:

1. **RP initiates** a transaction with the Credential Verifier, specifying the credential type and claims
2. **Wallet presents** the VP Token to the verifier (encrypted with JWE for HAIP, plain for Annex A)
3. **Verifier validates**: decrypts JWE if present, verifies issuer signatures against the trusted CA directory, checks disclosure digests, validates holder binding (KB-JWT or DeviceSignature), and checks expiry
4. **Verifier returns** a signed JWT attestation to the RP, confirming the verified claims

The RP uses the attestation for access control and session establishment.

## Related Pages

- [Protocols & Formats Summary](./summary_protocols_formats.md) — complete protocol and format reference
- [Credential Verifier Server](./credential_verifier_server.md) — server API and configuration
- [Demo Webapp](./demo_webapp.md) — reference implementation
