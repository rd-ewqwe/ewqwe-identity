# User Journey - Sequence Diagram

According to the [EU Age Verification Profile (Annex A)](https://ageverification.dev/Technical%20Specification/annexes/annex-A/annex-A-av-profile), a compliant age verification solution consists of three main components:

- The **Relying Party (RP)** - A web application that requests proof of age from users, for example to verify age requirements for accessing age-restricted content or services.
- The **Age Verification App Instance (AVI)** - The user's digital wallet that securely stores Proof of Age attestations and other credentials. The AVI can be implemented as a mobile application, desktop application, or browser extension.
- The **EwQwE Credential Verifier** - A trusted service that verifies credentials presented by the AVI on behalf of the RP and issues cryptographically signed attestations confirming successful verification.

## Credential Presentation Flow

The sequence diagram below shows the complete flow for credential presentation, implementing the requirements from [Annex A.5](https://ageverification.dev/Technical%20Specification/annexes/annex-A/annex-A-av-profile#a5-proof-of-age-attestation-presentation):

1. **Primary Method**: Attempting the W3C Digital Credentials API (as per [Annex A.5](https://ageverification.dev/Technical%20Specification/annexes/annex-A/annex-A-av-profile#a5-proof-of-age-attestation-presentation) - default method)
2. **Fallback Mechanism**: Using OpenID4VP via postMessage when the native API is unavailable (as per [Annex A.5.2](https://ageverification.dev/Technical%20Specification/annexes/annex-A/annex-A-av-profile#openid-for-verifiable-presentations-profile-requirements) - required fallback)
3. **Verification**: Backend verification and signed attestation issuance

```mermaid
sequenceDiagram
    participant User
    participant WebappUI as Relying Party (RP)<br/>Web Application
    participant Wallet as Age Verification<br/>App Instance (AVI)<br/>(Browser Extension)
    participant Backend as RP<br/>Backend
    participant Verifier as EwQwE<br/>Credential Verifier

    User->>WebappUI: 1. Click "Request Credentials"
    User->>WebappUI: e.g. Click "Verify Age"
    
    Note over WebappUI,Wallet: Primary Method: W3C Digital Credentials API (Annex A.5)
    WebappUI->>WebappUI: 2. Try navigator.credentials.get()<br/>{digital: {protocol: "openid4vp"}}
    WebappUI->>WebappUI: ❌ NetworkError: No provider registered
    
    Note over WebappUI,Wallet: Fallback: OpenID4VP via postMessage<br/>(Annex A.5.2 - Required fallback)
    WebappUI->>Wallet: 3. postMessage EU_AV_WALLET_REQUEST<br/>{protocol: "openid4vp", data: {...}}
    Wallet->>Wallet: 4. Parse DCQL query
    Wallet->>Wallet: 5. Match credentials from storage
    Wallet->>WebappUI: 6. Show credential selector overlay
    User->>Wallet: 7. User selects credential
    Wallet->>Wallet: 8. Build OpenID4VP response<br/>{vp_token, presentation_submission}
    Wallet->>WebappUI: 9. postMessage EU_AV_WALLET_RESPONSE<br/>{response: {vp_token, ...}}
    
    Note over WebappUI,Verifier: Verification Flow
    WebappUI->>Backend: 10. POST /api/verify<br/>{vp_token, nonce, client_id}
    Backend->>Verifier: 11. POST /verify (HTTPS + mTLS)
    Verifier->>Verifier: 12. Verify VP token
    Verifier->>Verifier: 13. Validate credential signature
    Verifier->>Verifier: 14. Create signed attestation (ES256)
    Verifier-->>Backend: 15. Return {success, claims, attestation_jwt}
    Backend-->>WebappUI: 16. Return verification result
    WebappUI->>User: 17. Display verification result
```
