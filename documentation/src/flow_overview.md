# User Journey - Sequence Diagram

A Digital Identity verification solution is composed of 3 main components:

- The Relying Party (RP) web application which requires a verifiable credential from a user, for example to verify the user's age,
- The user's Digital Wallet that holds the user's credentials. The Digital Wallet can run as a mobile application, desktop application, or browser extension,.
- The EwQwE Credential Verifier server that verifies the credential presented by the user and issues a signed attestation back to the Relying Party.
-language tool linter are you ere

```mermaid
sequenceDiagram
    participant User
    participant WebappUI as RP Webapp UI<br/>(Browser)
    participant Wallet as User's Wallet
    participant Backend as RP Webapp<br/>Backend
    participant Verifier as EwQwE<br/>Credential Verifier

    User->>WebappUI: 1. Click "Provide<br/>Verifiable Credentials"
    User->>WebappUI: e.g. Click "Verify Age"
    WebappUI->>Wallet: 2. postMessage EU_AV_WALLET_REQUEST<br/>{protocol, data}
    Wallet->>Wallet: 3. Query matching credentials from storage
    Wallet->>WebappUI: 4. Show credential selector overlay
    User->>Wallet: 5. User selects credential
    Wallet->>WebappUI: 6. postMessage EU_AV_WALLET_RESPONSE<br/>{vp_token, ...}
    WebappUI->>Backend: 7. POST /api/verify<br/>{vp_token, nonce, client_id}
    Backend->>Verifier: 8. POST /verify (TLS with CA)
    Verifier->>Verifier: 9. Verify credential
    Verifier->>Verifier: 10. Create signed attestation
    Verifier-->>Backend: 11. Return {success, claims, attestation}
    Backend-->>WebappUI: 12. Return verification result<br/>{verified, claims, attestation}
    WebappUI->>User: 13. Display verification result
```
