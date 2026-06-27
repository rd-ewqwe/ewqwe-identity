# Demo Webapp (Relying Party)

The **Demo Webapp** is a vanilla TypeScript SPA that demonstrates how to integrate credential verification into your own web application. It's MIT-licensed so you can freely adapt and embed it.

It implements the full OpenID4VP cross-device flow:

1. Select a credential type (Proof of Age, mDL, or National ID)
2. The webapp initiates a transaction with the Credential Verifier
3. A QR code is displayed for the user to scan with their EUDI Wallet
4. The wallet presents the credential to the verifier
5. The webapp polls for the result and displays the verification outcome

## Running

```bash
cd typescript
pnpm install
pnpm --filter @ewqwe/digital-identity build
pnpm --filter @ewqwe/demo-webapp dev    # https://localhost:5174
```

The demo webapp connects to the Credential Verifier at the URL configured in its environment. See the [TypeScript workspace README](https://github.com/rd-ewqwe/ewqwe-identity/blob/main/typescript/README.md) for details.

## Protocol Support

The webapp supports two OpenID4VP profiles, selected automatically based on credential type:

| Credential Type | Profile | Client ID Scheme | Response Mode |
|----------------|---------|-----------------|---------------|
| Proof of Age | EU Age Verification (Annex A) | `redirect_uri` | `direct_post` |
| mDL / National ID | HAIP | `x509_san_dns` | `direct_post.jwt` |

For details on these profiles, see the [Protocols & Formats Summary](./summary_protocols_formats.md).

## Integration Pattern

The demo webapp demonstrates the standard integration pattern for a Relying Party:

```typescript
// 1. Initiate a transaction
const init = await fetch("/api/openid4vp/init", {
  method: "POST",
  body: JSON.stringify({ credential_type: "proof-of-age" })
});
const { transaction_id, qr_code_data_url } = await init.json();

// 2. Display QR code for wallet scanning
displayQRCode(qr_code_data_url);

// 3. Poll for verification result
const status = await pollStatus(transaction_id);

// 4. Receive signed attestation
if (status.result === "verified") {
  const attestation = status.attestation; // Signed JWT
}
```

See the [Demo Architecture](./demo_architecture.md) page for the full system setup and testing flow.

## Source Code

The demo webapp is in `typescript/demo-webapp/`. It uses:

- **`@ewqwe/digital-identity`** — shared library for DCQL query building, protocol profiles, and the verifier API client
- **Vite** — dev server and build tool
- **Vanilla TypeScript** — no framework
