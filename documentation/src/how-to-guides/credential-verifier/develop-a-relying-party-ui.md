# Develop your own relying-party UI

This guide shows how to add credential verification to a user interface of your own. The credential verifier already ships with a standard user interface, the [verifier app](../../reference/verifier-app/verifier-app.md). Build your own interface only when you need to embed verification in your own product, with your own layout and your own session.

The repository contains an **example relying party** in `typescript/demo-webapp/`. The example is an advanced, working reference that shows one way to build such an interface. It is not part of the credential verifier and is not a supported deployment.

## Goal

Build a user interface that requests a credential from a wallet, sends the presentation to the credential verifier, and shows the result.

## Prerequisites

- A running credential verifier. See [Install and run the server](./install-and-run.md).
- Node.js 18 or later and pnpm, to run the example.
- A wallet that holds a credential. See [Test with the age verification app](./test-with-the-av-app.md) or [Test with the EUDI wallet](./test-with-the-eudi-wallet.md).

## Choose an interface

| Interface                      | Use it when                                                 |
| :----------------------------- | :---------------------------------------------------------- |
| The verifier app               | You want the standard interface, with no extra development. |
| Your own UI, with the HTTP API | You want your own layout, integrated in your own product.   |
| The example relying party      | You want a working reference to start from.                 |

The verifier app is described in [Run the verifier app](../../tutorials/verifier-app/run-the-verifier-app.md). This guide covers the other two rows.

## What your interface must do

A relying-party interface performs five steps. The credential verifier performs the cryptography; your interface drives the flow and shows the result.

1. Start a transaction with [the OpenID4VP init endpoint](../../reference/credential-verifier/http-api.md).
2. Present the authorization request to the wallet. Use the W3C Digital Credentials API when the browser provides it, and the OpenID4VP redirect or QR-code flow otherwise. See [Protocol modes](../../explanation/openid4vp/protocol-modes.md).
3. Receive the verifiable presentation. The wallet either posts the presentation directly, or your interface collects it and sends it to the verifier.
4. Ask the credential verifier to verify the presentation. See [Verify a credential](./verify-a-credential.md).
5. Show the result, which is the signed attestation that the verifier returns.

The request parameters and the DCQL query are described in [OpenID4VP request parameters](../../reference/openid4vp/request-parameters.md) and [DCQL queries](../../reference/openid4vp/dcql-queries.md).

## The example relying party

The example lives in `typescript/demo-webapp/`. It uses TypeScript, Vite, and Tailwind CSS, without a front-end framework.

| Path                                              | Contents                                         |
| :------------------------------------------------ | :----------------------------------------------- |
| `typescript/demo-webapp/vite.config.ts`           | The Vite configuration and the reverse proxy.    |
| `typescript/demo-webapp/index.html`               | The HTML entry page.                             |
| `typescript/demo-webapp/src/main.ts`              | The entry point that starts the application.     |
| `typescript/demo-webapp/src/relying_party_app.ts` | The relying-party application logic.             |
| `typescript/demo-webapp/src/credentials.ts`       | The credential request and verification logic.   |
| `typescript/demo-webapp/src/dc_api_service.ts`    | The W3C Digital Credentials API integration.     |
| `typescript/demo-webapp/src/hpke.ts`              | The HPKE decryption helper for the Annex C flow. |
| `typescript/demo-webapp/src/debug.ts`             | The debug helpers.                               |
| `typescript/demo-webapp/package.json`             | The scripts and the dependencies.                |

Run the example from the TypeScript workspace root.

```bash
cd typescript
pnpm install
pnpm --filter @ewqwe/digital-identity build
pnpm --filter @ewqwe/demo-webapp dev
```

Open `https://localhost:5174/`. The Vite dev server serves the interface and forwards each `/ewqwe_api/` request to the credential verifier. Vite generates a development certificate on the first run, so the browser shows a warning; accept the certificate and continue.

The Vite server reads one environment variable:

| Variable                  | Default                  | Purpose                                  |
| :------------------------ | :----------------------- | :--------------------------------------- |
| `CREDENTIAL_VERIFIER_URL` | `https://127.0.0.1:9443` | The base URL of the credential verifier. |

The dev server forwards every `/ewqwe_api/` request to the credential verifier, so the browser talks to one origin and no client certificate is needed in the browser. In a production deployment, terminate the client certificate at your own proxy or web server.

## Incorporate verification in your own interface

Use the example as a template and keep the following points.

1. Keep the verifier call on your backend. The browser must not hold the client certificate, and the verifier must not be reachable without one in production.
2. Bind each request to a transaction. Never invent the nonce in the browser. Read the nonce and the `state` from the transaction that the verifier created, and send that `state` back with the presentation.
3. Verify the attestation that the verifier returns before you trust the result. Fetch the public key from the JWKS endpoint and check the signature and the `exp` claim. See [Attestations](../../reference/credential-verifier/attestations.md).
4. Request only the claims that your product needs. An age check asks for the derived claim `age_over_18`, not the birth date. See [Selective disclosure](../../explanation/digital-credential/selective-disclosure.md).
5. Handle every status. A transaction can expire, and a presentation can fail a check.

## Troubleshooting

| Symptom                                  | Cause                                             | Action                                                      |
| :--------------------------------------- | :------------------------------------------------ | :---------------------------------------------------------- |
| The dev server cannot reach the verifier | The verifier is not running, or the URL is wrong. | Start the verifier and check `CREDENTIAL_VERIFIER_URL`.     |
| Every request returns 404                | The verifier does not serve the path.             | Check the base URL of the verifier.                         |
| The verifier rejects the presentation    | The nonce or the `state` does not match.          | Read the nonce and the `state` from the stored transaction. |
| The browser shows a certificate warning  | The development certificate is self-signed.       | Accept the certificate for `https://localhost:5174/`.       |

## Related pages

- [HTTP API](../../reference/credential-verifier/http-api.md)
- [Verify a credential](./verify-a-credential.md)
- [OpenID4VP request parameters](../../reference/openid4vp/request-parameters.md)
- [Protocol modes](../../explanation/openid4vp/protocol-modes.md)
- [The verifier app](../../reference/verifier-app/verifier-app.md)
