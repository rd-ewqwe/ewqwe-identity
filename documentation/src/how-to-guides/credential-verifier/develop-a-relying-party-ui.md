# Develop your own relying-party UI

This guide shows how to add credential verification to a user interface of your own. The credential verifier already ships with a standard user interface, the [verifier app](../../reference/verifier-app/verifier-app.md). Build your own interface only when you need to embed verification in your own product, with your own layout and your own session.

The repository contains an **example relying party** in `webapp/`. The example is an advanced, working reference that shows one way to build such an interface. It is not part of the credential verifier and is not a supported deployment.

## Goal

Build a user interface that requests a credential from a wallet, sends the presentation to the credential verifier, and shows the result.

## Prerequisites

- A running credential verifier. See [Install and run the server](./install-and-run.md).
- Deno 1.40 or later, to run the example.
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

The example lives in `webapp/` and uses Deno and TypeScript. It has no front-end framework.

| Path                        | Contents                                                 |
| :-------------------------- | :------------------------------------------------------- |
| `webapp/deno.json`          | Deno tasks and the module imports.                       |
| `webapp/server.ts`          | The proxy server that forwards requests to the verifier. |
| `webapp/src/rp.ts`          | The relying-party application logic.                     |
| `webapp/src/credentials.ts` | The credential request and verification logic.           |
| `webapp/src/config.ts`      | The credential type configurations.                      |
| `webapp/src/types.ts`       | The TypeScript type definitions.                         |

Run the example with two processes, in this order.

```bash
# Terminal 1: the proxy server on port 5175
cd webapp
CA_CERT_PATH=../certificates/tls/ewqwe.ca.pem deno task api
```

```bash
# Terminal 2: the Vite dev server on port 5174
cd webapp
deno task vite
```

Open `https://localhost:5174/`. The Vite dev server serves the interface and forwards each `/ewqwe_api/` request to the proxy on port 5175.

The proxy reads two environment variables:

| Variable                  | Default                  | Purpose                                           |
| :------------------------ | :----------------------- | :------------------------------------------------ |
| `CREDENTIAL_VERIFIER_URL` | `https://127.0.0.1:9443` | The base URL of the credential verifier.          |
| `CA_CERT_PATH`            | none                     | The CA certificate that the proxy trusts for TLS. |

The proxy forwards every `/ewqwe_api/` request to the credential verifier, so the browser talks to one origin and no client certificate is needed in the browser. In a production deployment, terminate the client certificate at your own proxy or web server.

## Incorporate verification in your own interface

Use the example as a template and keep the following points.

1. Keep the verifier call on your backend. The browser must not hold the client certificate, and the verifier must not be reachable without one in production.
2. Bind each request to a transaction. Never invent the nonce in the browser. Read the nonce and the `state` from the transaction that the verifier created, and send that `state` back with the presentation.
3. Verify the attestation that the verifier returns before you trust the result. Fetch the public key from the JWKS endpoint and check the signature and the `exp` claim. See [Attestations](../../reference/credential-verifier/attestations.md).
4. Request only the claims that your product needs. An age check asks for the derived claim `age_over_18`, not the birth date. See [Selective disclosure](../../explanation/digital-credential/selective-disclosure.md).
5. Handle every status. A transaction can expire, and a presentation can fail a check.

## Troubleshooting

| Symptom                                 | Cause                                       | Action                                                      |
| :-------------------------------------- | :------------------------------------------ | :---------------------------------------------------------- |
| The proxy cannot reach the verifier     | The CA certificate is not trusted.          | Set `CA_CERT_PATH` to your verifier CA certificate.         |
| Every request returns 404               | The wallet path is not served.              | Check that the proxy forwards to `CREDENTIAL_VERIFIER_URL`. |
| The verifier rejects the presentation   | The nonce or the `state` does not match.    | Read the nonce and the `state` from the stored transaction. |
| The browser shows a certificate warning | The development certificate is self-signed. | Accept the certificate for `https://localhost:5174/`.       |

## Related pages

- [HTTP API](../../reference/credential-verifier/http-api.md)
- [Verify a credential](./verify-a-credential.md)
- [OpenID4VP request parameters](../../reference/openid4vp/request-parameters.md)
- [Protocol modes](../../explanation/openid4vp/protocol-modes.md)
- [The verifier app](../../reference/verifier-app/verifier-app.md)
