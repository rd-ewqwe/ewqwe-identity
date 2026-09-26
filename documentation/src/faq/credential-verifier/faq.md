# Questions about the server

This page answers recurring questions about the credential verifier. Each answer links to the page that holds the full explanation.

## What does the credential verifier do?

The verifier accepts a Verifiable Presentation (VP Token) from a relying party, checks the presentation, and returns a signed attestation that states the outcome. The full sequence of checks is described in [the verification process](../../explanation/credential-verifier/verification-process.md).

## Does the verify endpoint require a client certificate?

Yes. The verification endpoint requires mutual TLS, so the caller must present a client certificate signed by a CA in `client_ca_cert_chain`. The setup is described in [configure TLS](../../how-to-guides/credential-verifier/configure-tls.md).

## Does the verifier need a Redis server?

No, not by default. The transaction store defaults to SQLite in memory, and Redis is one of several selectable backends. See [configure storage](../../how-to-guides/credential-verifier/configure-storage.md).

## Why does the verifier report `issuer_trusted` as false?

The issuer certificate chain does not terminate at a certificate in the trusted issuer CA directory. Add the issuer CA file to that directory and restart the server, because the directory is read only at startup. See [the security model](../../explanation/credential-verifier/security-model.md).

## Why does the verify endpoint return HTTP 200 with `success` false?

For an SD-JWT VC, the presentation was well formed but one of the checks failed. The `errors` array names the failing checks, and the attestation records the failure. See [verify a credential](../../how-to-guides/credential-verifier/verify-a-credential.md).

## Why does the verify endpoint return HTTP 400?

The request is malformed, refers to a transaction that does not match, or presents an mDoc that fails a check, such as an untrusted issuer. The response body states the reason. See [the HTTP API reference](../../reference/credential-verifier/http-api.md).

## How does the verifier prevent a replay of a presentation?

The verifier reads the nonce from its own transaction store, never from the request body, and compares it with the nonce bound into the presentation. A successful verification consumes the stored transaction, which removes the context that an mDoc presentation needs. See [the security model](../../explanation/credential-verifier/security-model.md) for the limits of this binding.

## Does the verifier reveal the user's birth date?

Only if the relying party asks for the birth date claim. An age request normally asks for the derived claim `age_over_18`, which reveals a boolean and not a date. See [selective disclosure](../../explanation/digital-credential/selective-disclosure.md).

## How long is a transaction valid?

A transaction lives for `transaction_ttl_secs`, which defaults to 300 seconds. An expired transaction cannot be verified. See [configure storage](../../how-to-guides/credential-verifier/configure-storage.md).

## How long is an attestation valid?

An attestation is valid for 300 seconds by default. The relying party should verify the `exp` claim before it uses the result. See [attestations](../../reference/credential-verifier/attestations.md).

## How do I verify the signature of an attestation?

Fetch the public key from the JWKS endpoint and select the key whose `kid` matches the `kid` in the attestation JWT header. See [attestations](../../reference/credential-verifier/attestations.md).

## What is the verification journal?

The journal is an append-only, hash-chained audit log of successful verifications, scoped per authenticated user. The verifier disables it by default. See [the verification journal](../../reference/credential-verifier/verification-journal.md).

## Can I run the verifier without TLS?

No. The listener always uses TLS, so the server always needs a private key, a certificate, and a CA chain. See [install and run the server](../../how-to-guides/credential-verifier/install-and-run.md).

## How do I turn off authentication for local tests?

Set `disable_authentication = true` and name the test user in `disabled_authentication_user`. Use this setting only on a local test machine. See [configuration](../../reference/credential-verifier/configuration.md).

## How do I test the server with a real wallet?

Use the step-by-step guides for the wallet that you have. See [test with the EUDI wallet](../../how-to-guides/credential-verifier/test-with-the-eudi-wallet.md) or [test with the AV app](../../how-to-guides/credential-verifier/test-with-the-av-app.md).
