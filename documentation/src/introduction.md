# Introduction

![ewQwe logo](images/ewqwe_logo.png)

**ewQwe Digital Identity** is a software suite for digital identity based on the European Digital Identity (EUDI) standards. Its principal product is the **ewQwe Credential Verifier**, a server that a Relying Party uses to verify the credentials that a user presents from a digital wallet.

A **Relying Party** (RP) is a web application or service that needs a fact about a user, for example that the user is at least 18 years old. A **wallet** is the application that stores the user's credentials and presents them. A **credential** is a signed document that an issuer, such as a government authority, has issued to the user.

The verifier performs the cryptographic work of verification, so a web application does not implement it. The Relying Party sends a Verifiable Presentation to the verifier. The verifier validates the presentation and returns a signed attestation that states the result.

## What the credential verifier does

- It accepts a Verifiable Presentation in the ISO/IEC 18013-5 mDoc format or the SD-JWT VC format.
- It extracts the disclosed claims and checks the credential expiration.
- It binds the presentation to the nonce that the server issued for the transaction, which prevents replay.
- It verifies the issuer signature and the holder signature, using the trusted issuer certificate authorities that the operator configures.
- It returns a signed attestation, in JWT or COSE/CBOR form, that states the verification result.
- It records every verification in an append-only journal.

The server implements the [W3C Digital Credentials API](https://www.w3.org/TR/digital-credentials/), [OpenID for Verifiable Presentations 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) (OpenID4VP), and the [EU Age Verification Profile](https://ageverification.dev/Technical%20Specification/annexes/annex-A/annex-A-av-profile). It supports the High Assurance Interoperability Profile (HAIP) additions for the EUDI Wallet.

## The verifier app

The credential verifier ships with its own web application, the **verifier app**. An operator signs in, selects a credential type, and shows a QR code. The holder scans the QR code with a wallet, and the app shows the verification result. The verifier app is the standard user interface of the credential verifier and needs no other software.

The verifier also exposes an HTTP API, so a product can build a user interface of its own. The repository contains an example relying party in `webapp/` that shows one way to do this. See [Develop your own relying-party UI](./how-to-guides/credential-verifier/develop-a-relying-party-ui.md).

## Who this documentation is for

This documentation addresses the users of the credential verifier server:

| Reader                  | Starting point                                                                                                                                                    |
| :---------------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| System operator         | [Run the verifier app](./tutorials/verifier-app/run-the-verifier-app.md) and [Install and run the server](./how-to-guides/credential-verifier/install-and-run.md) |
| Relying Party developer | [HTTP API](./reference/credential-verifier/http-api.md) and [Verify a credential](./how-to-guides/credential-verifier/verify-a-credential.md)                     |
| Product developer       | [Develop your own relying-party UI](./how-to-guides/credential-verifier/develop-a-relying-party-ui.md)                                                            |
| Security architect      | [Verification process](./explanation/credential-verifier/verification-process.md) and [Security model](./explanation/credential-verifier/security-model.md)       |
| Standards engineer      | [OpenID4VP request parameters](./reference/openid4vp/request-parameters.md) and [Credential formats](./reference/digital-credential/credential-formats.md)        |

## How this documentation is organized

The book follows the [Diataxis framework](https://diataxis.fr). Each section serves one need of the reader:

- **Tutorials** teach the verifier app in a guided lesson.
- **Reference** states the facts of the server: the configuration, the HTTP API, the attestations, the journal, the protocols, and the credential formats.
- **Explanation** describes why the server works the way it does.
- **How-to guides** give the steps for a specific task, such as deploying the server with TLS.
- **FAQ** answers recurring questions and links to the page that holds the full answer.

The [Glossary](./glossary.md) defines the terms that the documentation uses. The [References](./references.md) page lists the external standards.

> [!NOTE]
> The example relying party in `webapp/` is an advanced reference for building your own interface. It is not part of the credential verifier server, and it is not intended for production use as it stands.

## Related components

The credential verifier depends on three crates of this repository:

- `crates/openid4vp` builds and validates OpenID4VP requests and matches DCQL queries.
- `crates/ewqwe-digital-credential` builds and verifies mDoc and SD-JWT VC credentials.
- `crates/ewqwe-credential-verifier-ui` is the verifier app, the built-in web application that an operator uses to run age verifications.

The server returns a signed attestation, so a Relying Party can trust the result without performing the verification itself. See the [HTTP API](./reference/credential-verifier/http-api.md) for the request and response of each endpoint.
