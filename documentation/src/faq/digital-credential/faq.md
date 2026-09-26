# Questions about credentials

This page answers common questions about credential formats and credential building. Each answer links to the page that holds the full explanation.

## Which credential formats does the verifier accept?

The verifier accepts `mso_mdoc` (ISO/IEC 18013-5) and `dc+sd-jwt` (SD-JWT VC). See [Credential formats](../../reference/digital-credential/credential-formats.md).

## How does the verifier detect the credential format?

The verifier reads the presentation itself. A value with the `~` separator is an SD-JWT VC, and any other value is parsed as a Base64URL-encoded CBOR mDoc. See [Credential formats](../../reference/digital-credential/credential-formats.md).

## What is the difference between mso_mdoc and SD-JWT VC?

The mso_mdoc format uses CBOR encoding and COSE signatures, and the SD-JWT VC format uses JSON and JWS signatures. Both formats support selective disclosure and holder binding. See [Credential formats](../../reference/digital-credential/credential-formats.md).

## Which credential types can the verifier verify?

The verifier has no fixed list of types. It verifies the type that the operator requests in the DCQL query, provided the issuer chains to a trusted CA. See [Credential types](../../reference/digital-credential/credential-types.md).

## Which credential type should I use for age verification?

Use an mDL or a Proof of Age attestation. The Proof of Age attestation carries only `age_over_18` and no identity data. See [Credential types](../../reference/digital-credential/credential-types.md).

## Does the EUDI PID carry an age attribute?

No. The EU ARF PID Rulebook removed the age attributes from the PID, and `age_over_18` is not a valid PID attribute. See [Credential types](../../reference/digital-credential/credential-types.md).

## Can an mDL use the SD-JWT VC format?

No. The 4th Driving Licence Regulation requires the ISO/IEC 18013-5 data model, so an mDL uses the mso_mdoc format only. See [Credential types](../../reference/digital-credential/credential-types.md).

## What does selective disclosure do?

Selective disclosure lets a holder reveal a subset of the claims in a credential while the verifier still checks the issuer signature. See [Selective disclosure](../../explanation/digital-credential/selective-disclosure.md).

## Why does a verified credential show only some of its claims?

The holder revealed only those claims. Each format commits to every claim with a salted hash, so the holder chooses which claims to disclose. See [Selective disclosure](../../explanation/digital-credential/selective-disclosure.md).

## What is holder binding?

Holder binding is the proof that the presenter controls the private key that the credential names. An mDoc uses the `deviceSignature`, and an SD-JWT VC uses the Key Binding JWT. See [Credential formats](../../reference/digital-credential/credential-formats.md).

## How do I build a test credential?

Use the `CredentialIssuer` type of the `ewqwe_digital_credential` library. The type generates an ephemeral issuing authority and builds a signed credential in either format. See [Issue a test credential](../../how-to-guides/digital-credential/issue-a-test-credential.md).

## Must a test credential use the nonce of the current transaction?

Yes. The verifier compares the nonce of the presentation with the nonce of the stored transaction, and rejects a mismatch. See [Request parameters](../../reference/openid4vp/request-parameters.md).

## Why does an mDoc presentation need a state value?

The verifier rebuilds the OpenID4VP session transcript from the stored transaction to verify the `deviceSignature`. Without the `state` value, the verifier cannot find the transaction. See [Verify a credential](../../how-to-guides/credential-verifier/verify-a-credential.md).

## Which signature algorithms does the verifier accept?

For mDoc, the verifier accepts the COSE algorithms ES256, ES384, ES512, RS256, RS384, and RS512. For SD-JWT VC, the verifier accepts the JWS algorithms that the issuer JWT names, which are ES256, ES384, RS256, RS384, and RS512. See [Credential formats](../../reference/digital-credential/credential-formats.md).
