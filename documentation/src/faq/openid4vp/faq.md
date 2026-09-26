# Questions about OpenID4VP

## What is OpenID4VP?

OpenID for Verifiable Presentations (OpenID4VP) is an OpenID specification that lets a relying party ask a wallet for a verifiable presentation. The relying party encodes the request in a URL, and the wallet returns the presentation over HTTP. See [OpenID4VP authorization request parameters](../../reference/openid4vp/request-parameters.md).

## Why does the system use OpenID4VP at all?

The EU Age Verification Profile names the W3C Digital Credentials API as the primary method and OpenID4VP as the fallback for browsers that do not provide that API. See [Protocol modes](../../explanation/openid4vp/protocol-modes.md).

## Does the verifier need a signed authorization request?

No. The age verification profile uses the `redirect_uri` client identifier scheme, which forbids a signed request. Trust rests on TLS and the web PKI instead of a trust list of relying parties. See [Client identifier schemes](../../reference/openid4vp/request-parameters.md).

## Which client identifier scheme should I use?

Use `redirect_uri` for a proof of age from the age verification app, and use `x509_san_dns` for a mobile driving licence or a national identity from the EUDI Wallet. The scheme must match the target wallet, because the EUDI Wallet rejects the `redirect_uri` scheme. See [Client identifier schemes](../../reference/openid4vp/request-parameters.md).

## What is the difference between direct_post and fragment?

With `direct_post`, the wallet posts the presentation to the `response_uri` of the relying party, which enables cross-device flows. With `fragment`, the wallet returns the presentation in the URL fragment, which only works on one device. The age verification profile requires `direct_post`. See [Response modes](../../reference/openid4vp/request-parameters.md).

## Why does the response arrive as an HTTP POST instead of a redirect?

The cross-device flow needs a response channel that does not depend on the device that started the request. An HTTP POST to a public `response_uri` reaches the relying party from any phone that scanned the QR code. See [Protocol modes](../../explanation/openid4vp/protocol-modes.md).

## What is DCQL, and why does it replace presentation_definition?

DCQL is the Digital Credentials Query Language, defined in Section 6 of OpenID4VP 1.0. It expresses the required credentials and claims, and the age verification profile mandates it in place of the older DIF Presentation Exchange `presentation_definition`. See [DCQL queries](../../reference/openid4vp/dcql-queries.md).

## How do I request age over 21 instead of age over 18?

Change the claim name in the query path from `age_over_18` to `age_over_21`. The document type and the namespace stay the same. See [Age verification query examples](../../reference/openid4vp/dcql-queries.md).

## Can I accept either a proof of age or a driving licence?

Yes. Add one credential query for each option and group them in a `credential_sets` entry, so the wallet can satisfy the query with either credential. See [Multiple credential options](../../reference/openid4vp/dcql-queries.md).

## How does the system prevent replay attacks?

The relying party generates a fresh random `nonce` for every request, stores it, and rejects any presentation that carries a different nonce. The wallet echoes the nonce in the presentation, which binds the presentation to one transaction. See [OpenID4VP authorization request parameters](../../reference/openid4vp/request-parameters.md).

## Do I need to send client_metadata?

No. The age verification profile does not require `client_metadata`, and the system omits it to keep the request URL short for QR codes. See [OpenID4VP authorization request parameters](../../reference/openid4vp/request-parameters.md).

## Does the wallet send a presentation_submission with a DCQL query?

No. With a DCQL query, the `vp_token` itself maps credential identifiers to presentations, so the wallet does not send `presentation_submission`. That field belongs to the older `presentation_definition` queries. See [The vp_token response](../../reference/openid4vp/dcql-queries.md).

## What does the av:// link scheme do?

The `av://` link scheme lets the operating system open the age verification application on the device. The wallet then returns the response with an HTTP POST, not through the link itself. See [The av:// application link scheme](../../reference/openid4vp/request-parameters.md).

## Why must I send the request parameters by value instead of using a request_uri?

The profile forbids a JWT-secured authorization request by reference, because that mechanism protects the request only when a trust list of relying parties exists. For age verification no such trust list exists, so the profile requires all parameters inline in the URL. See [Protocol modes](../../explanation/openid4vp/protocol-modes.md).

## What is the difference between the same-device and cross-device flows?

In the same-device flow, the relying party and the wallet run on one device and the browser redirects to the result. In the cross-device flow, the wallet runs on a second device that scans a QR code, and the first device learns about the result through polling or a WebSocket. See [Same-device and cross-device flows](../../explanation/openid4vp/protocol-modes.md).
