# OpenID4VP authorization request parameters

OpenID for Verifiable Presentations (OpenID4VP) is an OpenID specification that lets a relying party ask a wallet for a verifiable presentation. A verifiable presentation is a credential that the wallet presents for its holder, together with cryptographic proof that the holder approved the presentation.

The relying party encodes an OpenID4VP authorization request as a set of URL parameters. The wallet reads the parameters, asks the user for consent, and returns an authorization response. This page lists the request parameters, the client identifier schemes, the response modes, and the application link scheme. The EU Age Verification Profile fixes the value of several of these parameters.

A relying party can also send the same request to the W3C Digital Credentials API instead of a URL. For the comparison between the two protocols, see [Protocol modes](../../explanation/openid4vp/protocol-modes.md).

## Authorization request parameters

| Parameter                 | Required    | Description                                                                                                                   | Value in the age verification profile          |
| :------------------------ | :---------- | :---------------------------------------------------------------------------------------------------------------------------- | :--------------------------------------------- |
| `response_type`           | Yes         | Requests a verifiable presentation token.                                                                                     | `vp_token`                                     |
| `client_id`               | Yes         | Identifies the relying party. The value carries a scheme prefix. See [Client identifier schemes](#client-identifier-schemes). | `redirect_uri:` followed by the response URI   |
| `nonce`                   | Yes         | A random value that binds the presentation to this one transaction.                                                           | A fresh random string for every request        |
| `response_mode`           | Yes         | Selects how the wallet returns the authorization response. See [Response modes](#response-modes).                             | `direct_post`                                  |
| `response_uri`            | Conditional | The endpoint that receives the wallet POST. Required when `response_mode` is `direct_post`.                                   | An HTTPS URL on the relying party              |
| `dcql_query`              | Conditional | The query for the credentials and claims. See [DCQL queries](./dcql-queries.md).                                              | A DCQL JSON object                             |
| `state`                   | No          | An opaque value that correlates the response with the request.                                                                | A random string, or omitted                    |
| `presentation_definition` | Conditional | A DIF Presentation Exchange query. OpenID4VP accepts this field or `dcql_query`, but not both.                                | Not used                                       |
| `client_metadata`         | No          | Metadata about the relying party, such as a display name and the supported presentation formats.                              | Omitted                                        |
| `scope`                   | No          | OpenID Connect scopes.                                                                                                        | Not used                                       |
| `redirect_uri`            | No          | A fallback redirect after the response is delivered.                                                                          | Not used with `direct_post`                    |

Either `presentation_definition` or `dcql_query` must be present, but not both. The EU Age Verification Profile requires `dcql_query`.

> [!NOTE]
> The `nonce` and `state` values are 22-character base64url strings in this system. They carry 128 bits of entropy, which is equivalent to a UUID version 4, and the specification does not require the UUID format.

## Client identifier schemes

The `client_id` parameter starts with a scheme prefix. The prefix tells the wallet how to interpret the identifier and how much trust to place in it. Different profiles require different schemes.

| Scheme                     | Identifier format                                                                             | Signed request                         | Trust mechanism                                   | Profile                               |
| :------------------------- | :-------------------------------------------------------------------------------------------- | :------------------------------------- | :------------------------------------------------ | :------------------------------------ |
| `redirect_uri:`            | The prefix plus the response URI, for example `redirect_uri:https://rp.example.com/callback`. | No                                     | TLS and the web PKI                               | EU Age Verification Profile (Annex A) |
| `x509_san_dns:`            | The prefix plus a DNS name, for example `x509_san_dns:rp.example.com`.                        | Yes, a JAR signed with an `x5c` header | The DNS subject alternative name of a certificate | HAIP (EUDI Wallet)                    |
| `x509_hash:`               | The prefix plus a certificate hash.                                                           | Yes, a JAR signed with an `x5c` header | The hash of an X.509 certificate                  | HAIP (EUDI Wallet)                    |
| `verifier_attestation:`    | The prefix plus an attested identifier, for example `verifier_attestation:my-verifier`.       | Yes, a JAR signed with a `jwt` header  | A JWT from a trusted attestation issuer           | HAIP (optional)                       |
| No prefix (pre-registered) | The identifier alone.                                                                         | Optional                               | Pre-configured in the wallet                      | Custom deployment                     |

### The redirect_uri scheme

The `client_id` value equals the `response_uri`, as in `client_id=redirect_uri:https://rp.example.com/ewqwe_api/openid4vp/direct_post`. The request is unsigned. It carries no JWT-secured authorization request (JAR), no `x5c` header, and no cryptographic verification. Trust rests on TLS and the web PKI. This scheme is the simplest to implement and is the one that the EU Age Verification Profile mandates.

### The x509_san_dns scheme

The `client_id` value is a DNS name that matches a subject alternative name (SAN) in an X.509 certificate, as in `client_id=x509_san_dns:rp.example.com`. The request must be signed as a JAR (RFC 9101), and the `x5c` JOSE header carries the certificate chain. The wallet validates the certificate against its reader trust store, so the root certificate authority of the relying party must be trusted by the wallet.

### Other schemes

The `x509_hash` scheme identifies the relying party by the hash of its certificate instead of by a DNS name. The `verifier_attestation` scheme identifies the relying party by an identifier that a trusted attestation issuer attests. The `verifier_attestation` scheme needs a published trust framework with designated attestation issuers, and no such framework exists for general age verification. The pre-registered scheme uses a plain identifier that the wallet holds in its configuration.

## Response modes

The `response_mode` parameter selects how the wallet returns the authorization response.

| Mode              | Description                                                  | Use                                                           |
| :---------------- | :----------------------------------------------------------- | :------------------------------------------------------------ |
| `fragment`        | The wallet returns the VP token in the URL fragment.         | Same-device flows. Not used by the age verification profile.  |
| `direct_post`     | The wallet posts the VP token to the `response_uri`.         | Cross-device flows. Required by the age verification profile. |
| `direct_post.jwt` | The wallet posts an encrypted JWT to the `response_uri`.     | Optional privacy extension. Used by HAIP.                     |

## The av:// application link scheme

The relying party builds the request URL with the `av://` scheme for a same-device flow. The operating system opens the age verification application that registered the scheme. The wallet then returns the response through `direct_post`, which is a separate HTTP POST to the `response_uri`.

## Complete example authorization request

The following URL is a complete authorization request for a same-device flow. All parameters appear by value in the URL.

```text
av://?response_type=vp_token&response_mode=direct_post&client_id=redirect_uri%3Ahttps%3A%2F%2Frp.example.com%2Fewqwe_api%2Fopenid4vp%2Fdirect_post&response_uri=https%3A%2F%2Frp.example.com%2Fewqwe_api%2Fopenid4vp%2Fdirect_post&nonce=tMQ3X8j5LwnKpZiHvRqCaA&state=A7kB2mN9xYzL4pWqRsGtUj&dcql_query=%7B%22credentials%22%3A%5B%7B%22id%22%3A%22eu_av_proof%22%2C%22format%22%3A%22mso_mdoc%22%2C%22meta%22%3A%7B%22doctype_value%22%3A%22eu.europa.ec.av.1%22%7D%2C%22claims%22%3A%5B%7B%22path%22%3A%5B%22eu.europa.ec.av.1%22%2C%22age_over_18%22%5D%7D%5D%7D%5D%7D
```

The same request, with the parameters decoded:

| Parameter       | Decoded value                                                              |
| :-------------- | :------------------------------------------------------------------------- |
| `response_type` | `vp_token`                                                                 |
| `response_mode` | `direct_post`                                                              |
| `client_id`     | `redirect_uri:https://rp.example.com/ewqwe_api/openid4vp/direct_post`      |
| `response_uri`  | `https://rp.example.com/ewqwe_api/openid4vp/direct_post`                   |
| `nonce`         | `tMQ3X8j5LwnKpZiHvRqCaA`                                                   |
| `state`         | `A7kB2mN9xYzL4pWqRsGtUj`                                                   |
| `dcql_query`    | The JSON object shown below                                                |

The decoded `dcql_query` value:

```json
{
  "credentials": [
    {
      "id": "eu_av_proof",
      "format": "mso_mdoc",
      "meta": {
        "doctype_value": "eu.europa.ec.av.1"
      },
      "claims": [
        {
          "path": ["eu.europa.ec.av.1", "age_over_18"]
        }
      ]
    }
  ]
}
```

## Authorization response parameters

The wallet sends the authorization response to the `response_uri` as an `application/x-www-form-urlencoded` body.

| Parameter                  | Required | Description                                                                                                                                                            |
| :------------------------- | :------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `vp_token`                 | Yes      | Carries the verifiable presentation. With a DCQL query, the token is a JSON object whose keys are credential identifiers and whose values are arrays of presentations. |
| `presentation_submission`  | No       | Maps the presentation to the request. The wallet does not send this field with a DCQL query.                                                                           |
| `state`                    | No       | An echo of the `state` value from the request.                                                                                                                         |

## Related pages

- For the query structure and examples, see [DCQL queries](./dcql-queries.md).
- For the reasons behind the protocol choice, see [Protocol modes](../../explanation/openid4vp/protocol-modes.md).
- For recurring questions, see the [OpenID4VP FAQ](../../faq/openid4vp/faq.md).
