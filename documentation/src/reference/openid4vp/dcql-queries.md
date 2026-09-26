# DCQL queries

The Digital Credentials Query Language (DCQL) is defined in Section 6 of the OpenID4VP 1.0 specification. A relying party uses DCQL to state which credentials and which claims it requires from a wallet. The credential verifier evaluates the query against the presentations that the wallet returns.

A DCQL query is a JSON object. The query travels in the `dcql_query` parameter of an authorization request. For the surrounding request parameters, see [OpenID4VP authorization request parameters](./request-parameters.md).

## Query structure

A query holds one or more credential queries. The fields below belong to two nested objects. A credential query holds `id`, `format`, `meta`, `claims`, and the optional `claim_sets`. A claim query holds `path`, `values`, and the optional `id` and `intent_to_retain`.

| Field              | Required           | Description                                                                                                                                     |
| :----------------- | :----------------- | :---------------------------------------------------------------------------------------------------------------------------------------------- |
| `credentials`      | Yes                | The list of credential queries.                                                                                                                 |
| `credential_sets`  | No                 | Groups of alternative credential queries. The wallet satisfies the query when it can satisfy one complete option.                               |
| `id`               | Yes                | The identifier of one credential query. The authorization response uses this identifier as a key.                                               |
| `format`           | Yes                | The credential format. Age verification uses `mso_mdoc`, which means an ISO mobile document such as a mobile driving licence or a proof of age. |
| `meta`             | Yes for `mso_mdoc` | Format-specific metadata. An `mso_mdoc` query names the document type in `doctype_value`.                                                       |
| `claims`           | Yes                | The claims to request from the credential.                                                                                                      |
| `claim_sets`       | No                 | Alternative combinations of claims. A claim query needs an `id` only when a `claim_sets` entry references it.                                   |
| `path`             | Yes                | The location of one claim. The first element is the namespace and the second element is the claim name.                                         |
| `values`           | No                 | The permitted values for a claim. The wallet returns the claim only when its value appears in this list.                                        |
| `intent_to_retain` | No                 | Whether the relying party intends to keep the claim. The field is omitted in this system, which is equivalent to `false`, the safe default.     |

## Namespaces

A claim path starts with the namespace of the credential. Age verification uses two namespaces.

| Namespace           | Description                                       | Document type           |
| :------------------ | :------------------------------------------------ | :---------------------- |
| `eu.europa.ec.av.1` | The EU Age Verification namespace (proof of age). | `eu.europa.ec.av.1`     |
| `org.iso.18013.5.1` | The ISO mobile driving licence namespace.         | `org.iso.18013.5.1.mDL` |

## Age verification query examples

### Minimal age over 18

The simplest age verification request asks only for `age_over_18` from a proof of age.

```json
{
  "credentials": [
    {
      "id": "proof_of_age",
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

### Age over 21

For a jurisdiction that requires age 21 or older, request `age_over_21` instead.

```json
{
  "credentials": [
    {
      "id": "proof_of_age",
      "format": "mso_mdoc",
      "meta": {
        "doctype_value": "eu.europa.ec.av.1"
      },
      "claims": [
        {
          "path": ["eu.europa.ec.av.1", "age_over_21"]
        }
      ]
    }
  ]
}
```

### Value matching

Add a `values` list to accept the claim only when its value matches. The example below accepts the presentation only when `age_over_18` is `true`.

```json
{
  "credentials": [
    {
      "id": "proof_of_age",
      "format": "mso_mdoc",
      "meta": {
        "doctype_value": "eu.europa.ec.av.1"
      },
      "claims": [
        {
          "path": ["eu.europa.ec.av.1", "age_over_18"],
          "values": [true]
        }
      ]
    }
  ]
}
```

### mDL fallback

If the user holds a mobile driving licence instead of a proof of age, request the same claim from the ISO mobile driving licence namespace.

```json
{
  "credentials": [
    {
      "id": "age_from_mdl",
      "format": "mso_mdoc",
      "meta": {
        "doctype_value": "org.iso.18013.5.1.mDL"
      },
      "claims": [
        {
          "path": ["org.iso.18013.5.1", "age_over_18"]
        }
      ]
    }
  ]
}
```

### Multiple credential options

A `credential_sets` list lets the wallet choose between alternatives. Each option is an array of credential identifiers, and the wallet satisfies the set when it can satisfy one complete option. The example below accepts a proof of age or a mobile driving licence.

```json
{
  "credentials": [
    {
      "id": "eu_age_proof",
      "format": "mso_mdoc",
      "meta": {
        "doctype_value": "eu.europa.ec.av.1"
      },
      "claims": [
        {
          "path": ["eu.europa.ec.av.1", "age_over_18"]
        }
      ]
    },
    {
      "id": "mdl_age_proof",
      "format": "mso_mdoc",
      "meta": {
        "doctype_value": "org.iso.18013.5.1.mDL"
      },
      "claims": [
        {
          "path": ["org.iso.18013.5.1", "age_over_18"]
        }
      ]
    }
  ],
  "credential_sets": [
    {
      "options": [["eu_age_proof"], ["mdl_age_proof"]]
    }
  ]
}
```

## The vp_token response

The wallet returns the presentation in the `vp_token` parameter. With a DCQL query, the token is a JSON object whose keys are the credential identifiers from the query. Each value is an array of presentations.

```json
{
  "proof_of_age": ["base64url encoded DeviceResponse"]
}
```

An `mso_mdoc` presentation is a CBOR-encoded device response as defined in ISO/IEC 18013-5. The wallet does not send a `presentation_submission` field with a DCQL query.

## Related pages

- For the surrounding request parameters, see [OpenID4VP authorization request parameters](./request-parameters.md).
- For the credential types that the queries address, see [Credential types](../digital-credential/credential-types.md).
- For how a wallet discloses only the requested claims, see [Selective disclosure](../../explanation/digital-credential/selective-disclosure.md).
- For recurring questions, see the [OpenID4VP FAQ](../../faq/openid4vp/faq.md).
