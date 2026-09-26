# Credential types

A credential type identifies the schema and the meaning of a set of claims. In the `mso_mdoc` format, the `docType` field names the credential type. In the SD-JWT VC format, the `vct` claim names the credential type. For the definition of the formats, see [Credential formats](credential-formats.md).

This page describes the three credential types that are relevant to age verification, and the claims of each type.

## How the verifier selects a type

The credential verifier does not hold a fixed list of allowed credential types. It verifies the type that the operator requests, provided the issuer certificate chains to a trusted issuer CA.

The operator names the requested type in one of two ways.

- A full DCQL query in the `dcql_query` field of the transaction request. The query sets `meta.doctype_value` for `mso_mdoc` and `meta.vct_values` for SD-JWT VC.
- A shorthand in the `credential_type` field of the transaction request. The verifier accepts `proof-of-age`, `mdl`, and `national-id`, and builds a default query for that type.

For the request fields, see [Request parameters](../openid4vp/request-parameters.md). For the query structure, see [DCQL queries](../openid4vp/dcql-queries.md).

## Mobile driver's license (mDL)

The mobile driver's license is a digital driving licence. The type uses the `mso_mdoc` format only. The 4th Driving Licence Regulation requires the ISO/IEC 18013-5 data model, so an mDL must not use the SD-JWT VC format.

| Property  | Value                   |
| :-------- | :---------------------- |
| docType   | `org.iso.18013.5.1.mDL` |
| Namespace | `org.iso.18013.5.1`     |
| Format    | mso_mdoc                |
| Standard  | ISO/IEC 18013-5         |

The mDL supports the age attributes `age_over_18`, `age_over_21`, and `age_over_NN` for age verification. These attributes are optional.

### mDL attributes

The table below lists the attributes of the `org.iso.18013.5.1` namespace.

| Attribute identifier     | Description                                        | Presence  | Encoding                         |
| :----------------------- | :------------------------------------------------- | :-------- | :------------------------------- |
| `family_name`            | Current family name or surname                     | Mandatory | `tstr`, UTF-8, maximum 150 chars |
| `given_name`             | Current first name, including middle names         | Mandatory | `tstr`                           |
| `birth_date`             | Date of birth                                      | Mandatory | `full-date`, RFC 8943, tag 1004  |
| `portrait`               | Facial image of the holder                         | Mandatory | `bstr`, JPEG, ISO 19794-5        |
| `issue_date`             | Date of issuance                                   | Mandatory | `tdate` or `full-date`           |
| `expiry_date`            | Date of expiry                                     | Mandatory | `tdate` or `full-date`           |
| `issuing_authority`      | Authority that issued the document                 | Mandatory | `tstr`                           |
| `issuing_country`        | Country code, ISO 3166-1 alpha-2                   | Mandatory | `tstr`                           |
| `document_number`        | Unique document identifier                         | Optional  | `tstr`                           |
| `driving_privileges`     | Vehicle categories and restrictions                | Mandatory | Complex type                     |
| `un_distinguishing_sign` | UN distinguishing sign of the issuing country      | Optional  | `tstr`                           |
| `administrative_number`  | Administrative number for the document             | Optional  | `tstr`                           |
| `sex`                    | Sex, 0 unknown, 1 male, 2 female, 9 not applicable | Optional  | `uint`                           |
| `height`                 | Height in centimetres                              | Optional  | `uint`                           |
| `weight`                 | Weight in kilograms                                | Optional  | `uint`                           |
| `eye_colour`             | Eye colour                                         | Optional  | `tstr`                           |
| `hair_colour`            | Hair colour                                        | Optional  | `tstr`                           |
| `birth_place`            | Place of birth                                     | Optional  | `tstr`                           |
| `resident_address`       | Current address                                    | Optional  | `tstr`                           |
| `resident_city`          | City of residence                                  | Optional  | `tstr`                           |
| `resident_state`         | State or province of residence                     | Optional  | `tstr`                           |
| `resident_postal_code`   | Postal code                                        | Optional  | `tstr`                           |
| `resident_country`       | Country of residence, ISO 3166-1 alpha-2           | Optional  | `tstr`                           |
| `age_over_18`            | Whether the holder is over 18                      | Optional  | `bool`                           |
| `age_over_21`            | Whether the holder is over 21                      | Optional  | `bool`                           |
| `age_over_NN`            | Whether the holder is over NN years                | Optional  | `bool`                           |
| `age_in_years`           | Age in years                                       | Optional  | `uint`                           |
| `age_birth_year`         | Year of birth                                      | Optional  | `uint`                           |
| `nationality`            | Nationality                                        | Optional  | `tstr`                           |

The `driving_privileges` attribute is an array with the following structure.

```cddl
driving_privileges = [ * DrivingPrivilege ]

DrivingPrivilege = {
  "vehicle_category_code": tstr,
  ? "issue_date": full-date,
  ? "expiry_date": full-date,
  ? "codes": [ * Code ]
}

Code = {
  "code": tstr,
  ? "sign": tstr,
  ? "value": tstr
}
```

## EUDI person identification data (PID)

Person identification data is the EU digital identity credential. The PID is available in both formats. The attributes are defined in Commission Implementing Regulation (CIR) 2024/2977 and the EU ARF PID Rulebook.

| Property  | Value                              |
| :-------- | :--------------------------------- |
| docType   | `eu.europa.ec.eudi.pid.1`          |
| Namespace | `eu.europa.ec.eudi.pid.1`          |
| vct       | `urn:eudi:pid:1`                   |
| Formats   | mso_mdoc and dc+sd-jwt             |
| Standard  | CIR 2024/2977, EU ARF PID Rulebook |

### Mandatory attributes

| Data identifier | ISO attribute id | SD-JWT claim     | Description                     | Encoding (ISO)   | Encoding (SD-JWT)  |
| :-------------- | :--------------- | :--------------- | :------------------------------ | :--------------- | :----------------- |
| `family_name`   | `family_name`    | `family_name`    | Current surname                 | `tstr`           | string             |
| `given_name`    | `given_name`     | `given_name`     | Current first and middle names  | `tstr`           | string             |
| `birth_date`    | `birth_date`     | `birthdate`      | Date of birth, YYYY-MM-DD       | `full-date`      | string, ISO 8601-1 |
| `birth_place`   | `place_of_birth` | `place_of_birth` | Place of birth                  | `place_of_birth` | JSON object        |
| `nationality`   | `nationality`    | `nationalities`  | Nationality, ISO 3166-1 alpha-2 | `nationalities`  | array of strings   |

### Optional attributes

| Data identifier                  | SD-JWT claim                     | Description                     | Encoding (ISO) | Encoding (SD-JWT) |
| :------------------------------- | :------------------------------- | :------------------------------ | :------------- | :---------------- |
| `resident_address`               | `address.formatted`              | Full current address            | `tstr`         | string            |
| `resident_country`               | `address.country`                | Country of residence            | `tstr`         | string            |
| `resident_state`                 | `address.region`                 | State or province               | `tstr`         | string            |
| `resident_city`                  | `address.locality`               | City or town                    | `tstr`         | string            |
| `resident_postal_code`           | `address.postal_code`            | Postal code                     | `tstr`         | string            |
| `resident_street`                | `address.street_address`         | Street name                     | `tstr`         | string            |
| `resident_house_number`          | `address.house_number`           | House number                    | `tstr`         | string            |
| `personal_administrative_number` | `personal_administrative_number` | Unique PID number               | `tstr`         | string            |
| `portrait`                       | `picture`                        | Facial image, JPEG, ISO 19794-5 | `bstr`         | data URL, base64  |
| `family_name_birth`              | `birth_family_name`              | Surname at birth                | `tstr`         | string            |
| `given_name_birth`               | `birth_given_name`               | First name at birth             | `tstr`         | string            |
| `sex`                            | `sex`                            | Sex, 0 to 9, see ISO 5218       | `uint`         | number            |
| `email_address`                  | `email`                          | Email address, RFC 5322         | `tstr`         | string            |
| `mobile_phone_number`            | `phone_number`                   | Mobile phone with country code  | `tstr`         | string            |

### Mandatory metadata

| Data identifier     | SD-JWT claim        | Description                         |
| :------------------ | :------------------ | :---------------------------------- |
| `expiry_date`       | `date_of_expiry`    | Administrative expiry date          |
| `issuing_authority` | `issuing_authority` | Issuing authority name              |
| `issuing_country`   | `issuing_country`   | Issuing country, ISO 3166-1 alpha-2 |

### Optional metadata

| Data identifier        | SD-JWT claim           | Description              |
| :--------------------- | :--------------------- | :----------------------- |
| `document_number`      | `document_number`      | PID document number      |
| `issuing_jurisdiction` | `issuing_jurisdiction` | Jurisdiction, ISO 3166-2 |
| `issuance_date`        | `date_of_issuance`     | Date of issuance         |

The `place_of_birth` and `nationalities` attributes have the following structure in the mso_mdoc format.

```cddl
place_of_birth = {
  ? "country": tstr,   ; ISO 3166-1 alpha-2 country code
  ? "region": tstr,    ; state, province, or district
  ? "locality": tstr   ; municipality, city, town, or village
}
; At least one of country, region, or locality must be present.

nationalities = [ + CountryCode ]
CountryCode = tstr     ; ISO 3166-1 alpha-2 country code
```

> [!IMPORTANT]
> The PID does not carry age attributes. The EU ARF PID Rulebook removed `age_over_18` and `age_over_21` in version 1.1, in line with CIR 2024/2977. For age verification, use an mDL or a Proof of Age attestation.

## EU Age Verification proof of age

The proof of age attestation is the dedicated credential of the EU Age Verification Profile. The attestation carries one claim, `age_over_18`. The attestation holds no identity data.

| Property  | Value                       |
| :-------- | :-------------------------- |
| docType   | `eu.europa.ec.av.1`         |
| Namespace | `eu.europa.ec.av.1`         |
| Format    | mso_mdoc only               |
| Standard  | EU Age Verification Profile |

The table below lists the attributes of the `eu.europa.ec.av.1` namespace.

| Attribute identifier | Description                   | Presence  | Encoding |
| :------------------- | :---------------------------- | :-------- | :------- |
| `age_over_18`        | Whether the holder is over 18 | Mandatory | `bool`   |

The proof of age attestation uses the following protocols.

| Step                   | Protocol                                   | Detail                                     |
| :--------------------- | :----------------------------------------- | :----------------------------------------- |
| Issuance               | OpenID for Verifiable Credential Issuance  | Credential configuration id `proof_of_age` |
| Presentation, primary  | W3C Digital Credentials API                | ISO/IEC 18013-7 Annex C                    |
| Presentation, fallback | OpenID4VP with `response_mode=direct_post` | Annex A                                    |

A DCQL query that requests this attestation has the following form.

```json
{
  "credentials": [
    {
      "id": "proof_of_age",
      "format": "mso_mdoc",
      "meta": { "doctype_value": "eu.europa.ec.av.1" },
      "claims": [{ "path": ["eu.europa.ec.av.1", "age_over_18"] }]
    }
  ]
}
```

## Other credential types

The verifier accepts other credential types when the operator configures them. Any credential whose issuer chains to a trusted CA is verified, provided the DCQL query requests its `docType` or `vct`. For example, the relying-party example in `typescript/demo-webapp/` also configures a Health ID credential, which uses the SD-JWT VC format. To request a type that is not one of the three above, supply a full `dcql_query` in the transaction request.

## Related topics

- [Credential formats](credential-formats.md) describes the structure and the verification steps of both formats.
- [DCQL queries](../openid4vp/dcql-queries.md) describes how a request names a credential type.
- [Issue a test credential](../../how-to-guides/digital-credential/issue-a-test-credential.md) shows how to build a credential of these types.
- [Glossary](../../glossary.md) defines the abbreviations used on this page.
