# Credential Type Specifications

This document specifies the credential types used in this project:

- **Mobile Driver's License (mDL)** - Full driving licence with optional age verification attributes
- **Person Identification Data (PID/National ID)** - EU digital identity (no age attributes)
- **Proof of Age (EU AV)** - Dedicated privacy-preserving age verification attestation

The authoritative specifications are defined in:

1. **ISO/IEC 18013-5:2021** - For mDL (paid standard from ISO)
2. **EU Commission Implementing Regulation (CIR) 2024/2977** - For PID attributes
3. **EU Architecture and Reference Framework (ARF)** - Attestation Rulebooks
4. **EU Age Verification Profile** - For dedicated Proof of Age attestations

These specifications define attributes using:

- **CBOR/CDDL** (Concise Data Definition Language) for ISO/IEC 18013-5-compliant formats
- **JSON claims** for SD-JWT VC formats

The encoding is specified in prose and tables rather than JSON Schema.

**Related Documentation**:

- For DCQL queries to request these credentials, see [DCQL Age Verification](./dcql_age_verification.md)
- For sample credential data, see [Digital Credential Browser Storage](./digital_credentials_browser_storage.md)

---

## Authoritative Sources

| Standard                  | Description                                | URL/Reference                                                                                                                                                                                           |
|:--------------------------|:-------------------------------------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| ISO/IEC 18013-5:2021      | Mobile Driving Licence (mDL) application   | <https://www.iso.org/standard/69084.html>                                                                                                                                                               |
| CIR 2024/2977             | EU Implementing Regulation on PID and EAA  | <https://data.europa.eu/eli/reg_impl/2024/2977/oj>                                                                                                                                                      |
| EU ARF Annex 2.02 Topic 3 | PID Rulebook HLRs (PID_04, PID_05, PID_14) | <https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework/blob/main/docs/annexes/annex-2/annex-2.02-high-level-requirements-by-topic.md#a232-topic-3---pid-rulebook> |
| EU ARF PID Rulebook       | PID attribute encoding specification       | <https://github.com/eu-digital-identity-wallet/eudi-doc-attestation-rulebooks-catalog/blob/main/rulebooks/pid/pid-rulebook.md>                                                                          |
| EU ARF mDL Rulebook       | mDL attribute encoding specification       | <https://github.com/eu-digital-identity-wallet/eudi-doc-attestation-rulebooks-catalog/blob/main/rulebooks/mdl/mdl-rulebook.md>                                                                          |
| EU ARF Main Repository    | Architecture Reference Framework           | <https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework>                                                                                                           |
| EU Age Verification Profile | Proof of Age attestation specification   | <https://ageverification.dev/Technical%20Specification/annexes/annex-A/annex-A-av-profile>                                                                                                              |

---

## 1. Mobile Driver's License (mDL)

### Document Type

```text
org.iso.18013.5.1.mDL
```

### Namespace

```text
org.iso.18013.5.1
```

### Specification

The mDL data model is **fully specified in ISO/IEC 18013-5:2021**. Within the EUDI Wallet ecosystem, mDLs:

- **SHALL** comply with ISO/IEC 18013-5
- **SHALL NOT** be implemented as SD-JWT VC-compliant attestations (per the 4th Driving Licence Regulation)
- Use CBOR encoding according to RFC 8949

### mDL Attributes (ISO/IEC 18013-5 Namespace: `org.iso.18013.5.1`)

| Attribute Identifier     | Description                                       | Presence  | Encoding                               |
|:-------------------------|:--------------------------------------------------|:----------|:---------------------------------------|
| `family_name`            | Current family name(s) or surname(s)              | Mandatory | `tstr` (UTF-8 string, max 150 chars)   |
| `given_name`             | Current first name(s), including middle name(s)   | Mandatory | `tstr`                                 |
| `birth_date`             | Date of birth                                     | Mandatory | `full-date` (RFC 8943, tag 1004)       |
| `portrait`               | Facial image of the holder                        | Mandatory | `bstr` (JPEG, ISO 19794-5 compliant)   |
| `issue_date`             | Date of mDL issuance                              | Mandatory | `tdate` or `full-date`                 |
| `expiry_date`            | Date of mDL expiry                                | Mandatory | `tdate` or `full-date`                 |
| `issuing_authority`      | Authority that issued the mDL                     | Mandatory | `tstr`                                 |
| `issuing_country`        | Country code (ISO 3166-1 alpha-2)                 | Mandatory | `tstr`                                 |
| `document_number`        | Unique document identifier                        | Optional  | `tstr`                                 |
| `driving_privileges`     | Categories and restrictions                       | Mandatory | Complex type (see ISO 18013-5)         |
| `un_distinguishing_sign` | UN distinguishing sign of issuing country         | Optional  | `tstr`                                 |
| `administrative_number`  | Administrative number for the document            | Optional  | `tstr`                                 |
| `sex`                    | Sex of holder (0=unknown, 1=male, 2=female, 9=N/A)| Optional  | `uint`                                 |
| `height`                 | Height in centimetres                             | Optional  | `uint`                                 |
| `weight`                 | Weight in kilograms                               | Optional  | `uint`                                 |
| `eye_colour`             | Eye colour                                        | Optional  | `tstr`                                 |
| `hair_colour`            | Hair colour                                       | Optional  | `tstr`                                 |
| `birth_place`            | Place of birth                                    | Optional  | `tstr`                                 |
| `resident_address`       | Current address                                   | Optional  | `tstr`                                 |
| `resident_city`          | City of residence                                 | Optional  | `tstr`                                 |
| `resident_state`         | State/province of residence                       | Optional  | `tstr`                                 |
| `resident_postal_code`   | Postal code                                       | Optional  | `tstr`                                 |
| `resident_country`       | Country of residence (ISO 3166-1 alpha-2)         | Optional  | `tstr`                                 |
| `age_over_18`            | Whether holder is over 18                         | Optional  | `bool`                                 |
| `age_over_21`            | Whether holder is over 21                         | Optional  | `bool`                                 |
| `age_over_NN`            | Whether holder is over NN years                   | Optional  | `bool`                                 |
| `age_in_years`           | Age in years                                      | Optional  | `uint`                                 |
| `age_birth_year`         | Year of birth                                     | Optional  | `uint`                                 |
| `nationality`            | Nationality                                       | Optional  | `tstr`                                 |

### Driving Privileges Structure

The `driving_privileges` attribute contains an array of vehicle category authorizations:

```cddl
driving_privileges = [* DrivingPrivilege]

DrivingPrivilege = {
  "vehicle_category_code": tstr,
  ? "issue_date": full-date,
  ? "expiry_date": full-date,
  ? "codes": [* Code]
}

Code = {
  "code": tstr,
  ? "sign": tstr,
  ? "value": tstr
}
```

---

## 2. Person Identification Data (PID) / National ID

### Document Type (ISO/IEC 18013-5 format)

```text
eu.europa.ec.eudi.pid.1
```

### Namespace (ISO/IEC 18013-5 format)

```text
eu.europa.ec.eudi.pid.1
```

### Verifiable Credential Type (SD-JWT VC format)

```text
urn:eudi:pid:1
```

### PID Specification

PID attributes are defined in **CIR 2024/2977** and the **EU ARF PID Rulebook**. PIDs:

- **SHALL** be issued in both ISO/IEC 18013-5 format AND SD-JWT VC format
- Use namespace `eu.europa.ec.eudi.pid.1` for ISO format
- Use vct claim `urn:eudi:pid:1` for SD-JWT VC format

### PID Attributes

#### Mandatory Attributes (CIR 2024/2977)

| Data Identifier | ISO Attribute ID | SD-JWT Claim     | Description                      | Encoding (ISO)   | Encoding (SD-JWT)   |
|:----------------|:-----------------|:-----------------|:---------------------------------|:-----------------|:--------------------|
| `family_name`   | `family_name`    | `family_name`    | Current surname(s)               | `tstr`           | string              |
| `given_name`    | `given_name`     | `given_name`     | Current first/middle name(s)     | `tstr`           | string              |
| `birth_date`    | `birth_date`     | `birthdate`      | Date of birth (YYYY-MM-DD)       | `full-date`      | string (ISO 8601-1) |
| `birth_place`   | `place_of_birth` | `place_of_birth` | Place of birth                   | `place_of_birth` | JSON object         |
| `nationality`   | `nationality`    | `nationalities`  | Nationality (ISO 3166-1 alpha-2) | `nationalities`  | array of strings    |

#### Optional Attributes (CIR 2024/2977)

| Data Identifier                  | ISO Attribute ID                 | SD-JWT Claim                     | Description                       | Encoding (ISO) | Encoding (SD-JWT) |
|:---------------------------------|:---------------------------------|:---------------------------------|:----------------------------------|:---------------|:------------------|
| `resident_address`               | `resident_address`               | `address.formatted`              | Full current address              | `tstr`         | string            |
| `resident_country`               | `resident_country`               | `address.country`                | Country of residence              | `tstr`         | string            |
| `resident_state`                 | `resident_state`                 | `address.region`                 | State/province                    | `tstr`         | string            |
| `resident_city`                  | `resident_city`                  | `address.locality`               | City/town                         | `tstr`         | string            |
| `resident_postal_code`           | `resident_postal_code`           | `address.postal_code`            | Postal code                       | `tstr`         | string            |
| `resident_street`                | `resident_street`                | `address.street_address`         | Street name                       | `tstr`         | string            |
| `resident_house_number`          | `resident_house_number`          | `address.house_number`           | House number                      | `tstr`         | string            |
| `personal_administrative_number` | `personal_administrative_number` | `personal_administrative_number` | Unique PID number                 | `tstr`         | string            |
| `portrait`                       | `portrait`                       | `picture`                        | Facial image (JPEG, ISO 19794-5)  | `bstr`         | data URL (base64) |
| `family_name_birth`              | `family_name_birth`              | `birth_family_name`              | Surname at birth                  | `tstr`         | string            |
| `given_name_birth`               | `given_name_birth`               | `birth_given_name`               | First name at birth               | `tstr`         | string            |
| `sex`                            | `sex`                            | `sex`                            | Sex (0-9, see ISO 5218)           | `uint`         | number            |
| `email_address`                  | `email_address`                  | `email`                          | Email address (RFC 5322)          | `tstr`         | string            |
| `mobile_phone_number`            | `mobile_phone_number`            | `phone_number`                   | Mobile phone (+country code)      | `tstr`         | string            |

#### Mandatory Metadata (CIR 2024/2977)

| Data Identifier     | ISO Attribute ID    | SD-JWT Claim        | Description                         |
|:--------------------|:--------------------|:--------------------|:------------------------------------|
| `expiry_date`       | `expiry_date`       | `date_of_expiry`    | Administrative expiry date          |
| `issuing_authority` | `issuing_authority` | `issuing_authority` | Issuing authority name              |
| `issuing_country`   | `issuing_country`   | `issuing_country`   | Issuing country (ISO 3166-1 alpha-2)|

#### Optional Metadata (CIR 2024/2977)

| Data Identifier        | ISO Attribute ID       | SD-JWT Claim           | Description               |
|:-----------------------|:-----------------------|:-----------------------|:--------------------------|
| `document_number`      | `document_number`      | `document_number`      | PID document number       |
| `issuing_jurisdiction` | `issuing_jurisdiction` | `issuing_jurisdiction` | Jurisdiction (ISO 3166-2) |
| `issuance_date`        | `issuance_date`        | `date_of_issuance`     | Date of issuance          |

### Complex Type Definitions

#### place_of_birth (ISO format)

```cddl
place_of_birth = {
  ? "country": tstr,   ; ISO 3166-1 alpha-2 country code
  ? "region": tstr,    ; state, province, district
  ? "locality": tstr   ; municipality, city, town, village
}
; At least one of country, region, or locality SHALL be present
```

#### nationalities (ISO format)

```cddl
nationalities = [+ CountryCode]
CountryCode = tstr  ; ISO 3166-1 alpha-2 country code
```

---

## Encoding Rules

### ISO/IEC 18013-5 Format (CBOR)

1. **String encoding**: `tstr` SHALL be UTF-8, max 150 characters
2. **Date encoding**:
   - `full-date` = `#6.1004(tstr)` per RFC 8943 (YYYY-MM-DD)
   - `tdate` = RFC 3339 datetime string
3. **Timestamps**: No fractional seconds; offset SHALL be "Z" (UTC)
4. **CBOR canonical rules**:
   - Integers as small as possible
   - Length expressions as short as possible
   - Definite-length items only

### SD-JWT VC Format (JSON)

1. **Type claim**: `vct` SHALL be `urn:eudi:pid:1` (or domestic extension)
2. **Date encoding**: ISO 8601-1 YYYY-MM-DD format
3. **Technical validity**: Use standard JWT claims `nbf` and `exp`
4. **Hierarchical claims**: Use dot notation (e.g., `address.country`)

---

## Implementation in This Project

The configuration in [webapp/src/config.ts](../webapp/src/config.ts) uses claim paths based on the ISO 18013-5 namespace pattern:

```typescript
// mDL claims use org.iso.18013.5.1 namespace (per ISO/IEC 18013-5)
{ id: "age_over_18", path: "org.iso.18013.5.1/age_over_18" }

// PID (national-id) claims use eu.europa.ec.eudi.pid.1 namespace (per EU ARF)
{ id: "family_name", path: "eu.europa.ec.eudi.pid.1/family_name" }

// Proof of Age uses eu.europa.ec.av.1 namespace (per EU Age Verification Profile)
{ id: "age_over_18", path: "eu.europa.ec.av.1/age_over_18" }
```

### Credential Types Summary

| Type ID         | Name                    | docType                   | Namespace                  | Age Verification |
|:----------------|:------------------------|:--------------------------|:---------------------------|:-----------------|
| `mdl`           | Mobile Driver's License | `org.iso.18013.5.1.mDL`   | `org.iso.18013.5.1`        | ✅ `age_over_18`, `age_over_21` |
| `national-id`   | National ID (PID)       | `eu.europa.ec.eudi.pid.1` | `eu.europa.ec.eudi.pid.1`  | ❌ Not supported  |
| `proof-of-age`  | Proof of Age (EU AV)    | `eu.europa.ec.av.1`       | `eu.europa.ec.av.1`        | ✅ `age_over_18` only |

### Authoritative Requirements (EU ARF Annex 2.02 Topic 3)

The PID docType and namespace values are mandated by the following High-Level Requirements:

| Requirement | Specification                                                                                                                                                                     |
|:------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **PID_04**  | "PID Providers SHALL use **eu.europa.ec.eudi.pid.1** as the attestation type for ISO/IEC 18013-5-compliant PIDs."                                                                 |
| **PID_05**  | "When issuing a PID compliant with [ISO/IEC 18013-5], a PID Provider SHALL use the value **eu.europa.ec.eudi.pid.1** for the identifier of the namespace for the PID attributes." |
| **PID_14**  | "A PID Provider issuing [SD-JWT VC]-compliant PIDs SHALL include the vct claim... The type indicated by the vct claim SHALL be **urn:eudi:pid:1**"                                |

### Important Note on Age Verification Attributes

Per the EU ARF PID Rulebook changelog (v1.1): *"Age verification attributes removed, following CIR 2024/2977"*

This means `age_over_18` and `age_over_21` are **NOT valid PID attributes** under the EU regulations. For age verification, use either:

1. **mDL** (`org.iso.18013.5.1.mDL`) - Contains `age_over_18`, `age_over_21` as optional attributes
2. **Proof of Age** (`eu.europa.ec.av.1`) - Dedicated privacy-preserving attestation with only `age_over_18`

---

## 3. Proof of Age Attestation (EU Age Verification)

### Document Type

```text
eu.europa.ec.av.1
```

### Namespace

```text
eu.europa.ec.av.1
```

### Specification

The Proof of Age attestation is defined in the **EU Age Verification Profile**. Key characteristics:

- **Format**: ISO mDoc only (ISO/IEC 18013-5) - NOT SD-JWT VC
- **Purpose**: Privacy-preserving age verification with minimal data disclosure
- **Single attribute**: Contains only `age_over_18` boolean
- **No personal data**: Does not store any identity information

### Proof of Age Attributes

| Attribute Identifier | Description              | Presence  | Encoding |
|:---------------------|:-------------------------|:----------|:---------|
| `age_over_18`        | Whether holder is over 18| Mandatory | `bool`   |

### Protocol Stack

| Protocol   | Usage                                         | Specification                         |
|:-----------|:----------------------------------------------|:--------------------------------------|
| Issuance   | OpenID4VCI with `credential_configuration_ids: ["proof_of_age"]` | OpenID for Verifiable Credential Issuance |
| Presentation (Primary) | W3C Digital Credentials API         | ISO/IEC 18013-7 Annex C               |
| Presentation (Fallback) | OpenID4VP with `response_mode=direct_post` | OpenID for Verifiable Presentations |

### DCQL Query Example

```json
{
  "credentials": [{
    "id": "proof_of_age",
    "format": "mso_mdoc",
    "meta": { "doctype_value": "eu.europa.ec.av.1" },
    "claims": [{"path": ["eu.europa.ec.av.1", "age_over_18"]}]
  }]
}
```

---

## References

1. **ISO/IEC 18013-5:2021** - Personal identification — ISO-compliant driving licence — Part 5: Mobile driving licence (mDL) application
   - <https://www.iso.org/standard/69084.html>
   - Status: Published (2021-09), revision in progress (DIS 18013-5)

2. **Commission Implementing Regulation (EU) 2024/2977** - Rules on PID and EAA
   - <https://data.europa.eu/eli/reg_impl/2024/2977/oj>

3. **EU Architecture and Reference Framework (ARF)**
   - Main document: <https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework>
   - **Annex 2.02 Topic 3 (PID Rulebook HLRs)**: <https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework/blob/main/docs/annexes/annex-2/annex-2.02-high-level-requirements-by-topic.md#a232-topic-3---pid-rulebook>
   - PID Rulebook: <https://github.com/eu-digital-identity-wallet/eudi-doc-attestation-rulebooks-catalog/blob/main/rulebooks/pid/pid-rulebook.md>
   - mDL Rulebook: <https://github.com/eu-digital-identity-wallet/eudi-doc-attestation-rulebooks-catalog/blob/main/rulebooks/mdl/mdl-rulebook.md>

4. **RFC 8949** - Concise Binary Object Representation (CBOR)

5. **RFC 8943** - Concise Binary Object Representation (CBOR) Tags for Date

6. **RFC 8610** - Concise Data Definition Language (CDDL)

7. **SD-JWT VC** - SD-JWT-based Verifiable Credentials (IETF draft)
   - <https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/>

8. **OpenID Connect Core 1.0** - Standard Claims (for SD-JWT VC claim names)
   - <https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims>

9. **OpenID Connect for Identity Assurance** (EKYC) - Extended claims
   - <https://openid.net/specs/openid-connect-4-identity-assurance-1_0.html>

10. **EU Age Verification Profile** - Proof of Age attestation specification
    - <https://ageverification.dev/Technical%20Specification/annexes/annex-A/annex-A-av-profile>
    - Architecture and Technical Specifications: <https://ageverification.dev/docs/architecture-and-technical-specifications.md>
