# Credential Type Specifications

This document specifies the credential types used in this project. The system supports credentials from the EUDI Wallet ecosystem, organized by category:

**Government**:

- **Mobile Driver's License (mDL)** — Full driving licence with optional age verification attributes
- **Person Identification Data (PID/National ID)** — EU digital identity (mso_mdoc and SD-JWT VC)
- **Proof of Age (EU AV)** — Dedicated privacy-preserving age verification attestation
- **Tax Identification** — Tax number attestation (mso_mdoc and SD-JWT VC)
- **Pseudonym (Age Over 18)** — Privacy-preserving age pseudonym (mso_mdoc and SD-JWT VC)
- **Certificate of Residence** — Proof of residential address

**Travel**:

- **Photo ID** — ISO 23220-2 photo identification
- **Travel Reservation** — Booking/reservation attestation

**Finance**:

- **IBAN** — Bank account attestation (mso_mdoc and SD-JWT VC)

**Health**:

- **European Health Insurance Card (EHIC)** — Cross-border healthcare attestation (mso_mdoc and SD-JWT VC)
- **Health ID** — Health insurance identification (mso_mdoc and SD-JWT VC)

**Social Security**:

- **Portable Document A1 (PDA1)** — Social security coordination (mso_mdoc and SD-JWT VC)

**Retail**:

- **Loyalty Card** — Retail loyalty programme attestation
- **MSISDN** — Mobile phone number attestation (mso_mdoc and SD-JWT VC)

**Other**:

- **Power of Representation (PoR)** — Legal representation attestation (mso_mdoc and SD-JWT VC)

The authoritative specifications are defined in:

1. **ISO/IEC 18013-5:2021** — For mDL (paid standard from ISO)
2. **ISO/IEC 23220-2** — For Photo ID
3. **EU Commission Implementing Regulation (CIR) 2024/2977** — For PID attributes
4. **EU Architecture and Reference Framework (ARF)** — Attestation Rulebooks
5. **EU Age Verification Profile** — For dedicated Proof of Age attestations
6. **IETF SD-JWT VC** — For SD-JWT-based Verifiable Credentials

These specifications define attributes using:

- **CBOR/CDDL** (Concise Data Definition Language) for ISO/IEC 18013-5-compliant formats (mso_mdoc)
- **JSON claims** for SD-JWT VC formats (dc+sd-jwt)

The encoding is specified in prose and tables rather than JSON Schema.

**Related Documentation**:

- For DCQL queries to request these credentials, see [DCQL Age Verification](./dcql_age_verification.md)
- For sample credential data, see [Digital Credential Browser Storage](./digital_credentials_browser_storage.md)

---

## Authoritative Sources

| Standard                  | Description                                | URL/Reference                                                                                                                                                                                           |
| :------------------------ | :----------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| ISO/IEC 18013-5:2021      | Mobile Driving Licence (mDL) application   | <https://www.iso.org/standard/69084.html>                                                                                                                                                               |
| CIR 2024/2977             | EU Implementing Regulation on PID and EAA  | <https://data.europa.eu/eli/reg_impl/2024/2977/oj>                                                                                                                                                      |
| EU ARF Annex 2.02 Topic 3 | PID Rulebook HLRs (PID_04, PID_05, PID_14) | <https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework/blob/main/docs/annexes/annex-2/annex-2.02-high-level-requirements-by-topic.md#a232-topic-3---pid-rulebook> |
| EU ARF PID Rulebook       | PID attribute encoding specification       | <https://github.com/eu-digital-identity-wallet/eudi-doc-attestation-rulebooks-catalog/blob/main/rulebooks/pid/pid-rulebook.md>                                                                          |
| EU ARF mDL Rulebook       | mDL attribute encoding specification       | <https://github.com/eu-digital-identity-wallet/eudi-doc-attestation-rulebooks-catalog/blob/main/rulebooks/mdl/mdl-rulebook.md>                                                                          |
| EU ARF Main Repository    | Architecture Reference Framework           | <https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework>                                                                                                           |
| EU Age Verification Profile | Proof of Age attestation specification   | <https://ageverification.dev/Technical%20Specification/annexes/annex-A/annex-A-av-profile>                                                                                                              |

---

## Credential Formats

The EUDI Wallet ecosystem supports two credential formats. Many credential types are available in both formats.

### mso_mdoc (ISO/IEC 18013-5)

- **DCQL format identifier**: `"mso_mdoc"`
- **Type identifier**: `docType` (e.g., `eu.europa.ec.eudi.pid.1`)
- **Claim paths**: Namespace-based — `[namespace, claimName]` (e.g., `["eu.europa.ec.eudi.pid.1", "family_name"]`)
- **Encoding**: CBOR (RFC 8949) with COSE signatures
- **VP format algorithms**: COSE algorithm identifiers (e.g., ES256 = `-7`)
- **DCQL meta field**: `meta.doctype_value`

### dc+sd-jwt (SD-JWT VC)

- **DCQL format identifier**: `"dc+sd-jwt"` (canonical since November 2024; replaces earlier `"vc+sd-jwt"`)
- **Type identifier**: `vct` — Verifiable Credential Type (e.g., `urn:eudi:pid:1`)
- **Claim paths**: Flat JSON paths — `[claimName]` (e.g., `["family_name"]`)
- **Encoding**: JSON with selective disclosure (IETF draft-ietf-oauth-sd-jwt-vc)
- **VP format algorithms**: JOSE algorithm strings (e.g., `"ES256"`)
- **DCQL meta field**: `meta.vct_values`

### Naming Convention

For mso_mdoc types, the docType and namespace follow the pattern `eu.europa.ec.eudi.<type>.1` (dot-separated). For SD-JWT VC types, the vct follows the URN pattern `urn:eu.europa.ec.eudi:<type>:1` (colon-separated). Notable exception: PID uses `urn:eudi:pid:1` (shorter URN) for the SD-JWT VC vct.

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
| :----------------------- | :------------------------------------------------ | :-------- | :------------------------------------- |
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
| :-------------- | :--------------- | :--------------- | :------------------------------ | :--------------- | :------------------ |
| `family_name`   | `family_name`    | `family_name`    | Current surname(s)               | `tstr`           | string              |
| `given_name`    | `given_name`     | `given_name`     | Current first/middle name(s)     | `tstr`           | string              |
| `birth_date`    | `birth_date`     | `birthdate`      | Date of birth (YYYY-MM-DD)       | `full-date`      | string (ISO 8601-1) |
| `birth_place`   | `place_of_birth` | `place_of_birth` | Place of birth                   | `place_of_birth` | JSON object         |
| `nationality`   | `nationality`    | `nationalities`  | Nationality (ISO 3166-1 alpha-2) | `nationalities`  | array of strings    |

#### Optional Attributes (CIR 2024/2977)

| Data Identifier                  | ISO Attribute ID                 | SD-JWT Claim                     | Description                       | Encoding (ISO) | Encoding (SD-JWT) |
| :------------------------------- | :------------------------------- | :------------------------------- | :-------------------------------- | :------------- | :---------------- |
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
| :------------------ | :------------------ | :------------------ | :---------------------------------- |
| `expiry_date`       | `expiry_date`       | `date_of_expiry`    | Administrative expiry date          |
| `issuing_authority` | `issuing_authority` | `issuing_authority` | Issuing authority name              |
| `issuing_country`   | `issuing_country`   | `issuing_country`   | Issuing country (ISO 3166-1 alpha-2)|

#### Optional Metadata (CIR 2024/2977)

| Data Identifier        | ISO Attribute ID       | SD-JWT Claim           | Description               |
| :--------------------- | :--------------------- | :--------------------- | :------------------------ |
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

The configuration in `js-lib/ewqwe-digital-identity/src/config.ts` defines all credential types with their format, identifiers, and claims. The DCQL query builder in `js-lib/ewqwe-digital-identity/src/dcql.ts` handles both formats:

```typescript
// mso_mdoc: namespace-based claim paths
{ id: "age_over_18", path: ["org.iso.18013.5.1", "age_over_18"] }

// dc+sd-jwt: flat JSON claim paths
{ id: "family_name", path: ["family_name"] }
```

### Webapp UI

The [Relying Party Demo Webapp](./demo_webapp.md) currently offers four credential types for selection:

| Credential | Format | Profile |
| :--------- | :----- | :------ |
| Proof of Age | MSO MDOC | Annex A |
| Mobile Driver's License | MSO MDOC | HAIP |
| National ID (PID) | MSO MDOC | HAIP |
| Health ID | SD-JWT VC | HAIP |

The Profile Information section displays both the protocol profile badge (HAIP or Annex A) and the credential format badge (MSO MDOC or SD-JWT VC).

### Credential Types Summary

| Type ID               | Name                      | Format      | docType / vct                                      | Age Verification |
| :-------------------- | :------------------------ | :---------- | :------------------------------------------------- | :--------------- |
| `mdl`                 | Mobile Driver's License   | mso_mdoc    | `org.iso.18013.5.1.mDL`                            | ✅ `age_over_18`, `age_over_21` |
| `national-id`         | National ID (PID)         | mso_mdoc    | `eu.europa.ec.eudi.pid.1`                           | ❌ |
| `national-id-sd-jwt`  | National ID (PID)         | dc+sd-jwt   | `urn:eudi:pid:1`                                    | ❌ |
| `proof-of-age`        | Proof of Age (EU AV)      | mso_mdoc    | `eu.europa.ec.av.1`                                 | ✅ `age_over_18` only |
| `tax`                 | Tax Identification        | mso_mdoc    | `eu.europa.ec.eudi.tax.1`                           | ❌ |
| `tax-sd-jwt`          | Tax Identification        | dc+sd-jwt   | `urn:eu.europa.ec.eudi:tax:1`                       | ❌ |
| `pseudonym-age`       | Pseudonym (Age Over 18)   | mso_mdoc    | `eu.europa.ec.eudi.pseudonym.age_over_18.1`        | ✅ `age_over_18` only |
| `pseudonym-age-sd-jwt`| Pseudonym (Age Over 18)   | dc+sd-jwt   | `urn:eu.europa.ec.eudi:pseudonym_age_over_18:1`    | ✅ `age_over_18` only |
| `cor`                 | Certificate of Residence  | mso_mdoc    | `eu.europa.ec.eudi.cor.1`                           | ❌ |
| `photo-id`            | Photo ID                  | mso_mdoc    | `org.iso.23220.2.photoid.1`                         | ❌ |
| `reservation`         | Travel Reservation        | mso_mdoc    | `org.iso.18013.5.1.reservation`                     | ❌ |
| `iban`                | IBAN                      | mso_mdoc    | `eu.europa.ec.eudi.iban.1`                          | ❌ |
| `iban-sd-jwt`         | IBAN                      | dc+sd-jwt   | `urn:eu.europa.ec.eudi:iban:1`                      | ❌ |
| `ehic`                | EHIC                      | mso_mdoc    | `eu.europa.ec.eudi.ehic.1`                          | ❌ |
| `ehic-sd-jwt`         | EHIC                      | dc+sd-jwt   | `urn:eu.europa.ec.eudi:ehic:1`                      | ❌ |
| `health-id`           | Health ID                 | mso_mdoc    | `eu.europa.ec.eudi.hiid.1`                          | ❌ |
| `health-id-sd-jwt`    | Health ID                 | dc+sd-jwt   | `urn:eu.europa.ec.eudi:hiid:1`                      | ❌ |
| `pda1`                | Portable Document A1      | mso_mdoc    | `eu.europa.ec.eudi.pda1.1`                          | ❌ |
| `pda1-sd-jwt`         | Portable Document A1      | dc+sd-jwt   | `urn:eu.europa.ec.eudi:pda1:1`                      | ❌ |
| `loyalty`             | Loyalty Card              | mso_mdoc    | `eu.europa.ec.eudi.loyalty.1`                       | ❌ |
| `msisdn`              | MSISDN                    | mso_mdoc    | `eu.europa.ec.eudi.msisdn.1`                        | ❌ |
| `msisdn-sd-jwt`       | MSISDN                    | dc+sd-jwt   | `urn:eu.europa.ec.eudi:msisdn:1`                    | ❌ |
| `por`                 | Power of Representation   | mso_mdoc    | `eu.europa.ec.eudi.por.1`                           | ❌ |
| `por-sd-jwt`          | Power of Representation   | dc+sd-jwt   | `urn:eu.europa.ec.eudi:por:1`                       | ❌ |

### Authoritative Requirements (EU ARF Annex 2.02 Topic 3)

The PID docType and namespace values are mandated by the following High-Level Requirements:

| Requirement | Specification                                                                                                                                                                     |
| :---------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
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
| :------------------- | :----------------------- | :-------- | :------- |
| `age_over_18`        | Whether holder is over 18| Mandatory | `bool`   |

### Protocol Stack

| Protocol   | Usage                                         | Specification                         |
| :--------- | :-------------------------------------------- | :------------------------------------ |
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

## 4. Tax Identification

### Document Types

| Format    | Identifier                          |
| :-------- | :---------------------------------- |
| mso_mdoc  | `eu.europa.ec.eudi.tax.1`          |
| dc+sd-jwt | `urn:eu.europa.ec.eudi:tax:1` (vct)|

### Namespace (mso_mdoc)

```text
eu.europa.ec.eudi.tax.1
```

### Claims

| Claim ID                 | Name                     | Description                           |
| :----------------------- | :----------------------- | :------------------------------------ |
| `tax_number`             | Tax Number               | Tax identification number             |
| `registered_family_name` | Registered Family Name   | Family name registered with tax authority |
| `registered_given_name`  | Registered Given Names   | Given names registered with tax authority |
| `issuing_country`        | Issuing Country          | Country code (ISO 3166-1 alpha-2)     |

---

## 5. Pseudonym (Age Over 18)

### Document Types

| Format    | Identifier                                            |
| :-------- | :---------------------------------------------------- |
| mso_mdoc  | `eu.europa.ec.eudi.pseudonym.age_over_18.1`          |
| dc+sd-jwt | `urn:eu.europa.ec.eudi:pseudonym_age_over_18:1` (vct)|

### Namespace (mso_mdoc)

```text
eu.europa.ec.eudi.pseudonym.age_over_18.1
```

### Claims

| Claim ID       | Name         | Description              | Encoding       |
| :------------- | :----------- | :----------------------- | :------------- |
| `age_over_18`  | Age Over 18  | Whether holder is over 18| `bool`         |

This credential provides a privacy-preserving pseudonymous attestation of age, disclosing only the `age_over_18` boolean without any identifying information.

---

## 6. Certificate of Residence

### Document Type

```text
eu.europa.ec.eudi.cor.1
```

### Namespace

```text
eu.europa.ec.eudi.cor.1
```

### Format

mso_mdoc only.

### Claims

| Claim ID               | Name                 | Description                          |
| :--------------------- | :------------------- | :----------------------------------- |
| `resident_address`     | Resident Address     | Full residential address             |
| `resident_country`     | Resident Country     | Country of residence (ISO 3166-1)    |
| `resident_city`        | Resident City        | City of residence                    |
| `resident_postal_code` | Resident Postal Code | Postal code                          |
| `issuing_country`      | Issuing Country      | Country code (ISO 3166-1 alpha-2)    |

---

## 7. Photo ID

### Document Type

```text
org.iso.23220.2.photoid.1
```

### Namespace

```text
org.iso.23220.photoid.1
```

### Specification

Photo ID is defined in **ISO/IEC 23220-2** and provides a general-purpose photo identification credential.

### Format

mso_mdoc only.

### Claims

| Claim ID             | Name               | Description                          |
| :------------------- | :----------------- | :----------------------------------- |
| `family_name`        | Family Name        | Current surname(s)                   |
| `given_name`         | Given Names        | Current first/middle name(s)         |
| `birth_date`         | Birth Date         | Date of birth                        |
| `portrait`           | Portrait           | Facial image of the holder           |
| `document_number`    | Document Number    | Unique document identifier           |
| `issuing_authority`  | Issuing Authority  | Authority that issued the document   |
| `issuing_country`    | Issuing Country    | Country code (ISO 3166-1 alpha-2)    |
| `expiry_date`        | Expiry Date        | Date of document expiry              |

---

## 8. Travel Reservation

### Document Type

```text
org.iso.18013.5.1.reservation
```

### Namespace

```text
org.iso.18013.5.1.reservation
```

### Format

mso_mdoc only.

### Claims

| Claim ID             | Name               | Description                          |
| :------------------- | :----------------- | :----------------------------------- |
| `reservation_number` | Reservation Number | Booking/reservation identifier       |
| `family_name`        | Family Name        | Passenger surname(s)                 |
| `given_name`         | Given Names        | Passenger first/middle name(s)       |

---

## 9. IBAN

### Document Types

| Format    | Identifier                           |
| :-------- | :----------------------------------- |
| mso_mdoc  | `eu.europa.ec.eudi.iban.1`          |
| dc+sd-jwt | `urn:eu.europa.ec.eudi:iban:1` (vct)|

### Namespace (mso_mdoc)

```text
eu.europa.ec.eudi.iban.1
```

### Claims

| Claim ID         | Name            | Description                |
| :--------------- | :-------------- | :------------------------- |
| `iban`           | IBAN            | International Bank Account Number |
| `account_holder` | Account Holder  | Name of the account holder |
| `bic`            | BIC             | Bank Identifier Code       |

---

## 10. European Health Insurance Card (EHIC)

### Document Types

| Format    | Identifier                           |
| :-------- | :----------------------------------- |
| mso_mdoc  | `eu.europa.ec.eudi.ehic.1`          |
| dc+sd-jwt | `urn:eu.europa.ec.eudi:ehic:1` (vct)|

### Namespace (mso_mdoc)

```text
eu.europa.ec.eudi.ehic.1
```

### Claims

| Claim ID              | Name                | Description                          |
| :-------------------- | :------------------ | :----------------------------------- |
| `family_name`         | Family Name         | Holder's surname(s)                  |
| `given_name`          | Given Names         | Holder's first/middle name(s)        |
| `birth_date`          | Birth Date          | Date of birth                        |
| `personal_id`         | Personal ID         | Personal identification number       |
| `institution_id`      | Institution ID      | EHIC institution identifier          |
| `institution_country` | Institution Country | Country of the insuring institution  |
| `card_number`         | Card Number         | EHIC card number                     |
| `expiry_date`         | Expiry Date         | Card expiry date                     |

---

## 11. Health ID

### Document Types

| Format    | Identifier                           |
| :-------- | :----------------------------------- |
| mso_mdoc  | `eu.europa.ec.eudi.hiid.1`          |
| dc+sd-jwt | `urn:eu.europa.ec.eudi:hiid:1` (vct)|

### Namespace (mso_mdoc)

```text
eu.europa.ec.eudi.hiid.1
```

### Claims

| Claim ID              | Name                | Description                          |
| :-------------------- | :------------------ | :----------------------------------- |
| `family_name`         | Family Name         | Holder's surname(s)                  |
| `given_name`          | Given Names         | Holder's first/middle name(s)        |
| `birth_date`          | Birth Date          | Date of birth                        |
| `health_insurance_id` | Health Insurance ID | Health insurance identifier          |
| `issuing_country`     | Issuing Country     | Country code (ISO 3166-1 alpha-2)    |

---

## 12. Portable Document A1 (PDA1)

### Document Types

| Format    | Identifier                           |
| :-------- | :----------------------------------- |
| mso_mdoc  | `eu.europa.ec.eudi.pda1.1`          |
| dc+sd-jwt | `urn:eu.europa.ec.eudi:pda1:1` (vct)|

### Namespace (mso_mdoc)

```text
eu.europa.ec.eudi.pda1.1
```

### Specification

The Portable Document A1 (PDA1) is a social security coordination document used within the EU. It certifies the social security legislation applicable to the holder, typically when working in another EU member state.

### Claims

| Claim ID                 | Name                    | Description                                |
| :----------------------- | :---------------------- | :----------------------------------------- |
| `family_name`            | Family Name             | Holder's surname(s)                        |
| `given_name`             | Given Names             | Holder's first/middle name(s)              |
| `birth_date`             | Birth Date              | Date of birth                              |
| `nationality`            | Nationality             | Nationality (ISO 3166-1 alpha-2)           |
| `social_security_number` | Social Security Number  | Social security identification number      |
| `issuing_country`        | Issuing Country         | Country code (ISO 3166-1 alpha-2)          |
| `expiry_date`            | Expiry Date             | Document expiry date                       |

---

## 13. Loyalty Card

### Document Type

```text
eu.europa.ec.eudi.loyalty.1
```

### Namespace

```text
eu.europa.ec.eudi.loyalty.1
```

### Format

mso_mdoc only.

### Claims

| Claim ID       | Name           | Description                     |
| :------------- | :------------- | :------------------------------ |
| `family_name`  | Family Name    | Holder's surname(s)             |
| `given_name`   | Given Names    | Holder's first/middle name(s)   |
| `loyalty_number` | Loyalty Number | Loyalty programme number      |
| `program_name` | Program Name   | Name of the loyalty programme   |

---

## 14. Mobile Phone Number (MSISDN)

### Document Types

| Format    | Identifier                              |
| :-------- | :-------------------------------------- |
| mso_mdoc  | `eu.europa.ec.eudi.msisdn.1`           |
| dc+sd-jwt | `urn:eu.europa.ec.eudi:msisdn:1` (vct) |

### Namespace (mso_mdoc)

```text
eu.europa.ec.eudi.msisdn.1
```

### Claims

| Claim ID                 | Name                   | Description                        |
| :----------------------- | :--------------------- | :--------------------------------- |
| `phone_number`           | Phone Number           | Mobile phone number (MSISDN)       |
| `registered_family_name` | Registered Family Name | Family name registered with carrier|

---

## 15. Power of Representation (PoR)

### Document Types

| Format    | Identifier                          |
| :-------- | :---------------------------------- |
| mso_mdoc  | `eu.europa.ec.eudi.por.1`          |
| dc+sd-jwt | `urn:eu.europa.ec.eudi:por:1` (vct)|

### Namespace (mso_mdoc)

```text
eu.europa.ec.eudi.por.1
```

### Claims

| Claim ID                     | Name                       | Description                          |
| :--------------------------- | :------------------------- | :----------------------------------- |
| `legal_person_id`            | Legal Person ID            | Identifier of the legal entity       |
| `legal_person_name`          | Legal Person Name          | Name of the legal entity             |
| `representative_family_name` | Representative Family Name | Surname of the representative        |
| `representative_given_name`  | Representative Given Names | Given names of the representative    |

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
