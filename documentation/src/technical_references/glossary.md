# Glossary

This glossary defines acronyms and terminology used across the ewQwe Age Verification project and the broader EU digital identity ecosystem.

---

## A

**ARF** — *Architecture and Reference Framework*
The EU Commission's technical blueprint for the European Digital Identity Wallet ecosystem. Defines the architecture, roles, and interoperability requirements for all EUDI components.

**Attestation**
A digitally-signed document issued by a trusted authority that asserts facts about a subject (e.g. "this person is over 18"). The general term used in the EU ARF for any credential or verifiable document, whether mDL, PID, or any other type.

**AVI** — *Age Verification App Instance*
Term used in the EU Age Verification Profile for the wallet-side component that stores and presents Proof of Age attestations. Corresponds to the `wallet/` component in this project.

---

## B

**Binding Proof** → see *Holder Binding Proof*

---

## C

**CBOR** — *Concise Binary Object Representation* (RFC 7049 / RFC 8949)
A binary data serialization format, similar to JSON but more compact. Used extensively in mDoc/mDL credentials. All mso_mdoc structures are CBOR-encoded.

**CDDL** — *Concise Data Definition Language* (RFC 8610)
A schema language for describing CBOR data structures. Used in ISO 18013-5 to formally define mDoc structures.

**CIR** — *Commission Implementing Regulation*
EU regulatory acts that specify technical details of the EUDI Wallet framework. CIR 2024/2977 defines the PID attribute set.

**`client_id`**
In OpenID4VP, the identifier of the Relying Party (Verifier). The format depends on the `client_id_scheme`:

- `redirect_uri:https://rp.example.com/cb` — RP identified by its redirect URI (AnnexA profile)
- `x509_san_dns:rp.example.com` — RP identified by a DNS SAN in its X.509 certificate (HAIP profile)
- `x509_hash:<base64url_sha256>` — RP identified by the SHA‑256 hash of its leaf X.509 certificate (HAIP profile, **recommended** over `x509_san_dns`)

**cnf** — *Confirmation Claim* (RFC 7800)
A JWT claim that contains the holder's public key (usually as a `jwk`). Used in SD-JWT VCs to bind the credential to a specific cryptographic key, enabling holder binding.

**COSE** — *CBOR Object Signing and Encryption* (RFC 8152 / RFC 9052)
The CBOR equivalent of JOSE (JSON Object Signing and Encryption). Defines:

- `COSE_Sign1` — single-signer signatures
- `COSE_Mac0` — message authentication codes
- `COSE_Encrypt0` / `COSE_Encrypt` — encryption structures

**COSE_Sign1**
A COSE structure for a signed object with a single signer. Used for MSO (issuer auth) and device signatures in mso_mdoc. Structure: `[protected_header, unprotected_header, payload, signature]`.

---

## D

**DC API** — *Digital Credentials API*
A W3C browser API (`navigator.credentials.get()`) that enables web pages to request verifiable credentials from wallets. Replaces the earlier WebAuthn-based flow for identity credentials.

**DCQL** — *Digital Credentials Query Language*
A JSON-based query language used in OpenID4VP `dcql_query` parameter to specify which credential types and claims are requested. More expressive than Presentation Exchange (PE).

**DeviceAuthentication**
An mDL CBOR structure that the device (holder) signs to prove session binding. Contains: `["DeviceAuthentication", SessionTranscript, DocType, DeviceNameSpacesBytes]`. The signed bytes are `DeviceAuthenticationBytes = Tag(24, bstr(cbor(DeviceAuthentication)))`.

**DeviceSigned**
The part of an mDoc `Document` that contains the device-generated signature (`DeviceAuth`) and any device-disclosed namespaces. Proves the holder controls the credential's device key.

**Disclosure** (SD-JWT)
A base64url-encoded JSON array `[salt, claim_name, claim_value]` that reveals a single selectively-disclosed claim. The holder includes chosen Disclosures in a presentation.

**docType**
The CBOR text string identifier for an mDoc credential type. Examples:

- `org.iso.18013.5.1.mDL` — Mobile Driver's Licence
- `eu.europa.ec.eudi.pid.1` — EU Person Identification Data
- `eu.europa.ec.eudi.ageproof.1` — EU Age Verification (AVI profile)

---

## E

**EUDI Wallet** — *European Union Digital Identity Wallet*
The EU-standardised digital wallet app (Android/iOS) for holding and presenting European Digital Identity documents. Governed by the EU ARF.

**EC** — *Elliptic Curve*
Cryptographic scheme used for compact key sizes and signatures. Common curves in this project:

- **P-256** (secp256r1): used for ES256 signatures, JWK thumbprints
- **P-384** (secp384r1): used for ES384 signatures

---

## H

**HAIP** — *High Assurance Interoperability Profile*
An OpenID4VP profile requiring JARM (`response_mode=direct_post.jwt`) and X.509-based RP authentication (`client_id_scheme=x509_hash`). Provides higher security guarantees than the basic profile.

**Holder**
The entity (person, organisation) who possesses a credential and presents it to verifiers. In this project, corresponds to the wallet / AVI.

**Holder Binding Proof**
Proof that the holder of a credential controls the private key bound to it. This prevents credential theft — a stolen credential is useless without the binding key.

- In **mso_mdoc**: the `DeviceSigned` block containing a `COSE_Sign1` over `DeviceAuthenticationBytes` signed with the device private key
- In **SD-JWT VC**: the Key Binding JWT (KB-JWT) signed with the key in the `cnf.jwk` claim

See [OpenID4VP §5.3](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.3).

---

## I

**ISO 18013-5**
The ISO standard defining the Mobile Driver's Licence (mDL) data model and presentation protocol. Basis for the mso_mdoc credential format and the COSE-based signing scheme used across EU digital credentials.

**Issuer**
A trusted authority that issues credentials (attests facts about a subject). Signs the MSO (mDL) or the JWT (SD-JWT VC).

**IssuerSigned**
The part of an mDoc `Document` containing the issuer-authenticated claims and the MSO (`COSE_Sign1`). Enables selective disclosure — only the chosen `IssuerSignedItem` entries are revealed.

**IssuerSignedItem**
A single disclosed claim in an mso_mdoc document. Contains: `digestID`, `random` (salt), `elementIdentifier` (claim name), `elementValue` (claim value). Encoded as `Tag(24, bstr(cbor(IssuerSignedItem)))`.

---

## J

**JARM** — *JWT Secured Authorization Response Mode*
An extension of OAuth 2.0 that wraps authorization responses in a JWT. In OpenID4VP, `response_mode=direct_post.jwt` uses JWE/JWS to encrypt/sign the VP Token response from wallet to RP. Required by the HAIP profile.

**JWE** — *JSON Web Encryption* (RFC 7516)
A standard for encrypting data as a JSON structure. Used in JARM to encrypt the VP Token when `response_mode=direct_post.jwt`.

**JWK** — *JSON Web Key* (RFC 7517)
A JSON representation of a cryptographic key (EC or RSA). The verifier's JWK is used to encrypt JARM responses; its thumbprint is included in the `SessionTranscript` for HAIP flows.

**JWK Thumbprint** (RFC 7638)
A SHA-256 hash of the canonical JSON representation of a JWK. Used in the `OID4VPHandoverInfo` to bind the session transcript to the verifier's encryption key.

**JWS** — *JSON Web Signature* (RFC 7515)
A standard for signing data as a JSON structure. The basis for standard JWTs and SD-JWT VC issuer signatures.

**JWT** — *JSON Web Token* (RFC 7519)
A compact, URL-safe representation of claims signed (and optionally encrypted) as JSON.

---

## K

**KB-JWT** — *Key Binding JWT*
The trailing JWT in an SD-JWT presentation that proves the holder controls the key in `cnf.jwk`. Contains `aud`, `nonce`, `iat`, and `sd_hash`. Required for holder binding in SD-JWT VC presentations.

---

## M

**mDL** — *Mobile Driver's Licence*
A digital driving licence defined by ISO/IEC 18013-5. Uses the `mso_mdoc` credential format with docType `org.iso.18013.5.1.mDL`.

**mDoc** / **mso_mdoc**
Short for "Mobile Document" / "Mobile Security Object + mDoc". The credential format defined in ISO 18013-5 using CBOR encoding and COSE signing. Used for mDL, EU PID, EU Age Verification, and other digital documents.

**MSO** — *Mobile Security Object*
The signed CBOR data structure embedded in an mDoc's `issuerAuth` COSE_Sign1. Contains SHA-256 digests of each claim (rather than the values themselves), enabling selective disclosure while maintaining issuer authenticity.

---

## N

**Namespace**
In mDL/mDoc, claims are grouped into namespaces (CBOR text strings). Examples:

- `org.iso.18013.5.1` — Core mDL attributes (given_name, birth_date, etc.)
- `org.iso.18013.5.1.aamva` — North American additions
- `eu.europa.ec.eudi.pid.1` — EU PID attributes

**nonce**
A random value included in an Authorization Request to prevent replay attacks. Bound into the `SessionTranscript` (mDL) or KB-JWT (SD-JWT VC) of the presentation.

---

## O

**OID4VP** / **OpenID4VP** — *OpenID for Verifiable Presentations*
The protocol used to request and receive Verifiable Presentations from a wallet. Builds on OAuth 2.0 authorization flows. Supports both mso_mdoc and SD-JWT VC credential formats. Key specs versions: 1.0 (current stable).

**OID4VCI** / **OpenID4VCI** — *OpenID for Verifiable Credential Issuance*
The companion protocol to OID4VP for issuing credentials into wallets.

---

## P

**PE** — *Presentation Exchange*
An older query language for specifying credential requirements in OID4VP, defined by the Decentralized Identity Foundation (DIF). Being superseded by DCQL in newer profiles.

**PID** — *Person Identification Data*
The EU digital identity credential containing core identity attributes (name, birth date, nationality, etc.). Specified in CIR 2024/2977. Available in both `mso_mdoc` and `SD-JWT VC` formats.

**Presentation** / **VP**
A holder-constructed object that packages one or more credentials (or selective disclosures from them) together with holder binding proof, for transmission to a verifier. In OpenID4VP the main artifact is called the **VP Token**.

**Proof of Age (PoA)** / **Age Verification Attestation**
A credential or derived presentation that proves an age threshold (e.g. "over 18") without revealing exact birth date. Core use case of this project.

---

## R

**RP** — *Relying Party*
The service or application that requests and verifies credentials. Also called **Verifier**. In this project, corresponds to the `webapp/` component.

**response_mode**
OpenID4VP parameter controlling how the wallet returns the VP Token:

- `fragment` — appended to redirect URI as URL fragment (same-device, cross-origin)
- `direct_post` — wallet POSTs to `response_uri` (cross-device or CORS-friendly)
- `direct_post.jwt` — wallet POSTs a JWE/JWS-wrapped VP Token (HAIP/JARM)
- `dc_api` — delivered via browser DC API (no redirect needed)
- `dc_api.jwt` — DC API with JARM wrapping

**response_uri**
The URL to which the wallet POSTs the VP Token in `direct_post` and `direct_post.jwt` modes.

---

## S

**Salted Hashing**
The mechanism used for selective disclosure in both mDL and SD-JWT. Each claim is combined with a random salt before hashing. This prevents a verifier from guessing undisclosed claim values by brute-forcing the hash.

**SAN** — *Subject Alternative Name*
An X.509 certificate extension field listing alternative identities for the certificate subject (DNS names, IP addresses, email). Used in `x509_san_dns` client_id scheme to identify RPs.

**SD-JWT VC** — *Selective Disclosure JWT for Verifiable Credentials*
A credential format combining standard JWTs with selective disclosure via SHA-256 commitments. Defined in [IETF SD-JWT VC](https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc.html).

**SessionTranscript**
An mDL CBOR structure that ties a device signature to a specific presentation session. For OID4VP flows it contains the `OID4VPHandover`, which commits to the `client_id`, `nonce`, `response_uri`, and (for HAIP) the verifier's JWK thumbprint.

**`_sd`**
The JSON array in an SD-JWT VC issuer JWT that holds base64url-encoded SHA-256 digests of the Disclosures. The holder reveals values by including the matching Disclosures in the presentation.

**`_sd_alg`**
The hash algorithm used for Disclosure digests in SD-JWT VCs. Currently always `sha-256`.

---

## T

**Tag(24)** — `#6.24(bstr)`
A CBOR semantic tag applied to a byte string to indicate that its content is CBOR-encoded. Extensively used in mDL:

- `IssuerSignedItemBytes = #6.24(bstr .cbor IssuerSignedItem)`
- `DeviceAuthenticationBytes = #6.24(bstr .cbor DeviceAuthentication)`
- `DeviceNameSpacesBytes = #6.24(bstr .cbor DeviceNameSpaces)`

The full `Tag(24, bstr(...))` encoding must be hashed/signed, not just the inner bytes.

---

## V

**VC** / **Verifiable Credential**
A tamper-evident credential whose authorship can be cryptographically verified. The W3C Verifiable Credentials Data Model provides a general framework; mso_mdoc and SD-JWT VC are two concrete serialisations.

**Verifiable Presentation** / **VP**
A holder-generated package wrapping one or more Verifiable Credentials and a binding proof. Transmitted to a verifier (RP) in response to a presentation request.

**Verifier** → see *RP*

**VP Token**
The OpenID4VP parameter name for the value carrying the Verifiable Presentation. For mso_mdoc it is the base64url-encoded `DeviceResponse`; for SD-JWT VC it is the SD-JWT string.

**vct** — *Verifiable Credential Type*
A URI in SD-JWT VC that identifies the type/schema of the credential. E.g. `https://credentials.example.com/identity_credential`.

---

## W

**W3C DC API** → see *DC API*

**Wallet**
The software (mobile app or browser extension) that stores, manages, and presents digital credentials on behalf of the holder. In this project: the `wallet-extension/` browser wallet or the EUDI Android Wallet.

---

## X

**x5chain** (COSE header label 33)
An unprotected COSE header containing a DER-encoded X.509 certificate chain. Used in mDL `issuerAuth` to carry the issuer certificate for chain verification.

**x5c** (JOSE header)
The JSON/JWT equivalent of `x5chain`. An array of base64-encoded DER X.509 certificates. Used in JAR (JWT Authorization Request) to carry the RP's certificate for `x509_hash` / `x509_san_dns` verification.
