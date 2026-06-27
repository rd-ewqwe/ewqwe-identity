# Summary of Protocols and Formats

This page summarises the protocols, standards, credential formats, and implementation profiles used in the EU Digital Identity ecosystem. It serves as a compact reference; detailed user journeys and flow diagrams are in the [User Journey](./user-journey.md).

---

## Protocols — ISO/IEC 18013-7 Annexes

ISO/IEC 18013-7 defines how mobile driving licences (mDLs) and generic mDocs are presented **over the internet** (remote presentation), extending the proximity-based protocols of ISO/IEC 18013-5. Three distinct annexes define different transport and invocation mechanisms.

### Annex A: REST API (Device Retrieval)

| Aspect | Detail |
|--------|--------|
| **Invocation** | HTTP POST directly to a wallet endpoint or proxy server |
| **Request payload** | CBOR-encoded `DeviceRequest` (ISO 18013-5) |
| **Response payload** | CBOR-encoded `DeviceResponse` |
| **Encryption** | Network-layer session encryption (no standardised session protocol) |
| **Trust model** | No global trust list; verifier authenticates via TLS |
| **Developer impact** | Requires CBOR parsing, COSE cryptography, and session key establishment at the network layer |
| **Wallet support** | None of the major EUDI wallets (France Identité, EUDI Wallet DE, IT Wallet, Spanish EUDIW) implement Annex A |

### Annex B: OpenID4VP (OpenID for Verifiable Presentations)

| Aspect | Detail |
|--------|--------|
| **Invocation** | Universal / deep links (`openid4vp://`), `request_uri` fetch, HTTP `direct_post` |
| **Request payload** | DCQL query (JSON); legacy PEX supported as fallback |
| **Response payload** | `vp_token` containing mDoc or SD-JWT, optionally JWE-encrypted (`direct_post.jwt`) |
| **Request signing** | JAR (JWT Secured Authorization Request, RFC 9101) — required by HAIP |
| **Trust model** | Verifier identity verified via X.509 certificates or redirect URI matching |
| **Developer impact** | Requires JWT/JWE handling, DCQL evaluation, and OpenID4VP state management |
| **Wallet support** | **All major EUDI wallets** |

### Annex C: W3C Digital Credentials API (DC API)

Annex C defines two sub-protocols that both run over the W3C Digital Credentials API
(`navigator.credentials.get({ digital: ... })`). The browser/OS handles wallet discovery,
invocation, and user consent via a credential chooser, then delivers the request to the
user-selected wallet.

#### Sub-protocol A: Raw ISO mDoc (`org-iso-mdoc`)

The classic ISO 18013-7 Annex C payload: a CBOR-structured request with HPKE encryption.

| Aspect | Detail |
|--------|--------|
| **Protocol identifier** | `org-iso-mdoc` |
| **Invocation** | Browser API: `navigator.credentials.get({ digital: { requests: [...] } })` |
| **Request payload** | `["dcapi", { nonce, recipientPublicKey }]` (CBOR) + CBOR `DeviceRequest` — both base64url-encoded as opaque strings in the `data` field |
| **Response payload** | HPKE-encrypted mDoc inside the `["dcapi", { enc, cipherText }]` CBOR wrapper — returned as an opaque string in the `data` field |
| **Encryption** | HPKE (X25519 + HKDF-SHA256 + AES-128-GCM) |
| **Wallet support** | Rare — most wallets do not implement a separate CBOR/HPKE code path just for Annex C |

#### Sub-protocol B: OpenID4VP over DC API (`openid4vp-v1-*`)

This is what wallets actually implement. The verifier sends a **standard OpenID4VP Authorization
Request** (with `dcql_query`, `nonce`, `client_metadata`), and the wallet returns a VP Token
— all tunnelled through the DC API instead of via `openid4vp://` deep links or `direct_post`.

| Aspect | Detail |
|--------|--------|
| **Protocol identifiers** | `openid4vp-v1-unsigned`, `openid4vp-v1-signed`, `openid4vp-v1-multisigned` (see [OpenID4VP §A.1](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-A.1)) |
| **Invocation** | Browser API: `navigator.credentials.get({ digital: { requests: [...] } })` |
| **Request payload** | Standard OpenID4VP Authorization Request parameters as JSON in the `data` field: `response_type`, `response_mode`, `nonce`, `dcql_query`, `client_metadata`, optionally `client_id` and `request` for signed requests |
| **Response payload** | OpenID4VP Authorization Response containing the `vp_token`, optionally JWE-encrypted (`response_mode: "dc_api.jwt"`): the encrypted JWT is returned as a JSON string in the `data` field |
| **Response modes** | `dc_api` (unencrypted JSON, not recommended) or `dc_api.jwt` (JWE-encrypted Authorization Response — the wallet encrypts the `vp_token` using the verifier's public key from `client_metadata.jwks`, per [OpenID4VP §8.3](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.3)) |
| **Wallet support** | **Theoretical — not yet confirmed in production.** The EUDI Wallet Core library includes DC API handling code, but production wallets (France Identité, EUDI Wallet DE, IT Wallet, Spanish EUDIW) do not yet recognize the `openid4vp` protocol identifier inside the DC API handler. See [the demo webapp page](./demo_webapp.md) for details. |

#### Summary comparison

| Aspect | `org-iso-mdoc` | `openid4vp-v1-*` |
|--------|----------------|-------------------|
| **Payload format** | CBOR (`["dcapi", ...]`) | JSON (OpenID4VP) |
| **Encryption** | HPKE (mandatory) | JWE (`dc_api.jwt`, mandatory by modern profiles) |
| **Request structure** | `encryptionInfo` + `deviceRequest` CBOR blobs | `dcql_query`, `nonce`, `client_metadata` |
| **Response structure** | CBOR-encoded HPKE ciphertext | JWE-encrypted VP Token |
| **Wallet implementation** | Separate code path (CBOR + COSE + HPKE) | Reuses OpenID4VP logic from Annex B |
| **Adoption** | Low | **Not yet demonstrated in production** — documented as broken on Android 15+ in practice (see [the demo webapp page](./demo_webapp.md)) |

**In short**: "Wraps OpenID4VP as `dc_api.jwt`" means the wallet receives a standard OpenID4VP
Authorization Request through the DC API, processes it with its existing OpenID4VP handler,
then encrypts the resulting VP Token as a JWE (using `response_mode: dc_api.jwt`) before
returning it through the DC API.

---

## OpenID4VP Profiles

### EU Age Verification Profile (EU-AV Blueprint)

| Aspect | Detail |
|--------|--------|
| **Purpose** | Privacy-preserving, anonymous age checks (e.g. "Over 18" for online services) |
| **Driven by** | [Digital Services Act (DSA)](https://digital-strategy.ec.europa.eu/en/policies/digital-services-act-package) |
| **Primary method** | ISO/IEC 18013-7 Annex C (W3C DC API) |
| **Fallback method** | OpenID4VP Annex B (`redirect_uri` scheme, no JAR, `direct_post`) |
| **Request signing** | **No JAR** — deliberately omitted to prevent verifier tracking |
| **Privacy model** | Double-blind: verifier gets binary yes/no without user identity; issuer cannot see where credential is used |
| **Client ID scheme** | `redirect_uri` (fallback only) |
| **Credential format** | `mso_mdoc` (`eu.europa.ec.av.1`) |
| **Wallet support** | AV-compatible wallets (EUDI Wallet Referenz, AVI) via Annex B deep-link fallback. Annex C (W3C DC API) is the *specified* primary method, but no wallet has demonstrated working Annex C support in production as of mid-2026. |

### High Assurance Interoperability Profile (HAIP)

| Aspect | Detail |
|--------|--------|
| **Purpose** | High-security credential exchange for PID, mDL, and other sensitive credentials |
| **Managed by** | OpenID Foundation |
| **Request signing** | **Strict JAR required** — verifier MUST authenticate via EU Trust List X.509 certificates |
| **Response encryption** | JWE (`direct_post.jwt`) — mandatory |
| **Client ID schemes** | `x509_san_dns`, `x509_hash`, `x509_san_uri` |
| **Credential formats** | `mso_mdoc` (mDL, PID) and `dc+sd-jwt` (PID) |
| **Query language** | DCQL (mandated by EUDIW per [ARF](https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework)) |
| **Wallet support** | All major EUDI wallets (France Identité, EUDI Wallet DE, IT Wallet, Spanish EUDIW) |

---

## Credential Formats

### mso_mdoc (ISO/IEC 18013-5)

| Aspect | Detail |
|--------|--------|
| **Data model** | CBOR-encoded `DeviceResponse` containing one or more `Document` objects |
| **Issuer signature** | `COSE_Sign1` — the Mobile Security Object (MSO) over the issuer-signed data |
| **Device signature** | `COSE_Sign1` — `DeviceSignature` over `DeviceAuthentication` (includes `SessionTranscript`) |
| **Selective disclosure** | MSO contains SHA-256 digests of each claim issuer-signed item; wallet discloses only requested items |
| **Key binding** | `DeviceKey` in MSO → `DeviceSignature` proves holder possession of corresponding private key |
| **Used by** | mDL, PID, EU Age Verification, National ID, EHIC, and most other EUDI credentials |
| **Namespace** | e.g. `org.iso.18013.5.1` (mDL), `eu.europa.ec.av.1` (Age Verification) |

### SD-JWT VC (Selective Disclosure JWT for Verifiable Credentials)

| Aspect | Detail |
|--------|--------|
| **Standard** | [IETF SD-JWT VC](https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc.html) |
| **Data model** | JWT-encoded verifiable credential with selectively-disclosable claims |
| **Issuer signature** | JWT signed with issuer's private key (`x5c` certificate chain) |
| **Holder binding** | KB-JWT (Key Binding JWT) — proves holder possession of the bound key |
| **Selective disclosure** | `_sd` digests in the issuer JWT; wallet reveals only requested salted digests |
| **Key binding** | `cnf` (confirmation) claim in issuer JWT → holder proves possession of corresponding private key via KB-JWT |
| **Used by** | PID (HAIP profile), National ID, EHIC, and other EUDI credentials in the HAIP profile |
| **vct** | e.g. `urn:eu.europa.ec.eudi:pid:1` (PID), `urn:eu.europa.ec.eudi:ehic:1` (EHIC) |

### Key Differences: mso_mdoc vs SD-JWT VC

| Aspect | mso_mdoc | SD-JWT VC |
|--------|----------|-----------|
| **Encoding** | CBOR (binary) | JSON / JWT (text) |
| **Issuer signature** | COSE_Sign1 (CBOR) | JWT (JSON) |
| **Holder binding** | DeviceSignature over SessionTranscript | KB-JWT |
| **Selective disclosure** | MSO digest-based | `_sd` digests |
| **Namespace** | ISO namespace strings | vct (Verifiable Credential Type) |
| **Session binding** | OpenID4VP Handover (SessionTranscript) | KB-JWT nonce + audience |
| **Web-friendliness** | Requires CBOR/COSE libraries | Works with standard JWT libraries |

---

## EUDI Wallet Implementation Matrix

Wallet support for ISO/IEC 18013-7 annexes across major European member states, based on observed behaviour in testing and public documentation (as of May 2026):

| Scheme | Transport | Payload | Trust | France | Germany | Italy | Spain |
|--------|-----------|---------|-------|--------|---------|-------|-------|
| **ISO 18013-7 Annex A** | HTTP REST API | CBOR DeviceRequest/Response | Network-layer encryption | ❌ Not implemented | ❌ Not implemented | ❌ Not implemented | ❌ Not implemented |
| **ISO 18013-7 Annex B** | `openid4vp://`, `direct_post` | DCQL (JSON) | JAR + TLS | ✅ Production, DCQL + JAR | ✅ Beta/Sandbox, DCQL + JAR | ✅ Production, DCQL + JAR | ✅ Pilot, DCQL + JAR |
| **ISO 18013-7 Annex C** | `navigator.credentials.get()` | **Sub-protocol A**: CBOR `["dcapi",...]` + HPKE
**Sub-protocol B**: OpenID4VP JSON + JWE (`dc_api.jwt`) | Web origins + App Links | ⚠️ Sub-protocol B: in development — EUDI Wallet Core added DC API support, but the `openid4vp` protocol identifier is not yet recognised by production wallets (see note below)
❌ Sub-protocol A: not implemented | ⚠️ Sub-protocol B: in development (same limitation)
❌ Sub-protocol A: not implemented | ⚠️ Sub-protocol B: in development (same limitation)
❌ Sub-protocol A: not implemented | ⚠️ Sub-protocol B: in development (same limitation)
❌ Sub-protocol A: not implemented |

> **Note on Annex C**: While the EUDI Wallet Core library includes DC API plumbing, production wallets reject the `openid4vp` protocol identifier with "Unsupported protocol" errors. The W3C DC API Annex C flow is therefore **not functional** with any current EUDI wallet. All wallets use Annex B (deep-link OpenID4VP) for production flows. See [the demo webapp page](./demo_webapp.md) for the full technical analysis.
| **OpenID4VP HAIP** | OpenID4VP, `direct_post.jwt` | DCQL | Strict JAR + EU Trust List | ✅ DCQL + strict JAR | ✅ DCQL + strict JAR | ✅ DCQL + strict JAR | ✅ DCQL + strict JAR |
| **EUDIW EU-AV Blueprint** | Priority: Annex C → Annex B | DCQL (minimal disclosure) | No JAR | ✅ Drops JAR for privacy | ✅ Drops JAR for privacy | ✅ Drops JAR for privacy | ✅ Core focus, drops JAR |

> **Note:** This matrix reflects observed wallet behaviour from testing and public documentation, not formal compliance certifications. Wallet capabilities evolve rapidly — consult each member state's latest wallet release notes for current status.


---

## References

- [ISO/IEC 18013-5](https://www.iso.org/standard/69084.html) — mDL data model and mDoc format
- [ISO/IEC 18013-7](https://www.iso.org/standard/91154.html) — mDoc online presentation
- [OpenID4VP 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) — OpenID for Verifiable Presentations
- [RFC 9101 — JAR](https://datatracker.ietf.org/doc/html/rfc9101) — JWT Secured Authorization Request
- [RFC 9180 — HPKE](https://www.rfc-editor.org/rfc/rfc9180) — Hybrid Public Key Encryption
- [SD-JWT VC](https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc.html) — Selective Disclosure JWT for Verifiable Credentials
- [W3C Digital Credentials API](https://www.w3.org/TR/digital-credentials/) — browser API for credential presentation
- [EU Age Verification Profile](https://ageverification.dev/Technical%20Specification/annexes/annex-A/annex-A-av-profile/) — EU AV specification
- [High Assurance Interoperability Profile (HAIP)](https://openid.net/specs/openid-connect-4-verifiable-presentations.html) — high-security credential exchange
- [EUDI Wallet ARF](https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework) — Architecture and Reference Framework
- [ISO 18013-7](./technical_references/iso_18013_7.md) — detailed reference
- [Full reference list](./technical_references/references.md) — all authoritative sources
