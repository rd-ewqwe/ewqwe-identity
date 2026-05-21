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

| Aspect | Detail |
|--------|--------|
| **Invocation** | Browser API: `navigator.credentials.get({ digital: { requests: [...] } })` |
| **Request payload** | ISO 18013-7 Annex C wrapper `["dcapi", { nonce, recipientPublicKey }]` + CBOR `DeviceRequest` |
| **Response payload** | HPKE-encrypted mDoc inside the `["dcapi", { enc, cipherText }]` wrapper |
| **Encryption** | HPKE (X25519 + HKDF-SHA256 + AES-128-GCM) |
| **Transport** | Browser/OS handles wallet invocation; BLE proximity checks + relay servers for cross-device |
| **Trust model** | Trust based on web origins and platform-verified App Links |
| **Developer impact** | Minimal — browser handles wallet discovery and session binding |
| **Wallet support** | **All major EUDI wallets** (wraps OpenID4VP request as `dc_api.jwt`) |

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
| **Wallet support** | France Identité, EUDI Wallet Referenz, AVI, any AV-compatible wallet |

### High Assurance Interoperability Profile (HAIP)

| Aspect | Detail |
|--------|--------|
| **Purpose** | High-security credential exchange for PID, mDL, and other sensitive credentials |
| **Managed by** | OpenID Foundation |
| **Request signing** | **Strict JAR required** — verifier MUST authenticate via EU Trust List X.509 certificates |
| **Response encryption** | JWE (`direct_post.jwt`) — mandatory |
| **Client ID schemes** | `x509_san_dns`, `x509_hash`, `x509_san_uri` |
| **Credential formats** | `mso_mdoc` (mDL, PID) and `dc+sd-jwt` (PID) |
| **Query language** | DCQL (mandated by EUDIW) |
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

Wallet support for ISO/IEC 18013-7 annexes across major European member states (as of May 2026):

| Scheme | Transport | Payload | Trust | France | Germany | Italy | Spain |
|--------|-----------|---------|-------|--------|---------|-------|-------|
| **ISO 18013-7 Annex A** | HTTP REST API | CBOR DeviceRequest/Response | Network-layer encryption | ❌ Not implemented | ❌ Not implemented | ❌ Not implemented | ❌ Not implemented |
| **ISO 18013-7 Annex B** | `openid4vp://`, `direct_post` | DCQL (JSON) | JAR + TLS | ✅ Production, DCQL + JAR | ✅ Beta/Sandbox, DCQL + JAR | ✅ Production, DCQL + JAR | ✅ Pilot, DCQL + JAR |
| **ISO 18013-7 Annex C** | `navigator.credentials.get()` | Encapsulated OID4VP (`dc_api.jwt`) | Web origins + App Links | ✅ Wraps DCQL | ✅ Wraps DCQL | ✅ Wraps DCQL, OS-level wallet | ✅ Prioritised for web |
| **OpenID4VP HAIP** | OpenID4VP, `direct_post.jwt` | DCQL | Strict JAR + EU Trust List | ✅ DCQL + strict JAR | ✅ DCQL + strict JAR | ✅ DCQL + strict JAR | ✅ DCQL + strict JAR |
| **EUDIW EU-AV Blueprint** | Priority: Annex C → Annex B | DCQL (minimal disclosure) | No JAR | ✅ Drops JAR for privacy | ✅ Drops JAR for privacy | ✅ Drops JAR for privacy | ✅ Core focus, drops JAR |


---

## References

- [ISO/IEC 18013-5](https://www.iso.org/standard/69084.html) — mDL data model and mDoc format
- [ISO/IEC 18013-7](https://www.iso.org/standard/69086.html) — mDoc online presentation
- [OpenID4VP 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) — OpenID for Verifiable Presentations
- [RFC 9101 — JAR](https://datatracker.ietf.org/doc/html/rfc9101) — JWT Secured Authorization Request
- [RFC 9180 — HPKE](https://www.rfc-editor.org/rfc/rfc9180) — Hybrid Public Key Encryption
- [SD-JWT VC](https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc.html) — Selective Disclosure JWT for Verifiable Credentials
- [W3C Digital Credentials API](https://www.w3.org/TR/digital-credentials/) — browser API for credential presentation
- [EU Age Verification Profile](https://ageverification.dev/Technical%20Specification/annexes/annex-A/annex-A-av-profile/) — EU AV specification
- [High Assurance Interoperability Profile (HAIP)](https://openid.net/specs/openid-connect-4-verifiable-presentations.html) — high-security credential exchange
- [ISO 18013-7 Implementation Notes](./notes/iso-18013-7.md) — detailed technical report
