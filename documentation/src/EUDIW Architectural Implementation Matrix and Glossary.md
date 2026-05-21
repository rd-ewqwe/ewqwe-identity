# EUDIW Architectural Implementation Matrix (May 2026)

This document provides a detailed technical comparison of the ISO/IEC 18013-7 request mechanisms and European Digital Identity Wallet (EUDIW) implementation profiles across major European member states.

> For a broader overview including protocol details, credential formats (mso_mdoc vs SD-JWT VC), and the full glossary, see the [Protocols & Formats Summary](./summary_protocols_formats.md).

## Implementation Matrix

| Scheme / Architecture | Transport / Invocation Layer | Request / Payload Format | Trust & Security Model | France (France Identité) | Germany (EUDI Wallet DE) | Italy (IT Wallet) | Spain (Spanish EUDIW) |
| :---- | :---- | :---- | :---- | :---- | :---- | :---- | :---- |
| **ISO/IEC 18013-7 Annex A** | HTTP REST API (POST) direct to endpoint. | CBOR DeviceRequest / DeviceResponse. | Network-layer session encryption. No global trust list. | **Not Implemented** | **Not Implemented** | **Not Implemented** | **Not Implemented** |
| **ISO/IEC 18013-7 Annex B** | Universal/Deep links (openid4vp://), HTTP direct_post. | **DCQL** (legacy PEX supported as fallback in some environments). | JWT Secured Authorization Request (**JAR**) & standard TLS. | **Implemented** (Production). Uses DCQL & JAR. | **Implemented** (Beta/Sandbox). Uses DCQL & JAR. | **Implemented** (Production/IO App). Uses DCQL & JAR. | **Implemented** (Pilot). Uses DCQL & JAR. |
| **ISO/IEC 18013-7 Annex C** | Browser API (navigator.credentials.get); BLE/WebSocket tunnels. | Envelopes an OID4VP request (e.g., dc_api.jwt). | Trust based on web origins and platform-verified App Links. | **Implemented**. Wraps DCQL. Adapts JAR presence based on flow. | **Implemented**. Wraps DCQL via browser mediated flows. | **Implemented**. Wraps DCQL. Deeply integrated via OS-level wallet. | **Implemented**. Heavily prioritized for web-based pilots. |
| **OpenID4VP HAIP** | OpenID4VP (Annex B), custom schemes, direct_post.jwt. | **DCQL** (Mandated by EUDIW). | **Strict JAR:** Verifier MUST authenticate via EU Trust List x.509 certificates. | **Implemented**. Enforces DCQL & strict JAR requirements. | **Implemented**. Enforces DCQL & strict JAR requirements. | **Implemented**. Enforces DCQL & strict JAR requirements. | **Implemented**. Enforces DCQL & strict JAR requirements. |
| **EUDIW EU-AV Blueprint** | Prioritizes **Annex C** (DC API); fallback to Annex B. | **DCQL** optimized for minimal disclosure (Boolean ZKPs). | **No JAR:** Deliberately drops JAR to prevent Verifier tracking. | **Implemented**. Intentionally drops JAR for privacy. | **Implemented**. Intentionally drops JAR for privacy. | **Implemented**. Intentionally drops JAR for privacy. | **Implemented**. Core focus of current age-assurance pilots. Drops JAR. |

## Glossary

| Term | Definition |
|------|------------|
| **API** | Application Programming Interface |
| **BLE** | Bluetooth Low Energy — used by operating systems to prove physical proximity in cross-device flows |
| **CBOR** | Concise Binary Object Representation — a binary data serialization format used in ISO mDocs |
| **DC API** | Digital Credentials API — a W3C browser standard for requesting credentials through the web browser |
| **DCQL** | Digital Credential Query Language — the modern JSON-based query language adopted by the EUDIW to request specific data from wallets, replacing PEX |
| **DSA** | Digital Services Act — EU regulation driving the EU-AV blueprint for mandatory, anonymous age verification |
| **ECDH** | Elliptic Curve Diffie-Hellman — a key agreement protocol used to establish a shared secret for encrypted sessions |
| **EUDIW** | European Digital Identity Wallet |
| **EU-AV** | European Union Age Verification — the specific EUDIW blueprint/scheme for privacy-preserving age checks |
| **HAIP** | High Assurance Interoperability Profile — an OpenID profile ensuring strict security and trust requirements for verifiable presentations |
| **HPKE** | Hybrid Public Key Encryption — a modern cryptographic standard for encrypting payloads to a public key |
| **HTTP** | Hypertext Transfer Protocol |
| **ISO/IEC** | International Organization for Standardization / International Electrotechnical Commission |
| **JAR** | JWT Secured Authorization Request (RFC 9101) — a standard where the Verifier's request is cryptographically signed to prove its authenticity; required by HAIP, rejected by EU-AV |
| **JSON** | JavaScript Object Notation |
| **JWE** | JSON Web Encryption — used to encrypt the wallet's response back to the Verifier |
| **JWT** | JSON Web Token |
| **mDoc** | Mobile Document — the data model format standardized by ISO/IEC 18013-5, natively using CBOR |
| **mDL** | Mobile Driving License |
| **OIDC** | OpenID Connect — an identity layer built on top of the OAuth 2.0 framework |
| **OID4VP** | OpenID for Verifiable Presentations — the standard for presenting credentials over OIDC |
| **OS** | Operating System |
| **PEM** | Privacy-Enhanced Mail — a file format for storing cryptographic keys and certificates |
| **PEX** | Presentation Exchange — a legacy JSON query language used in earlier verifiable credential flows, largely replaced by DCQL in EUDIW |
| **PID** | Personal Identity Data — the core identity credential inside the EUDIW |
| **REST** | Representational State Transfer |
| **SD-JWT** | Selective Disclosure JSON Web Token — a credential format allowing the user to reveal only specific claims |
| **TLS** | Transport Layer Security |
| **URI** | Uniform Resource Identifier |
| **VC** | Verifiable Credential |
| **ZKP** | Zero-Knowledge Proof — a cryptographic method allowing one party to prove a statement without revealing any other underlying data |

## References

- [Protocols & Formats Summary](./summary_protocols_formats.md) — broader overview including protocol details and credential formats
- [User Journey](./user-journey.md) — end-to-end credential verification flows
- [ISO 18013-7 Implementation Notes](./notes/iso-18013-7.md) — detailed technical report on ISO 18013-7 mechanisms
