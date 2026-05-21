
**ewQwe** (pronounced */juːˈkwiː/*  *you-kwee*) **Digital Identity** is a comprehensive software suite for implementing Digital Identity solutions, with specific focus on [European Digital Identity (EUDI)](https://digital-strategy.ec.europa.eu/en/policies/eudi-regulation) standards and protocols.

## Primary Use Case: PID, mDL and Age Verification

The **ewQwe Credential Verifier Server** is a production-ready backend service designed for websites and applications (Relying Parties) that need to verify digital credentials from users' wallets. The primary use cases are:

- **Person Identification Data (PID)** — the core identity credential inside the EUDI Wallet, issued by EU member states. Used for online identification, age verification, and proof of identity.
- **Mobile Driving Licence (mDL)** — the ISO/IEC 18013-5 mobile driving licence, used for driving privilege verification, age checks (e.g. alcohol sales, car rental), and identity verification.
- **EU Age Verification** — following the [EU Age Verification Profile (Annex A)](https://ageverification.dev/Technical%20Specification/annexes/annex-A/annex-A-av-profile) and the [Digital Services Act (DSA)](https://digital-strategy.ec.europa.eu/en/policies/digital-services-act-package), enabling privacy-preserving age checks (e.g. "Over 18") without revealing the user's identity.

The verifier supports both the **High Assurance Interoperability Profile (HAIP)** — used by the EUDI Wallet for PID and mDL presentation with strict JAR signing and JWE encryption — and the **EU Age Verification (EU-AV) Blueprint** — optimised for privacy-preserving, anonymous age checks.

**Why Use ewQwe Credential Verifier?**

- ✅ **Standards Compliant** — Implements W3C Digital Credentials API, OpenID4VP 1.0, ISO/IEC 18013-5/7 (mDoc/mDL), SD-JWT VC, HAIP, and the EU Age Verification Profile
- ✅ **Production Ready** — Built with Rust for security, performance, and reliability
- ✅ **Privacy Preserving** — Supports selective disclosure, minimal data exposure, and zero-knowledge age proofs
- ✅ **Easy Integration** — Simple REST API for credential verification
- ✅ **Secure by Design** — TLS/mTLS authentication, signed attestations, comprehensive audit logging with hash-chained journal
- ✅ **Flexible Deployment** — Standalone server or integrated into existing infrastructure
- ✅ **Two Credential Formats** — Supports both `mso_mdoc` (CBOR-based, ISO/IEC 18013-5) and `dc+sd-jwt` (Selective Disclosure JWT) formats

### Supported Credential Types

The verifier supports a wide range of credential types across both formats:

| Credential Type | Format(s) | DocType / vct | Typical Claims |
|---|---|---|---|
| **mDL (Mobile Driving Licence)** | `mso_mdoc` | `org.iso.18013.5.1.mDL` | given_name, family_name, birth_date, age_over_18/21, portrait, driving_privileges, issue/expiry_date |
| **PID (Person Identification Data)** | `mso_mdoc`, `dc+sd-jwt` | `eu.europa.ec.eudi.pid.1` | given_name, family_name, birth_date, age_over_18, nationality, resident_address |
| **EU Age Verification** | `mso_mdoc` | `eu.europa.ec.av.1` | age_over_18 (boolean ZKP) |
| **National ID** | `mso_mdoc`, `dc+sd-jwt` | `eu.europa.ec.eudi.pid.1` | given_name, family_name, birth_date, portrait, document_number |
| **eHealth Insurance Card (EHIC)** | `mso_mdoc`, `dc+sd-jwt` | `eu.europa.ec.eudi.ehic.1` | given_name, family_name, birth_date, institution_id, expiry_date |
| **Health ID** | `mso_mdoc`, `dc+sd-jwt` | `eu.europa.ec.eudi.health.1` | given_name, family_name, birth_date, health_id, blood_type |
| **Tax ID** | `mso_mdoc`, `dc+sd-jwt` | `eu.europa.ec.eudi.tax.1` | tax_id, country_code |
| **PDA1 (Social Security)** | `mso_mdoc`, `dc+sd-jwt` | `eu.europa.ec.eudi.pda1.1` | given_name, family_name, birth_date, member_state, employer |
| **Certificate of Residence (CoR)** | `mso_mdoc` | `eu.europa.ec.eudi.cor.1` | given_name, family_name, address, issuing_country |
| **Proof of Registration (PoR)** | `mso_mdoc`, `dc+sd-jwt` | `eu.europa.ec.eudi.por.1` | given_name, family_name, registration_number, issuing_authority |
| **Photo ID** | `mso_mdoc` | `eu.europa.ec.eudi.photo-id.1` | given_name, family_name, portrait, document_number |
| **IBAN (Bank Account)** | `mso_mdoc`, `dc+sd-jwt` | `eu.europa.ec.eudi.iban.1` | iban, bank_name, account_holder |
| **MSISDN (Mobile Number)** | `mso_mdoc`, `dc+sd-jwt` | `eu.europa.ec.eudi.msisdn.1` | msisdn, country_code |
| **Pseudonymised Age** | `mso_mdoc`, `dc+sd-jwt` | `eu.europa.ec.eudi.pseudonym-age.1` | age_over_18, pseudonym |
| **Loyalty Card** | `mso_mdoc` | `eu.europa.ec.eudi.loyalty.1` | loyalty_id, program_name, points_balance |
| **Reservation** | `mso_mdoc` | `eu.europa.ec.eudi.reservation.1` | reservation_id, venue, date |

For the complete credential type configuration including all claim paths and namespace mappings, see [`@ewqwe/digital-identity` config source](https://github.com/ewqwe-identity/ewqwe-identity/tree/main/js-lib/ewqwe-digital-identity/src/config.ts).

## What This Documentation Provides

This documentation serves three main purposes:

### 1. ewQwe Credential Verifier Installation and Configuration

Comprehensive guides for deploying the credential verifier server in development and production environments:

- Installation prerequisites and dependencies
- TLS/mTLS configuration for secure communications
- Redis session storage setup
- Logging and telemetry integration with OpenTelemetry
- API reference and verification workflow
- Security considerations and production deployment checklist

See the [ewQwe Credential Verification Server](./credential_verifier_server.md) chapter for complete details.

### 2. Demo Wallet and Demo Web App for Integration Testing

Complete working demonstration system to help Relying Parties implement credential verification in their own web applications:

- **Demo Wallet Browser Extension** — Reference implementation of an Age Verification App Instance (AVI) that stores and presents credentials
- **Sample Demo Web App** — Starter code showing how to request credentials, interact with wallets, and verify attestations
- **Step-by-step integration guide** — From wallet installation to complete verification flow
- **Source code on GitHub** — Production-ready TypeScript code you can fork and customise

The demo webapp serves as both a functional test environment and a **starting point for your own Relying Party implementation**. See the [Demo Architecture](./demo_architecture.md) chapter to get started.

### 3. Technical References and Protocol Documentation

Authoritative references and detailed specifications for the standards and protocols used:

- [W3C Digital Credentials API](https://wicg.github.io/digital-credentials/) implementation
- [OpenID for Verifiable Presentations (OpenID4VP)](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) protocol
- [ISO/IEC 18013-5](https://www.iso.org/standard/69084.html) mobile driver's license (mDL) format
- [ISO/IEC 18013-7](https://www.iso.org/standard/69086.html) — online mDoc presentation (Annex B: OpenID4VP, Annex C: DC API)
- [Digital Credentials Query Language (DCQL)](./dcql_age_verification.md) for credential requests
- [High Assurance Interoperability Profile (HAIP)](https://openid.net/specs/openid-connect-4-verifiable-presentations.html) for high-security credential exchange
- EU Age Verification Profile specifications and requirements
- Credential format structures and namespace mappings
- Browser storage mechanisms and security considerations

## Quick Start

Ready to get started? Follow these paths based on your role:

**For Developers Building Relying Party Applications:**

1. Review the [User Journey](./user-journey.md) to understand the complete flow
2. Follow the [Demo Architecture](./demo_architecture.md) setup guide to run the demo system
3. Explore the demo webapp source code as a template for your implementation
4. Deploy the [Credential Verifier Server](./credential_verifier_server.md) for your production use

**For System Administrators Deploying the Verifier:**

1. Start with the [Credential Verifier Server](./credential_verifier_server.md) installation guide
2. Configure TLS certificates and Redis storage
3. Set up monitoring and logging with OpenTelemetry
4. Review security considerations and production checklist

**For Technical Architects and Standards Compliance:**

1. Study the [Components Architecture](./architecture.md) overview
2. Review protocol specifications in [W3C Credential Request](./w3c_credential_request.md)
3. Understand [DCQL Age Verification](./dcql_age_verification.md) query language
4. Examine [Credential Type Specifications](./credential_type_specifications.md)

## Acronyms and Abbreviations

This documentation uses terminology from European Digital Identity, ISO/IEC 18013-7, and credential verification standards:

| Term               | Definition                                                         |
| :----------------- | :----------------------------------------------------------------- |
| **AP**             | Attestation Provider                                               |
| **ARF**            | Architecture and Reference Framework                               |
| **AV app**         | Age Verification App                                               |
| **AVI**            | Age Verification App Instance (the user's digital wallet)          |
| **AVAP**           | Age Verification App Provider                                      |
| **BLE**            | Bluetooth Low Energy — used by operating systems to prove physical proximity in cross-device flows |
| **CA**             | Certificate Authority                                              |
| **CBOR**           | Concise Binary Object Representation — a binary data serialisation format used in ISO mDocs |
| **DC API**         | Digital Credentials API — a W3C browser standard for requesting credentials directly through the web browser |
| **DCQL**           | Digital Credential Query Language — the modern JSON-based query language for requesting specific data from wallets, replacing PEX |
| **DG CNECT**       | Directorate General Network, Content and Technology                |
| **DSA**            | Digital Services Act — EU regulation driving mandatory, anonymous age verification |
| **eIDAS**          | Electronic Identification, Authentication and Trust Services       |
| **EU**             | European Union                                                     |
| **EUDI**           | European Digital Identity                                          |
| **EUDIW**          | European Digital Identity Wallet (also EUDI Wallet)                |
| **EU-AV**          | European Union Age Verification — the EUDIW blueprint for privacy-preserving age checks |
| **HAIP**           | High Assurance Interoperability Profile — an OpenID profile for high-security credential exchange with strict JAR requirements |
| **HPKE**           | Hybrid Public Key Encryption — a modern cryptographic standard for encrypting payloads to a public key (used in Annex C) |
| **JAR**            | JWT Secured Authorization Request (RFC 9101) — cryptographically signed verifier request, required by HAIP |
| **JWE**            | JSON Web Encryption — used to encrypt the wallet's response (required by HAIP) |
| **JWT**            | JSON Web Token                                                      |
| **LoA**            | Level of Assurance                                                 |
| **mDL**            | Mobile Driver's License (ISO/IEC 18013-5 format)                   |
| **mDoc**           | Mobile Document — CBOR-encoded credential format (ISO/IEC 18013-5) |
| **OIDC**           | OpenID Connect — an identity layer on top of OAuth 2.0             |
| **OID4VP**         | OpenID for Verifiable Presentations — standard for presenting credentials over OIDC |
| **PEX**            | Presentation Exchange — legacy JSON query language, largely replaced by DCQL |
| **PID**            | Person Identification Data — the core identity credential inside the EUDI Wallet |
| **RP**             | Relying Party — web application requesting credential verification  |
| **SD-JWT**         | Selective Disclosure JSON Web Token — a credential format supporting selective claim disclosure |
| **TLS**            | Transport Layer Security                                           |
| **U**              | User                                                               |
| **VP**             | Verifiable Presentation — credential data presented by the wallet  |
| **WB**             | Web Browser (or web app)                                           |
| **ZKP**            | Zero Knowledge Proof — cryptographic method allowing one party to prove a statement without revealing underlying data |

## Getting Help and Contributing

- **Issues**: Report bugs or request features on [GitHub Issues](https://github.com/your-org/ewqwe-identity/issues)
- **Discussions**: Join the community for questions and best practices
- **Source Code**: Available on GitHub (links provided in each component chapter)
- **Specifications**: Links to authoritative standards throughout the documentation

## License and Usage

The ewQwe Credential Verifier is provided under a Business Source License (BSL 1.1) with free testing and experimentation. The other components (Demo Wallet and Demo Webapp) are open source software under an MIT license. See individual component repositories for specific license details and usage terms.
