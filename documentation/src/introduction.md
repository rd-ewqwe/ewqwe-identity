
**EwQwE** (pronounced */juːˈkwiː/*  *you-kwee*) **Digital Identity** is a comprehensive software suite for implementing Digital Identity solutions, with specific focus on [European Digital Identity (EUDI)](https://digital-strategy.ec.europa.eu/en/policies/eudi-regulation) standards and protocols.

## Primary Use Case: EU Age Verification

The **EwQwE Credential Verifier Server** is a production-ready backend service designed specifically for websites and applications (Relying Parties) that need to perform [EU-compliant Age Verification](https://ageverification.dev/av-doc-technical-specification/docs/architecture-and-technical-specifications/#23-user-journey) following the [EU Age Verification Profile (Annex A)](https://ageverification.dev/Technical%20Specification/annexes/annex-A/annex-A-av-profile).

**Why Use EwQwE Credential Verifier?**

- ✅ **Standards Compliant** - Implements W3C Digital Credentials API, OpenID4VP, and ISO/IEC 18013-5 (mDoc)
- ✅ **Production Ready** - Built with Rust for security, performance, and reliability
- ✅ **Privacy Preserving** - Supports selective disclosure and minimal data exposure
- ✅ **Easy Integration** - Simple REST API for credential verification
- ✅ **Secure by Design** - TLS/mTLS authentication, signed attestations, comprehensive audit logging
- ✅ **Flexible Deployment** - Standalone server or integrated into existing infrastructure

While designed for EU Age Verification, the credential verifier supports **any credential type** including Driver's Licenses, National ID cards, professional qualifications, and custom credential schemas.

## What This Documentation Provides

This documentation serves three main purposes:

### 1. EwQwE Credential Verifier Installation and Configuration

Comprehensive guides for deploying the credential verifier server in development and production environments:

- Installation prerequisites and dependencies
- TLS/mTLS configuration for secure communications
- Redis session storage setup
- Logging and telemetry integration with OpenTelemetry
- API reference and verification workflow
- Security considerations and production deployment checklist

See the [EwQwE Credential Verification Server](./credential_verifier_server.md) chapter for complete details.

### 2. Demo Wallet and Demo Web App for Integration Testing

Complete working demonstration system to help Relying Parties implement credential verification in their own web applications:

- **Demo Wallet Browser Extension** - Reference implementation of an Age Verification App Instance (AVI) that stores and presents credentials
- **Sample Demo Web App** - Starter code showing how to request credentials, interact with wallets, and verify attestations
- **Step-by-step integration guide** - From wallet installation to complete verification flow
- **Source code on GitHub** - Production-ready TypeScript/Deno code you can fork and customize

The demo webapp serves as both a functional test environment and a **starting point for your own Relying Party implementation**. See the [Demo Architecture](./demo_architecture.md) chapter to get started.

### 3. Technical References and Protocol Documentation

Authoritative references and detailed specifications for the standards and protocols used:

- [W3C Digital Credentials API](https://wicg.github.io/digital-credentials/) implementation
- [OpenID for Verifiable Presentations (OpenID4VP)](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) protocol
- [ISO/IEC 18013-5](https://www.iso.org/standard/69084.html) mobile driver's license (mDL) format
- [Digital Credentials Query Language (DCQL)](./dcql_age_verification.md) for credential requests
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

This documentation uses terminology from European Digital Identity and credential verification standards:

| Term               | Definition                                                      |
| :----------------- | :-------------------------------------------------------------- |
| **AP**             | Attestation Provider                                            |
| **ARF**            | Architecture and Reference Framework                            |
| **AV app**         | Age Verification App                                            |
| **AVI**            | Age Verification App Instance (the user's digital wallet)       |
| **AVAP**           | Age Verification App Provider                                   |
| **CA**             | Certificate Authority                                           |
| **DG CNECT**       | Directorate General Network, Content and Technology             |
| **eIDAS**          | Electronic Identification, Authentication and Trust Services    |
| **EU**             | European Union                                                  |
| **EUDI**           | European Digital Identity                                       |
| **EUDIW**          | European Digital Identity Wallet (also EUDI Wallet)             |
| **LoA**            | Level of Assurance                                              |
| **mDL**            | Mobile Driver's License (ISO/IEC 18013-5 format)                |
| **mDoc**           | Mobile Document (CBOR-encoded credential format)                |
| **PID**            | Person Identification Data (EU Digital Identity credential)     |
| **RP**             | Relying Party (web application requesting credential verification) |
| **U**              | User                                                            |
| **VP**             | Verifiable Presentation (credential presented by wallet)        |
| **WB**             | Web Browser (or web app)                                        |
| **ZKP**            | Zero Knowledge Proof                                            |

## Getting Help and Contributing

- **Issues**: Report bugs or request features on [GitHub Issues](https://github.com/your-org/ewqwe-identity/issues)
- **Discussions**: Join the community for questions and best practices
- **Source Code**: Available on GitHub (links provided in each component chapter)
- **Specifications**: Links to authoritative standards throughout the documentation

## License and Usage

The EwQwE Credential Verifier is provided under a Business Source License (BSL 1.1) with free testing and experimentation. The other components (Demo Wallet and Demo Webapp) are open source software under an MIT license. See individual component repositories for specific license details and usage terms.
