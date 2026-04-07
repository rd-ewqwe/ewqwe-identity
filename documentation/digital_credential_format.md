## Digital Credential format

According to the [OpenID for Verifiable Credential Issuance 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html), the digital credential may be of any format including the following 3:

- [IETF SD-JWT VC](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#I-D.ietf-oauth-sd-jwt-vc)
- [ISO mDOC](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#ISO.18013-5)
- [W3C VCDM](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#VC_DATA)

## EU Age Verification

### Profile

The EU Age Verification profile is specified in [Annex A of this document](https://ageverification.dev/Technical%20Specification/annexes/annex-A/annex-A-av-profile) and specifies the use of:

- OpenID for Verifiable Credential Issuance for the issuance of Proof Of Age Attestations
- W3C Digital Credentials API [W3C Digital Credentials API] as specified in [ISO/IEC 18013-7], Annex C
- OpenID for Verifiable Presentations [OID4VP] as a fallback mechanism
- ISO mDoc [ISO18013-5] for the attestation format.

### Application Provider (AP)

The application provider provides the Digital Credential to the Age Verification App Instance (AVI) using OAuth 2.0 with the PKCE extension as specified in [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636)
