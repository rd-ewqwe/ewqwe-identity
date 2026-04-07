# Credential Formats: mso_mdoc and SD-JWT VC

This page explains how the two credential formats used in this project are constructed, encoded, and signed at a technical level. Understanding these internals is essential for implementing verifiers correctly.

---

## mso_mdoc (ISO/IEC 18013-5)

The **mso_mdoc** format (Mobile Security Object / mDoc) is defined in ISO/IEC 18013-5. It is the format used for the Mobile Driver's Licence (mDL), the EU Person Identification Data (PID), the EU Age Verification profile, and many other EU digital credentials.

### Overall Structure

An mDoc presentation consists of a `DeviceResponse` CBOR structure:

```cbor
DeviceResponse = {
  "version": "1.0",
  "documents": [ Document+ ],          ; one or more documents
  "status": 0                          ; 0 = OK
}

Document = {
  "docType": tstr,                     ; e.g. "org.iso.18013.5.1.mDL"
  "issuerSigned": IssuerSigned,
  "deviceSigned": DeviceSigned
}
```

### IssuerSigned and the MSO

`IssuerSigned` carries the issuer-authenticated data:

```cbor
IssuerSigned = {
  "nameSpaces": IssuerNameSpaces,      ; disclosed claim values
  "issuerAuth": COSE_Sign1             ; the Mobile Security Object (MSO)
}
```

The **MSO** is a signed CBOR data structure embedded as the payload of a `COSE_Sign1`. It contains:

```cbor
MobileSecurityObject = {
  "version": "1.0",
  "digestAlgorithm": "SHA-256",
  "valueDigests": {
    "org.iso.18013.5.1": {
      0: bstr,    ; SHA-256 digest of IssuerSignedItemBytes for element 0
      1: bstr,    ; ...
      ...
    }
  },
  "deviceKeyInfo": { "deviceKey": COSE_Key },
  "docType": tstr,
  "validityInfo": { "signed": tdate, "validFrom": tdate, "validUntil": tdate }
}
```

**Key point**: the MSO does **not** contain the claim values directly. It contains SHA-256 hashes of each claim. The actual values are disclosed selectively in `IssuerNameSpaces`.

#### IssuerSignedItem and Salted Hashing

Each claim is wrapped as an `IssuerSignedItemBytes`:

```cbor
IssuerSignedItemBytes = #6.24(bstr .cbor IssuerSignedItem)

IssuerSignedItem = {
  "digestID": uint,          ; matches the index in MSO valueDigests
  "random": bstr,            ; random salt (min 16 bytes)
  "elementIdentifier": tstr, ; claim name, e.g. "given_name"
  "elementValue": any        ; the claim value
}
```

The digest in the MSO is:

```cbor
digest = SHA-256( cbor(IssuerSignedItemBytes) )
       = SHA-256( cbor(Tag(24, bstr(cbor(IssuerSignedItem)))) )
```

**Important**: the hash is computed over the full `Tag(24, bstr(...))` encoding, not just the inner CBOR bytes.

#### Issuer Signing (`issuerAuth`)

The MSO is signed as a `COSE_Sign1` with a detached (or embedded) payload:

```cbor
COSE_Sign1 = [
  protected: bstr .cbor { 1: alg },   ; e.g. alg = -7 (ES256)
  unprotected: { 33: [x5chain certs] },
  payload: bstr .cbor MobileSecurityObject,
  signature: bstr
]
```

The issuer certificate chain is carried in the `x5chain` (header label 33) unprotected header. Verifiers check the chain up to a trusted root.

### DeviceSigned and Device Authentication

`DeviceSigned` proves that the holder (device) is the legitimate subject of the credential — it is **holder binding**.

```cbor
DeviceSigned = {
  "nameSpaces": DeviceNameSpacesBytes,  ; Tag(24, bstr .cbor DeviceNameSpaces)
  "deviceAuth": DeviceAuth
}

DeviceAuth = {
  "deviceSignature": COSE_Sign1         ; or "deviceMac": COSE_Mac0
}
```

#### DeviceAuthentication Payload

The COSE_Sign1 device signature uses a **detached payload** called `DeviceAuthenticationBytes`:

```cbor
DeviceAuthentication = [
  "DeviceAuthentication",
  SessionTranscript,          ; binds to the specific presentation session
  DocType,                    ; e.g. "org.iso.18013.5.1.mDL"
  DeviceNameSpacesBytes       ; Tag(24, bstr .cbor DeviceNameSpaces)
]

DeviceAuthenticationBytes = #6.24(bstr .cbor DeviceAuthentication)
```

The wallet signs over `DeviceAuthenticationBytes` (the `Tag(24, bstr(...))` wrapper **must** be included). The verifier must reconstruct the identical bytes and use them as the COSE detached payload.

### SessionTranscript and OpenID4VP Handover

For OpenID4VP presentations, `SessionTranscript` is:

```cbor
SessionTranscript = [
  null,            ; DeviceEngagementBytes (absent for OID4VP)
  null,            ; EReaderKeyBytes (absent for OID4VP)
  OID4VPHandover
]

OID4VPHandover = [
  "OpenID4VPHandover",
  SHA-256( cbor(OID4VPHandoverInfo) )
]

OID4VPHandoverInfo = [
  clientId,             ; the RP's client_id (e.g. "redirect_uri:https://..." or "x509_san_dns:...")
  nonce,                ; from the Authorization Request
  jwkThumbprint,        ; bstr | null — SHA-256 JWK thumbprint of verifier's encryption key
  responseUri           ; the response_uri from the Authorization Request
]
```

The `jwkThumbprint` is present only when `response_mode=direct_post.jwt` (JARM encryption is used). For plain `direct_post`, it is CBOR `null`.

---

## SD-JWT VC

**SD-JWT VC** (Selective Disclosure JWT for Verifiable Credentials) is defined in [IETF SD-JWT VC](https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc.html). It is used for the EU PID, mDL (HAIP profile), and many other credentials in the EUDI ecosystem.

### Structure

An SD-JWT VC is composed of:

```text
<Issuer-signed JWT>~<Disclosure_1>~<Disclosure_2>~...~<KB-JWT>
```

- **Issuer-signed JWT**: a standard JWT (JWS) containing `_sd` arrays of digests
- **Disclosures**: base64url-encoded JSON arrays `[salt, claim_name, claim_value]`
- **KB-JWT** (Key Binding JWT): proves holder control (optional but required for wallet binding)

### Issuer-Signed JWT

```json
{
  "alg": "ES256",
  "typ": "vc+sd-jwt"
}
.
{
  "iss": "https://issuer.example.com",
  "iat": 1700000000,
  "exp": 1800000000,
  "vct": "https://credentials.example.com/identity_credential",
  "cnf": { "jwk": { ... } },      // holder's public key (holder binding)
  "_sd_alg": "sha-256",
  "_sd": [
    "X9yH0Ajf...",   // SHA-256 digest of Disclosure for "given_name"
    "aB3kLm9n...",   // SHA-256 digest of Disclosure for "family_name"
    ...
  ],
  "age_equal_or_over": {
    "_sd": [ "qR7sT2uV..." ]   // nested selective disclosure
  }
}
.
<signature>
```

### Disclosures

Each selectively-disclosed claim is represented as a Disclosure:

```spec
Disclosure = BASE64URL( JSON([ salt, claim_name, claim_value ]) )

Example (decoded):
[ "dX23abc_SALT_VALUE", "given_name", "Elton" ]
```

The digest embedded in the JWT is:

```spec
digest = BASE64URL( SHA-256( ASCII(Disclosure) ) )
```

To reveal a claim, the holder includes the corresponding Disclosure in the SD-JWT presentation. The verifier recomputes the digest and checks it against the `_sd` array.

### Key Binding JWT (KB-JWT)

The KB-JWT proves that the holder controls the private key corresponding to the `cnf.jwk` in the issuer JWT. It binds the presentation to a specific transaction:

```json
{
  "alg": "ES256",
  "typ": "kb+jwt"
}
.
{
  "iat": 1700000100,
  "aud": "https://verifier.example.com",   // client_id of the RP
  "nonce": "abc123",                        // nonce from Authorization Request
  "sd_hash": "BASE64URL(SHA-256(issuer_jwt~disc1~disc2~))"  // commitment
}
.
<holder_signature>
```

The `sd_hash` is the SHA-256 hash of the SD-JWT string up to and including the last `~` before the KB-JWT. This prevents the KB-JWT from being replayed with a different set of disclosures.

See also [OpenID4VP §5.3](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.3) for the Holder Binding Proof requirements.

### Issuer Signing

SD-JWT VCs use standard JSON Web Signatures (JWS, RFC 7515). Common algorithms:

| Algorithm | Curve    | OID                 |
|-----------|----------|---------------------|
| ES256     | P-256    | SHA-256             |
| ES384     | P-384    | SHA-384             |
| RS256     | RSA-2048 | PKCS#1 v1.5 SHA-256 |
| PS256     | RSA-2048 | RSASSA-PSS SHA-256  |

---

## Comparison Table

| Property                  | mso_mdoc                              | SD-JWT VC                            |
|---------------------------|---------------------------------------|--------------------------------------|
| Encoding                  | CBOR (binary)                         | JSON / Base64URL                     |
| Container                 | `DeviceResponse`                      | `<jwt>~<disc>~...~<kb-jwt>`          |
| Issuer signature          | `COSE_Sign1` (EC/RSA)                 | JWS (EC/RSA)                         |
| Selective disclosure      | Salted SHA-256 per `IssuerSignedItem` | Salted SHA-256 per Disclosure        |
| Holder binding            | `DeviceSigned` (COSE_Sign1/Mac0)      | KB-JWT (JWS)                         |
| Session binding           | `SessionTranscript` (in DeviceAuth)   | `aud` + `nonce` in KB-JWT            |
| Multi-document            | Yes (`documents` array)               | One credential per presentation      |
| Binary-friendly           | Yes (native CBOR)                     | Base64URL encoding needed            |
| Primary standard          | ISO/IEC 18013-5                       | IETF SD-JWT VC + OpenID4VP           |

---

## COSE Algorithms (mso_mdoc)

| COSE alg ID | Name      | Description                  |
|-------------|-----------|------------------------------|
| -7          | ES256     | ECDSA with P-256, SHA-256    |
| -35         | ES384     | ECDSA with P-384, SHA-384    |
| -36         | ES512     | ECDSA with P-521, SHA-512    |
| -37         | PS256     | RSASSA-PSS with SHA-256      |
| -257        | RS256     | RSASSA-PKCS1-v1_5 SHA-256    |
| 5           | HMAC256   | HMAC with SHA-256 (MAC auth) |

---

## Verification Steps Summary

### mso_mdoc Verification

1. Decode the `DeviceResponse` from base64url → CBOR
2. For each `Document`:
   a. Decode the `issuerAuth` `COSE_Sign1`
   b. Verify the issuer certificate chain (x5chain header) up to a trusted root
   c. Verify the `COSE_Sign1` signature over the MSO payload
   d. Check MSO `expiry`, `validFrom`, `docType`
   e. For each disclosed `IssuerSignedItem`:
      - Re-encode as `IssuerSignedItemBytes = Tag(24, bstr(cbor(IssuerSignedItem)))`
      - Compute `SHA-256(cbor(IssuerSignedItemBytes))`
      - Check it matches the MSO `valueDigests[namespace][digestID]`
   f. Reconstruct `SessionTranscript` from the Authorization Request parameters
   g. Build `DeviceAuthentication` → `DeviceAuthenticationBytes = Tag(24, bstr(cbor(DeviceAuthentication)))`
   h. Verify the `deviceSignature` `COSE_Sign1` with the MSO `deviceKey` over `DeviceAuthenticationBytes`

### SD-JWT VC Verification

1. Split the SD-JWT on `~` into: issuer JWT, disclosures, KB-JWT
2. Verify the issuer JWT signature using the issuer's public key (from `iss` metadata or `x5c` header)
3. Check standard JWT claims (`exp`, `nbf`, `iss`, `vct`)
4. For each presented Disclosure:
   - Compute `BASE64URL(SHA-256(disclosure_string))`
   - Check the digest appears in the issuer JWT's `_sd` array (recursively for nested claims)
5. Verify the KB-JWT signature using the `cnf.jwk` from the issuer JWT
6. Check KB-JWT `aud` matches `client_id`, `nonce` matches the request nonce
7. Check `sd_hash` = `BASE64URL(SHA-256(issuer_jwt~disc1~disc2~...))`
