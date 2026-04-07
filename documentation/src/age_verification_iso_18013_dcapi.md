# ISO/IEC 18013-5 + 18013-7 DCAPI (Age Verification)

This chapter explains the **ISO mDoc** request/response format used with the **W3C Digital Credentials API** in the **EU Age Verification Profile Annex A, A.5 (Proof of Age attestation presentation)**.

It focuses on:

- **ISO/IEC 18013-7, Annex C**: how Digital Credentials API requests/responses carry an ISO mDoc transaction.
- **ISO/IEC 18013-5, §8.3.2.1.2.1**: the **DeviceRequest** format (what the Relying Party requests).
- **ISO/IEC 18013-5, §8.3.2.1.2.3**: the **DeviceResponse** format (what the Wallet returns).

## Why Annex A.5 mentions ISO 18013-7 Annex C

Annex A.5 uses the W3C Digital Credentials API as the browser-facing mechanism for credential selection and exchange.
ISO/IEC 18013-7 defines a *transport binding* that describes how an mDoc exchange is packaged for that API.

In other words:

- **The browser API call** is defined by W3C.
- **The credential message format** is defined by ISO mDoc.
- **The wrapper + encryption packaging** (so the browser sees opaque bytes) is defined by ISO/IEC 18013-7 Annex C.

## Mental model (high level)

A conforming Relying Party builds a request with two base64url-encoded CBOR blobs:

- `encryptionInfo`: tells the wallet **how** to encrypt the response back to the RP.
- `deviceRequest`: tells the wallet **what** to present (ISO mDoc DeviceRequest).

The wallet produces a response as a base64url-encoded CBOR blob containing:

- an **HPKE-encrypted** ISO mDoc DeviceResponse.

## Normative requirements (what you must do)

The following is a practical, implementation-oriented reading of the ISO requirements referenced by Annex A.5.

### 1) Use CBOR as the binary format

- `encryptionInfo`, `deviceRequest`, and the final `EncryptedResponse` are CBOR-encoded.
- CBOR is then encoded as **base64url without padding**.

### 2) Bind request and response with a nonce

- The RP includes a cryptographic `nonce` in `encryptionInfo`.
- The wallet uses it in the cryptographic context so the response cannot be replayed in a different session.

### 3) Provide a COSE_Key for the wallet to encrypt to

- The RP includes a `recipientPublicKey` as a **COSE_Key** structure.
- The wallet uses that key for **HPKE** encryption (RFC 9180) of the `DeviceResponse`.

### 4) The response is an HPKE-encrypted DeviceResponse

- The wallet returns an object that contains an HPKE ephemeral public key (commonly exposed as `enc`) and the HPKE ciphertext (`cipherText`).
- After HPKE decryption, the RP obtains an ISO mDoc **DeviceResponse**.

## ISO/IEC 18013-7 Annex C wrapper (DCAPI packaging)

ISO/IEC 18013-7 Annex C defines a simple wrapper that tags the payload for the Digital Credentials API use-case.
A common representation used in profiles is:

- `encryptionInfo = base64url_nopad(CBOR(["dcapi", { nonce, recipientPublicKey }]))`
- `deviceRequest   = base64url_nopad(CBOR(DeviceRequest))`
- `response        = base64url_nopad(CBOR(["dcapi", { enc, cipherText }]))`

Where:

- `nonce` is a CBOR byte string (`bstr`).
- `recipientPublicKey` is a COSE_Key.
- `enc` is the HPKE sender’s ephemeral public key (the RP needs it to decrypt).
- `cipherText` is the HPKE ciphertext of the CBOR-encoded `DeviceResponse`.

## ISO/IEC 18013-5 §8.3.2.1.2.1: DeviceRequest (what the RP asks for)

The DeviceRequest expresses:

- Which document type(s) you accept (e.g. PID, mDL).
- Which namespace(s) and element identifiers you request.
- Whether you request issuer-signed and/or device-signed data.
- Session binding and reader authentication mechanisms (where applicable).

### Age Verification-specific guidance

For age verification, the most important implementation rule is **data minimization**:

- Request only what you need to determine an “over age” result.
- Avoid requesting full identity attributes (name, address, portrait) if your policy does not require them.

In an EU Age Verification Profile context, that typically means requesting either:

- A **Proof of Age attestation** namespace/claims (preferred), or
- A minimal set of attributes sufficient to compute an age threshold (fallback / legacy).

## ISO/IEC 18013-5 §8.3.2.1.2.3: DeviceResponse (what the Wallet returns)

The DeviceResponse includes the presentation data and cryptographic material needed for verification:

- Document(s) returned by the wallet.
- Issuer-signed data and potentially device-signed data.
- Integrity protection structures defined by ISO mDoc.

In the DCAPI flow, the DeviceResponse is **not** returned in plaintext: it is embedded inside `cipherText` and must be HPKE-decrypted first.

## End-to-end flow (sequence)

1. RP generates a fresh HPKE recipient key pair (or equivalent) and a fresh random nonce.
2. RP builds `encryptionInfo` (CBOR → base64url no pad).
3. RP builds `DeviceRequest` (CBOR → base64url no pad) with age-verification-minimal queries.
4. RP calls the W3C Digital Credentials API with those parameters.
5. Wallet parses both blobs, prepares DeviceResponse.
6. Wallet HPKE-encrypts the DeviceResponse to the RP public key and returns `EncryptedResponse` (CBOR → base64url no pad).
7. RP base64url-decodes + CBOR-decodes the wrapper, then HPKE-decrypts `cipherText` using `enc`.
8. RP CBOR-decodes the resulting DeviceResponse and verifies it (issuer trust, signatures, validity).

---

# Implementation examples

The examples below are intentionally explicit about the byte transformations (CBOR ↔ base64url) and the HPKE boundary.

## Example 1: TypeScript (RP side) – build request, decrypt response

This is illustrative pseudocode showing the structure and steps; you can adapt it to Deno/Node.

```ts
import { encode as cborEncode, decode as cborDecode } from "cbor-x";
import { base64url } from "rfc4648";

// HPKE libraries vary; treat these as placeholders.
import {
  generateHpkeKeyPair,
  hpkeOpen,
} from "./hpke_placeholder.ts";

type CoseKey = Record<string, unknown>;

function b64urlNoPad(bytes: Uint8Array): string {
  return base64url.stringify(bytes, { pad: false });
}

function b64urlNoPadToBytes(s: string): Uint8Array {
  return base64url.parse(s, { loose: true });
}

// 1) Prepare recipient public key (COSE_Key) + nonce
const { privateKey, publicKeyCoseKey } = await generateHpkeKeyPair();
const nonce = crypto.getRandomValues(new Uint8Array(16));

// 2) Build encryptionInfo wrapper
const encryptionInfoCbor = cborEncode([
  "dcapi",
  {
    nonce, // bstr in CBOR
    recipientPublicKey: publicKeyCoseKey as CoseKey,
  },
]);
const encryptionInfo = b64urlNoPad(encryptionInfoCbor);

// 3) Build DeviceRequest (structure is ISO-defined; keep this minimal for age verification)
const deviceRequestCbor = cborEncode({
  // NOTE: This is a simplified, schematic shape.
  // In real implementations it must match ISO/IEC 18013-5 §8.3.2.1.2.1.
  version: "1.0",
  docRequests: [
    {
      docType: "eu.europa.ec.av.1", // example: Proof of Age attestation
      itemsRequest: {
        // request only the minimum required elements
        nameSpaces: {
          "eu.europa.ec.av.1": {
            age_over_18: true,
          },
        },
      },
    },
  ],
});
const deviceRequest = b64urlNoPad(deviceRequestCbor);

// 4) Call Digital Credentials API (sketch)
// const resp = await navigator.credentials.get({
//   digital: {
//     requests: [{ encryptionInfo, deviceRequest }],
//   },
// });

// Assume the wallet gives us a base64url response string:
const encryptedResponseB64Url = "...";

// 5) Decode EncryptedResponse wrapper
const encryptedResponseBytes = b64urlNoPadToBytes(encryptedResponseB64Url);
const [tag, data] = cborDecode(encryptedResponseBytes) as [string, any];
if (tag !== "dcapi") throw new Error("Unexpected response tag");

const enc = data.enc as Uint8Array;        // sender ephemeral key
const cipherText = data.cipherText as Uint8Array;

// 6) HPKE decrypt to recover DeviceResponse bytes
const deviceResponseBytes = await hpkeOpen({
  recipientPrivateKey: privateKey,
  enc,
  cipherText,
  // Depending on suite/profile you may also bind AAD/info.
});

// 7) CBOR-decode DeviceResponse
const deviceResponse = cborDecode(deviceResponseBytes);
console.log(deviceResponse);
```

## Example 2: Rust (RP side) – decode wrapper and HPKE decrypt

This is a compact sketch of the RP-side decode/decrypt steps.

```rust
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ciborium::de::from_reader;
use hpke::{
    aead::AesGcm128,
    kdf::HkdfSha256,
    kem::X25519HkdfSha256,
    Deserializable, OpModeR,
};

fn b64url_no_pad_decode(s: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(s.as_bytes()).expect("b64url")
}

// This assumes you already have the recipient private key in the HPKE type.
// Real code must also parse COSE_Key and map it to the HPKE KEM.
fn main() {
    let encrypted_response_b64 = "...";
    let bytes = b64url_no_pad_decode(encrypted_response_b64);

    // EncryptedResponse = ["dcapi", { enc: bstr, cipherText: bstr }]
    let mut cursor = std::io::Cursor::new(bytes);
    let decoded: ciborium::Value = from_reader(&mut cursor).expect("cbor");

    // Parse out `enc` and `cipherText` from decoded CBOR...
    // Then HPKE open:

    // let (enc_bytes, ciphertext_bytes) = ...;
    // let enc = <hpke::kem::X25519HkdfSha256 as hpke::Kem>::EncappedKey::from_bytes(&enc_bytes).unwrap();
    // let recipient_sk = ...;

    // let mut pt = vec![0u8; ciphertext_bytes.len()];
    // let (_ctx, pt_len) = hpke::single_shot_open::<AesGcm128, HkdfSha256, X25519HkdfSha256, _>(
    //     &OpModeR::Base,
    //     &recipient_sk,
    //     &enc,
    //     b"", // info
    //     &ciphertext_bytes,
    //     b"", // aad
    //     &mut pt,
    // ).expect("hpke open");
    // pt.truncate(pt_len);

    // Finally CBOR-decode DeviceResponse from `pt`.
}
```

## Example 3: Wallet side (conceptual)

A wallet implementation typically:

- Parses `encryptionInfo` and `deviceRequest`.
- Selects appropriate credential(s).
- Builds `DeviceResponse` and CBOR-encodes it.
- Uses HPKE with `recipientPublicKey` to encrypt to `cipherText`.
- Emits `EncryptedResponse = ["dcapi", { enc, cipherText }]`.

---

# Interop checklist (things that commonly break)

- Base64url encoding must be **no padding**.
- CBOR must preserve byte strings as byte strings (avoid accidental UTF-8 conversions).
- COSE_Key must be correctly constructed (key type, curve, x/y coordinates, etc.).
- HPKE suite parameters (KEM/KDF/AEAD) must match across RP and wallet.
- Bind `nonce` into the cryptographic context as required by your chosen profile.

# Security guidance (Age Verification)

- Prefer an "over age" attestation over sending date of birth.
- Treat `nonce` as single-use; reject reused nonces server-side.
- Enforce HTTPS and validate RP origin and audience binding.
- Store as little as possible; log only opaque transaction IDs.

# References

- EU Age Verification Profile – Annex A, A.5 and the Appendix "Metadata": <https://ageverification.dev/av-doc-technical-specification/docs/annexes/annex-A/annex-A-av-profile/#ap-metadata>
- HPKE (RFC 9180): <https://www.rfc-editor.org/rfc/rfc9180>
- CBOR (RFC 8949): <https://www.rfc-editor.org/rfc/rfc8949>
- COSE (RFC 9052): <https://www.rfc-editor.org/rfc/rfc9052>
