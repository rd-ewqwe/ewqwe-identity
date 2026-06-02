//! ISO 18013-7 Annex C, Sub-protocol A: Raw ISO mDoc ("org-iso-mdoc").
//!
//! Implements the CBOR + HPKE code path for the W3C Digital Credentials API.
//! This is the "classic" ISO 18013-7 Annex C flow, where the request and
//! response are wrapped in CBOR `["dcapi", ...]` arrays and encrypted with HPKE.
//!
//! ## Flow
//!
//! 1. RP generates a fresh HPKE key pair and a random nonce
//! 2. RP builds `encryptionInfo` (CBOR → base64url) telling the wallet how to encrypt
//! 3. RP builds `deviceRequest` (CBOR → base64url) telling the wallet what to present
//! 4. RP calls `navigator.credentials.get()` with `protocol: "org-iso-mdoc"`
//! 5. Wallet returns an HPKE-encrypted `DeviceResponse`
//! 6. RP HPKE-decrypts the response and sends the plain DeviceResponse to the verifier
//!
//! ## Related
//!
//! For Annex C Sub-protocol B (OpenID4VP over DC API, `protocol: "openid4vp-v1-*"`),
//! see `credentials.ts` → `requestViaOpenID4VPOverDCAPI()`.
//!
//! ## References
//! - EU Age Verification Profile Annex A, §A.5
//! - ISO/IEC 18013-7 Annex C, Sub-protocol A ("org-iso-mdoc")
//! - HPKE RFC 9180
//! - OpenID4VP §A (Sub-protocol B: openid4vp-v1-*)

import { encode as cborEncode, decode as cborDecode } from "cbor-x";
import { base64url } from "rfc4648";
import { generateHpkeKeyPair, hpkeOpen, type CoseKey } from "./hpke.ts";

// ============================================================================
// Types
// ============================================================================

/** The two CBOR blobs passed to `navigator.credentials.get()`. */
export interface DcApiRequest {
  /** base64url(CBOR(["dcapi", { nonce, recipientPublicKey }])) */
  encryptionInfo: string;
  /** base64url(CBOR(DeviceRequest)) */
  deviceRequest: string;
}

/**
 * A single digital credential request inside the W3C Digital Credentials API
 * `navigator.credentials.get()` call.
 *
 * Per the EU Age Verification Profile and France Identité playground examples,
 * the request must include `protocol: "org-iso-mdoc"` alongside the CBOR blobs.
 */
export interface DigitalCredentialRequest {
  /** The ISO 18013-7 Annex C data blob (encryptionInfo + deviceRequest). */
  data: {
    encryptionInfo: string;
    deviceRequest: string;
  };
  /**
   * The protocol identifier. Must be set to `"org-iso-mdoc"` for mDoc/mDL
   * presentations per ISO 18013-7 Annex C.
   */
  protocol: string;
}

/**
 * The top-level options object passed to `navigator.credentials.get()`.
 */
export interface DigitalCredentialRequestOptions {
  digital: {
    requests: DigitalCredentialRequest[];
  };
}

/** Parsed encrypted response from the wallet. */
export interface EncryptedResponseData {
  /** HPKE sender's ephemeral public key (for decryption) */
  enc: Uint8Array;
  /** HPKE ciphertext (contains the DeviceResponse) */
  cipherText: Uint8Array;
}

/** Result of opening an encrypted response. */
export interface DcApiDecryptedResponse {
  /** The decrypted, CBOR-encoded DeviceResponse bytes */
  deviceResponse: Uint8Array;
  /** The nonce from the encryptionInfo (for verifier binding) */
  nonce: Uint8Array;
}

// ============================================================================
// DC API Service
// ============================================================================

export class DcApiService {
  private hpkePrivateKey: Uint8Array | null = null;
  private nonce: Uint8Array | null = null;

  /**
   * Build the two CBOR blobs (`encryptionInfo` + `deviceRequest`) required
   * by the W3C Digital Credentials API per ISO 18013-7 Annex C.
   *
   * The returned `DcApiRequest` provides the CBOR data blobs. When passing
   * these to `navigator.credentials.get()`, the caller must wrap them in a
   * `DigitalCredentialRequest` with `protocol: "org-iso-mdoc"`:
   *
   * ```typescript
   * const blobs = service.buildRequest(nonce, pubKey, docType, claims);
   * const credential = await navigator.credentials.get({
   *     digital: {
   *         requests: [{
   *             data: blobs,
   *             protocol: "org-iso-mdoc",
   *         }],
   *     },
   * });
   * ```
   *
   * @param nonce     Random nonce (at least 16 bytes) for replay protection.
   * @param recipientPublicKey COSE_Key format public key for HPKE encryption.
   * @param docType   Expected document type (e.g. "eu.europa.ec.av.1").
   * @param requestedClaims  ISO namespace → claim names to request.
   *                         e.g. { "eu.europa.ec.av.1": ["age_over_18"] }
   */
  buildRequest(
    nonce: Uint8Array,
    recipientPublicKey: CoseKey,
    docType: string,
    requestedClaims: Record<string, string[]>,
  ): DcApiRequest {
    // --- 1. Build encryptionInfo ---
    // Per EU AV Profile Annex A, §A.5:
    //   EncryptionInfo = ["dcapi", EncryptionParameters]
    //   EncryptionParameters = { "nonce": bstr, "recipientPublicKey": COSE_Key }
    const encryptionInfoCbor = cborEncode([
      "dcapi",
      {
        nonce, // cbor-x will encode Uint8Array as CBOR bstr
        recipientPublicKey,
      },
    ]);
    const encryptionInfo = base64url.stringify(encryptionInfoCbor, {
      pad: false,
    });

    // --- 2. Build DeviceRequest ---
    // Per ISO 18013-5 §8.3.2.1.2.1:
    //   DeviceRequest = { "version": "1.0", "docRequests": [DocRequest] }
    //   DocRequest = { "docType": tstr, "itemsRequest": ItemsRequest }
    const nameSpaces: Record<string, Record<string, boolean>> = {};
    for (const [ns, claims] of Object.entries(requestedClaims)) {
      nameSpaces[ns] = {};
      for (const claim of claims) {
        nameSpaces[ns][claim] = true;
      }
    }

    const deviceRequestCbor = cborEncode({
      version: "1.0",
      docRequests: [
        {
          docType,
          itemsRequest: {
            nameSpaces,
          },
        },
      ],
    });
    const deviceRequest = base64url.stringify(deviceRequestCbor, {
      pad: false,
    });

    return { encryptionInfo, deviceRequest };
  }

  /**
   * Parse the wallet's `EncryptedResponse` (the decoded CBOR from the
   * base64url-encoded wrapper returned by `navigator.credentials.get()`).
   *
   * The response wrapper format per ISO 18013-7 Annex C is:
   *   EncryptedResponse = ["dcapi", { "enc": bstr, "cipherText": bstr }]
   */
  parseResponse(encryptedResponseB64: string): EncryptedResponseData {
    const bytes = base64url.parse(encryptedResponseB64, { loose: true });
    const decoded = cborDecode(bytes);

    // Expect: ["dcapi", { enc: Uint8Array, cipherText: Uint8Array }]
    if (
      !Array.isArray(decoded) ||
      decoded.length !== 2 ||
      decoded[0] !== "dcapi"
    ) {
      throw new Error(`Unexpected EncryptedResponse format: ${decoded}`);
    }

    const data = decoded[1] as Record<string, unknown>;
    if (
      !(data.enc instanceof Uint8Array) ||
      !(data.cipherText instanceof Uint8Array)
    ) {
      throw new Error(
        "EncryptedResponse missing enc or cipherText byte strings",
      );
    }

    return {
      enc: data.enc,
      cipherText: data.cipherText,
    };
  }

  /**
   * Generate a fresh HPKE key pair and a random nonce for a new DC API transaction.
   * Call this once per verification attempt.
   */
  async prepareTransaction(): Promise<{
    privateKey: Uint8Array;
    publicKeyCoseKey: CoseKey;
    nonce: Uint8Array;
  }> {
    const { privateKey, publicKeyCoseKey } = await generateHpkeKeyPair();
    const nonce = crypto.getRandomValues(new Uint8Array(16));
    this.hpkePrivateKey = privateKey;
    this.nonce = nonce;
    return { privateKey, publicKeyCoseKey, nonce };
  }

  /**
   * HPKE-decrypt the wallet's encrypted response.
   *
   * Uses the private key and nonce stored from `prepareTransaction()`.
   *
   * @returns The decrypted DeviceResponse bytes (CBOR).
   */
  async decryptResponse(data: EncryptedResponseData): Promise<Uint8Array> {
    if (!this.hpkePrivateKey) {
      throw new Error(
        "prepareTransaction() must be called before decryptResponse()",
      );
    }
    return hpkeOpen({
      recipientPrivateKey: this.hpkePrivateKey,
      enc: data.enc,
      cipherText: data.cipherText,
    });
  }

  /**
   * Get the nonce generated during `prepareTransaction()` for verifier binding.
   */
  getNonce(): Uint8Array | null {
    return this.nonce;
  }
}
