//! HPKE (RFC 9180) utilities for ISO 18013-7 Annex C / W3C DC API.
//!
//! Implements HPKE Base mode decryption using the cipher suite required by
//! ISO 18013-7 Annex C:
//! - KEM:  DHKEM(X25519, HKDF-SHA256)
//! - KDF:  HKDF-SHA256
//! - AEAD: AES-128-GCM
//!
//! The browser's Web Crypto API (`SubtleCrypto`) does **not** support the
//! X25519 curve natively.  This module uses `@noble/curves` (pure JS, no
//! native deps) for X25519 key generation and ECDH.  HKDF and AES-128-GCM
//! use the Web Crypto API (well supported in all modern browsers).
//!
//! ## References
//! - RFC 9180 (HPKE)
//! - EU Age Verification Profile Annex A, §A.5

// @noble/curves uses exports map with .js extension for deep imports.
import { x25519 } from "@noble/curves/ed25519.js";

// ============================================================================
// Types
// ============================================================================

/** COSE_Key structure for X25519 (kty: 1 = OKP, crv: 4 = X25519). */
export interface CoseKey {
  kty: number;
  crv: number;
  x: Uint8Array;
}

/** Parameters for HPKE decryption (Base mode). */
export interface HpkeDecryptParams {
  /** The recipient's X25519 private key (32 raw bytes). */
  recipientPrivateKey: Uint8Array;
  /** The sender's ephemeral public key (32 raw bytes). */
  enc: Uint8Array;
  /** The ciphertext to decrypt (includes 16-byte GCM tag). */
  cipherText: Uint8Array;
}

// ============================================================================
// Constants
// ============================================================================

const HPKE_SUITE_ID = new Uint8Array([
  0x4b,
  0x45,
  0x4d,
  0x00, // "KEM\0"
  0x00,
  0x20, // KEM ID: 0x0020 = DHKEM(X25519, HKDF-SHA256)
  0x00,
  0x01, // KDF ID: 0x0001 = HKDF-SHA256
  0x00,
  0x01, // AEAD ID: 0x0001 = AES-128-GCM
]);

const LABEL_SHARED_SECRET = new Uint8Array([
  0x73, 0x68, 0x61, 0x72, 0x65, 0x64, 0x5f, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74,
]); // "shared_secret"
const LABEL_KEY = new Uint8Array([0x6b, 0x65, 0x79]); // "key"
const LABEL_BASE_NONCE = new Uint8Array([
  0x62, 0x61, 0x73, 0x65, 0x5f, 0x6e, 0x6f, 0x6e, 0x63, 0x65,
]); // "base_nonce"

// ============================================================================
// Helper: cast Uint8Array to BufferSource for Web Crypto API
// ============================================================================

/**
 * @noble/curves returns `Uint8Array<ArrayBufferLike>` which is not assignable
 * to Web Crypto's `BufferSource`.  This helper strips the generic by
 * constructing a plain `Uint8Array` with a concrete `ArrayBuffer`.
 */
function toBuf(a: Uint8Array): BufferSource {
  // Copy into a plain Uint8Array backed by a concrete ArrayBuffer,
  // then widen to BufferSource.  The double-cast bypasses TS6's strict
  // generic constraint on Uint8Array<ArrayBufferLike>.
  return new Uint8Array(a) as unknown as BufferSource;
}

// ============================================================================
// Public API
// ============================================================================

/**
 * Generate an X25519 HPKE key pair via @noble/curves.
 *
 * Returns the private key as 32 raw bytes and the public key in COSE_Key
 * format for the `encryptionInfo` CBOR blob.
 */
export async function generateHpkeKeyPair(): Promise<{
  privateKey: Uint8Array;
  publicKeyCoseKey: CoseKey;
}> {
  const privKey = x25519.utils.randomSecretKey();
  const pubKey = x25519.getPublicKey(privKey);

  const coseKey: CoseKey = {
    kty: 1, // OKP
    crv: 4, // X25519
    x: pubKey,
  };

  return { privateKey: privKey, publicKeyCoseKey: coseKey };
}

/**
 * HPKE Base mode decryption.
 *
 * DHKEM(X25519, HKDF-SHA256) + AES-128-GCM per ISO 18013-7 Annex C.
 */
export async function hpkeOpen(params: HpkeDecryptParams): Promise<Uint8Array> {
  const { recipientPrivateKey, enc, cipherText } = params;

  // 1. ECDH with X25519 via @noble/curves (Web Crypto API does not support X25519).
  const sharedSecret = x25519.getSharedSecret(recipientPrivateKey, enc);

  // 2. HPKE context setup per RFC 9180 §5.1.
  const info = new Uint8Array(0);
  const { key, nonce } = await hpkeContextSetup(sharedSecret, info);

  // 3. AES-128-GCM decrypt via Web Crypto API.
  // Ensure inputs are proper ArrayBuffer-based for Web Crypto API.
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: toBuf(nonce), tagLength: 128 },
    key,
    toBuf(cipherText),
  );

  return new Uint8Array(plaintext);
}

// ============================================================================
// Internal HPKE helpers (RFC 9180 §4, §5.1)
// ============================================================================

async function hpkeContextSetup(
  sharedSecret: Uint8Array,
  info: Uint8Array,
): Promise<{ key: CryptoKey; nonce: Uint8Array }> {
  const infoHash = await sha256(info);
  const contextId = concatBuffers(HPKE_SUITE_ID, new Uint8Array(infoHash));

  // labeled_extract(salt, label, ikm) = Extract(salt, labeled_ikm)
  const secret = await hkdfExtract(
    new Uint8Array(0),
    LABEL_SHARED_SECRET,
    sharedSecret,
  );

  // labeled_expand(prk, label, info, L)
  const keyBytes = await hkdfExpand(secret, LABEL_KEY, contextId, 16);

  const key = await crypto.subtle.importKey(
    "raw",
    toBuf(keyBytes),
    { name: "AES-GCM" },
    false,
    ["decrypt"],
  );

  const baseNonce = await hkdfExpand(secret, LABEL_BASE_NONCE, contextId, 12);

  return { key, nonce: baseNonce };
}

/** labeled_extract from RFC 9180 §4. */
async function hkdfExtract(
  salt: Uint8Array,
  label: Uint8Array,
  ikm: Uint8Array,
): Promise<Uint8Array> {
  const labeledIkm = concatBuffers(
    new Uint8Array([0x48, 0x50, 0x4b, 0x45, 0x2d, 0x76, 0x31]), // "HPKE-v1"
    HPKE_SUITE_ID,
    label,
    ikm,
  );

  const hmacSalt = salt.length > 0 ? salt : new Uint8Array(32);
  const key = await crypto.subtle.importKey(
    "raw",
    toBuf(hmacSalt),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const prk = await crypto.subtle.sign("HMAC", key, toBuf(labeledIkm));
  return new Uint8Array(prk);
}

/** labeled_expand from RFC 9180 §4. */
async function hkdfExpand(
  prk: Uint8Array,
  label: Uint8Array,
  info: Uint8Array,
  length: number,
): Promise<Uint8Array> {
  const lengthBytes = new Uint8Array(2);
  lengthBytes[0] = (length >> 8) & 0xff;
  lengthBytes[1] = length & 0xff;

  const labeledInfo = concatBuffers(
    lengthBytes,
    new Uint8Array([0x48, 0x50, 0x4b, 0x45, 0x2d, 0x76, 0x31]),
    HPKE_SUITE_ID,
    label,
    info,
  );

  const key = await crypto.subtle.importKey(
    "raw",
    toBuf(prk),
    { name: "HKDF" },
    false,
    ["deriveBits"],
  );
  const derived = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(0),
      info: toBuf(labeledInfo),
    },
    key,
    length * 8,
  );

  return new Uint8Array(derived);
}

// ============================================================================
// Utilities
// ============================================================================

async function sha256(data: Uint8Array): Promise<ArrayBuffer> {
  return crypto.subtle.digest("SHA-256", toBuf(data));
}

function concatBuffers(...buffers: Uint8Array[]): Uint8Array {
  const totalLength = buffers.reduce((sum, b) => sum + b.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const buf of buffers) {
    result.set(buf, offset);
    offset += buf.length;
  }
  return result;
}
