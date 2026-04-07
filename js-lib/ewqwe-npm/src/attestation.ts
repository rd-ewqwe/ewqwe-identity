/**
 * Attestation JWT parsing and verification utilities.
 *
 * Browser- and Node-compatible — uses the Web Crypto API only (SubtleCrypto).
 *
 * @module
 */

// ============================================================================
// Types
// ============================================================================

/**
 * Decoded payload of a credential verification attestation JWT.
 *
 * Standard JWT claims are typed; all credential-specific claims (e.g.
 * `age_over_18`, `given_name`) are accessible via index signature because they
 * are format-agnostic and defined by the credential schema, not this library.
 */
export interface Attestation {
  /** Issuer — credential verifier identifier. */
  iss: string;
  /** Subject — transaction / attestation event ID. */
  sub: string;
  /** Audience — relying party identifier (client_id). */
  aud: string;
  /** Expiration time (Unix timestamp seconds). */
  exp: number;
  /** Issued at (Unix timestamp seconds). */
  iat: number;
  /** Not before (Unix timestamp seconds). */
  nbf: number;
  /** Unique attestation ID (UUID). */
  jti: string;
  /** Nonce from the OpenID4VP request (replay prevention). */
  nonce?: string;
  /** Credential doc_type (e.g. `"org.iso.18013.5.1.mDL"`). */
  doc_type?: string;
  /** Credential namespace (e.g. `"org.iso.18013.5.1"`). */
  namespace?: string;
  /** All credential-specific claims, keyed by claim name. */
  [key: string]: unknown;
}

// ============================================================================
// Internal helpers
// ============================================================================

/**
 * Base64url-decode a string to a Uint8Array.
 * Handles the standard base64url alphabet (no padding required).
 */
export function base64urlDecode(input: string): Uint8Array {
  // Restore padding and convert base64url → base64
  const base64 = input.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64.padEnd(
    base64.length + ((4 - (base64.length % 4)) % 4),
    "=",
  );

  if (typeof atob === "function") {
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(padded, "base64"));
  }

  throw new Error("No base64 decoder available in this runtime");
}

function getSubtleCrypto(): SubtleCrypto {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    throw new Error("Web Crypto API is not available in this runtime");
  }
  return subtle;
}

function splitJwt(jwt: string): [string, string, Uint8Array] {
  const parts = jwt.split(".");
  if (parts.length !== 3) {
    throw new Error("Invalid JWT: expected 3 dot-separated parts");
  }
  const [headerB64, payloadB64, sigB64] = parts;
  const signature = base64urlDecode(sigB64);
  return [headerB64, payloadB64, signature];
}

function decodePayload(payloadB64: string): Attestation {
  const json = new TextDecoder().decode(base64urlDecode(payloadB64));
  return JSON.parse(json) as Attestation;
}

// ============================================================================
// PEM / SPKI import
// ============================================================================

/**
 * Import an ES256 (ECDSA P-256) public key for attestation signature verification.
 *
 * Accepts either:
 * - A raw SPKI DER encoded as a base64 string (no headers), or
 * - A PEM-encoded SubjectPublicKeyInfo certificate (`-----BEGIN PUBLIC KEY-----`), or
 * - A PEM-encoded X.509 certificate (`-----BEGIN CERTIFICATE-----`): the Subject
 *   Public Key Info is automatically extracted from the TBSCertificate.
 */
export function importVerifierPublicKey(pemOrSpki: string): Promise<CryptoKey> {
  const trimmed = pemOrSpki.trim();

  let spkiDer: ArrayBuffer;

  if (trimmed.startsWith("-----BEGIN CERTIFICATE-----")) {
    // X.509 certificate: extract SPKI from TBSCertificate
    const b64 = trimmed
      .replace(/-----BEGIN CERTIFICATE-----/, "")
      .replace(/-----END CERTIFICATE-----/, "")
      .replace(/\s+/g, "");
    const certDer = base64urlDecode(b64.replace(/\+/g, "+").replace(/\//g, "/"))
      .buffer as ArrayBuffer;
    spkiDer = extractSpkiFromCert(certDer);
  } else if (trimmed.startsWith("-----BEGIN PUBLIC KEY-----")) {
    const b64 = trimmed
      .replace(/-----BEGIN PUBLIC KEY-----/, "")
      .replace(/-----END PUBLIC KEY-----/, "")
      .replace(/\s+/g, "");
    spkiDer = base64urlDecode(b64.replace(/\+/g, "+").replace(/\//g, "/"))
      .buffer as ArrayBuffer;
  } else {
    // Assume raw base64 (not base64url) SPKI DER
    const b64 = trimmed.replace(/\s+/g, "");
    spkiDer = base64urlDecode(b64.replace(/\+/g, "+").replace(/\//g, "/"))
      .buffer as ArrayBuffer;
  }

  return getSubtleCrypto().importKey(
    "spki",
    spkiDer,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
}

/**
 * Minimal DER parser: walk the certificate DER to extract the SubjectPublicKeyInfo.
 *
 * The ASN.1 structure is:
 *   Certificate SEQUENCE {
 *     TBSCertificate SEQUENCE {
 *       ... fields ...
 *       subjectPublicKeyInfo SEQUENCE { algorithm, subjectPublicKey }
 *       ...
 *     }
 *     ...
 *   }
 *
 * We locate the SPKI by finding the AlgorithmIdentifier OID for id-ecPublicKey
 * (1.2.840.10045.2.1) inside the TBSCertificate and backing up to its containing
 * SEQUENCE, which is the SPKI.
 */
function extractSpkiFromCert(der: ArrayBuffer): ArrayBuffer {
  const bytes = new Uint8Array(der);

  // OID for id-ecPublicKey: 1.2.840.10045.2.1 → hex 2a 86 48 ce 3d 02 01
  const EC_OID = new Uint8Array([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]);

  // Search for the OID bytes
  outer: for (let i = 0; i < bytes.length - EC_OID.length; i++) {
    for (let j = 0; j < EC_OID.length; j++) {
      if (bytes[i + j] !== EC_OID[j]) continue outer;
    }
    // Found OID at offset i. It is wrapped as: 06 <len> <oid bytes>
    // The containing SEQUENCE (AlgorithmIdentifier) starts just before with 30 <len>.
    // The SPKI SEQUENCE wraps that AlgorithmIdentifier.
    // Back up past: OID tag (1) + OID length byte (1) = we're already at OID content,
    // so the OID TLV starts at i-2.
    const oidTlvStart = i - 2;
    // AlgorithmIdentifier SEQUENCE starts before that
    const algIdStart = oidTlvStart - 2; // tag(1) + len(1) — works for short lengths
    if (algIdStart < 2) continue;
    // SPKI SEQUENCE is the parent; its tag is at algIdStart - 2 (for short-form len)
    // But DER lengths can be multi-byte. Scan backwards for the enclosing SEQUENCE tag.
    const spkiStart = findEnclosingSequence(bytes, algIdStart);
    if (spkiStart < 0) continue;
    const [, spkiEnd] = readTlvBounds(bytes, spkiStart);
    return bytes.slice(spkiStart, spkiEnd).buffer;
  }

  throw new Error(
    "Could not extract SubjectPublicKeyInfo from certificate — EC public key OID not found",
  );
}

/** Return the offset of the SEQUENCE tag that begins at or just before `contentStart`. */
function findEnclosingSequence(
  bytes: Uint8Array,
  contentStart: number,
): number {
  // Walk backwards looking for a 0x30 SEQUENCE tag whose declared length covers contentStart
  for (let i = contentStart - 2; i >= 0; i--) {
    if (bytes[i] !== 0x30) continue;
    try {
      const [bodyStart, end] = readTlvBounds(bytes, i);
      if (bodyStart <= contentStart && contentStart < end) return i;
    } catch {
      // ignore parse errors while scanning
    }
  }
  return -1;
}

/**
 * Parse a DER TLV at `offset`.
 * Returns `[bodyStart, end]` where `end` is the first byte after the TLV.
 */
function readTlvBounds(bytes: Uint8Array, offset: number): [number, number] {
  let pos = offset + 1; // skip tag
  let len: number;
  if (bytes[pos] & 0x80) {
    const numBytes = bytes[pos] & 0x7f;
    len = 0;
    for (let k = 0; k < numBytes; k++) {
      len = (len << 8) | bytes[++pos];
    }
    pos++;
  } else {
    len = bytes[pos++];
  }
  return [pos, pos + len];
}

// ============================================================================
// Public API
// ============================================================================

/**
 * Decode and verify an attestation JWT signed by the credential verifier.
 *
 * Steps:
 * 1. Fetches the JWKS from `jwksUrl`.
 * 2. Locates the verification key using the `kid` from the JWT header (falls back
 *    to the first key carrying an `x5c` certificate chain).
 * 3. Imports the public key from the DER certificate in `x5c[0]`.
 * 4. Verifies the ES256 signature and checks `exp` / `nbf`.
 * 5. Returns the verified {@link Attestation}.
 *
 * @param jwt     - Compact-serialized JWT from `VerifyResponse.attestation`.
 * @param jwksUrl - URL of the JWK Set that contains the attestation signing key,
 *                  e.g. `"/ewqwe_api/openid4vp/.well-known/jwks.json"`.
 * @throws If the JWKS cannot be fetched, no matching key is found, or verification fails.
 */
export async function parseAttestation(
  jwt: string,
  jwksUrl: string,
): Promise<Attestation> {
  // Decode the JWT header to obtain the key ID
  const parts = jwt.split(".");
  if (parts.length !== 3) {
    throw new Error("Invalid JWT: expected 3 dot-separated parts");
  }
  const header = JSON.parse(
    new TextDecoder().decode(base64urlDecode(parts[0])),
  ) as Record<string, unknown>;
  const kid = typeof header.kid === "string" ? header.kid : undefined;

  // Fetch the JWK Set
  const resp = await fetch(jwksUrl);
  if (!resp.ok) {
    throw new Error(
      `Failed to fetch JWKS from ${jwksUrl}: HTTP ${resp.status}`,
    );
  }
  const jwks = (await resp.json()) as { keys?: unknown[] };
  const keys = Array.isArray(jwks.keys) ? jwks.keys : [];

  // Find the matching key: prefer kid match, fall back to first key with x5c
  let jwk: unknown = undefined;
  if (kid !== undefined) {
    jwk = keys.find((k: unknown) => {
      const keyObj = k as Record<string, unknown>;
      return keyObj.kid === kid;
    });
  }
  if (!jwk) {
    jwk = keys.find((k: unknown) => {
      const keyObj = k as Record<string, unknown>;
      return Array.isArray(keyObj.x5c) && keyObj.x5c.length > 0;
    });
  }
  if (!jwk) {
    throw new Error(
      `No suitable attestation verification key found in JWKS${kid !== undefined ? ` for kid="${kid}"` : ""}`,
    );
  }

  const jwkObj = jwk as Record<string, unknown>;
  if (!Array.isArray(jwkObj.x5c) || jwkObj.x5c.length === 0) {
    throw new Error("JWKS attestation key does not include an x5c certificate");
  }

  // x5c values are standard base64-encoded DER (RFC 7517 §4.7).
  // Reconstruct a PEM so importVerifierPublicKey takes the certificate branch
  // and extracts the SubjectPublicKeyInfo via the DER parser.
  const certPem = `-----BEGIN CERTIFICATE-----\n${jwkObj.x5c[0]}\n-----END CERTIFICATE-----`;
  const publicKey = await importVerifierPublicKey(certPem);

  return verifyAttestation(jwt, publicKey);
}

/**
 * Verify an ES256 attestation JWT signature and return the decoded claims.
 *
 * @param jwt - The compact-serialized JWT string.
 * @param publicKey - The verifier's public key, obtained from `importVerifierPublicKey`.
 * @throws If the signature is invalid, the JWT is malformed, or the claims are expired.
 */
export async function verifyAttestation(
  jwt: string,
  publicKey: CryptoKey,
): Promise<Attestation> {
  const [headerB64, payloadB64, signature] = splitJwt(jwt);

  const message = new TextEncoder().encode(`${headerB64}.${payloadB64}`);

  const valid = await getSubtleCrypto().verify(
    { name: "ECDSA", hash: { name: "SHA-256" } },
    publicKey,
    signature.buffer as ArrayBuffer,
    message,
  );

  if (!valid) {
    throw new Error("Attestation JWT signature verification failed");
  }

  const claims = decodePayload(payloadB64);

  const nowSeconds = Math.floor(Date.now() / 1000);
  if (claims.exp !== undefined && claims.exp < nowSeconds) {
    throw new Error(
      `Attestation JWT is expired (exp=${claims.exp}, now=${nowSeconds})`,
    );
  }
  if (claims.nbf !== undefined && claims.nbf > nowSeconds) {
    throw new Error(
      `Attestation JWT is not yet valid (nbf=${claims.nbf}, now=${nowSeconds})`,
    );
  }

  return claims;
}
