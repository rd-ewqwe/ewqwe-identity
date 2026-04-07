/**
 * @ewqwe/identity-backend — Cryptographic Operations
 *
 * PEM parsing, X.509 certificate handling, JAR signing (RFC 9101),
 * and JWE decryption for HAIP direct_post.jwt responses.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9101 (JAR)
 * @see https://www.rfc-editor.org/rfc/rfc7516 (JWE)
 */

import * as jose from "jose";
import type { JarKeyMaterial, JweKeyMaterial } from "./types.ts";

// ============================================================================
// PEM / DER Utilities
// ============================================================================

/** Convert a PEM-encoded key to an ArrayBuffer (DER). */
export function pemToArrayBuffer(pem: string): ArrayBuffer {
  const base64 = pem
    .replace(/-----BEGIN [A-Z ]+-----/g, "")
    .replace(/-----END [A-Z ]+-----/g, "")
    .replace(/\s+/g, "");
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
 * Parse PEM-encoded certificate chain into individual base64-encoded
 * DER certificates suitable for use in the JWT x5c header (RFC 7515 §4.1.6).
 */
export function parsePemCertChain(pemChain: string): string[] {
  const certs: string[] = [];
  const regex =
    /-----BEGIN CERTIFICATE-----\s*([\s\S]*?)\s*-----END CERTIFICATE-----/g;
  let match;
  while ((match = regex.exec(pemChain)) !== null) {
    certs.push(match[1].replace(/\s+/g, ""));
  }
  return certs;
}

/**
 * Extract the SAN DNS name from a base64-encoded DER certificate.
 * Uses ASN.1 pattern matching to find the Subject Alternative Name extension.
 */
export function extractSanDnsFromCert(base64Der: string): string | null {
  const der = Uint8Array.from(atob(base64Der), (c) => c.charCodeAt(0));
  // Search for the SAN OID (2.5.29.17 = 55 1d 11)
  for (let i = 0; i < der.length - 4; i++) {
    if (der[i] === 0x55 && der[i + 1] === 0x1d && der[i + 2] === 0x11) {
      for (let j = i + 3; j < der.length - 2; j++) {
        if (der[j] === 0x82) {
          // tag [2] = dNSName
          const len = der[j + 1];
          if (len > 0 && j + 2 + len <= der.length) {
            const name = new TextDecoder().decode(
              der.slice(j + 2, j + 2 + len),
            );
            if (/^[a-zA-Z0-9.-]+$/.test(name)) {
              return name;
            }
          }
        }
      }
    }
  }
  return null;
}

// ============================================================================
// Key Initialization
// ============================================================================

/**
 * Load the JAR signing key and X.509 certificate chain from PEM files.
 * Returns key material needed for signing JWT Authorization Requests.
 *
 * Uses `Deno.readTextFile` — server-side only.
 */
export async function initializeJarKey(
  certPath: string,
  keyPath: string,
  keyId: string,
): Promise<JarKeyMaterial> {
  // Load certificate chain
  const certPem = await Deno.readTextFile(certPath);
  const x5cChain = parsePemCertChain(certPem);
  if (x5cChain.length === 0) {
    throw new Error(`No certificates found in ${certPath}`);
  }

  // Extract SAN DNS name from leaf certificate
  const sanDns = extractSanDnsFromCert(x5cChain[0]);
  if (!sanDns) {
    throw new Error(
      `Could not extract SAN DNS name from leaf certificate in ${certPath}`,
    );
  }

  // Load private key (extractable for JWK export)
  const keyPem = await Deno.readTextFile(keyPath);
  const ecKey = await crypto.subtle.importKey(
    "pkcs8",
    pemToArrayBuffer(keyPem),
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign"],
  );
  const signingKey = ecKey as unknown as jose.KeyLike;
  const signingKeyJwk = await jose.exportJWK(ecKey);
  signingKeyJwk.kid = keyId;
  signingKeyJwk.use = "sig";
  signingKeyJwk.alg = "ES256";

  return { signingKey, signingKeyJwk, x5cChain, sanDnsName: sanDns, keyId };
}

/**
 * Generate an ECDH P-256 key pair for decrypting JWE responses from wallets.
 * Used when response_mode=direct_post.jwt (HAIP profile).
 */
export async function initializeJweKey(keyId: string): Promise<JweKeyMaterial> {
  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits", "deriveKey"],
  );
  const publicJwk = await jose.exportJWK(keyPair.publicKey);
  publicJwk.kid = keyId;
  publicJwk.use = "enc";
  publicJwk.alg = "ECDH-ES";

  return { decryptionKey: keyPair.privateKey, publicJwk, keyId };
}

// ============================================================================
// JAR Signing
// ============================================================================

export interface JarPayload {
  clientId: string;
  clientIdScheme: string;
  responseMode: string;
  responseUri: string;
  state: string;
  nonce: string;
  dcqlQuery: unknown;
  clientMetadata: unknown;
  expiresAt: number;
}

/**
 * Sign a JWT Authorization Request (JAR) per RFC 9101.
 * Returns the compact JWS string.
 */
export async function signJar(
  payload: JarPayload,
  jarKey: JarKeyMaterial,
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const exp = Math.floor(payload.expiresAt / 1000);

  const jwtPayload = {
    iss: payload.clientId,
    aud: "https://self-issued.me/v2",
    iat: now,
    exp,
    client_id: payload.clientId,
    client_id_scheme: payload.clientIdScheme,
    response_type: "vp_token",
    response_mode: payload.responseMode,
    response_uri: payload.responseUri,
    state: payload.state,
    nonce: payload.nonce,
    dcql_query: payload.dcqlQuery,
    client_metadata: payload.clientMetadata,
  };

  return await new jose.SignJWT(jwtPayload as jose.JWTPayload)
    .setProtectedHeader({
      alg: "ES256",
      typ: "oauth-authz-req+jwt",
      kid: jarKey.keyId,
      x5c: jarKey.x5cChain,
    })
    .sign(jarKey.signingKey);
}

// ============================================================================
// JWE Decryption
// ============================================================================

export interface DecryptedWalletResponse {
  vpToken: string;
  presentationSubmission: string;
  state: string;
}

/**
 * Decrypt a JWE response from the EUDI wallet (direct_post.jwt mode).
 * The JWE may contain a nested JWS or a plain JSON payload.
 */
export async function decryptJweResponse(
  jweCompact: string,
  jweKey: JweKeyMaterial,
): Promise<DecryptedWalletResponse> {
  // Import the ECDH private key for jose
  const privateJwk = await crypto.subtle.exportKey("jwk", jweKey.decryptionKey);
  const privateJwkWithKid: jose.JWK = {
    ...privateJwk,
    kty: privateJwk.kty ?? "EC",
    kid: jweKey.keyId,
  };
  const decryptKey = await jose.importJWK(privateJwkWithKid, "ECDH-ES");

  const { plaintext } = await jose.compactDecrypt(jweCompact, decryptKey);
  const decryptedText = new TextDecoder().decode(plaintext);

  // The decrypted content may be a nested JWS or a plain JSON payload
  let payload: jose.JWTPayload;
  if (decryptedText.split(".").length === 3) {
    // Nested JWS — decode payload without verification
    const jwtParts = decryptedText.split(".");
    const payloadJson = new TextDecoder().decode(
      jose.base64url.decode(jwtParts[1]),
    );
    payload = JSON.parse(payloadJson);
  } else {
    payload = JSON.parse(decryptedText);
  }

  return {
    vpToken: (payload.vp_token as string) || "",
    presentationSubmission: (payload.presentation_submission as string) || "",
    state: (payload.state as string) || "",
  };
}

// ============================================================================
// Public JWKS
// ============================================================================

/**
 * Build the public JWK Set for JAR signature verification.
 */
export function buildPublicJwkSet(jarKey: JarKeyMaterial): {
  keys: jose.JWK[];
} {
  const publicKeyJwk = { ...jarKey.signingKeyJwk };
  delete publicKeyJwk.d; // Remove private component
  publicKeyJwk.kid = jarKey.keyId;
  publicKeyJwk.use = "sig";
  publicKeyJwk.alg = "ES256";
  return { keys: [publicKeyJwk] };
}
