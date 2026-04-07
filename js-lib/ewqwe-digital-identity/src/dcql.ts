/**
 * @ewqwe/digital-identity — DCQL Query Utilities
 *
 * Functions to build, parse, and convert DCQL (Digital Credentials Query Language)
 * queries for EU Age Verification and OpenID4VP presentations.
 *
 * Browser-compatible — no server-side APIs.
 *
 * @see https://openid.net/specs/openid-4-verifiable-presentations-1_0.html §6–7
 * @see https://ageverification.dev/Technical%20Specification/annexes/annex-A/annex-A-av-profile
 */

import type { CredentialType, InitTransactionRequest } from "./types.ts";
import { CREDENTIAL_TYPES } from "./config.ts";

// =============================================================================
// Constants — Namespaces and Document Types
// =============================================================================

/** EU Age Verification namespace. */
export const EU_AV_NAMESPACE = "eu.europa.ec.av.1";

/** EU Age Verification mDoc document type. */
export const EU_AV_DOCTYPE = "eu.europa.ec.av.1.mdoc";

/** ISO 18013-5 mDL namespace. */
export const ISO_MDL_NAMESPACE = "org.iso.18013.5.1";

/** ISO 18013-5 mDL document type. */
export const ISO_MDL_DOCTYPE = "org.iso.18013.5.1.mDL";

/** EU PID namespace. */
export const EU_PID_NAMESPACE = "eu.europa.ec.eudi.pid.1";

/** EU PID document type. */
export const EU_PID_DOCTYPE = "eu.europa.ec.eudi.pid.1";

// ============================================================================
// DCQL (Digital Credentials Query Language) — OpenID4VP 1.0 §6
// ============================================================================

/** A single claim constraint in a DCQL credential query. */
export interface DCQLClaimsQuery {
  /** Claim identifier (for referencing in claim_sets). */
  id?: string;
  /** Path to the claim — e.g. ["age_over_18"] for mso_mdoc. */
  path: string[];
  /** Namespace for mso_mdoc claims (e.g. "eu.europa.ec.av.1"). */
  namespace?: string;
  /** Expected values — if provided, claim must match one of these. */
  values?: unknown[];
  /** Whether to retain this claim after verification. */
  intent_to_retain?: boolean;
}

/**
 * A single credential query in DCQL.
 *
 * Format identifiers per the OpenID4VP 1.0 spec (Appendix B):
 * - `"mso_mdoc"` — ISO/IEC 18013-5 Mobile Documents (§B.2)
 * - `"dc+sd-jwt"` — IETF SD-JWT VC (§B.3), canonical since Nov 2024
 *   (was `"vc+sd-jwt"` before Nov 2024; both SHOULD be accepted per
 *   draft-ietf-oauth-sd-jwt-vc-08 §3.2.1)
 * - `"jwt_vc_json"` — W3C VC signed as JWT (§B.1.3.1)
 * - `"ldp_vc"` — W3C VC with Linked Data Proofs (§B.1.3.2)
 *
 * @see https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B
 * @see https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-08.html#section-3.2.1
 */
export interface DCQLCredentialQuery {
  /** Unique identifier for this credential query. */
  id: string;
  /**
   * Credential format identifier.
   *
   * `"mso_mdoc"` is for ISO/IEC 18013-5 Mobile Documents (mDL/mDoc).
   *
   * `"sd-jwt"` formats are for IETF SD-JWT Verifiable Credentials.  The current
   * IANA-registered identifier for SD-JWT VC is `"dc+sd-jwt"` (application/dc+sd-jwt),
   * which is the canonical name to use going forward. The older `"vc+sd-jwt"`
   * SHOULD also be accepted during the transitional period per draft-ietf-oauth-sd-jwt-vc-08 §3.2.1.
   *
   * `"jwt_vc_json"` is for W3C Verifiable Credentials signed as JWT without JSON-LD.
   *
   * `"ldp_vc"` is for W3C Verifiable Credentials with Linked Data Proofs.
   */
  format: "mso_mdoc" | "dc+sd-jwt" | "vc+sd-jwt" | "jwt_vc_json" | "ldp_vc";
  /** Format-specific metadata. */
  meta?: {
    /** Document type for mso_mdoc (e.g. "org.iso.18013.5.1.mDL"). */
    doctype_value?: string;
    /** Verifiable Credential Type values for dc+sd-jwt / vc+sd-jwt. */
    vct_values?: string[];
    /** Type values for jwt_vc_json / ldp_vc. */
    type_values?: string[][];
  };
  /** Claims to request from the credential. */
  claims?: DCQLClaimsQuery[];
  /** Named subsets of claims; the wallet picks one set. */
  claim_sets?: string[][];
  /** Allow the wallet to return multiple matching credentials. */
  multiple?: boolean;
  /** Require cryptographic holder binding in the presentation. */
  require_cryptographic_holder_binding?: boolean;
}

/** A credential set defining alternatives (OR logic). */
export interface DCQLCredentialSetQuery {
  /** Which credential query options satisfy this set. */
  options: string[][];
  /** Whether this credential set is required (default: true). */
  required?: boolean;
  /** Human-readable purpose for this credential set. */
  purpose?: string;
}

/** The complete DCQL query structure — OpenID4VP 1.0 §6. */
export interface DCQLQuery {
  /** Array of credential queries. */
  credentials: DCQLCredentialQuery[];
  /** Optional credential sets for defining alternatives. */
  credential_sets?: DCQLCredentialSetQuery[];
}

// =============================================================================
// Query Builder Functions
// =============================================================================

/**
 * Build a minimal age verification query using the EU AV profile.
 *
 * @param ageThreshold - The age threshold to verify (e.g. 18, 21)
 * @returns DCQL query requesting age_over_N = true
 */
export function buildAgeVerificationQuery(
  ageThreshold: number = 18,
): DCQLQuery {
  const claimName = `age_over_${ageThreshold}`;
  return {
    credentials: [
      {
        id: "eu_av_proof",
        format: "mso_mdoc",
        meta: { doctype_value: EU_AV_DOCTYPE },
        claims: [
          {
            path: [claimName],
            namespace: EU_AV_NAMESPACE,
            values: [true],
            intent_to_retain: false,
          },
        ],
      },
    ],
  };
}

/**
 * Build an age verification query with mDL fallback.
 *
 * Uses credential_sets to allow either EU AV proof OR mDL.
 *
 * @param ageThreshold - The age threshold to verify (e.g., 18, 21)
 * @returns DCQL query with EU AV primary and mDL fallback
 */
export function buildAgeVerificationQueryWithFallback(
  ageThreshold: number = 18,
): DCQLQuery {
  const claimName = `age_over_${ageThreshold}`;
  return {
    credentials: [
      {
        id: "eu_av_proof",
        format: "mso_mdoc",
        meta: { doctype_value: EU_AV_DOCTYPE },
        claims: [
          {
            path: [claimName],
            namespace: EU_AV_NAMESPACE,
            values: [true],
            intent_to_retain: false,
          },
        ],
      },
      {
        id: "mdl_fallback",
        format: "mso_mdoc",
        meta: { doctype_value: ISO_MDL_DOCTYPE },
        claims: [
          {
            path: [claimName],
            namespace: ISO_MDL_NAMESPACE,
            values: [true],
            intent_to_retain: false,
          },
        ],
      },
    ],
    credential_sets: [
      {
        options: [["eu_av_proof"], ["mdl_fallback"]],
        required: true,
      },
    ],
  };
}

/**
 * Default DCQL query requesting age_over_18 from EU PID.
 */
export function getDefaultAgeVerificationDCQL(): DCQLQuery {
  return {
    credentials: [
      {
        id: "eu-pid-age-verification",
        format: "mso_mdoc",
        meta: { doctype_value: EU_PID_DOCTYPE },
        claims: [{ path: [EU_PID_NAMESPACE, "age_over_18"] }],
      },
    ],
  };
}

/**
 * Build an `InitTransactionRequest` directly from a credential type and
 * selected claims — the canonical way to initialize an OpenID4VP transaction.
 *
 * Builds a **DCQL query** directly (never a legacy `PresentationDefinition`),
 * so no server-side conversion is required.
 *
 * @param publicUrl - The public URL the wallet is going to call back to
 * @param credentialType - The type of credential to request
 * @param selectedClaims - Array of claim IDs to include (e.g. `["age_over_18"]`)
 * @returns `InitTransactionRequest` ready to POST to `/api/openid4vp/init`
 */
export function buildInitTransactionRequest(
  publicUrl: string,
  credentialType: CredentialType,
  selectedClaims: string[],
): InitTransactionRequest {
  const config = CREDENTIAL_TYPES[credentialType];
  if (!config) {
    throw new Error(`Unknown credential type: ${credentialType}`);
  }

  // Build DCQL Claims Path Pointers: [namespace, element] per OpenID4VP §7.2
  const claims: DCQLClaimsQuery[] = selectedClaims.map((claimId) => ({
    id: claimId,
    path: [config.namespace, claimId],
    intent_to_retain: false,
  }));

  const dcqlQuery: DCQLQuery = {
    credentials: [
      {
        id: `${credentialType}_credential`,
        format: "mso_mdoc",
        meta: { doctype_value: config.docType },
        claims,
      },
    ],
  };

  return {
    public_url: publicUrl,
    dcql_query: dcqlQuery,
    nonce: generateNonce(),
    credential_type: credentialType,
    client_metadata: {
      client_name: "ewQwe Digital Credentials Demo",
      // COSE algorithm integer IDs (RFC 8152 / IANA COSE Algorithms):
      // ES256=-7, ES384=-35, ES512=-36 — per OpenID4VP §B.2.2
      vp_formats: {
        mso_mdoc: {
          issuerauth_alg_values: [-7, -35, -36],
          deviceauth_alg_values: [-7, -35, -36],
        },
      },
    },
  };
}

/**
 * Determine the protocol profile based on credential type or explicit selection.
 *
 * - mDL and PID → HAIP (x509_san_dns, JAR signing, eudi-openid4vp://)
 * - Proof of Age → Annex A (redirect_uri, plain request, av://)
 */
export function determineProfile(
  credentialType?: string,
  explicitProfile?: "haip" | "annex-a",
): "haip" | "annex-a" {
  if (explicitProfile) return explicitProfile;
  if (credentialType === "proof-of-age") return "annex-a";
  return "haip";
}

// =============================================================================
// Query Utility Functions
// =============================================================================

/**
 * Generate a cryptographically secure nonce for OpenID4VP requests.
 *
 * @returns Base64URL-encoded random nonce
 */
export function generateNonce(): string {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return btoa(String.fromCharCode(...array))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

/**
 * Parse a DCQL query from a string (typically from URL parameters).
 *
 * @param queryString - JSON string containing DCQL query
 * @returns Parsed DCQL query or null if invalid
 */
export function parseDCQLQuery(queryString: string): DCQLQuery | null {
  try {
    return JSON.parse(queryString) as DCQLQuery;
  } catch {
    return null;
  }
}

/**
 * Extract the age threshold from a DCQL query.
 *
 * @param query - DCQL query to analyze
 * @returns Age threshold (e.g. 18, 21) or null if not an age verification query
 */
export function extractAgeThreshold(query: DCQLQuery): number | null {
  for (const credential of query.credentials) {
    for (const claim of credential.claims ?? []) {
      const path = claim.path[0];
      const match = path?.match(/^age_over_(\d+)$/);
      if (match) {
        return parseInt(match[1], 10);
      }
    }
  }
  return null;
}

/**
 * Build an OpenID4VP authorization request URL for same-device flow.
 */
export function buildAuthorizationRequest(params: {
  rpDomain: string;
  redirectUri: string;
  ageThreshold?: number;
  nonce?: string;
  state?: string;
}): Record<string, string> {
  const nonce = params.nonce ?? generateNonce();
  const state = params.state ?? generateNonce();
  const query = buildAgeVerificationQuery(params.ageThreshold ?? 18);

  return {
    client_id: `redirect_uri:${params.redirectUri}`,
    response_type: "vp_token",
    response_mode: "fragment",
    nonce,
    state,
    redirect_uri: params.redirectUri,
    dcql_query: JSON.stringify(query),
  };
}

/**
 * Build an OpenID4VP authorization request for cross-device flow.
 */
export function buildCrossDeviceAuthorizationRequest(params: {
  rpDomain: string;
  responseUri: string;
  ageThreshold?: number;
  nonce?: string;
  state?: string;
}): Record<string, string> {
  const nonce = params.nonce ?? generateNonce();
  const state = params.state ?? generateNonce();
  const query = buildAgeVerificationQueryWithFallback(
    params.ageThreshold ?? 18,
  );

  return {
    client_id: `x509_san_dns:${params.rpDomain}`,
    response_type: "vp_token",
    response_mode: "direct_post",
    nonce,
    state,
    response_uri: params.responseUri,
    dcql_query: JSON.stringify(query),
  };
}
