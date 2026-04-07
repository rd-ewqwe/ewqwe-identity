/**
 * DCQL (Digital Credentials Query Language) utilities for EU Age Verification.
 *
 * This module provides functions to build DCQL queries according to the
 * EU Age Verification Profile and OpenID4VP 1.0 specifications.
 *
 * @see https://ageverification.dev/Technical%20Specification/annexes/annex-A/annex-A-av-profile
 * @see https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
 */

// =============================================================================
// DCQL Type Definitions
// =============================================================================

/** A single claim constraint in a DCQL credential query */
export interface DCQLClaimQuery {
  /** Path to the claim in the namespace (e.g., ["age_over_18"]) */
  path: string[];
  /** Optional identifier for the claim */
  id?: string;
  /** Namespace containing the claim (e.g., "eu.europa.ec.av.1") */
  namespace?: string;
  /** Expected values - if provided, claim must match one of these */
  values?: unknown[];
  /** Whether to retain this claim after verification */
  intent_to_retain?: boolean;
}

/** A single credential query in DCQL */
export interface DCQLCredentialQuery {
  /** Unique identifier for this credential query */
  id: string;
  /** Document type format identifier */
  format: "mso_mdoc" | "vc+sd-jwt" | "jwt_vp_json";
  /** Additional format-specific metadata */
  meta?: {
    /** Document type for mso_mdoc format (e.g., "eu.europa.ec.av.1.mdoc") */
    doctype_value?: string;
  };
  /** Claims to request from the credential */
  claims?: DCQLClaimQuery[];
}

/** A credential set defining alternatives (OR logic) */
export interface DCQLCredentialSet {
  /** Which credential query options satisfy this set */
  options: string[][];
  /** Whether all credentials in an option are required */
  required?: boolean;
}

/** The complete DCQL query structure */
export interface DCQLQuery {
  /** Array of credential queries */
  credentials: DCQLCredentialQuery[];
  /** Optional credential sets for defining alternatives */
  credential_sets?: DCQLCredentialSet[];
}

// =============================================================================
// Constants - Namespaces and Document Types
// =============================================================================

/** EU Age Verification namespace */
export const EU_AV_NAMESPACE = "eu.europa.ec.av.1";

/** EU Age Verification mDoc document type */
export const EU_AV_DOCTYPE = "eu.europa.ec.av.1.mdoc";

/** ISO 18013-5 mDL namespace */
export const ISO_MDL_NAMESPACE = "org.iso.18013.5.1";

/** ISO 18013-5 mDL document type */
export const ISO_MDL_DOCTYPE = "org.iso.18013.5.1.mDL";

// =============================================================================
// Query Builder Functions
// =============================================================================

/**
 * Build a minimal age verification query using EU AV profile.
 *
 * @param ageThreshold - The age threshold to verify (e.g., 18, 21)
 * @returns DCQL query for age_over claim
 *
 * @example
 * ```typescript
 * const query = buildAgeVerificationQuery(18);
 * // Returns query requesting age_over_18 = true
 * ```
 */
export function buildAgeVerificationQuery(ageThreshold: number = 18): DCQLQuery {
  const claimName = `age_over_${ageThreshold}`;

  return {
    credentials: [
      {
        id: "eu_av_proof",
        format: "mso_mdoc",
        meta: {
          doctype_value: EU_AV_DOCTYPE,
        },
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
 * Uses credential_sets to allow either EU AV proof OR mDL
 * (useful when user may have either credential type).
 *
 * @param ageThreshold - The age threshold to verify (e.g., 18, 21)
 * @returns DCQL query with EU AV primary and mDL fallback
 *
 * @example
 * ```typescript
 * const query = buildAgeVerificationQueryWithFallback(18);
 * // Accepts either EU AV proof OR mDL with age_over_18
 * ```
 */
export function buildAgeVerificationQueryWithFallback(
  ageThreshold: number = 18
): DCQLQuery {
  const claimName = `age_over_${ageThreshold}`;

  return {
    credentials: [
      // Primary: EU Age Verification
      {
        id: "eu_av_proof",
        format: "mso_mdoc",
        meta: {
          doctype_value: EU_AV_DOCTYPE,
        },
        claims: [
          {
            path: [claimName],
            namespace: EU_AV_NAMESPACE,
            values: [true],
            intent_to_retain: false,
          },
        ],
      },
      // Fallback: ISO mDL
      {
        id: "mdl_fallback",
        format: "mso_mdoc",
        meta: {
          doctype_value: ISO_MDL_DOCTYPE,
        },
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
 * Build an OpenID4VP authorization request for same-device flow.
 *
 * @param params - Request parameters
 * @returns Complete authorization request URL parameters
 *
 * @example
 * ```typescript
 * const request = buildAuthorizationRequest({
 *   rpDomain: "shop.example.com",
 *   redirectUri: "https://shop.example.com/callback",
 *   ageThreshold: 18,
 * });
 * ```
 */
export function buildAuthorizationRequest(params: {
  /** Relying party domain or client identifier */
  rpDomain: string;
  /** Redirect URI for response (same-device flow) */
  redirectUri: string;
  /** Age threshold to verify */
  ageThreshold?: number;
  /** Custom nonce (auto-generated if not provided) */
  nonce?: string;
  /** Session state for correlation */
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
 *
 * @param params - Request parameters
 * @returns Complete authorization request for cross-device flow
 *
 * @example
 * ```typescript
 * const request = buildCrossDeviceAuthorizationRequest({
 *   rpDomain: "shop.example.com",
 *   responseUri: "https://shop.example.com/response",
 *   ageThreshold: 21,
 * });
 * ```
 */
export function buildCrossDeviceAuthorizationRequest(params: {
  /** Relying party domain */
  rpDomain: string;
  /** URI where wallet will POST the VP token */
  responseUri: string;
  /** Age threshold to verify */
  ageThreshold?: number;
  /** Custom nonce (auto-generated if not provided) */
  nonce?: string;
  /** Session state for correlation */
  state?: string;
}): Record<string, string> {
  const nonce = params.nonce ?? generateNonce();
  const state = params.state ?? generateNonce();
  const query = buildAgeVerificationQueryWithFallback(params.ageThreshold ?? 18);

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

// =============================================================================
// Utility Functions
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
 * @returns Age threshold (e.g., 18, 21) or null if not an age verification query
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
