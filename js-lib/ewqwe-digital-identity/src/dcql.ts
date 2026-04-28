/**
 * @ewqwe/digital-identity — DCQL Query Utilities
 *
 * Functions to build, parse, and convert DCQL (Digital Credentials Query Language)
 * queries for EU Age Verification and OpenID4VP presentations.
 *
 * Node.js compatible — uses Node.js crypto API.
 *
 * @see https://openid.net/specs/openid-4-verifiable-presentations-1_0.html §6–7
 * @see https://ageverification.dev/Technical%20Specification/annexes/annex-A/annex-A-av-profile
 */

import type {
  CredentialType,
  InitTransactionRequest,
  VpFormats,
} from "./types.js";
import { CREDENTIAL_TYPES } from "./config.js";

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

/**
 * A single entry in `trusted_authorities` — identifies an authority or trust framework
 * that certifies credential issuers the Verifier will accept.
 *
 * A Credential matches if it satisfies **at least one** entry in the array.
 *
 * Type identifiers defined by OpenID4VP 1.0 §6.1.1:
 * - `"aki"` — X.509 Authority Key Identifier, base64url-encoded (§6.1.1.1)
 * - `"etsi_tl"` — ETSI Trusted List identifier (§6.1.1.2)
 * - `"openid_federation"` — OpenID Federation Entity Identifier (§6.1.1.3)
 *
 * @see https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1
 */
export interface TrustedAuthoritiesQuery {
  /** Type identifier for the trust framework. */
  type: "aki" | "etsi_tl" | "openid_federation" | string;
  /** Non-empty array of values interpreted according to `type`. */
  values: string[];
}

/** A single claim constraint in a DCQL credential query. */
export interface DCQLClaimsQuery {
  /** Claim identifier (for referencing in claim_sets). */
  id?: string;
  /**
   * Claims Path Pointer (OpenID4VP 1.0 §7).
   *
   * A **non-empty** array whose elements must be:
   * - `string` — navigate into the named key of an object (§7.1)
   * - `number` (non-negative integer) — select the element at this index in an array (§7.1)
   * - `null` — select **all** elements of the currently selected array(s) (§7.1)
   *
   * For `mso_mdoc` credentials (§7.2) exactly two strings are required:
   * `[namespace, dataElementIdentifier]`.
   *
   * Examples from §7.3:
   * - `["address", "street_address"]` — nested object key
   * - `["degrees", null, "type"]` — all `type` values across the `degrees` array
   * - `["nationalities", 1]` — second element of the `nationalities` array
   */
  path: (string | number | null)[];
  /** Expected values — if provided, claim must match one of these (§6.3). */
  values?: (string | number | boolean)[];
  /** Whether to retain this claim after verification (mso_mdoc only, §B.2.4). */
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
  /**
   * Expected authorities or trust frameworks that certify issuers the Verifier will accept.
   *
   * OPTIONAL non-empty array. Every Credential returned by the Wallet SHOULD match at least
   * one of the conditions. The Verifier still bears its own responsibility to verify issuer
   * trust; this field is a hint to the Wallet to avoid sending credentials likely to be
   * rejected. See §6.1.1 for matching semantics per type.
   *
   * @see https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1
   */
  trusted_authorities?: TrustedAuthoritiesQuery[];
  /**
   * Require cryptographic holder binding in the presentation.
   *
   * OPTIONAL. Default is `true` per §6.1 — a Verifiable Presentation with Cryptographic
   * Holder Binding is required unless explicitly set to `false`.
   */
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
            path: [EU_AV_NAMESPACE, claimName],
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
            path: [EU_AV_NAMESPACE, claimName],
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
            path: [ISO_MDL_NAMESPACE, claimName],
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
 * @returns `InitTransactionRequest` ready to POST to `/ewqwe_api/openid4vp/init`
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

  const isSdJwt = config.format === "dc+sd-jwt";

  // Build DCQL Claims Path Pointers:
  // - mso_mdoc: [namespace, element] per OpenID4VP §7.2
  // - dc+sd-jwt: [claimName] per OpenID4VP §B.3 (flat JSON path)
  // Note: `intent_to_retain` is an mso_mdoc-only field (OpenID4VP §7.2.5).
  // It MUST NOT appear in dc+sd-jwt credential queries.
  const claims: DCQLClaimsQuery[] = selectedClaims.map((claimId) => {
    const query: DCQLClaimsQuery = {
      id: claimId,
      path: isSdJwt ? [claimId] : [config.namespace, claimId],
    };
    if (!isSdJwt) {
      query.intent_to_retain = false;
    }
    return query;
  });

  const credentialQuery: DCQLCredentialQuery = isSdJwt
    ? {
        id: `${credentialType}_credential`,
        format: "dc+sd-jwt",
        meta: { vct_values: [config.vct!] },
        claims,
      }
    : {
        id: `${credentialType}_credential`,
        format: "mso_mdoc",
        meta: { doctype_value: config.docType },
        claims,
      };

  const dcqlQuery: DCQLQuery = {
    credentials: [credentialQuery],
  };

  // Build vp_formats based on the credential format
  const vp_formats: VpFormats = isSdJwt
    ? {
        "dc+sd-jwt": {
          "sd-jwt_alg_values": ["ES256", "ES384", "ES512"],
          "kb-jwt_alg_values": ["ES256", "ES384", "ES512"],
        },
      }
    : {
        mso_mdoc: {
          issuerauth_alg_values: [-7, -35, -36],
          deviceauth_alg_values: [-7, -35, -36],
        },
      };

  return {
    public_url: publicUrl,
    dcql_query: dcqlQuery,
    nonce: generateNonce(),
    credential_type: credentialType,
    client_metadata: {
      client_name: "ewQwe Digital Credentials Demo",
      vp_formats,
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
  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);

  if (typeof btoa === "function") {
    let binary = "";
    for (const byte of bytes) {
      binary += String.fromCharCode(byte);
    }
    return btoa(binary)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");
  }

  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes)
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");
  }

  throw new Error("No base64 encoder available in this runtime");
}

/**
 * Validate the structural rules of a DCQL query per OpenID4VP 1.0 §6 and §6.4.1.
 *
 * Rules enforced:
 *
 * **§6 — Top level**
 * - `credentials` MUST be non-empty.
 * - Credential query `id` values MUST be unique across `credentials`.
 * - `credential_sets`, if present, MUST be non-empty.
 * - Each `credential_sets` option element MUST reference a valid credential query `id`.
 *
 * **§6.1 — Credential Query**
 * - Each credential `id` MUST be a non-empty string of alphanumeric, `-`, or `_`.
 * - `trusted_authorities`, if present, MUST be non-empty.
 *
 * **§6.3 & §6.4.1 — Claims / claim_sets**
 * - `claim_sets` MUST NOT be present when `claims` is absent.
 * - Claim `id` values MUST be unique within a single `claims` array.
 * - When `claim_sets` is present, every claim MUST have a non-empty `id`.
 * - Every identifier referenced in `claim_sets` MUST appear in `claims`.
 *
 * @param query - The DCQL query to validate.
 * @returns An object `{ valid: true }` or `{ valid: false, error: string }`.
 */
export function isValidDCQLQuery(
  query: DCQLQuery,
): { valid: true } | { valid: false; error: string } {
  const err = (msg: string) => ({ valid: false as const, error: msg });
  const idPattern = /^[A-Za-z0-9_-]+$/;

  // §6: credentials MUST be non-empty.
  if (!query.credentials || query.credentials.length === 0) {
    return err("DCQL query 'credentials' must be non-empty");
  }

  const seenCredIds = new Set<string>();
  for (const cred of query.credentials) {
    // §6.1: id must be non-empty alphanumeric/underscore/hyphen.
    if (!cred.id || !idPattern.test(cred.id)) {
      return err(
        `Credential query id ${JSON.stringify(cred.id)} must be a non-empty alphanumeric/underscore/hyphen string`,
      );
    }
    if (seenCredIds.has(cred.id)) {
      return err(`Duplicate credential query id ${JSON.stringify(cred.id)}`);
    }
    seenCredIds.add(cred.id);

    // §6.1.1: trusted_authorities, if present, must be non-empty.
    if (cred.trusted_authorities !== undefined) {
      if (cred.trusted_authorities.length === 0) {
        return err(
          `Credential query ${JSON.stringify(cred.id)}: 'trusted_authorities' must be non-empty when present`,
        );
      }
    }

    // §6.4.1: claim_sets MUST NOT be present if claims is absent.
    if (cred.claim_sets !== undefined && cred.claims === undefined) {
      return err(
        `Credential query ${JSON.stringify(cred.id)}: 'claim_sets' must not be present when 'claims' is absent`,
      );
    }

    if (cred.claims !== undefined) {
      // Claim IDs must be unique within the claims array.
      const seenClaimIds = new Set<string>();
      for (const claim of cred.claims) {
        if (claim.id !== undefined) {
          if (!claim.id || !idPattern.test(claim.id)) {
            return err(
              `Credential query ${JSON.stringify(cred.id)}: claim id ${JSON.stringify(claim.id)} must be a non-empty alphanumeric/underscore/hyphen string`,
            );
          }
          if (seenClaimIds.has(claim.id)) {
            return err(
              `Credential query ${JSON.stringify(cred.id)}: duplicate claim id ${JSON.stringify(claim.id)}`,
            );
          }
          seenClaimIds.add(claim.id);
        }
      }

      if (cred.claim_sets !== undefined) {
        // When claim_sets is present, every claim MUST have an id.
        for (const claim of cred.claims) {
          if (claim.id === undefined) {
            return err(
              `Credential query ${JSON.stringify(cred.id)}: all claims must have an 'id' when 'claim_sets' is present`,
            );
          }
        }
        // Every id in claim_sets must reference a known claim id.
        for (const set of cred.claim_sets) {
          for (const refId of set) {
            if (!seenClaimIds.has(refId)) {
              return err(
                `Credential query ${JSON.stringify(cred.id)}: 'claim_sets' references unknown claim id ${JSON.stringify(refId)}`,
              );
            }
          }
        }
      }
    }
  }

  // §6: credential_sets, if present, must be non-empty and reference valid credential IDs.
  if (query.credential_sets !== undefined) {
    if (query.credential_sets.length === 0) {
      return err("'credential_sets' must be non-empty when present");
    }
    for (const cs of query.credential_sets) {
      for (const optionSet of cs.options) {
        for (const refId of optionSet) {
          if (!seenCredIds.has(refId)) {
            return err(
              `'credential_sets' option references unknown credential query id ${JSON.stringify(refId)}`,
            );
          }
        }
      }
    }
  }

  return { valid: true };
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
      const pathComp = claim.path[claim.path.length - 1];
      if (typeof pathComp !== "string") continue;
      const match = pathComp.match(/^age_over_(\d+)$/);
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
 *
 * Note: When using the HAIP profile with the EUDI Wallet, the client_id should be
 * `x509_hash:<cert_hash>` instead of `x509_san_dns:<domain>` for a direct cryptographic
 * binding to the verifier's certificate. The `x509_san_dns` form is maintained here for
 * legacy compatibility and for deployments that still rely on DNS-based identification.
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
