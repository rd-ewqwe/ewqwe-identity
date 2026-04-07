/**
 * @ewqwe/digital-identity — Protocol & Credential Configuration
 *
 * Defines protocol profiles (HAIP, Annex A), credential type specifications
 * (mDL, PID, Proof of Age), and helper functions for querying them.
 *
 * Browser-compatible — no server-side APIs.
 *
 * @see https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
 * @see https://ageverification.dev/Technical%20Specification/annexes/annex-A/annex-A-av-profile
 * @see ISO/IEC 18013-5:2021 for mDL claims
 */

import type {
  ClaimDefinition,
  CredentialTypeConfig,
  ProfileId,
  ProtocolProfile,
} from "./types.ts";

// =============================================================================
// Protocol Profiles
// =============================================================================

/**
 * Protocol Profile Configurations
 *
 * **HAIP (High Assurance Interoperability Profile):**
 * - Used for: mDL, PID (National ID)
 * - Client ID Scheme: x509_san_dns (X.509 certificate with SAN DNS)
 * - Request Format: JAR (JWT Authorization Request with x5c header)
 * - Response Mode: direct_post.jwt (encrypted/signed response)
 * - URL Schemes: eudi-openid4vp://, openid4vp://
 * - Reference: OpenID4VP HAIP Draft
 *
 * **Annex A (EU Age Verification Profile):**
 * - Used for: Proof of Age attestations
 * - Client ID Scheme: redirect_uri (redirect URI as client identifier)
 * - Request Format: Plain JSON (redirect_uri scheme forbids signed requests)
 * - Response Mode: direct_post (plain VP token)
 * - URL Schemes: av://
 * - Reference: https://ageverification.dev/Technical%20Specification/annexes/annex-A/annex-A-av-profile
 *
 * Note: The key difference is client_id_scheme. HAIP uses x509_san_dns with signed JARs,
 * while Annex A uses redirect_uri with plain JSON (signed requests are explicitly forbidden).
 */
export const PROTOCOL_PROFILES: Record<ProfileId, ProtocolProfile> = {
  haip: {
    id: "haip",
    name: "HAIP Profile",
    description: "High Assurance Interoperability Profile for EUDI Wallet",
    clientIdScheme: "x509_san_dns",
    requestFormat: "jar",
    responseMode: "direct_post.jwt",
    urlSchemes: ["eudi-openid4vp://", "openid4vp://"],
    requiresJarSigning: true,
  },
  "annex-a": {
    id: "annex-a",
    name: "Annex A Profile",
    description: "EU Age Verification Profile for Proof of Age",
    clientIdScheme: "redirect_uri",
    requestFormat: "plain",
    responseMode: "direct_post",
    urlSchemes: ["av://"],
    requiresJarSigning: false,
  },
};

// =============================================================================
// Credential Types
// =============================================================================

/**
 * Credential type configurations based on ISO 18013-5, EU ARF, and EU Age Verification Profile.
 *
 * References:
 * - mDL: ISO/IEC 18013-5:2021
 * - PID: EU ARF Annex 2.02 Topic 3 (PID_04, PID_05)
 * - Proof of Age: EU Age Verification Profile (https://ageverification.dev)
 */
export const CREDENTIAL_TYPES: Record<string, CredentialTypeConfig> = {
  mdl: {
    id: "mdl",
    name: "Mobile Driver's License",
    docType: "org.iso.18013.5.1.mDL",
    namespace: "org.iso.18013.5.1",
    profile: "haip",
    claims: [
      {
        id: "family_name",
        name: "Family Name",
        path: "org.iso.18013.5.1/family_name",
      },
      {
        id: "given_name",
        name: "Given Names",
        path: "org.iso.18013.5.1/given_name",
      },
      {
        id: "birth_date",
        name: "Birth Date",
        path: "org.iso.18013.5.1/birth_date",
      },
      {
        id: "portrait",
        name: "Portrait",
        path: "org.iso.18013.5.1/portrait",
      },
      {
        id: "age_over_21",
        name: "Age Over 21",
        path: "org.iso.18013.5.1/age_over_21",
      },
      {
        id: "age_over_18",
        name: "Age Over 18",
        path: "org.iso.18013.5.1/age_over_18",
      },
      {
        id: "document_number",
        name: "Document Number",
        path: "org.iso.18013.5.1/document_number",
      },
      {
        id: "issue_date",
        name: "Issue Date",
        path: "org.iso.18013.5.1/issue_date",
      },
      {
        id: "expiry_date",
        name: "Expiry Date",
        path: "org.iso.18013.5.1/expiry_date",
      },
      {
        id: "issuing_authority",
        name: "Issuing Authority",
        path: "org.iso.18013.5.1/issuing_authority",
      },
      {
        id: "issuing_country",
        name: "Issuing Country",
        path: "org.iso.18013.5.1/issuing_country",
      },
      {
        id: "driving_privileges",
        name: "Driving Privileges",
        path: "org.iso.18013.5.1/driving_privileges",
      },
    ],
  },
  "national-id": {
    id: "national-id",
    name: "National ID (PID)",
    docType: "eu.europa.ec.eudi.pid.1",
    namespace: "eu.europa.ec.eudi.pid.1",
    profile: "haip",
    claims: [
      {
        id: "family_name",
        name: "Family Name",
        path: "eu.europa.ec.eudi.pid.1/family_name",
      },
      {
        id: "given_name",
        name: "Given Names",
        path: "eu.europa.ec.eudi.pid.1/given_name",
      },
      {
        id: "birth_date",
        name: "Birth Date",
        path: "eu.europa.ec.eudi.pid.1/birth_date",
      },
      {
        id: "portrait",
        name: "Portrait",
        path: "eu.europa.ec.eudi.pid.1/portrait",
      },
      {
        id: "nationality",
        name: "Nationality",
        path: "eu.europa.ec.eudi.pid.1/nationality",
      },
      {
        id: "place_of_birth",
        name: "Place of Birth",
        path: "eu.europa.ec.eudi.pid.1/place_of_birth",
      },
      {
        id: "resident_address",
        name: "Resident Address",
        path: "eu.europa.ec.eudi.pid.1/resident_address",
      },
      {
        id: "resident_country",
        name: "Resident Country",
        path: "eu.europa.ec.eudi.pid.1/resident_country",
      },
      {
        id: "sex",
        name: "Sex",
        path: "eu.europa.ec.eudi.pid.1/sex",
      },
    ],
  },
  "proof-of-age": {
    id: "proof-of-age",
    name: "Proof of Age (EU AV)",
    docType: "eu.europa.ec.av.1",
    namespace: "eu.europa.ec.av.1",
    profile: "annex-a",
    claims: [
      {
        id: "age_over_18",
        name: "Age Over 18",
        path: "eu.europa.ec.av.1/age_over_18",
      },
    ],
  },
};

// =============================================================================
// Helper Functions
// =============================================================================

/**
 * Get default selected claims for a credential type (first 5 claims).
 */
export function getDefaultClaims(credentialType: string): string[] {
  const config = CREDENTIAL_TYPES[credentialType];
  if (!config) return [];
  return config.claims.slice(0, 5).map((c) => c.id);
}

/**
 * Get claim definitions for a credential type.
 */
export function getClaimsForType(credentialType: string): ClaimDefinition[] {
  return CREDENTIAL_TYPES[credentialType]?.claims || [];
}

/**
 * Get the protocol profile for a credential type.
 */
export function getProfileForType(
  credentialType: string,
): ProtocolProfile | null {
  const config = CREDENTIAL_TYPES[credentialType];
  if (!config) return null;
  return PROTOCOL_PROFILES[config.profile] || null;
}

/**
 * Get the profile ID for a credential type.
 */
export function getProfileIdForType(credentialType: string): ProfileId {
  const config = CREDENTIAL_TYPES[credentialType];
  return config?.profile || "haip";
}
