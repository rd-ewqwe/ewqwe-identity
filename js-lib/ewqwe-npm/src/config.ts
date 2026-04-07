/**
 * @ewqwe/digital-identity — Protocol & Credential Configuration
 *
 * Defines protocol profiles (HAIP, Annex A), credential type specifications
 * (mDL, PID, Proof of Age), and helper functions for querying them.
 *
 * Node.js compatible — no platform-specific APIs.
 *
 * @see https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
 * @see https://ageverification.dev/Technical%20Specification/annexes/annex-A/annex-A-av-profile
 * @see ISO/IEC 18013-5:2021 for mDL claims
 */

import type {
  ClaimDefinition,
  CredentialType,
  CredentialTypeConfig,
  ProfileId,
  ProtocolProfile,
} from "./types.js";

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
 * - EUDI Wallet document categories: WalletCoreConfig.kt `documentCategories`
 *
 * Credential format identifiers:
 * - `"mso_mdoc"` — ISO/IEC 18013-5 Mobile Documents (CBOR-encoded, namespace-based claims)
 * - `"dc+sd-jwt"` — IETF SD-JWT VC (JSON-encoded, flat or nested claim paths)
 *
 * SD-JWT VC credential types use `vct` (Verifiable Credential Type) as the type
 * identifier instead of `docType`/`namespace`. Claims use JSON paths instead of
 * namespace-based paths. See OpenID4VP 1.0 §B.3 and draft-ietf-oauth-sd-jwt-vc-08.
 */
export const CREDENTIAL_TYPES: Record<CredentialType, CredentialTypeConfig> = {
  // ===========================================================================
  // Government
  // ===========================================================================

  mdl: {
    id: "mdl",
    name: "Mobile Driver's License",
    format: "mso_mdoc",
    docType: "org.iso.18013.5.1.mDL",
    namespace: "org.iso.18013.5.1",
    profile: "haip",
    claims: [
      { id: "family_name", name: "Family Name" },
      { id: "given_name", name: "Given Names" },
      { id: "birth_date", name: "Birth Date" },
      { id: "portrait", name: "Portrait" },
      { id: "age_over_21", name: "Age Over 21" },
      { id: "age_over_18", name: "Age Over 18" },
      { id: "document_number", name: "Document Number" },
      { id: "issue_date", name: "Issue Date" },
      { id: "expiry_date", name: "Expiry Date" },
      { id: "issuing_authority", name: "Issuing Authority" },
      { id: "issuing_country", name: "Issuing Country" },
      { id: "driving_privileges", name: "Driving Privileges" },
    ],
  },

  "national-id": {
    id: "national-id",
    name: "National ID (PID)",
    format: "mso_mdoc",
    docType: "eu.europa.ec.eudi.pid.1",
    namespace: "eu.europa.ec.eudi.pid.1",
    profile: "haip",
    claims: [
      { id: "family_name", name: "Family Name" },
      { id: "given_name", name: "Given Names" },
      { id: "birth_date", name: "Birth Date" },
      { id: "portrait", name: "Portrait" },
      { id: "nationality", name: "Nationality" },
      { id: "place_of_birth", name: "Place of Birth" },
      { id: "resident_address", name: "Resident Address" },
      { id: "resident_country", name: "Resident Country" },
      { id: "sex", name: "Sex" },
    ],
  },

  "national-id-sd-jwt": {
    id: "national-id-sd-jwt",
    name: "National ID (PID) — SD-JWT VC",
    format: "dc+sd-jwt",
    docType: "urn:eudi:pid:1",
    namespace: "urn:eudi:pid:1",
    vct: "urn:eudi:pid:1",
    profile: "haip",
    claims: [
      { id: "family_name", name: "Family Name" },
      { id: "given_name", name: "Given Names" },
      { id: "birthdate", name: "Birth Date" },
      { id: "picture", name: "Portrait" },
      { id: "nationalities", name: "Nationalities" },
      { id: "place_of_birth", name: "Place of Birth" },
      { id: "address", name: "Address" },
      { id: "sex", name: "Sex" },
    ],
  },

  "proof-of-age": {
    id: "proof-of-age",
    name: "Proof of Age (EU AV)",
    format: "mso_mdoc",
    docType: "eu.europa.ec.av.1",
    namespace: "eu.europa.ec.av.1",
    profile: "annex-a",
    claims: [{ id: "age_over_18", name: "Age Over 18" }],
  },

  tax: {
    id: "tax",
    name: "Tax Identification",
    format: "mso_mdoc",
    docType: "eu.europa.ec.eudi.tax.1",
    namespace: "eu.europa.ec.eudi.tax.1",
    profile: "haip",
    claims: [
      { id: "tax_number", name: "Tax Number" },
      { id: "registered_family_name", name: "Registered Family Name" },
      { id: "registered_given_name", name: "Registered Given Names" },
      { id: "issuing_country", name: "Issuing Country" },
    ],
  },

  "tax-sd-jwt": {
    id: "tax-sd-jwt",
    name: "Tax Identification — SD-JWT VC",
    format: "dc+sd-jwt",
    docType: "urn:eu.europa.ec.eudi:tax:1",
    namespace: "urn:eu.europa.ec.eudi:tax:1",
    vct: "urn:eu.europa.ec.eudi:tax:1",
    profile: "haip",
    claims: [
      { id: "tax_number", name: "Tax Number" },
      { id: "registered_family_name", name: "Registered Family Name" },
      { id: "registered_given_name", name: "Registered Given Names" },
      { id: "issuing_country", name: "Issuing Country" },
    ],
  },

  "pseudonym-age": {
    id: "pseudonym-age",
    name: "Pseudonym (Age Over 18)",
    format: "mso_mdoc",
    docType: "eu.europa.ec.eudi.pseudonym.age_over_18.1",
    namespace: "eu.europa.ec.eudi.pseudonym.age_over_18.1",
    profile: "haip",
    claims: [{ id: "age_over_18", name: "Age Over 18" }],
  },

  "pseudonym-age-sd-jwt": {
    id: "pseudonym-age-sd-jwt",
    name: "Pseudonym (Age Over 18) — SD-JWT VC",
    format: "dc+sd-jwt",
    docType: "urn:eu.europa.ec.eudi:pseudonym_age_over_18:1",
    namespace: "urn:eu.europa.ec.eudi:pseudonym_age_over_18:1",
    vct: "urn:eu.europa.ec.eudi:pseudonym_age_over_18:1",
    profile: "haip",
    claims: [{ id: "age_over_18", name: "Age Over 18" }],
  },

  cor: {
    id: "cor",
    name: "Certificate of Residence",
    format: "mso_mdoc",
    docType: "eu.europa.ec.eudi.cor.1",
    namespace: "eu.europa.ec.eudi.cor.1",
    profile: "haip",
    claims: [
      { id: "resident_address", name: "Resident Address" },
      { id: "resident_country", name: "Resident Country" },
      { id: "resident_city", name: "Resident City" },
      { id: "resident_postal_code", name: "Resident Postal Code" },
      { id: "issuing_country", name: "Issuing Country" },
    ],
  },

  // ===========================================================================
  // Travel
  // ===========================================================================

  "photo-id": {
    id: "photo-id",
    name: "Photo ID",
    format: "mso_mdoc",
    docType: "org.iso.23220.2.photoid.1",
    namespace: "org.iso.23220.photoid.1",
    profile: "haip",
    claims: [
      { id: "family_name", name: "Family Name" },
      { id: "given_name", name: "Given Names" },
      { id: "birth_date", name: "Birth Date" },
      { id: "portrait", name: "Portrait" },
      { id: "document_number", name: "Document Number" },
      { id: "issuing_authority", name: "Issuing Authority" },
      { id: "issuing_country", name: "Issuing Country" },
      { id: "expiry_date", name: "Expiry Date" },
    ],
  },

  reservation: {
    id: "reservation",
    name: "Travel Reservation",
    format: "mso_mdoc",
    docType: "org.iso.18013.5.1.reservation",
    namespace: "org.iso.18013.5.1.reservation",
    profile: "haip",
    claims: [
      { id: "reservation_number", name: "Reservation Number" },
      { id: "family_name", name: "Family Name" },
      { id: "given_name", name: "Given Names" },
    ],
  },

  // ===========================================================================
  // Finance
  // ===========================================================================

  iban: {
    id: "iban",
    name: "IBAN",
    format: "mso_mdoc",
    docType: "eu.europa.ec.eudi.iban.1",
    namespace: "eu.europa.ec.eudi.iban.1",
    profile: "haip",
    claims: [
      { id: "iban", name: "IBAN" },
      { id: "account_holder", name: "Account Holder" },
      { id: "bic", name: "BIC" },
    ],
  },

  "iban-sd-jwt": {
    id: "iban-sd-jwt",
    name: "IBAN — SD-JWT VC",
    format: "dc+sd-jwt",
    docType: "urn:eu.europa.ec.eudi:iban:1",
    namespace: "urn:eu.europa.ec.eudi:iban:1",
    vct: "urn:eu.europa.ec.eudi:iban:1",
    profile: "haip",
    claims: [
      { id: "iban", name: "IBAN" },
      { id: "account_holder", name: "Account Holder" },
      { id: "bic", name: "BIC" },
    ],
  },

  // ===========================================================================
  // Health
  // ===========================================================================

  ehic: {
    id: "ehic",
    name: "European Health Insurance Card",
    format: "mso_mdoc",
    docType: "eu.europa.ec.eudi.ehic.1",
    namespace: "eu.europa.ec.eudi.ehic.1",
    profile: "haip",
    claims: [
      { id: "family_name", name: "Family Name" },
      { id: "given_name", name: "Given Names" },
      { id: "birth_date", name: "Birth Date" },
      { id: "personal_id", name: "Personal ID" },
      { id: "institution_id", name: "Institution ID" },
      { id: "institution_country", name: "Institution Country" },
      { id: "card_number", name: "Card Number" },
      { id: "expiry_date", name: "Expiry Date" },
    ],
  },

  "ehic-sd-jwt": {
    id: "ehic-sd-jwt",
    name: "European Health Insurance Card — SD-JWT VC",
    format: "dc+sd-jwt",
    docType: "urn:eu.europa.ec.eudi:ehic:1",
    namespace: "urn:eu.europa.ec.eudi:ehic:1",
    vct: "urn:eu.europa.ec.eudi:ehic:1",
    profile: "haip",
    claims: [
      { id: "family_name", name: "Family Name" },
      { id: "given_name", name: "Given Names" },
      { id: "birth_date", name: "Birth Date" },
      { id: "personal_id", name: "Personal ID" },
      { id: "institution_id", name: "Institution ID" },
      { id: "institution_country", name: "Institution Country" },
      { id: "card_number", name: "Card Number" },
      { id: "expiry_date", name: "Expiry Date" },
    ],
  },

  "health-id": {
    id: "health-id",
    name: "Health ID",
    format: "mso_mdoc",
    docType: "eu.europa.ec.eudi.hiid.1",
    namespace: "eu.europa.ec.eudi.hiid.1",
    profile: "haip",
    claims: [
      { id: "family_name", name: "Family Name" },
      { id: "given_name", name: "Given Names" },
      { id: "birth_date", name: "Birth Date" },
      { id: "health_insurance_id", name: "Health Insurance ID" },
      { id: "issuing_country", name: "Issuing Country" },
    ],
  },

  "health-id-sd-jwt": {
    id: "health-id-s-jwt",
    name: "Health ID — SD-JWT VC",
    format: "dc+sd-jwt",
    docType: "urn:eu.europa.ec.eudi:hiid:1",
    namespace: "urn:eu.europa.ec.eudi:hiid:1",
    vct: "urn:eu.europa.ec.eudi:hiid:1",
    profile: "haip",
    claims: [
      { id: "family_name", name: "Family Name" },
      { id: "given_name", name: "Given Names" },
      { id: "birth_date", name: "Birth Date" },
      { id: "health_insurance_id", name: "Health Insurance ID" },
      { id: "issuing_country", name: "Issuing Country" },
    ],
  },

  // ===========================================================================
  // Social Security
  // ===========================================================================

  pda1: {
    id: "pda1",
    name: "Portable Document A1",
    format: "mso_mdoc",
    docType: "eu.europa.ec.eudi.pda1.1",
    namespace: "eu.europa.ec.eudi.pda1.1",
    profile: "haip",
    claims: [
      { id: "family_name", name: "Family Name" },
      { id: "given_name", name: "Given Names" },
      { id: "birth_date", name: "Birth Date" },
      { id: "nationality", name: "Nationality" },
      { id: "social_security_number", name: "Social Security Number" },
      { id: "issuing_country", name: "Issuing Country" },
      { id: "expiry_date", name: "Expiry Date" },
    ],
  },

  "pda1-sd-jwt": {
    id: "pda1-sd-jwt",
    name: "Portable Document A1 — SD-JWT VC",
    format: "dc+sd-jwt",
    docType: "urn:eu.europa.ec.eudi:pda1:1",
    namespace: "urn:eu.europa.ec.eudi:pda1:1",
    vct: "urn:eu.europa.ec.eudi:pda1:1",
    profile: "haip",
    claims: [
      { id: "family_name", name: "Family Name" },
      { id: "given_name", name: "Given Names" },
      { id: "birth_date", name: "Birth Date" },
      { id: "nationality", name: "Nationality" },
      { id: "social_security_number", name: "Social Security Number" },
      { id: "issuing_country", name: "Issuing Country" },
      { id: "expiry_date", name: "Expiry Date" },
    ],
  },

  // ===========================================================================
  // Retail
  // ===========================================================================

  loyalty: {
    id: "loyalty",
    name: "Loyalty Card",
    format: "mso_mdoc",
    docType: "eu.europa.ec.eudi.loyalty.1",
    namespace: "eu.europa.ec.eudi.loyalty.1",
    profile: "haip",
    claims: [
      { id: "family_name", name: "Family Name" },
      { id: "given_name", name: "Given Names" },
      { id: "loyalty_number", name: "Loyalty Number" },
      { id: "program_name", name: "Program Name" },
    ],
  },

  msisdn: {
    id: "msisdn",
    name: "Mobile Phone Number (MSISDN)",
    format: "mso_mdoc",
    docType: "eu.europa.ec.eudi.msisdn.1",
    namespace: "eu.europa.ec.eudi.msisdn.1",
    profile: "haip",
    claims: [
      { id: "phone_number", name: "Phone Number" },
      { id: "registered_family_name", name: "Registered Family Name" },
    ],
  },

  "msisdn-sd-jwt": {
    id: "msisdn-sd-jwt",
    name: "Mobile Phone Number (MSISDN) — SD-JWT VC",
    format: "dc+sd-jwt",
    docType: "urn:eu.europa.ec.eudi:msisdn:1",
    namespace: "urn:eu.europa.ec.eudi:msisdn:1",
    vct: "urn:eu.europa.ec.eudi:msisdn:1",
    profile: "haip",
    claims: [
      { id: "phone_number", name: "Phone Number" },
      { id: "registered_family_name", name: "Registered Family Name" },
    ],
  },

  // ===========================================================================
  // Other
  // ===========================================================================

  por: {
    id: "por",
    name: "Power of Representation",
    format: "mso_mdoc",
    docType: "eu.europa.ec.eudi.por.1",
    namespace: "eu.europa.ec.eudi.por.1",
    profile: "haip",
    claims: [
      { id: "legal_person_id", name: "Legal Person ID" },
      { id: "legal_person_name", name: "Legal Person Name" },
      { id: "representative_family_name", name: "Representative Family Name" },
      { id: "representative_given_name", name: "Representative Given Names" },
    ],
  },

  "por-sd-jwt": {
    id: "por-sd-jwt",
    name: "Power of Representation — SD-JWT VC",
    format: "dc+sd-jwt",
    docType: "urn:eu.europa.ec.eudi:por:1",
    namespace: "urn:eu.europa.ec.eudi:por:1",
    vct: "urn:eu.europa.ec.eudi:por:1",
    profile: "haip",
    claims: [
      { id: "legal_person_id", name: "Legal Person ID" },
      { id: "legal_person_name", name: "Legal Person Name" },
      { id: "representative_family_name", name: "Representative Family Name" },
      { id: "representative_given_name", name: "Representative Given Names" },
    ],
  },
};

// =============================================================================
// Helper Functions
// =============================================================================

/**
 * Get default selected claims for a credential type (first 5 claims).
 */
export function getDefaultClaims(credentialType: CredentialType): string[] {
  const config = CREDENTIAL_TYPES[credentialType];
  if (!config) return [];
  return config.claims.slice(0, 5).map((c) => c.id);
}

/**
 * Get claim definitions for a credential type.
 */
export function getClaimsForType(
  credentialType: CredentialType,
): ClaimDefinition[] {
  return CREDENTIAL_TYPES[credentialType]?.claims || [];
}

/**
 * Get the protocol profile for a credential type.
 */
export function getProfileForType(
  credentialType: CredentialType,
): ProtocolProfile | null {
  const config = CREDENTIAL_TYPES[credentialType];
  if (!config) return null;
  return PROTOCOL_PROFILES[config.profile] || null;
}

/**
 * Get the profile ID for a credential type.
 */
export function getProfileIdForType(credentialType: CredentialType): ProfileId {
  const config = CREDENTIAL_TYPES[credentialType];
  return config?.profile || "haip";
}
