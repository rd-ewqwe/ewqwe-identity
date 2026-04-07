import type { CredentialTypeConfig, ClaimDefinition } from "./types.ts";

/**
 * Credential type configurations based on ISO 18013-5 and other standards
 */
export const CREDENTIAL_TYPES: Record<string, CredentialTypeConfig> = {
  mdl: {
    id: "mdl",
    name: "Mobile Driver's License",
    docType: "org.iso.18013.5.1.mDL",
    namespace: "org.iso.18013.5.1",
    claims: [
      { id: "family_name", name: "Family Name", path: "org.iso.18013.5.1/family_name" },
      { id: "given_name", name: "Given Names", path: "org.iso.18013.5.1/given_name" },
      { id: "birth_date", name: "Birth Date", path: "org.iso.18013.5.1/birth_date" },
      { id: "portrait", name: "Portrait", path: "org.iso.18013.5.1/portrait" },
      { id: "age_over_21", name: "Age Over 21", path: "org.iso.18013.5.1/age_over_21" },
      { id: "age_over_18", name: "Age Over 18", path: "org.iso.18013.5.1/age_over_18" },
      { id: "document_number", name: "Document Number", path: "org.iso.18013.5.1/document_number" },
      { id: "issue_date", name: "Issue Date", path: "org.iso.18013.5.1/issue_date" },
      { id: "expiry_date", name: "Expiry Date", path: "org.iso.18013.5.1/expiry_date" },
      { id: "issuing_authority", name: "Issuing Authority", path: "org.iso.18013.5.1/issuing_authority" },
      { id: "issuing_country", name: "Issuing Country", path: "org.iso.18013.5.1/issuing_country" },
      { id: "driving_privileges", name: "Driving Privileges", path: "org.iso.18013.5.1/driving_privileges" },
    ],
  },
  "national-id": {
    id: "national-id",
    name: "National ID",
    docType: "org.iso.18013.5.1.PID",
    namespace: "org.iso.18013.5.1",
    claims: [
      { id: "family_name", name: "Family Name", path: "org.iso.18013.5.1/family_name" },
      { id: "given_name", name: "Given Names", path: "org.iso.18013.5.1/given_name" },
      { id: "birth_date", name: "Birth Date", path: "org.iso.18013.5.1/birth_date" },
      { id: "portrait", name: "Portrait", path: "org.iso.18013.5.1/portrait" },
      { id: "age_over_21", name: "Age Over 21", path: "org.iso.18013.5.1/age_over_21" },
      { id: "age_over_18", name: "Age Over 18", path: "org.iso.18013.5.1/age_over_18" },
      { id: "nationality", name: "Nationality", path: "org.iso.18013.5.1/nationality" },
      { id: "resident_address", name: "Resident Address", path: "org.iso.18013.5.1/resident_address" },
      { id: "gender", name: "Gender", path: "org.iso.18013.5.1/gender" },
    ],
  },
};

/**
 * Get default selected claims for a credential type
 */
export function getDefaultClaims(credentialType: string): string[] {
  const config = CREDENTIAL_TYPES[credentialType];
  if (!config) return [];
  
  // Default to first 5 claims
  return config.claims.slice(0, 5).map((c) => c.id);
}

/**
 * Get claim definitions for a credential type
 */
export function getClaimsForType(credentialType: string): ClaimDefinition[] {
  return CREDENTIAL_TYPES[credentialType]?.claims || [];
}
