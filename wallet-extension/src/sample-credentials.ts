/**
 * Sample Credentials for EU Age Verification Wallet
 *
 * Pre-loaded credentials for demo/testing:
 * - 2x Mobile Driver's License (mDL)
 * - 2x EU Person Identification Data (PID)
 * - 2x Proof of Age (EU AV)
 */

import type { StoredCredential } from "./types";

/**
 * Generate sample credentials for the wallet
 * These represent realistic credential data following EU/ISO standards
 */
export function generateSampleCredentials(): StoredCredential[] {
  const now = new Date();

  // Helper to create dates
  const addDays = (date: Date, days: number): string => {
    const d = new Date(date);
    d.setDate(d.getDate() + days);
    return d.toISOString();
  };

  const addYears = (date: Date, years: number): string => {
    const d = new Date(date);
    d.setFullYear(d.getFullYear() + years);
    return d.toISOString();
  };

  return [
    // ═══════════════════════════════════════════════════════════════
    // Mobile Driver's License (mDL) - 2 samples
    // ═══════════════════════════════════════════════════════════════
    {
      id: "mdl-sample-001",
      type: "mdl",
      docType: "org.iso.18013.5.1.mDL",
      namespace: "org.iso.18013.5.1",
      displayName: "Driver's License - DE",
      issuer: "Kraftfahrt-Bundesamt",
      issuedAt: addDays(now, -180),
      expiresAt: addYears(now, 10),
      claims: {
        family_name: "Müller",
        given_name: "Hans",
        birth_date: "1985-03-15",
        issue_date: addDays(now, -180).split("T")[0],
        expiry_date: addYears(now, 10).split("T")[0],
        issuing_country: "DE",
        issuing_authority: "Kraftfahrt-Bundesamt",
        document_number: "DE-DL-2024-7834521",
        portrait: null, // Would be base64 image in real implementation
        driving_privileges: [
          {
            vehicle_category_code: "B",
            issue_date: "2005-06-20",
            expiry_date: addYears(now, 10).split("T")[0],
          },
          {
            vehicle_category_code: "A",
            issue_date: "2010-08-15",
            expiry_date: addYears(now, 10).split("T")[0],
          },
        ],
        un_distinguishing_sign: "D",
        age_over_18: true,
        age_over_21: true,
        age_in_years: 40,
        resident_address: "Berliner Straße 42, 10115 Berlin",
        resident_city: "Berlin",
        resident_postal_code: "10115",
        resident_country: "DE",
      },
    },
    {
      id: "mdl-sample-002",
      type: "mdl",
      docType: "org.iso.18013.5.1.mDL",
      namespace: "org.iso.18013.5.1",
      displayName: "Driver's License - FR",
      issuer: "Préfecture de Police de Paris",
      issuedAt: addDays(now, -365),
      expiresAt: addYears(now, 15),
      claims: {
        family_name: "Dubois",
        given_name: "Marie",
        birth_date: "1992-07-22",
        issue_date: addDays(now, -365).split("T")[0],
        expiry_date: addYears(now, 15).split("T")[0],
        issuing_country: "FR",
        issuing_authority: "Préfecture de Police de Paris",
        document_number: "FR-DL-2023-9012345",
        portrait: null,
        driving_privileges: [
          {
            vehicle_category_code: "B",
            issue_date: "2012-09-10",
            expiry_date: addYears(now, 15).split("T")[0],
          },
        ],
        un_distinguishing_sign: "F",
        age_over_18: true,
        age_over_21: true,
        age_in_years: 33,
        resident_address: "15 Rue de Rivoli, 75001 Paris",
        resident_city: "Paris",
        resident_postal_code: "75001",
        resident_country: "FR",
      },
    },

    // ═══════════════════════════════════════════════════════════════
    // EU Person Identification Data (PID) - 2 samples
    // ═══════════════════════════════════════════════════════════════
    {
      id: "pid-sample-001",
      type: "national-id",
      docType: "eu.europa.ec.eudi.pid.1",
      namespace: "eu.europa.ec.eudi.pid.1",
      displayName: "National ID - NL",
      issuer: "Rijksdienst voor Identiteitsgegevens",
      issuedAt: addDays(now, -90),
      expiresAt: addYears(now, 10),
      claims: {
        family_name: "van den Berg",
        given_name: "Jan Willem",
        birth_date: "1988-11-03",
        age_over_18: true,
        age_in_years: 37,
        age_birth_year: 1988,
        family_name_birth: "van den Berg",
        given_name_birth: "Jan Willem",
        birth_place: "Amsterdam",
        birth_country: "NL",
        birth_state: "Noord-Holland",
        birth_city: "Amsterdam",
        resident_address: "Prinsengracht 263, 1016 GV Amsterdam",
        resident_country: "NL",
        resident_state: "Noord-Holland",
        resident_city: "Amsterdam",
        resident_postal_code: "1016 GV",
        resident_street: "Prinsengracht 263",
        gender: "male",
        nationality: ["NL"],
        issuance_date: addDays(now, -90).split("T")[0],
        expiry_date: addYears(now, 10).split("T")[0],
        issuing_authority: "Rijksdienst voor Identiteitsgegevens",
        document_number: "NL-PID-2024-5678901",
        issuing_country: "NL",
        issuing_jurisdiction: "NL",
      },
    },
    {
      id: "pid-sample-002",
      type: "national-id",
      docType: "eu.europa.ec.eudi.pid.1",
      namespace: "eu.europa.ec.eudi.pid.1",
      displayName: "National ID - ES",
      issuer: "Dirección General de la Policía",
      issuedAt: addDays(now, -45),
      expiresAt: addYears(now, 10),
      claims: {
        family_name: "García López",
        given_name: "Elena",
        birth_date: "1995-02-14",
        age_over_18: true,
        age_in_years: 30,
        age_birth_year: 1995,
        family_name_birth: "García López",
        given_name_birth: "Elena",
        birth_place: "Madrid",
        birth_country: "ES",
        birth_state: "Comunidad de Madrid",
        birth_city: "Madrid",
        resident_address: "Calle Gran Vía 28, 28013 Madrid",
        resident_country: "ES",
        resident_state: "Comunidad de Madrid",
        resident_city: "Madrid",
        resident_postal_code: "28013",
        resident_street: "Calle Gran Vía 28",
        gender: "female",
        nationality: ["ES"],
        issuance_date: addDays(now, -45).split("T")[0],
        expiry_date: addYears(now, 10).split("T")[0],
        issuing_authority: "Dirección General de la Policía",
        document_number: "ES-PID-2024-2345678",
        issuing_country: "ES",
        issuing_jurisdiction: "ES",
      },
    },

    // ═══════════════════════════════════════════════════════════════
    // Proof of Age (EU Age Verification) - 2 samples
    // ═══════════════════════════════════════════════════════════════
    {
      id: "poa-sample-001",
      type: "proof-of-age",
      docType: "eu.europa.ec.av.1",
      namespace: "eu.europa.ec.av.1",
      displayName: "Proof of Age - Issued by DE",
      issuer: "EU Age Verification Authority - Germany",
      issuedAt: addDays(now, -7),
      expiresAt: addDays(now, 83), // 90 days validity per EU AV profile
      claims: {
        age_over_18: true,
        // Note: Proof of Age contains ONLY age_over_18 claim
        // No personal data is stored per EU AV specification
      },
    },
    {
      id: "poa-sample-002",
      type: "proof-of-age",
      docType: "eu.europa.ec.av.1",
      namespace: "eu.europa.ec.av.1",
      displayName: "Proof of Age - Issued by FR",
      issuer: "EU Age Verification Authority - France",
      issuedAt: addDays(now, -30),
      expiresAt: addDays(now, 60), // 90 days validity
      claims: {
        age_over_18: true,
      },
    },
  ];
}

/**
 * Get sample credentials grouped by type
 */
export function getSampleCredentialsByType(): Record<
  string,
  StoredCredential[]
> {
  const credentials = generateSampleCredentials();
  return {
    mdl: credentials.filter((c) => c.type === "mdl"),
    "national-id": credentials.filter((c) => c.type === "national-id"),
    "proof-of-age": credentials.filter((c) => c.type === "proof-of-age"),
  };
}
