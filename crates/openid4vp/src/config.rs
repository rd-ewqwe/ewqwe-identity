//! Protocol profiles and credential type configurations.
//!
//! Defines the two OpenID4VP profiles (HAIP and Annex A) and
//! the three credential types (mDL, PID, Proof of Age) with
//! their ISO namespaces, document types, and available claims.
//!
//! Mirrors the TypeScript `PROTOCOL_PROFILES` and `CREDENTIAL_TYPES`
//! from `@ewqwe/digital-identity`.

use crate::types::{
    ClaimDefinition, ClientIdScheme, CredentialType, CredentialTypeConfig, ProfileId,
    ProtocolProfile, ResponseMode,
};

// ============================================================================
// Protocol Profiles
// ============================================================================

/// HAIP profile — High Assurance Interoperability Profile for EUDI Wallets.
pub const PROFILE_HAIP: ProtocolProfile = ProtocolProfile {
    id: ProfileId::Haip,
    name: "HAIP",
    description: "High Assurance Interoperability Profile for EUDI Wallets",
    client_id_scheme: ClientIdScheme::X509SanDns,
    response_mode: ResponseMode::DirectPostJwt,
    url_schemes: &["eudi-openid4vp://", "openid4vp://"],
    requires_jar_signing: true,
};

/// Annex A profile — EU Age Verification Profile for age verification apps.
pub const PROFILE_ANNEX_A: ProtocolProfile = ProtocolProfile {
    id: ProfileId::AnnexA,
    name: "Annex A",
    description: "EU Age Verification Profile for age verification apps",
    client_id_scheme: ClientIdScheme::RedirectUri,
    response_mode: ResponseMode::DirectPost,
    url_schemes: &["av://"],
    requires_jar_signing: false,
};

/// Get the protocol profile for a given profile ID.
pub fn get_profile(id: ProfileId) -> &'static ProtocolProfile {
    match id {
        ProfileId::Haip => &PROFILE_HAIP,
        ProfileId::AnnexA => &PROFILE_ANNEX_A,
    }
}

// ============================================================================
// Credential Type Configurations
// ============================================================================

// --- mDL Claims (ISO 18013-5) ---

const MDL_CLAIMS: &[ClaimDefinition] = &[
    ClaimDefinition {
        id: "family_name",
        name: "Family Name",
        path: "family_name",
        description: Some("Last/surname"),
    },
    ClaimDefinition {
        id: "given_name",
        name: "Given Name",
        path: "given_name",
        description: Some("First name"),
    },
    ClaimDefinition {
        id: "birth_date",
        name: "Birth Date",
        path: "birth_date",
        description: Some("Date of birth"),
    },
    ClaimDefinition {
        id: "portrait",
        name: "Portrait",
        path: "portrait",
        description: Some("Photo of the holder"),
    },
    ClaimDefinition {
        id: "age_over_21",
        name: "Age Over 21",
        path: "age_over_21",
        description: Some("Whether holder is over 21"),
    },
    ClaimDefinition {
        id: "age_over_18",
        name: "Age Over 18",
        path: "age_over_18",
        description: Some("Whether holder is over 18"),
    },
    ClaimDefinition {
        id: "document_number",
        name: "Document Number",
        path: "document_number",
        description: Some("License document number"),
    },
    ClaimDefinition {
        id: "issue_date",
        name: "Issue Date",
        path: "issue_date",
        description: Some("Date of issuance"),
    },
    ClaimDefinition {
        id: "expiry_date",
        name: "Expiry Date",
        path: "expiry_date",
        description: Some("Date of expiration"),
    },
    ClaimDefinition {
        id: "issuing_authority",
        name: "Issuing Authority",
        path: "issuing_authority",
        description: Some("Authority that issued the license"),
    },
    ClaimDefinition {
        id: "issuing_country",
        name: "Issuing Country",
        path: "issuing_country",
        description: Some("Country of issuance"),
    },
    ClaimDefinition {
        id: "driving_privileges",
        name: "Driving Privileges",
        path: "driving_privileges",
        description: Some("Vehicle categories and restrictions"),
    },
];

// --- PID Claims (EU Personal Identification Data) ---

const PID_CLAIMS: &[ClaimDefinition] = &[
    ClaimDefinition {
        id: "family_name",
        name: "Family Name",
        path: "family_name",
        description: Some("Last/surname"),
    },
    ClaimDefinition {
        id: "given_name",
        name: "Given Name",
        path: "given_name",
        description: Some("First name"),
    },
    ClaimDefinition {
        id: "birth_date",
        name: "Birth Date",
        path: "birth_date",
        description: Some("Date of birth"),
    },
    ClaimDefinition {
        id: "portrait",
        name: "Portrait",
        path: "portrait",
        description: Some("Photo of the holder"),
    },
    ClaimDefinition {
        id: "nationality",
        name: "Nationality",
        path: "nationality",
        description: Some("Nationality"),
    },
    ClaimDefinition {
        id: "place_of_birth",
        name: "Place of Birth",
        path: "place_of_birth",
        description: Some("Place of birth"),
    },
    ClaimDefinition {
        id: "resident_address",
        name: "Resident Address",
        path: "resident_address",
        description: Some("Current address"),
    },
    ClaimDefinition {
        id: "resident_country",
        name: "Resident Country",
        path: "resident_country",
        description: Some("Country of residence"),
    },
    ClaimDefinition {
        id: "sex",
        name: "Sex",
        path: "sex",
        description: Some("Sex/gender"),
    },
];

// --- Proof of Age Claims (EU Age Verification) ---

const PROOF_OF_AGE_CLAIMS: &[ClaimDefinition] = &[ClaimDefinition {
    id: "age_over_18",
    name: "Age Over 18",
    path: "age_over_18",
    description: Some("Whether the holder is 18 years of age or older"),
}];

// --- Credential Type Configs ---

/// Mobile Driver's License (ISO 18013-5).
pub const CREDENTIAL_TYPE_MDL: CredentialTypeConfig = CredentialTypeConfig {
    id: CredentialType::Mdl,
    name: "Mobile Driver's License",
    doc_type: "org.iso.18013.5.1.mDL",
    namespace: "org.iso.18013.5.1",
    profile: ProfileId::Haip,
    claims: MDL_CLAIMS,
};

/// EU Personal Identification Data.
pub const CREDENTIAL_TYPE_PID: CredentialTypeConfig = CredentialTypeConfig {
    id: CredentialType::NationalId,
    name: "National ID (EU PID)",
    doc_type: "eu.europa.ec.eudi.pid.1",
    namespace: "eu.europa.ec.eudi.pid.1",
    profile: ProfileId::Haip,
    claims: PID_CLAIMS,
};

/// EU Proof of Age attestation.
pub const CREDENTIAL_TYPE_PROOF_OF_AGE: CredentialTypeConfig = CredentialTypeConfig {
    id: CredentialType::ProofOfAge,
    name: "Proof of Age",
    doc_type: "eu.europa.ec.av.1",
    namespace: "eu.europa.ec.av.1",
    profile: ProfileId::AnnexA,
    claims: PROOF_OF_AGE_CLAIMS,
};

/// Look up a credential type configuration by string key.
///
/// Accepts: `"mdl"`, `"national-id"`, `"proof-of-age"`, `"proof_of_age"`.
pub fn get_credential_type(key: &str) -> Option<&'static CredentialTypeConfig> {
    match key {
        "mdl" => Some(&CREDENTIAL_TYPE_MDL),
        "national-id" | "national_id" | "pid" => Some(&CREDENTIAL_TYPE_PID),
        "proof-of-age" | "proof_of_age" => Some(&CREDENTIAL_TYPE_PROOF_OF_AGE),
        _ => None,
    }
}

/// Determine the profile for a given credential type string.
///
/// `"proof-of-age"` / `"proof_of_age"` → `AnnexA`, everything else → `Haip`.
pub fn determine_profile(
    credential_type: Option<&str>,
    explicit_profile: Option<ProfileId>,
) -> ProfileId {
    if let Some(profile) = explicit_profile {
        return profile;
    }
    match credential_type {
        Some("proof-of-age") | Some("proof_of_age") => ProfileId::AnnexA,
        _ => ProfileId::Haip,
    }
}

/// Get the default claims (first 5) for a credential type.
pub fn get_default_claims(credential_type: &str) -> Vec<&'static str> {
    get_credential_type(credential_type)
        .map(|ct| ct.claims.iter().take(5).map(|c| c.id).collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_determine_profile() {
        assert_eq!(determine_profile(None, None), ProfileId::Haip);
        assert_eq!(
            determine_profile(Some("proof-of-age"), None),
            ProfileId::AnnexA
        );
        assert_eq!(
            determine_profile(Some("proof_of_age"), None),
            ProfileId::AnnexA
        );
        assert_eq!(determine_profile(Some("mdl"), None), ProfileId::Haip);
        // Explicit profile overrides
        assert_eq!(
            determine_profile(Some("proof-of-age"), Some(ProfileId::Haip)),
            ProfileId::Haip
        );
    }

    #[test]
    fn test_get_credential_type() {
        let mdl = get_credential_type("mdl").unwrap();
        assert_eq!(mdl.doc_type, "org.iso.18013.5.1.mDL");
        assert_eq!(mdl.namespace, "org.iso.18013.5.1");
        assert_eq!(mdl.profile, ProfileId::Haip);
        assert_eq!(mdl.claims.len(), 12);

        let poa = get_credential_type("proof-of-age").unwrap();
        assert_eq!(poa.doc_type, "eu.europa.ec.av.1");
        assert_eq!(poa.profile, ProfileId::AnnexA);
        assert_eq!(poa.claims.len(), 1);

        let pid = get_credential_type("national-id").unwrap();
        assert_eq!(pid.doc_type, "eu.europa.ec.eudi.pid.1");
        assert_eq!(pid.claims.len(), 9);

        assert!(get_credential_type("unknown").is_none());
    }

    #[test]
    fn test_get_default_claims() {
        let claims = get_default_claims("mdl");
        assert_eq!(claims.len(), 5);
        assert_eq!(claims[0], "family_name");

        let claims = get_default_claims("proof-of-age");
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0], "age_over_18");
    }
}
