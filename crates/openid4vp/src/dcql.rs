//! DCQL (Digital Credentials Query Language) builder utilities.
//!
//! Implements query construction per OpenID4VP 1.0 §6 for requesting
//! credentials from digital wallets. Supports EU Age Verification,
//! mDL, and PID credential types.
//!
//! References:
//! - <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6>
//! - EU Age Verification Profile Annex A

use crate::types::{DCQLClaimsQuery, DCQLCredentialMeta, DCQLCredentialQuery, DCQLQuery};

// ============================================================================
// Well-Known Namespaces and Document Types
// ============================================================================

/// EU Age Verification namespace.
pub const EU_AV_NAMESPACE: &str = "eu.europa.ec.av.1";
/// EU Age Verification document type.
pub const EU_AV_DOCTYPE: &str = "eu.europa.ec.av.1.mdoc";

/// ISO 18013-5 mobile driver's license namespace.
pub const ISO_MDL_NAMESPACE: &str = "org.iso.18013.5.1";
/// ISO 18013-5 mobile driver's license document type.
pub const ISO_MDL_DOCTYPE: &str = "org.iso.18013.5.1.mDL";

/// EU PID namespace.
pub const EU_PID_NAMESPACE: &str = "eu.europa.ec.eudi.pid.1";
/// EU PID document type.
pub const EU_PID_DOCTYPE: &str = "eu.europa.ec.eudi.pid.1";

// ============================================================================
// Query Builders
// ============================================================================

/// Build a minimal DCQL query for EU Age Verification.
///
/// Requests `age_over_{threshold}` from the `eu.europa.ec.av.1` namespace.
/// Default threshold is 18.
///
/// ```ignore
/// let query = build_age_verification_query(Some(21));
/// // Requests age_over_21 from eu.europa.ec.av.1
/// ```
pub fn build_age_verification_query(age_threshold: Option<u8>) -> DCQLQuery {
    let threshold = age_threshold.unwrap_or(18);
    let claim_id = format!("age_over_{threshold}");

    DCQLQuery {
        credentials: vec![DCQLCredentialQuery {
            id: "eu_av_proof".to_string(),
            format: "mso_mdoc".to_string(),
            meta: DCQLCredentialMeta {
                doctype_value: Some(EU_AV_NAMESPACE.to_string()),
                vct_values: None,
                type_values: None,
            },
            claims: Some(vec![DCQLClaimsQuery {
                id: Some(claim_id.clone()),
                // Claims Path Pointer for mso_mdoc: [namespace, element] (OpenID4VP §7.2)
                path: vec![EU_AV_NAMESPACE.to_string(), claim_id.clone()],
                values: None,
                intent_to_retain: Some(false),
            }]),
            claim_sets: None,
            multiple: None,
            require_cryptographic_holder_binding: None,
        }],
        credential_sets: None,
    }
}

/// Build an age verification query with mDL fallback via `credential_sets`.
///
/// Requests `age_over_{threshold}` from EU AV namespace, with a fallback
/// to the ISO mDL namespace if the wallet doesn't have an EU AV credential.
pub fn build_age_verification_query_with_fallback(age_threshold: Option<u8>) -> DCQLQuery {
    let threshold = age_threshold.unwrap_or(18);
    let claim_id = format!("age_over_{threshold}");

    DCQLQuery {
        credentials: vec![
            // Primary: EU Age Verification
            DCQLCredentialQuery {
                id: "eu_av_proof".to_string(),
                format: "mso_mdoc".to_string(),
                meta: DCQLCredentialMeta {
                    doctype_value: Some(EU_AV_NAMESPACE.to_string()),
                    vct_values: None,
                    type_values: None,
                },
                claims: Some(vec![DCQLClaimsQuery {
                    id: Some(claim_id.clone()),
                    // Claims Path Pointer for mso_mdoc: [namespace, element] (OpenID4VP §7.2)
                    path: vec![EU_AV_NAMESPACE.to_string(), claim_id.clone()],
                    values: None,
                    intent_to_retain: Some(false),
                }]),
                claim_sets: None,
                multiple: None,
                require_cryptographic_holder_binding: None,
            },
            // Fallback: ISO mDL
            DCQLCredentialQuery {
                id: "mdl_age_proof".to_string(),
                format: "mso_mdoc".to_string(),
                meta: DCQLCredentialMeta {
                    doctype_value: Some(ISO_MDL_DOCTYPE.to_string()),
                    vct_values: None,
                    type_values: None,
                },
                claims: Some(vec![DCQLClaimsQuery {
                    id: Some(claim_id.clone()),
                    // Claims Path Pointer for mso_mdoc: [namespace, element] (OpenID4VP §7.2)
                    path: vec![ISO_MDL_NAMESPACE.to_string(), claim_id.clone()],
                    values: None,
                    intent_to_retain: Some(false),
                }]),
                claim_sets: None,
                multiple: None,
                require_cryptographic_holder_binding: None,
            },
        ],
        credential_sets: Some(vec![crate::types::DCQLCredentialSetQuery {
            options: vec![
                vec!["eu_av_proof".to_string()],
                vec!["mdl_age_proof".to_string()],
            ],
            required: Some(true),
            purpose: Some("Verify age for restricted content access".to_string()),
        }]),
    }
}

/// Get the default age verification DCQL query.
///
/// Requests `age_over_18` from the EU PID namespace (`eu.europa.ec.eudi.pid.1`).
/// This matches the TypeScript `getDefaultAgeVerificationDCQL()`.
pub fn get_default_age_verification_dcql() -> DCQLQuery {
    DCQLQuery {
        credentials: vec![DCQLCredentialQuery {
            id: "eu_pid_age".to_string(),
            format: "mso_mdoc".to_string(),
            meta: DCQLCredentialMeta {
                doctype_value: Some(EU_PID_DOCTYPE.to_string()),
                vct_values: None,
                type_values: None,
            },
            claims: Some(vec![DCQLClaimsQuery {
                id: Some("age_over_18".to_string()),
                // Claims Path Pointer for mso_mdoc: [namespace, element] (OpenID4VP §7.2)
                path: vec![EU_PID_NAMESPACE.to_string(), "age_over_18".to_string()],
                values: None,
                intent_to_retain: Some(false),
            }]),
            claim_sets: None,
            multiple: None,
            require_cryptographic_holder_binding: None,
        }],
        credential_sets: None,
    }
}

/// Convert a legacy PresentationDefinition to DCQL.
///
/// Parses `input_descriptors` from the presentation definition and
/// maps their `constraints.fields` to DCQL claims queries.
/// Supports both bracket notation (`$['ns']['claim']`) and
/// dot notation (`$.credentialSubject.claim`).
pub fn convert_presentation_definition_to_dcql(
    presentation_definition: &serde_json::Value,
) -> Option<DCQLQuery> {
    let input_descriptors = presentation_definition
        .get("input_descriptors")
        .and_then(|v| v.as_array())?;

    let mut credentials = Vec::new();

    for descriptor in input_descriptors {
        let id = descriptor
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("credential")
            .to_string();

        // Try to extract format
        let format = descriptor
            .get("format")
            .and_then(|f| {
                if f.get("mso_mdoc").is_some() {
                    Some("mso_mdoc")
                } else if f.get("jwt_vc").is_some() || f.get("jwt_vc_json").is_some() {
                    Some("jwt_vc_json")
                } else if f.get("ldp_vc").is_some() {
                    Some("ldp_vc")
                } else {
                    None
                }
            })
            .unwrap_or("mso_mdoc")
            .to_string();

        // Extract claims from constraints.fields
        let claims = descriptor
            .get("constraints")
            .and_then(|c| c.get("fields"))
            .and_then(|f| f.as_array())
            .map(|fields| {
                fields
                    .iter()
                    .filter_map(|field| {
                        let path = field.get("path").and_then(|p| p.as_array())?;
                        let path_strings: Vec<String> = path
                            .iter()
                            .filter_map(|p| p.as_str().map(String::from))
                            .collect();
                        if path_strings.is_empty() {
                            return None;
                        }

                        // Extract claim ID from path or field ID
                        let claim_id = field
                            .get("id")
                            .and_then(|v| v.as_str())
                            .map(String::from)
                            .or_else(|| extract_claim_id_from_path(&path_strings[0]));

                        // For mso_mdoc, convert JSONPath bracket notation to
                        // Claims Path Pointer (two-element array) per §7.2:
                        //   "$['namespace']['element']" → ["namespace", "element"]
                        let converted_path = if format == "mso_mdoc" && path_strings.len() == 1 {
                            if let (Some(ns), Some(elem)) = (
                                extract_namespace_from_path(&path_strings[0]),
                                extract_claim_id_from_path(&path_strings[0]),
                            ) {
                                vec![ns, elem]
                            } else {
                                path_strings
                            }
                        } else {
                            path_strings
                        };

                        Some(DCQLClaimsQuery {
                            id: claim_id,
                            path: converted_path,
                            values: None,
                            intent_to_retain: field
                                .get("intent_to_retain")
                                .and_then(|v| v.as_bool()),
                        })
                    })
                    .collect::<Vec<_>>()
            });

        // Extract doctype from format metadata, falling back to the namespace
        // from the first converted claim's path (matching TypeScript behaviour).
        //
        // The webapp frontend sends `format: { mso_mdoc: { alg: [...] } }` without
        // a `doctype` field, so we derive it from the claims. The TypeScript
        // `convertPresentationDefinitionToDCQL` uses `path[0]` of the first claim
        // as the authoritative `doctype_value`, which is what the EUDI Wallet
        // needs to match against its stored credentials.
        let explicit_doctype = descriptor
            .get("format")
            .and_then(|f| f.get("mso_mdoc"))
            .and_then(|m| m.get("doctype"))
            .and_then(|d| d.as_str())
            .map(String::from);

        // Derive doctype from first claim's namespace (path[0]) if not explicit
        let doctype_value = explicit_doctype.or_else(|| {
            claims
                .as_ref()
                .and_then(|c| c.first())
                .and_then(|first_claim| first_claim.path.first().cloned())
        });

        let meta = DCQLCredentialMeta {
            doctype_value,
            vct_values: None,
            type_values: None,
        };

        credentials.push(DCQLCredentialQuery {
            id,
            format,
            meta,
            claims,
            claim_sets: None,
            multiple: None,
            require_cryptographic_holder_binding: None,
        });
    }

    if credentials.is_empty() {
        None
    } else {
        Some(DCQLQuery {
            credentials,
            credential_sets: None,
        })
    }
}

/// Generate a cryptographically random nonce (32 bytes, base64url-encoded).
pub fn generate_nonce() -> String {
    use base64::Engine;
    let mut bytes = [0u8; 32];
    openssl::rand::rand_bytes(&mut bytes).expect("openssl random bytes");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

// ============================================================================
// Path Parsing Helpers
// ============================================================================

/// Extract namespace from bracket notation path.
///
/// `"$['eu.europa.ec.av.1']['age_over_18']"` → `Some("eu.europa.ec.av.1")`
fn extract_namespace_from_path(path: &str) -> Option<String> {
    // Match $['namespace']['claim'] pattern
    if path.starts_with("$[") {
        let parts: Vec<&str> = path.split("']['").collect();
        if parts.len() >= 2 {
            let ns = parts[0].trim_start_matches("$['").trim_end_matches('\'');
            return Some(ns.to_string());
        }
    }
    None
}

/// Extract claim ID from a path expression.
///
/// - Bracket: `"$['ns']['claim_id']"` → `Some("claim_id")`
/// - Dot: `"$.credentialSubject.name"` → `Some("name")`
fn extract_claim_id_from_path(path: &str) -> Option<String> {
    if path.contains("']['") {
        // Bracket notation
        let parts: Vec<&str> = path.split("']['").collect();
        if let Some(last) = parts.last() {
            let id = last.trim_end_matches("']").trim_end_matches('\'');
            return Some(id.to_string());
        }
    } else if path.contains('.') {
        // Dot notation
        let parts: Vec<&str> = path.split('.').collect();
        return parts.last().map(|s| s.to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_age_verification_query() {
        let query = build_age_verification_query(None);
        assert_eq!(query.credentials.len(), 1);
        assert_eq!(query.credentials[0].id, "eu_av_proof");
        assert_eq!(query.credentials[0].format, "mso_mdoc");
        let claims = query.credentials[0].claims.as_ref().unwrap();
        assert_eq!(claims[0].id.as_deref(), Some("age_over_18"));
    }

    #[test]
    fn test_build_age_verification_query_custom_threshold() {
        let query = build_age_verification_query(Some(21));
        let claims = query.credentials[0].claims.as_ref().unwrap();
        assert_eq!(claims[0].id.as_deref(), Some("age_over_21"));
        // Claims Path Pointer: [namespace, element] per §7.2
        assert_eq!(claims[0].path.len(), 2);
        assert_eq!(claims[0].path[0], EU_AV_NAMESPACE);
        assert_eq!(claims[0].path[1], "age_over_21");
    }

    #[test]
    fn test_build_query_with_fallback() {
        let query = build_age_verification_query_with_fallback(None);
        assert_eq!(query.credentials.len(), 2);
        assert_eq!(query.credentials[0].id, "eu_av_proof");
        assert_eq!(query.credentials[1].id, "mdl_age_proof");

        let sets = query.credential_sets.as_ref().unwrap();
        assert_eq!(sets.len(), 1);
        assert_eq!(sets[0].options.len(), 2);
    }

    #[test]
    fn test_generate_nonce() {
        let nonce = generate_nonce();
        assert!(!nonce.is_empty());
        // base64url-encoded 32 bytes = 43 characters
        assert_eq!(nonce.len(), 43);

        // Nonces should be unique
        let nonce2 = generate_nonce();
        assert_ne!(nonce, nonce2);
    }

    #[test]
    fn test_extract_namespace_from_path() {
        assert_eq!(
            extract_namespace_from_path("$['eu.europa.ec.av.1']['age_over_18']"),
            Some("eu.europa.ec.av.1".to_string())
        );
        assert_eq!(
            extract_namespace_from_path("$['org.iso.18013.5.1']['family_name']"),
            Some("org.iso.18013.5.1".to_string())
        );
        assert_eq!(
            extract_namespace_from_path("$.credentialSubject.name"),
            None
        );
    }

    #[test]
    fn test_extract_claim_id_from_path() {
        assert_eq!(
            extract_claim_id_from_path("$['eu.europa.ec.av.1']['age_over_18']"),
            Some("age_over_18".to_string())
        );
        assert_eq!(
            extract_claim_id_from_path("$.credentialSubject.familyName"),
            Some("familyName".to_string())
        );
    }

    #[test]
    fn test_convert_presentation_definition() {
        let pd = serde_json::json!({
            "id": "age-verification",
            "input_descriptors": [{
                "id": "age_proof",
                "format": {
                    "mso_mdoc": {
                        "doctype": "eu.europa.ec.av.1"
                    }
                },
                "constraints": {
                    "fields": [{
                        "path": ["$['eu.europa.ec.av.1']['age_over_18']"],
                        "id": "age_over_18",
                        "intent_to_retain": false
                    }]
                }
            }]
        });

        let query = convert_presentation_definition_to_dcql(&pd).unwrap();
        assert_eq!(query.credentials.len(), 1);
        assert_eq!(query.credentials[0].id, "age_proof");
        let meta = &query.credentials[0].meta;
        assert_eq!(meta.doctype_value.as_deref(), Some("eu.europa.ec.av.1"));
        let claims = query.credentials[0].claims.as_ref().unwrap();
        assert_eq!(claims[0].id.as_deref(), Some("age_over_18"));
        // Bracket notation should be converted to two-element path (§7.2)
        assert_eq!(claims[0].path, vec!["eu.europa.ec.av.1", "age_over_18"]);
    }

    #[test]
    fn test_convert_presentation_definition_no_doctype() {
        // This matches what the webapp frontend actually sends:
        // format.mso_mdoc has alg but NO doctype.
        // The doctype_value must be derived from the first claim's namespace.
        let pd = serde_json::json!({
            "id": "age-verification",
            "input_descriptors": [{
                "id": "proof-of-age_credential",
                "format": {
                    "mso_mdoc": {
                        "alg": ["ES256", "ES384", "ES512", "EdDSA"]
                    }
                },
                "constraints": {
                    "limit_disclosure": "required",
                    "fields": [{
                        "path": ["$['eu.europa.ec.av.1']['age_over_18']"],
                        "id": "age_over_18",
                        "intent_to_retain": false
                    }]
                }
            }]
        });

        let query = convert_presentation_definition_to_dcql(&pd).unwrap();
        assert_eq!(query.credentials.len(), 1);
        let meta = &query.credentials[0].meta;
        // doctype_value should be derived from the first claim's namespace
        assert_eq!(meta.doctype_value.as_deref(), Some("eu.europa.ec.av.1"));
        let claims = query.credentials[0].claims.as_ref().unwrap();
        assert_eq!(claims[0].path, vec!["eu.europa.ec.av.1", "age_over_18"]);
    }

    #[test]
    fn test_default_age_verification_dcql() {
        let query = get_default_age_verification_dcql();
        assert_eq!(query.credentials.len(), 1);
        assert_eq!(query.credentials[0].id, "eu_pid_age");
        let meta = &query.credentials[0].meta;
        assert_eq!(
            meta.doctype_value.as_deref(),
            Some("eu.europa.ec.eudi.pid.1")
        );
    }
}
