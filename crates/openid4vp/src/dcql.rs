//! DCQL (Digital Credentials Query Language) builder utilities.
//!
//! Implements query construction per OpenID4VP 1.0 §6 for requesting
//! credentials from digital wallets. Supports EU Age Verification,
//! mDL, and PID credential types.
//!
//! References:
//! - <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6>
//! - EU Age Verification Profile Annex A

use crate::types::{
    ClaimsPathComponent, DCQLClaimsQuery, DCQLCredentialMeta, DCQLCredentialQuery, DCQLQuery,
};

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
/// ```
/// use ewqwe_openid4vp::build_age_verification_query;
/// let query = build_age_verification_query(Some(21));
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
                // id is omitted: only required when referenced by claim_sets,
                // which this query does not use.
                id: None,
                // Claims Path Pointer for mso_mdoc: [namespace, element] (OpenID4VP §7.2)
                path: vec![EU_AV_NAMESPACE.into(), claim_id.clone().into()],
                values: None,
                // intent_to_retain is omitted: false ("do not retain") is the
                // default interpretation when the field is absent.
                intent_to_retain: None,
            }]),
            claim_sets: None,
            multiple: None,
            trusted_authorities: None,
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
                    id: None,
                    // Claims Path Pointer for mso_mdoc: [namespace, element] (OpenID4VP §7.2)
                    path: vec![EU_AV_NAMESPACE.into(), claim_id.clone().into()],
                    values: None,
                    intent_to_retain: None,
                }]),
                claim_sets: None,
                multiple: None,
                trusted_authorities: None,
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
                    id: None,
                    // Claims Path Pointer for mso_mdoc: [namespace, element] (OpenID4VP §7.2)
                    path: vec![ISO_MDL_NAMESPACE.into(), claim_id.clone().into()],
                    values: None,
                    intent_to_retain: None,
                }]),
                claim_sets: None,
                multiple: None,
                trusted_authorities: None,
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
                id: None,
                // Claims Path Pointer for mso_mdoc: [namespace, element] (OpenID4VP §7.2)
                path: vec![EU_PID_NAMESPACE.into(), "age_over_18".into()],
                values: None,
                intent_to_retain: None,
            }]),
            claim_sets: None,
            multiple: None,
            trusted_authorities: None,
            require_cryptographic_holder_binding: None,
        }],
        credential_sets: None,
    }
}

/// Build a default DCQL query for the given credential type string.
///
/// - `"proof-of-age"` / `"proof_of_age"` → EU Age Verification (`eu.europa.ec.av.1`)
/// - `"mdl"` → ISO mDL (`org.iso.18013.5.1.mDL`)
/// - `"national-id"` / `"pid"` → EU PID (`eu.europa.ec.eudi.pid.1`)
/// - anything else → EU PID (backward-compatible default)
pub fn build_default_dcql_for_credential_type(credential_type: &str) -> DCQLQuery {
    match credential_type {
        "proof-of-age" | "proof_of_age" => build_age_verification_query(None),
        "mdl" => DCQLQuery {
            credentials: vec![DCQLCredentialQuery {
                id: "mdl_age".to_string(),
                format: "mso_mdoc".to_string(),
                meta: DCQLCredentialMeta {
                    doctype_value: Some(ISO_MDL_DOCTYPE.to_string()),
                    vct_values: None,
                    type_values: None,
                },
                claims: Some(vec![DCQLClaimsQuery {
                    id: None,
                    path: vec![ISO_MDL_NAMESPACE.into(), "age_over_18".into()],
                    values: None,
                    intent_to_retain: None,
                }]),
                claim_sets: None,
                multiple: None,
                trusted_authorities: None,
                require_cryptographic_holder_binding: None,
            }],
            credential_sets: None,
        },
        _ => get_default_age_verification_dcql(),
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
                        let converted_path: Vec<ClaimsPathComponent> = if format == "mso_mdoc"
                            && path_strings.len() == 1
                        {
                            if let (Some(ns), Some(elem)) = (
                                extract_namespace_from_path(&path_strings[0]),
                                extract_claim_id_from_path(&path_strings[0]),
                            ) {
                                vec![ClaimsPathComponent::Key(ns), ClaimsPathComponent::Key(elem)]
                            } else {
                                path_strings
                                    .into_iter()
                                    .map(ClaimsPathComponent::Key)
                                    .collect()
                            }
                        } else {
                            path_strings
                                .into_iter()
                                .map(ClaimsPathComponent::Key)
                                .collect()
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
                .and_then(|first_claim| match first_claim.path.first() {
                    Some(ClaimsPathComponent::Key(s)) => Some(s.clone()),
                    _ => None,
                })
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
            trusted_authorities: None,
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
    use crate::types::ClaimsPathComponent;

    #[test]
    fn test_build_age_verification_query() {
        let query = build_age_verification_query(None);
        assert_eq!(query.credentials.len(), 1);
        assert_eq!(query.credentials[0].id, "eu_av_proof");
        assert_eq!(query.credentials[0].format, "mso_mdoc");
        let claims = query.credentials[0].claims.as_ref().unwrap();
        assert_eq!(claims[0].id, None);
    }

    #[test]
    fn test_build_age_verification_query_custom_threshold() {
        let query = build_age_verification_query(Some(21));
        let claims = query.credentials[0].claims.as_ref().unwrap();
        assert_eq!(claims[0].id, None);
        // Claims Path Pointer: [namespace, element] per §7.2
        assert_eq!(claims[0].path.len(), 2);
        assert_eq!(
            claims[0].path[0],
            ClaimsPathComponent::from(EU_AV_NAMESPACE)
        );
        assert_eq!(claims[0].path[1], ClaimsPathComponent::from("age_over_21"));
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
        assert_eq!(
            claims[0].path,
            vec![
                ClaimsPathComponent::Key("eu.europa.ec.av.1".to_string()),
                ClaimsPathComponent::Key("age_over_18".to_string()),
            ]
        );
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
        assert_eq!(
            claims[0].path,
            vec![
                ClaimsPathComponent::Key("eu.europa.ec.av.1".to_string()),
                ClaimsPathComponent::Key("age_over_18".to_string()),
            ]
        );
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

    // =========================================================================
    // Appendix D — Non-normative DCQL query examples from the spec
    // https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-D
    // =========================================================================
    mod appendix_d {
        use crate::types::{
            ClaimsPathComponent, DCQLClaimsQuery, DCQLCredentialMeta, DCQLCredentialQuery,
            DCQLQuery,
        };

        // Helper: key component from a &str.
        fn key(s: &str) -> ClaimsPathComponent {
            ClaimsPathComponent::Key(s.to_string())
        }

        // Helper: assert a DCQLQuery round-trips through JSON unchanged.
        // Returns the deserialized value so callers can do further assertions.
        fn roundtrip(q: &DCQLQuery) -> DCQLQuery {
            let json = serde_json::to_value(q).expect("serialize");
            let back: DCQLQuery = serde_json::from_value(json).expect("deserialize");
            back
        }

        // Helper: deserialize the verbatim spec JSON into a DCQLQuery.
        fn from_spec(json: serde_json::Value) -> DCQLQuery {
            serde_json::from_value(json).expect("parse spec JSON")
        }

        /// Appendix D §1 — mVRC: single mso_mdoc credential requesting
        /// `vehicle_holder` from namespace `org.iso.7367.1` and
        /// `first_name` from namespace `org.iso.18013.5.1`.
        #[test]
        fn example1_mvrc_single_mdoc() {
            // Verbatim spec JSON (Appendix D, first example).
            let spec_json = serde_json::json!({
                "credentials": [{
                    "id": "my_credential",
                    "format": "mso_mdoc",
                    "meta": {"doctype_value": "org.iso.7367.1.mVRC"},
                    "claims": [
                        {"path": ["org.iso.7367.1", "vehicle_holder"]},
                        {"path": ["org.iso.18013.5.1", "first_name"]}
                    ]
                }]
            });

            let parsed = from_spec(spec_json);
            assert!(parsed.is_valid().is_ok(), "{:?}", parsed.is_valid());
            assert_eq!(parsed.credentials.len(), 1);
            assert!(parsed.credential_sets.is_none());

            let cred = &parsed.credentials[0];
            assert_eq!(cred.id, "my_credential");
            assert_eq!(cred.format, "mso_mdoc");
            assert_eq!(
                cred.meta.doctype_value.as_deref(),
                Some("org.iso.7367.1.mVRC")
            );

            let claims = cred.claims.as_ref().unwrap();
            assert_eq!(claims.len(), 2);
            assert_eq!(
                claims[0].path,
                vec![key("org.iso.7367.1"), key("vehicle_holder")]
            );
            assert_eq!(
                claims[1].path,
                vec![key("org.iso.18013.5.1"), key("first_name")]
            );

            // Also verify the equivalent query built from structs round-trips.
            let built = DCQLQuery {
                credentials: vec![DCQLCredentialQuery {
                    id: "my_credential".into(),
                    format: "mso_mdoc".into(),
                    meta: DCQLCredentialMeta {
                        doctype_value: Some("org.iso.7367.1.mVRC".into()),
                        ..Default::default()
                    },
                    claims: Some(vec![
                        DCQLClaimsQuery {
                            id: None,
                            path: vec![key("org.iso.7367.1"), key("vehicle_holder")],
                            values: None,
                            intent_to_retain: None,
                        },
                        DCQLClaimsQuery {
                            id: None,
                            path: vec![key("org.iso.18013.5.1"), key("first_name")],
                            values: None,
                            intent_to_retain: None,
                        },
                    ]),
                    claim_sets: None,
                    multiple: None,
                    trusted_authorities: None,
                    require_cryptographic_holder_binding: None,
                }],
                credential_sets: None,
            };
            assert!(built.is_valid().is_ok());
            let rt = roundtrip(&built);
            assert_eq!(rt.credentials[0].format, "mso_mdoc");
            assert_eq!(
                rt.credentials[0].claims.as_ref().unwrap()[0].path,
                vec![key("org.iso.7367.1"), key("vehicle_holder")]
            );
        }

        /// Appendix D §2 — Two credentials, both must be returned (no credential_sets).
        /// `pid` is dc+sd-jwt; `mdl` is mso_mdoc.
        #[test]
        fn example2_multiple_credentials_all_required() {
            let spec_json = serde_json::json!({
                "credentials": [
                    {
                        "id": "pid",
                        "format": "dc+sd-jwt",
                        "meta": {
                            "vct_values": ["https://credentials.example.com/identity_credential"]
                        },
                        "claims": [
                            {"path": ["given_name"]},
                            {"path": ["family_name"]},
                            {"path": ["address", "street_address"]}
                        ]
                    },
                    {
                        "id": "mdl",
                        "format": "mso_mdoc",
                        "meta": {"doctype_value": "org.iso.7367.1.mVRC"},
                        "claims": [
                            {"path": ["org.iso.7367.1", "vehicle_holder"]},
                            {"path": ["org.iso.18013.5.1", "first_name"]}
                        ]
                    }
                ]
            });

            let parsed = from_spec(spec_json);
            assert!(parsed.is_valid().is_ok(), "{:?}", parsed.is_valid());
            // Without credential_sets, all credentials are required (§6.4.2).
            assert_eq!(parsed.credentials.len(), 2);
            assert!(parsed.credential_sets.is_none());

            let pid = &parsed.credentials[0];
            assert_eq!(pid.id, "pid");
            assert_eq!(pid.format, "dc+sd-jwt");
            assert_eq!(
                pid.meta.vct_values.as_deref(),
                Some(&["https://credentials.example.com/identity_credential".to_string()][..])
            );
            let pid_claims = pid.claims.as_ref().unwrap();
            assert_eq!(pid_claims[0].path, vec![key("given_name")]);
            assert_eq!(pid_claims[1].path, vec![key("family_name")]);
            assert_eq!(
                pid_claims[2].path,
                vec![key("address"), key("street_address")]
            );

            let mdl = &parsed.credentials[1];
            assert_eq!(mdl.id, "mdl");
            assert_eq!(mdl.format, "mso_mdoc");

            roundtrip(&parsed); // must not panic
        }

        /// Appendix D §3 — Complex credential_sets:
        /// pid OR other_pid OR (pid_reduced_cred_1 + pid_reduced_cred_2),
        /// plus optional nice_to_have.
        #[test]
        fn example3_complex_credential_sets() {
            let spec_json = serde_json::json!({
                "credentials": [
                    {
                        "id": "pid",
                        "format": "dc+sd-jwt",
                        "meta": {"vct_values": ["https://credentials.example.com/identity_credential"]},
                        "claims": [
                            {"path": ["given_name"]},
                            {"path": ["family_name"]},
                            {"path": ["address", "street_address"]}
                        ]
                    },
                    {
                        "id": "other_pid",
                        "format": "dc+sd-jwt",
                        "meta": {"vct_values": ["https://othercredentials.example/pid"]},
                        "claims": [
                            {"path": ["given_name"]},
                            {"path": ["family_name"]},
                            {"path": ["address", "street_address"]}
                        ]
                    },
                    {
                        "id": "pid_reduced_cred_1",
                        "format": "dc+sd-jwt",
                        "meta": {"vct_values": ["https://credentials.example.com/reduced_identity_credential"]},
                        "claims": [
                            {"path": ["family_name"]},
                            {"path": ["given_name"]}
                        ]
                    },
                    {
                        "id": "pid_reduced_cred_2",
                        "format": "dc+sd-jwt",
                        "meta": {"vct_values": ["https://cred.example/residence_credential"]},
                        "claims": [
                            {"path": ["postal_code"]},
                            {"path": ["locality"]},
                            {"path": ["region"]}
                        ]
                    },
                    {
                        "id": "nice_to_have",
                        "format": "dc+sd-jwt",
                        "meta": {"vct_values": ["https://company.example/company_rewards"]},
                        "claims": [{"path": ["rewards_number"]}]
                    }
                ],
                "credential_sets": [
                    {
                        "options": [
                            ["pid"],
                            ["other_pid"],
                            ["pid_reduced_cred_1", "pid_reduced_cred_2"]
                        ]
                    },
                    {
                        "required": false,
                        "options": [["nice_to_have"]]
                    }
                ]
            });

            let parsed = from_spec(spec_json);
            assert!(parsed.is_valid().is_ok(), "{:?}", parsed.is_valid());
            assert_eq!(parsed.credentials.len(), 5);

            let sets = parsed.credential_sets.as_ref().unwrap();
            assert_eq!(sets.len(), 2);

            // First set is required (default), has three options.
            assert_eq!(sets[0].required, None); // default = true per §6.2
            assert_eq!(sets[0].options.len(), 3);
            assert_eq!(sets[0].options[0], vec!["pid"]);
            assert_eq!(sets[0].options[1], vec!["other_pid"]);
            assert_eq!(
                sets[0].options[2],
                vec!["pid_reduced_cred_1", "pid_reduced_cred_2"]
            );

            // Second set is optional.
            assert_eq!(sets[1].required, Some(false));
            assert_eq!(sets[1].options[0], vec!["nice_to_have"]);

            roundtrip(&parsed);
        }

        /// Appendix D §4 — mdl/photo_card: ID and address can come from either mDL
        /// or photo_card; address is optional.
        #[test]
        fn example4_mdl_or_photo_card_with_optional_address() {
            let spec_json = serde_json::json!({
                "credentials": [
                    {
                        "id": "mdl-id",
                        "format": "mso_mdoc",
                        "meta": {"doctype_value": "org.iso.18013.5.1.mDL"},
                        "claims": [
                            {"id": "given_name",  "path": ["org.iso.18013.5.1", "given_name"]},
                            {"id": "family_name", "path": ["org.iso.18013.5.1", "family_name"]},
                            {"id": "portrait",    "path": ["org.iso.18013.5.1", "portrait"]}
                        ]
                    },
                    {
                        "id": "mdl-address",
                        "format": "mso_mdoc",
                        "meta": {"doctype_value": "org.iso.18013.5.1.mDL"},
                        "claims": [
                            {"id": "resident_address", "path": ["org.iso.18013.5.1", "resident_address"]},
                            {"id": "resident_country", "path": ["org.iso.18013.5.1", "resident_country"]}
                        ]
                    },
                    {
                        "id": "photo_card-id",
                        "format": "mso_mdoc",
                        "meta": {"doctype_value": "org.iso.23220.photoid.1"},
                        "claims": [
                            {"id": "given_name",  "path": ["org.iso.18013.5.1", "given_name"]},
                            {"id": "family_name", "path": ["org.iso.18013.5.1", "family_name"]},
                            {"id": "portrait",    "path": ["org.iso.18013.5.1", "portrait"]}
                        ]
                    },
                    {
                        "id": "photo_card-address",
                        "format": "mso_mdoc",
                        "meta": {"doctype_value": "org.iso.23220.photoid.1"},
                        "claims": [
                            {"id": "resident_address", "path": ["org.iso.18013.5.1", "resident_address"]},
                            {"id": "resident_country", "path": ["org.iso.18013.5.1", "resident_country"]}
                        ]
                    }
                ],
                "credential_sets": [
                    {
                        "options": [["mdl-id"], ["photo_card-id"]]
                    },
                    {
                        "required": false,
                        "options": [["mdl-address"], ["photo_card-address"]]
                    }
                ]
            });

            let parsed = from_spec(spec_json);
            assert!(parsed.is_valid().is_ok(), "{:?}", parsed.is_valid());
            assert_eq!(parsed.credentials.len(), 4);

            let sets = parsed.credential_sets.as_ref().unwrap();
            assert_eq!(sets.len(), 2);

            // Required set: mdl-id OR photo_card-id.
            assert_eq!(sets[0].options, vec![vec!["mdl-id"], vec!["photo_card-id"]]);
            // Optional set: mdl-address OR photo_card-address.
            assert_eq!(sets[1].required, Some(false));
            assert_eq!(
                sets[1].options,
                vec![vec!["mdl-address"], vec!["photo_card-address"]]
            );

            // Claims have ids for use with claim_sets (§6.3).
            let mdl_id_claims = parsed.credentials[0].claims.as_ref().unwrap();
            assert_eq!(mdl_id_claims[0].id.as_deref(), Some("given_name"));
            assert_eq!(
                mdl_id_claims[0].path,
                vec![key("org.iso.18013.5.1"), key("given_name")]
            );

            roundtrip(&parsed);
        }

        /// Appendix D §5 — claim_sets: mandatory (last_name, date_of_birth) plus
        /// either postal_code or (locality + region).
        #[test]
        fn example5_claim_sets_mandatory_plus_alternatives() {
            let spec_json = serde_json::json!({
                "credentials": [{
                    "id": "pid",
                    "format": "dc+sd-jwt",
                    "meta": {
                        "vct_values": ["https://credentials.example.com/identity_credential"]
                    },
                    "claims": [
                        {"id": "a", "path": ["last_name"]},
                        {"id": "b", "path": ["postal_code"]},
                        {"id": "c", "path": ["locality"]},
                        {"id": "d", "path": ["region"]},
                        {"id": "e", "path": ["date_of_birth"]}
                    ],
                    "claim_sets": [
                        ["a", "c", "d", "e"],
                        ["a", "b", "e"]
                    ]
                }]
            });

            let parsed = from_spec(spec_json);
            assert!(parsed.is_valid().is_ok(), "{:?}", parsed.is_valid());
            let cred = &parsed.credentials[0];
            assert_eq!(cred.format, "dc+sd-jwt");

            let claims = cred.claims.as_ref().unwrap();
            assert_eq!(claims.len(), 5);
            // All claims must have ids when claim_sets is present (§6.4.1).
            for claim in claims {
                assert!(claim.id.is_some(), "every claim needs an id");
            }
            assert_eq!(claims[0].path, vec![key("last_name")]);
            assert_eq!(claims[4].path, vec![key("date_of_birth")]);

            let claim_sets = cred.claim_sets.as_ref().unwrap();
            assert_eq!(claim_sets.len(), 2);
            // First option: last_name + locality + region + date_of_birth (privacy-preferred).
            assert_eq!(claim_sets[0], vec!["a", "c", "d", "e"]);
            // Second option: last_name + postal_code + date_of_birth.
            assert_eq!(claim_sets[1], vec!["a", "b", "e"]);

            roundtrip(&parsed);
        }

        /// Appendix D §6 — values constraints: specific expected values for
        /// `last_name` and `postal_code` claims.
        #[test]
        fn example6_values_constraints() {
            let spec_json = serde_json::json!({
                "credentials": [{
                    "id": "my_credential",
                    "format": "dc+sd-jwt",
                    "meta": {
                        "vct_values": ["https://credentials.example.com/identity_credential"]
                    },
                    "claims": [
                        {"path": ["last_name"],  "values": ["Doe"]},
                        {"path": ["first_name"]},
                        {"path": ["address", "street_address"]},
                        {"path": ["postal_code"], "values": ["90210", "90211"]}
                    ]
                }]
            });

            let parsed = from_spec(spec_json);
            assert!(parsed.is_valid().is_ok(), "{:?}", parsed.is_valid());
            let claims = parsed.credentials[0].claims.as_ref().unwrap();
            assert_eq!(claims.len(), 4);

            // last_name: values = ["Doe"]
            assert_eq!(claims[0].path, vec![key("last_name")]);
            let last_name_vals = claims[0].values.as_ref().unwrap();
            assert_eq!(last_name_vals, &[serde_json::json!("Doe")]);

            // first_name: no values constraint
            assert_eq!(claims[1].path, vec![key("first_name")]);
            assert!(claims[1].values.is_none());

            // address.street_address: nested path, no values constraint
            assert_eq!(claims[2].path, vec![key("address"), key("street_address")]);
            assert!(claims[2].values.is_none());

            // postal_code: values = ["90210", "90211"]
            assert_eq!(claims[3].path, vec![key("postal_code")]);
            let postal_vals = claims[3].values.as_ref().unwrap();
            assert_eq!(
                postal_vals,
                &[serde_json::json!("90210"), serde_json::json!("90211")]
            );

            roundtrip(&parsed);
        }
    }
}
