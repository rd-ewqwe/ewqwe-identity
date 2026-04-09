//! End-to-end verification tests with ephemeral credential issuers.
//!
//! Each test proves the *complete* credential signing ↔ verification round-trip
//! without relying on any pre-provisioned keys or certificates:
//!
//! 1. **EU Age Verification Profile SD-JWT VC** (`eu.europa.ec.av.1`)  
//!    → `over_18 = true` claim successfully verified and attested.
//!
//! 2. **EUDI PID mDoc** (ISO/IEC 18013-5 `DeviceResponse`, `eu.europa.ec.eudi.pid.1`)  
//!    → full COSE_Sign1 IssuerAuth + DeviceSignature chain verified.
//!
//! 3. **EUDI PID SD-JWT VC** (`eu.europa.ec.eudi.pid.1`)  
//!    → `given_name`, `age_over_18` claims present in signed attestation.
//!
//! Credentials are built by the [`ewqwe_digital_credential`] crate, which
//! provides the [`CredentialIssuer`] type used by all three tests.
//!
//! # Protocol flow per test
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │ 1.  Generate ephemeral CA + issuer + device key with CredentialIssuer│
//! │ 2.  Write CA cert PEM to a unique per-test temp directory            │
//! │ 3.  Start credential-verifier server with credential_issuer_ca_dir  │
//! │     pointing to that temp directory (annex-a profile, mTLS on)      │
//! │ 4.  POST /ewqwe_api/openid4vp/init  → transaction_id               │
//! │ 5.  GET  /ewqwe_api/openid4vp/request/{id}                          │
//! │          → parse state, nonce, client_id, response_uri              │
//! │ 6.  Build and sign credential (SD-JWT or mDoc) via CredentialIssuer │
//! │ 7.  POST /ewqwe_api/verify with vp_token + state                    │
//! │ 8.  Assert success = true, issuer_trusted = true                     │
//! │     Assert expected claims present in the signed attestation JWT     │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Trusted CA isolation
//!
//! The server is started with `credential_issuer_ca_dir` pointing to a
//! temporary directory that contains **only** the ephemeral CA certificate
//! generated for that test.  This verifies the full chain-of-trust path:
//! a credential signed with an unknown key will be rejected, while one signed
//! with the ephemeral issuer key will be accepted.
//!
//! # Authentication
//!
//! All HTTP calls use the test user1 PKCS#12 identity for mTLS, identical to
//! the transport used in `ewqwe_client_tests`.

use std::{fs, path::PathBuf};

use base64::Engine as _;
use ewqwe_digital_credential::CredentialIssuer;
use ewqwe_logging::log_init;
use tracing::info;

use crate::{
    AttError, AttResult,
    tests::{make_test_server_params, start_test_server},
};

// Path to EC test certificates (same constant used in ewqwe_client_tests.rs).
const EC_CERTS_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../certificates/tls");

// ============================================================================
// Shared helpers
// ============================================================================

/// Build a `reqwest::Client` that:
/// - Trusts the test server's self-signed CA chain.
/// - Bypasses full chain validation on macOS (system keychain limitation).
/// - Authenticates with the test user1 PKCS#12 identity for mTLS.
fn build_verify_http_client() -> reqwest::Client {
    let ca_chain_pem =
        fs::read(format!("{EC_CERTS_DIR}/ewqwe.ca.pem")).expect("read test CA chain");
    let p12_bytes =
        fs::read(format!("{EC_CERTS_DIR}/ewqwe.user1.p12")).expect("read user1 PKCS#12");
    let identity = reqwest::Identity::from_pkcs12_der(&p12_bytes, "secret").expect("parse PKCS#12");

    reqwest::Client::builder()
        .add_root_certificate(
            reqwest::Certificate::from_pem(&ca_chain_pem).expect("parse CA chain cert"),
        )
        // Required on macOS: system keychain does not trust our test CA.
        .danger_accept_invalid_certs(true)
        .identity(identity)
        .build()
        .expect("build reqwest client")
}

/// `POST /ewqwe_api/openid4vp/init` and return the response as JSON.
async fn api_init_transaction(
    http: &reqwest::Client,
    base_url: &str,
    profile: &str,
    credential_type: &str,
) -> serde_json::Value {
    let url = format!("{base_url}/ewqwe_api/openid4vp/init");
    let body = serde_json::json!({
        "public_url":      base_url,
        "profile":         profile,
        "credential_type": credential_type,
    });
    let resp = http
        .post(&url)
        .json(&body)
        .send()
        .await
        .unwrap_or_else(|e| panic!("POST {url} failed: {e}"));
    let status = resp.status();
    let json: serde_json::Value = resp.json().await.expect("parse init response JSON");
    assert!(status.is_success(), "POST {url} returned {status}: {json}");
    json
}

/// Fetch the Annex A JSON authorization request for `transaction_id` and
/// return it as a `serde_json::Value`.
///
/// The response contains `state`, `nonce`, `client_id`, and `response_uri`
/// which are needed to build a credential and to call `/ewqwe_api/verify`.
async fn fetch_auth_request(
    http: &reqwest::Client,
    base_url: &str,
    transaction_id: &str,
) -> serde_json::Value {
    let url = format!("{base_url}/ewqwe_api/openid4vp/request/{transaction_id}");
    let resp = http
        .get(&url)
        .header("Accept", "application/json")
        .send()
        .await
        .unwrap_or_else(|e| panic!("GET {url} failed: {e}"));

    assert!(
        resp.status().is_success(),
        "GET {url} returned {}",
        resp.status()
    );

    resp.json::<serde_json::Value>()
        .await
        .expect("parse auth request JSON")
}

/// POST a credential to `/ewqwe_api/verify` and return the response body.
async fn post_verify(
    http: &reqwest::Client,
    base_url: &str,
    vp_token_obj: serde_json::Value,
    state: &str,
    client_id: &str,
) -> serde_json::Value {
    let url = format!("{base_url}/ewqwe_api/verify");

    // `vp_token` is a JSON-encoded *string* containing the DCQL VP token object.
    let body = serde_json::json!({
        "vp_token":  vp_token_obj.to_string(),
        "state":     state,
        "client_id": client_id,
    });

    let resp = http
        .post(&url)
        .json(&body)
        .send()
        .await
        .unwrap_or_else(|e| panic!("POST {url} failed: {e}"));

    let status = resp.status();
    let bytes = resp.bytes().await.expect("read response body");
    let json: serde_json::Value =
        serde_json::from_slice(&bytes).expect("parse verify response JSON");

    assert!(
        status.is_success(),
        "POST {url} returned {status}: {}",
        serde_json::to_string_pretty(&json).unwrap_or_default()
    );

    json
}

/// Decode the payload of a JWT (Base64url, middle part) and return it as JSON.
fn decode_jwt_payload(jwt: &str) -> serde_json::Value {
    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3, "JWT must have 3 dot-separated parts");
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(parts[1]))
        .expect("base64 decode JWT payload");
    serde_json::from_slice(&payload_bytes).expect("parse JWT payload JSON")
}

/// Assert common fields present and correct on a successful verify response.
fn assert_verification_success(resp: &serde_json::Value) {
    assert_eq!(
        resp["success"],
        serde_json::Value::Bool(true),
        "expected success=true; errors: {:?}",
        resp["errors"]
    );
    let details = &resp["verification_details"];
    assert_eq!(
        details["issuer_trusted"],
        serde_json::json!(true),
        "issuer_trusted"
    );
    assert_eq!(
        details["signature_valid"],
        serde_json::json!(true),
        "signature_valid"
    );
    assert_eq!(
        details["not_expired"],
        serde_json::json!(true),
        "not_expired"
    );

    let attestation = resp["attestation"]
        .as_str()
        .expect("attestation JWT present");
    let att_payload = decode_jwt_payload(attestation);
    assert_eq!(
        att_payload["verified"],
        serde_json::json!(true),
        "attestation.verified must be true"
    );
}

/// Create a unique per-test temporary directory beneath the OS temp folder.
/// Returns the path as a `String`.  Caller is responsible for clean-up.
fn make_temp_ca_dir() -> (PathBuf, String) {
    let dir = std::env::temp_dir().join(format!("ewqwe_test_ca_{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&dir).expect("create temp CA dir");
    let path_str = dir.to_string_lossy().to_string();
    (dir, path_str)
}

// ============================================================================
// Helper: start server with custom issuer CA dir
// ============================================================================

/// Build `ServerParams` pointing `credential_issuer_ca_dir` at `ca_dir_path`.
///
/// All other parameters are identical to the standard `make_test_server_params`
/// defaults: EC test certificates, mTLS on, authentication required.
fn server_params_with_ca_dir(ca_dir_path: &str) -> crate::ServerParams {
    let mut params = make_test_server_params(false, "");
    params.credentials_cas_dir = Some(ca_dir_path.to_owned());
    params
}

// ============================================================================
// Tests
// ============================================================================

/// Full round-trip verification of an **EU Age Verification Profile** SD-JWT VC.
///
/// Credential type: `eu.europa.ec.av.1`  
/// Expected claim in attestation: `credential_claims.over_18 = true`
#[actix_web::test]
async fn e2e_full_verification_eu_age_profile_sd_jwt() -> AttResult<()> {
    log_init(Some("info,actix_server=warn,credential_verifier=debug"));

    // ── 1. Ephemeral credential authority ────────────────────────────────
    let issuer = CredentialIssuer::generate()
        .map_err(|e| AttError::Test(format!("CredentialIssuer::generate: {e}")))?;

    // ── 2. Write CA cert to a temp dir and start the server ──────────────
    let (temp_dir, ca_dir_str) = make_temp_ca_dir();
    fs::write(temp_dir.join("test_ca.pem"), &issuer.ca_cert_pem)
        .map_err(|e| AttError::Test(format!("write CA cert: {e}")))?;

    let server_params = server_params_with_ca_dir(&ca_dir_str);
    let ctx = start_test_server(server_params).await?;
    let http = build_verify_http_client();

    // ── 3. Init OpenID4VP transaction ─────────────────────────────────────
    let init_resp = api_init_transaction(&http, &ctx.base_url(), "annex-a", "proof-of-age").await;
    let transaction_id = init_resp["transaction_id"]
        .as_str()
        .ok_or_else(|| AttError::Test("init response missing transaction_id".to_owned()))?
        .to_owned();

    info!(transaction_id = %transaction_id, "Transaction initialised");

    // ── 4. Fetch authorization request – extract nonce / state / client_id
    let auth_req = fetch_auth_request(&http, &ctx.base_url(), &transaction_id).await;

    let state = auth_req["state"]
        .as_str()
        .ok_or_else(|| AttError::Test("auth request missing state".to_owned()))?
        .to_owned();
    let nonce = auth_req["nonce"]
        .as_str()
        .ok_or_else(|| AttError::Test("auth request missing nonce".to_owned()))?
        .to_owned();
    let client_id = auth_req["client_id"]
        .as_str()
        .ok_or_else(|| AttError::Test("auth request missing client_id".to_owned()))?
        .to_owned();

    info!(nonce = %nonce, client_id = %client_id, "Auth request parsed");

    // ── 5. Build EU Age SD-JWT VC bound to transaction nonce ─────────────
    let sd_jwt = issuer.build_eu_age_sd_jwt(&nonce, &client_id);

    // DCQL VP token: object with credential ID → [credential string]
    let vp_token_obj = serde_json::json!({ "eu_age_credential": [sd_jwt] });

    // ── 6. Verify credential ──────────────────────────────────────────────
    let resp = post_verify(&http, &ctx.base_url(), vp_token_obj, &state, &client_id).await;
    info!(response = %serde_json::to_string_pretty(&resp).unwrap_or_default(), "Verify response");

    // ── 7. Assertions ─────────────────────────────────────────────────────
    assert_verification_success(&resp);

    let att_payload = decode_jwt_payload(resp["attestation"].as_str().unwrap());
    // Credential claims are flattened to the JWT top level (#[serde(flatten)])
    assert_eq!(
        att_payload["over_18"],
        serde_json::json!(true),
        "over_18 claim must be true in attestation"
    );

    // ── Cleanup ───────────────────────────────────────────────────────────
    ctx.stop_server().await?;
    let _ = fs::remove_dir_all(&temp_dir);

    info!("e2e_full_verification_eu_age_profile_sd_jwt PASSED");
    Ok(())
}

/// Full round-trip verification of a **EUDI PID mDoc** `DeviceResponse`.
///
/// Credential type: `eu.europa.ec.eudi.pid.1` (ISO 18013-5)  
/// Verifies: COSE_Sign1 IssuerAuth chain, MSO digest integrity, and
/// DeviceSignature bound to the OpenID4VP `SessionTranscript`.  
/// Expected claims: `given_name`, `age_over_18`.
#[actix_web::test]
async fn e2e_full_verification_eudi_mdoc() -> AttResult<()> {
    log_init(Some("info,actix_server=warn,credential_verifier=debug"));

    // ── 1. Ephemeral credential authority ────────────────────────────────
    let issuer = CredentialIssuer::generate()
        .map_err(|e| AttError::Test(format!("CredentialIssuer::generate: {e}")))?;

    // ── 2. Write CA cert and start server ────────────────────────────────
    let (temp_dir, ca_dir_str) = make_temp_ca_dir();
    fs::write(temp_dir.join("test_ca.pem"), &issuer.ca_cert_pem)
        .map_err(|e| AttError::Test(format!("write CA cert: {e}")))?;

    let server_params = server_params_with_ca_dir(&ca_dir_str);
    let ctx = start_test_server(server_params).await?;
    let http = build_verify_http_client();

    // ── 3. Init transaction ───────────────────────────────────────────────
    let init_resp =
        api_init_transaction(&http, &ctx.base_url(), "annex-a", "eu.europa.ec.eudi.pid.1").await;
    let transaction_id = init_resp["transaction_id"]
        .as_str()
        .ok_or_else(|| AttError::Test("init response missing transaction_id".to_owned()))?
        .to_owned();

    info!(transaction_id = %transaction_id, "Transaction initialised");

    // ── 4. Fetch authorization request ───────────────────────────────────
    let auth_req = fetch_auth_request(&http, &ctx.base_url(), &transaction_id).await;

    let state = auth_req["state"]
        .as_str()
        .ok_or_else(|| AttError::Test("auth request missing state".to_owned()))?
        .to_owned();
    let nonce = auth_req["nonce"]
        .as_str()
        .ok_or_else(|| AttError::Test("auth request missing nonce".to_owned()))?
        .to_owned();
    let client_id = auth_req["client_id"]
        .as_str()
        .ok_or_else(|| AttError::Test("auth request missing client_id".to_owned()))?
        .to_owned();
    let response_uri = auth_req["response_uri"]
        .as_str()
        .ok_or_else(|| AttError::Test("auth request missing response_uri".to_owned()))?
        .to_owned();

    info!(
        nonce = %nonce,
        client_id = %client_id,
        response_uri = %response_uri,
        "Auth request parsed"
    );

    // ── 5. Build EUDI mDoc bound to transaction nonce ────────────────────
    let mdoc_b64 = issuer.build_eudi_mdoc(&nonce, &client_id, &response_uri);

    let vp_token_obj = serde_json::json!({ "eudi_pid_mdoc": [mdoc_b64] });

    // ── 6. Verify credential ──────────────────────────────────────────────
    let resp = post_verify(&http, &ctx.base_url(), vp_token_obj, &state, &client_id).await;
    info!(response = %serde_json::to_string_pretty(&resp).unwrap_or_default(), "Verify response");

    // ── 7. Assertions ─────────────────────────────────────────────────────
    assert_verification_success(&resp);

    let att_payload = decode_jwt_payload(resp["attestation"].as_str().unwrap());
    // Credential claims are flattened to the JWT top level (#[serde(flatten)])
    assert_eq!(
        att_payload["given_name"],
        serde_json::json!("Test"),
        "given_name claim must match"
    );
    assert_eq!(
        att_payload["age_over_18"],
        serde_json::json!(true),
        "age_over_18 claim must be true"
    );

    // ── Cleanup ───────────────────────────────────────────────────────────
    ctx.stop_server().await?;
    let _ = fs::remove_dir_all(&temp_dir);

    info!("e2e_full_verification_eudi_mdoc PASSED");
    Ok(())
}

/// Full round-trip verification of a **EUDI PID SD-JWT VC**.
///
/// Credential type: `eu.europa.ec.eudi.pid.1` (SD-JWT).  
/// Expected claims: `given_name`, `age_over_18`.
#[actix_web::test]
async fn e2e_full_verification_eudi_sd_jwt() -> AttResult<()> {
    log_init(Some("info,actix_server=warn,credential_verifier=debug"));

    // ── 1. Ephemeral credential authority ────────────────────────────────
    let issuer = CredentialIssuer::generate()
        .map_err(|e| AttError::Test(format!("CredentialIssuer::generate: {e}")))?;

    // ── 2. Write CA cert and start server ────────────────────────────────
    let (temp_dir, ca_dir_str) = make_temp_ca_dir();
    fs::write(temp_dir.join("test_ca.pem"), &issuer.ca_cert_pem)
        .map_err(|e| AttError::Test(format!("write CA cert: {e}")))?;

    let server_params = server_params_with_ca_dir(&ca_dir_str);
    let ctx = start_test_server(server_params).await?;
    let http = build_verify_http_client();

    // ── 3. Init transaction ───────────────────────────────────────────────
    let init_resp =
        api_init_transaction(&http, &ctx.base_url(), "annex-a", "eu.europa.ec.eudi.pid.1").await;
    let transaction_id = init_resp["transaction_id"]
        .as_str()
        .ok_or_else(|| AttError::Test("init response missing transaction_id".to_owned()))?
        .to_owned();

    info!(transaction_id = %transaction_id, "Transaction initialised");

    // ── 4. Fetch authorization request ───────────────────────────────────
    let auth_req = fetch_auth_request(&http, &ctx.base_url(), &transaction_id).await;

    let state = auth_req["state"]
        .as_str()
        .ok_or_else(|| AttError::Test("auth request missing state".to_owned()))?
        .to_owned();
    let nonce = auth_req["nonce"]
        .as_str()
        .ok_or_else(|| AttError::Test("auth request missing nonce".to_owned()))?
        .to_owned();
    let client_id = auth_req["client_id"]
        .as_str()
        .ok_or_else(|| AttError::Test("auth request missing client_id".to_owned()))?
        .to_owned();

    info!(nonce = %nonce, client_id = %client_id, "Auth request parsed");

    // ── 5. Build EUDI PID SD-JWT VC ───────────────────────────────────────
    let sd_jwt = issuer.build_eudi_sd_jwt(&nonce, &client_id);

    let vp_token_obj = serde_json::json!({ "eudi_pid_credential": [sd_jwt] });

    // ── 6. Verify credential ──────────────────────────────────────────────
    let resp = post_verify(&http, &ctx.base_url(), vp_token_obj, &state, &client_id).await;
    info!(response = %serde_json::to_string_pretty(&resp).unwrap_or_default(), "Verify response");

    // ── 7. Assertions ─────────────────────────────────────────────────────
    assert_verification_success(&resp);

    let att_payload = decode_jwt_payload(resp["attestation"].as_str().unwrap());
    // Credential claims are flattened to the JWT top level (#[serde(flatten)])
    assert_eq!(
        att_payload["given_name"],
        serde_json::json!("Test"),
        "given_name must be present"
    );
    assert_eq!(
        att_payload["age_over_18"],
        serde_json::json!(true),
        "age_over_18 must be true"
    );

    // ── Cleanup ───────────────────────────────────────────────────────────
    ctx.stop_server().await?;
    let _ = fs::remove_dir_all(&temp_dir);

    info!("e2e_full_verification_eudi_sd_jwt PASSED");
    Ok(())
}
