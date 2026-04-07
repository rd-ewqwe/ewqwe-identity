# Credential Verifier Test Coverage

This file summarizes tests in `credential_verifier` grouped by functional coverage.
Each table has two columns: test name and what it verifies.

## Server configuration and params

| Test Name | Verifies |
|-----------|----------|
| `loads_toml_and_resolves_relative_paths_from_config_directory` | `ServerParams::load_from_file` path resolution and default credential issuer CA directory handling |
| `server_params_enable_disable_authentication_defaults` | `disable_authentication` default false and `disabled_authentication_user()` returns `test` if unset |
| `loads_toml_with_tracing_config` | `ServerParams::load_from_file` loads `tracing_config.rust_log` from TOML |
| `loads_toml_without_tracing_config_uses_default` | Default tracing config is applied when TOML excludes `tracing_config` |
| `loads_credential_server_toml_from_project` | `ServerParams::load_from_file` properly parses `credential-server.toml` and picks up `rust_log` + auth flags from canonical config |
| `server_params_tracing_config_override` | `ServerParams.tracing_config` can override `RUST_LOG` filter via config |

## TLS / auth middleware behavior

| Test Name | Verifies |
|-----------|----------|
| `test_verify_endpoint_requires_client_certificate` | Without client cert, `/ewqwe_api/verify` returns `401` when auth is enabled |
| `test_verify_endpoint_accepts_valid_client_certificate` | With valid cert, `/ewqwe_api/verify` passes auth and then returns bad request due payload |
| `test_verify_endpoint_allows_disable_authentication_without_cert` | With `disable_authentication=true`, cert not required and `/ewqwe_api/verify` is not `401` |

## Journal store and endpoints

| Test Name | Verifies |
|-----------|----------|
| `test_attestation_signature_hash_is_deterministic` | `compute_attestation_signature_hash` determinism and length |
| `test_different_attestations_produce_different_hashes` | Hash circuits differ for different JWTs |
| `test_genesis_entry_hash_uses_empty_previous` | `compute_entry_hash` handles `None` previous as equivalent to empty |
| `test_entry_hash_changes_with_previous` | Chaining changes entry hash value |
| `test_chain_hash_formula` | Hash formula correctness for journal chain |
| `test_store_initial_head_is_none` | New store has no head entry |
| `test_append_single_entry` | Appending one journal entry sets head and can list it |
| `test_append_multiple_entries_forms_chain` | Multiple appends maintain valid chain and `verify_chain` returns valid |
| `test_verify_chain_empty_journal_is_valid` | Empty journal chain is valid |
| `test_journal_entries_endpoint_allows_disable_authentication_without_cert` | With `disable_authentication`, journal entry endpoint works without client cert |

## Attestation signing and token fields

| Test Name | Verifies |
|-----------|----------|
| `test_signer_trait_implementations` | `JwtSigner` and `CoseSigner` work for both ES256/RS256 and implement `AttestationSigner` |
| `test_full_claims` | Attestation claims with optional fields (`doc_type`, `nonce`, custom claims) are encoded in JWT payload correctly |
| `test_unique_jti` | Different presentations have different `jti` fields |

## Error helper macros

| Test Name | Verifies |
|-----------|----------|
| `test_auth_error_interpolation` | `auth_error!` supports value interpolation in message |
| `test_result_helper_context` | `.context()` adds context to errors, with both constant and fmt variant |
| `test_result_helper_with_context` | `.with_context()` closure-based context adds dynamic context |
| `test_option_helper_context` | `Option::context` returns error when `None`, success when `Some` |
| `test_option_helper_with_context` | `Option::with_context` closure-based error context behavior |
| `test_option_helper_some_value` | `Option::context` preserves `Some` value |
| `test_result_helper_ok_value` | `Result::context` preserves `Ok` value |
| `test_auth_ensure_true_condition` | `auth_ensure!` not triggered when condition true |
| `test_auth_bail_immediately_returns` | `auth_bail!` returns early with expected message |

## Attestation COSE signer

| Test Name | Verifies |
|-----------|----------|
| `test_sign_and_verify_es256` | COSE Sign1 ES256 signing+verification through `CoseSigner` apply human claims |
| `test_sign_and_verify_rs256` | COSE Sign1 RS256 signing+verification with key-based claims |
| `test_signer_with_key_id` | COSE key ID routing in protected header works with `with_key_id` |

## Attestation JWT signer

| Test Name | Verifies |
|-----------|----------|
| `test_sign_with_es256` | JWT ES256 signing, decoding, claims handling with audience/issuer validation |
| `test_sign_with_rs256` | JWT RS256 signing, decoding, claims handling with audience/issuer validation |
| `test_signer_with_key_id` | JWT `kid` header is set and preserved in encoded token |

## Attestation struct

| Test Name | Verifies |
|-----------|----------|
| `test_new_claims` | default attestation fields and validity time window in `Attestation::new` |
| `test_builder_pattern` | `with_nonce`, `with_doc_type`, `with_namespace`, `with_credential_claims` builder style works |

## mDoc decoder

| Test Name | Verifies |
|-----------|----------|
| `test_cbor_to_json_primitives` | mDoc CBOR primitive conversion to JSON values works |
| `test_cbor_to_json_tagged_date` | CBOR tag 1004 date conversion into string value works |

## Test client helper

| Test Name | Verifies |
|-----------|----------|
| `test_client_creation` | `TestClient::new` constructs with base URL correctly |

## End-to-end tests

| Test Name | Verifies |
|-----------|----------|
| `test_start_server` | `start_default_test_server` and lifecycle with startup/shutdown succeeds |
| `test_version_endpoint` | `/version` endpoint returns expected Cargo package version |
| `test_issuer_certs_empty_dir_and_issuer_untrusted` | Server returns error (not success) when no trusted issuer CA certs are configured and a credential is submitted |

## End-to-end full verification tests (ephemeral PKI)

These tests exercise the **complete credential signing ↔ verification round-trip** using
credentials built by the [`ewqwe_digital_credential`](../crates/ewqwe-digital-credential/)
crate.  Each test generates a fresh ephemeral two-level PKI (CA → issuer leaf + device key),
starts the credential-verifier with that CA as the sole trusted issuer, runs the full
OpenID4VP flow (init → fetch auth request → post credential → assert attestation), and then
verifies that the signed attestation JWT contains the expected credential claims.

| Test Name | Verifies |
|-----------|----------|
| `e2e_full_verification_eu_age_profile_sd_jwt` | Full round-trip for an **EU Age Verification Profile SD-JWT VC** (`vct=eu.europa.ec.av.1`): ephemeral CA trusted, issuer JWT `x5c` chain validated, KB-JWT nonce-bound, `over_18=true` claim present in the signed attestation JWT |
| `e2e_full_verification_eudi_mdoc` | Full round-trip for a **EUDI PID mDoc** (ISO 18013-5 `DeviceResponse`, `docType=eu.europa.ec.eudi.pid.1`): COSE_Sign1 `IssuerAuth` chain verified against ephemeral CA, MSO `valueDigests` integrity checked, `DeviceSignature` bound to `SessionTranscript` from OpenID4VP handover; `given_name` and `age_over_18` claims present in attestation |
| `e2e_full_verification_eudi_sd_jwt` | Full round-trip for a **EUDI PID SD-JWT VC** (`vct=eu.europa.ec.eudi.pid.1`): same PKI trust chain and KB-JWT nonce binding as the EU Age test; `given_name` and `age_over_18` claims present in attestation |

## End-to-end tests via the `ewqwe_digital_identity` Rust client library

These tests exercise the credential-verifier REST API through the
[`ewqwe_digital_identity`](../crates/ewqwe-digital-identity/) client crate.
A custom `TestReqwestClient` transport is used in place of `DefaultHttpClient` so
that the test server's self-signed certificate is accepted on macOS
(`danger_accept_invalid_certs = true` is set only in test code, never in
production).

| Test Name | Verifies |
|-----------|----------|
| `e2e_ewqwe_client_version_endpoint` | `GET /version` returns the expected Cargo package version via `EwqweApiClient::get_version()` |
| `e2e_ewqwe_client_init_transaction` | `POST /ewqwe_api/openid4vp/init` creates a transaction; `InitTransactionResponse` has non-empty `transaction_id`, `client_id`, `request_uri`, `authorization_request_uri` and a positive `expires_in` |
| `e2e_ewqwe_client_transaction_status_pending` | `GET /ewqwe_api/openid4vp/status/:id` returns `status == pending` with an `expires_in` value for a freshly created transaction |
| `e2e_ewqwe_client_transaction_status_unknown_id` | An unknown transaction ID is treated as expired — the store's `is_expired` returns `true` for nonexistent keys, so the response is `status == expired` (HTTP 200), not an HTTP 404 |
| `e2e_ewqwe_client_jwks_endpoint` | `GET /ewqwe_api/openid4vp/.well-known/jwks.json` returns a JWK Set with at least one key, each having a `kty` field (RFC 7517 §4) |
| `e2e_ewqwe_client_get_authorization_request` | `GET /ewqwe_api/openid4vp/request/:id` returns a JSON object containing at least a `response_type` or `client_id` OpenID4VP field |
| `e2e_ewqwe_client_verify_requires_client_cert` | `POST /ewqwe_api/verify` fails (transport error or HTTP 401) when no client certificate is presented and `disable_authentication = false` |
| `e2e_ewqwe_client_full_flow_no_auth` | Full init → status poll → verify with `disable_authentication = true`: transaction starts `pending`; submitting a dummy VP Token is rejected with a non-success code (invalid credential payload) |
