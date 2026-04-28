//! Tests for the verification journal: hash computation, chain integrity, CAS
//! behaviour, and HTTP endpoints (list, verify, download).

use crate::{
    AttResult,
    journal::{
        DynJournalStore, JournalBackend, JournalConfig, JournalError, JournalQuery, JournalStore,
        append_verification, compute_attestation_signature_hash, compute_entry_hash,
    },
    tests::{
        make_test_server_params, start_journal_test_server, start_test_server,
        test_client::TestClient,
    },
};
use ewqwe_logging::log_init;
use serde_json::json;

// ============================================================================
// Helper: build an in-memory journal store for unit tests
// ============================================================================

async fn make_store() -> DynJournalStore {
    DynJournalStore::new(&JournalConfig {
        enabled: true,
        backend: JournalBackend::SqliteMemory,
    })
    .await
    .expect("failed to create in-memory journal store")
}

// ============================================================================
// Hash computation unit tests
// ============================================================================

#[test]
fn test_attestation_signature_hash_is_deterministic() {
    let jwt = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.signature";
    let h1 = compute_attestation_signature_hash(jwt);
    let h2 = compute_attestation_signature_hash(jwt);
    assert_eq!(h1, h2);
    assert_eq!(h1.len(), 64, "SHA-256 hex should be 64 chars");
}

#[test]
fn test_different_attestations_produce_different_hashes() {
    let h1 = compute_attestation_signature_hash("jwt1");
    let h2 = compute_attestation_signature_hash("jwt2");
    assert_ne!(h1, h2);
}

#[test]
fn test_genesis_entry_hash_uses_empty_previous() {
    let username = "alice@example.com";
    let attestation_hash = compute_attestation_signature_hash("some-attestation");
    let h_none = compute_entry_hash(username, None, &attestation_hash);
    let h_empty = compute_entry_hash(username, Some(""), &attestation_hash);
    assert_eq!(
        h_none, h_empty,
        "None previous and empty string should produce same hash"
    );
}

#[test]
fn test_entry_hash_changes_with_previous() {
    let username = "alice@example.com";
    let att_hash = compute_attestation_signature_hash("attestation");
    let h1 = compute_entry_hash(username, None, &att_hash);
    let h2 = compute_entry_hash(username, Some(&h1), &att_hash);
    assert_ne!(h1, h2, "Chaining should change the entry hash");
}

#[test]
fn test_chain_hash_formula() {
    // Verify the exact formula: SHA-256(username_bytes || previous_hash_bytes || att_sig_hash_bytes)
    use sha2::{Digest, Sha256};

    let username = "test@example.com";
    let att_hash = compute_attestation_signature_hash("test-attestation-jwt");
    let prev = "abc123";

    let mut hasher = Sha256::new();
    hasher.update(username.as_bytes());
    hasher.update(prev.as_bytes());
    hasher.update(att_hash.as_bytes());
    let expected = hex::encode(hasher.finalize());

    assert_eq!(
        compute_entry_hash(username, Some(prev), &att_hash),
        expected
    );
}

// ============================================================================
// Store unit tests
// ============================================================================

#[tokio::test]
async fn test_store_initial_head_is_none() {
    let store = make_store().await;
    let head = store.get_head("user@example.com").await.unwrap();
    assert!(head.is_none(), "Fresh journal should have no head");
}

#[tokio::test]
async fn test_append_single_entry() {
    let store = make_store().await;
    let username = "alice@example.com";

    append_verification(
        &store,
        username,
        "fake-attestation-jwt",
        Some("jti-001"),
        Some("rp.example.com"),
        Some("org.iso.18013.5.1.mDL"),
        Some("org.iso.18013.5.1"),
        json!({"success": true}),
        None,
        None,
    )
    .await
    .expect("first append should succeed");

    let head = store.get_head(username).await.unwrap();
    assert!(head.is_some(), "Head should be set after first append");

    let entries = store
        .list_entries(&JournalQuery {
            username: username.to_string(),
            limit: Some(10),
            before: None,
            after: None,
        })
        .await
        .unwrap();

    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].username, username);
    assert_eq!(entries[0].attestation_jti.as_deref(), Some("jti-001"));
    assert!(
        entries[0].previous_hash.is_none(),
        "Genesis entry has no previous hash"
    );
}

#[tokio::test]
async fn test_append_multiple_entries_forms_chain() {
    let store = make_store().await;
    let username = "bob@example.com";

    for i in 0..5u32 {
        append_verification(
            &store,
            username,
            &format!("jwt-{i}"),
            Some(&format!("jti-{i:03}")),
            Some("rp.example.com"),
            Some("org.iso.18013.5.1.mDL"),
            Some("org.iso.18013.5.1"),
            json!({"attempt": i}),
            None,
            None,
        )
        .await
        .expect("append should succeed");
    }

    let entries = store
        .list_entries(&JournalQuery {
            username: username.to_string(),
            limit: Some(10),
            before: None,
            after: None,
        })
        .await
        .unwrap();

    assert_eq!(entries.len(), 5, "Should have 5 entries");

    // Entries are returned newest-first; verify the chain still forms correctly
    // by using verify_chain.
    let result = store.verify_chain(username).await.unwrap();
    assert!(
        result.valid,
        "Chain should be valid after sequential appends: {:?}",
        result.error
    );
    assert_eq!(result.entries_verified, 5);
}

#[tokio::test]
async fn test_verify_chain_empty_journal_is_valid() {
    let store = make_store().await;
    let result = store.verify_chain("nobody@example.com").await.unwrap();
    assert!(result.valid);
    assert_eq!(result.entries_verified, 0);
    assert!(result.first_entry_hash.is_none());
    assert!(result.last_entry_hash.is_none());
}

#[tokio::test]
async fn test_stale_head_returns_error() {
    use crate::journal::JournalEntry;
    use chrono::Utc;

    let store = make_store().await;
    let username = "charlie@example.com";

    // Insert a real genesis entry first.
    append_verification(
        &store,
        username,
        "first-jwt",
        None,
        None,
        None,
        None,
        json!({}),
        None,
        None,
    )
    .await
    .unwrap();

    let head = store.get_head(username).await.unwrap().unwrap();

    // Now attempt a direct append with an incorrect expected_previous_hash.
    let att_hash = compute_attestation_signature_hash("second-jwt");
    let entry_hash = compute_entry_hash(username, Some("deliberate-wrong-hash"), &att_hash);
    let bad_entry = JournalEntry {
        id: uuid::Uuid::new_v4().to_string(),
        username: username.to_string(),
        previous_hash: Some("deliberate-wrong-hash".to_string()),
        entry_hash,
        attestation_signature_hash: att_hash,
        attestation_jti: None,
        client_id: None,
        doc_type: None,
        namespace: None,
        qrcode_app_user_id: None,
        qrcode_app_user_email: None,
        verification_summary: json!({}),
        created_at: Utc::now(),
    };

    let result = store
        .append_entry(&bad_entry, Some("deliberate-wrong-hash"))
        .await;

    assert!(
        matches!(result, Err(JournalError::StaleHead)),
        "Appending with wrong expected hash should return StaleHead, got: {result:?}"
    );

    // Verify the head was not corrupted.
    let head_after = store.get_head(username).await.unwrap().unwrap();
    assert_eq!(
        head, head_after,
        "Head should be unchanged after failed CAS"
    );
}

#[tokio::test]
async fn test_multiple_usernames_independent_chains() {
    let store = make_store().await;

    for user in &[
        "user_a@example.com",
        "user_b@example.com",
        "user_c@example.com",
    ] {
        for i in 0..3u32 {
            append_verification(
                &store,
                user,
                &format!("jwt-{user}-{i}"),
                None,
                None,
                None,
                None,
                json!({}),
                None,
                None,
            )
            .await
            .expect("append should succeed");
        }
    }

    for user in &[
        "user_a@example.com",
        "user_b@example.com",
        "user_c@example.com",
    ] {
        let result = store.verify_chain(user).await.unwrap();
        assert!(result.valid, "Chain for {user} should be valid");
        assert_eq!(result.entries_verified, 3);
    }
}

#[tokio::test]
async fn test_list_entries_limit() {
    let store = make_store().await;
    let username = "paged@example.com";

    for i in 0..10u32 {
        append_verification(
            &store,
            username,
            &format!("jwt-{i}"),
            None,
            None,
            None,
            None,
            json!({}),
            None,
            None,
        )
        .await
        .unwrap();
    }

    let entries = store
        .list_entries(&JournalQuery {
            username: username.to_string(),
            limit: Some(3),
            before: None,
            after: None,
        })
        .await
        .unwrap();

    assert_eq!(entries.len(), 3, "Limit should be respected");
}

#[tokio::test]
async fn test_list_entries_before_filter() {
    use chrono::Utc;

    let store = make_store().await;
    let username = "temporal@example.com";

    // Insert 5 entries.
    for i in 0..5u32 {
        append_verification(
            &store,
            username,
            &format!("jwt-{i}"),
            None,
            None,
            None,
            None,
            json!({}),
            None,
            None,
        )
        .await
        .unwrap();
    }

    // A `before` timestamp in the far future should return all entries.
    let far_future: chrono::DateTime<Utc> = "9999-01-01T00:00:00Z".parse().unwrap();
    let all = store
        .list_entries(&JournalQuery {
            username: username.to_string(),
            limit: None,
            before: Some(far_future),
            after: None,
        })
        .await
        .unwrap();
    assert_eq!(all.len(), 5);

    // A `before` timestamp in the past should return nothing.
    let past: chrono::DateTime<Utc> = "2000-01-01T00:00:00Z".parse().unwrap();
    let none = store
        .list_entries(&JournalQuery {
            username: username.to_string(),
            limit: None,
            before: Some(past),
            after: None,
        })
        .await
        .unwrap();
    assert!(none.is_empty());
}

#[tokio::test]
async fn test_verify_chain_detects_tampering() {
    use crate::journal::stores::sqlite::SqliteJournalStore;

    // Build the store directly so we can reach into the database for tampering.
    let store = SqliteJournalStore::new_memory()
        .await
        .expect("failed to create SQLite store");

    let username = "tampered@example.com";
    for i in 0..3u32 {
        append_verification(
            &store,
            username,
            &format!("jwt-{i}"),
            None,
            None,
            None,
            None,
            json!({}),
            None,
            None,
        )
        .await
        .unwrap();
    }

    // Chain should be clean before tampering.
    let before = store.verify_chain(username).await.unwrap();
    assert!(before.valid, "Chain should be valid before tampering");

    // Tamper with the middle entry by overwriting its attestation_signature_hash.
    let pool = store.pool_for_test();
    sqlx::query(
        "UPDATE journal_entries \
         SET attestation_signature_hash = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
         WHERE rowid = (SELECT rowid FROM journal_entries WHERE username = ?1 ORDER BY created_at ASC LIMIT 1 OFFSET 1)",
    )
    .bind(username)
    .execute(&pool)
    .await
    .expect("tamper update failed");

    let after = store.verify_chain(username).await.unwrap();
    assert!(
        !after.valid,
        "Chain should be invalid after tampering, got: {:?}",
        after.error
    );
}

// ============================================================================
// HTTP endpoint integration tests (requires test server with journal enabled)
// ============================================================================

#[actix_web::test]
async fn test_journal_entries_endpoint_requires_tls() -> AttResult<()> {
    let ctx = start_journal_test_server().await?;
    let client = TestClient::new(&ctx.base_url())?;

    // Without a client certificate the endpoint must reject with 401.
    let response = client
        .get_raw("/ewqwe_api/journal/user1.acme.com/entries")
        .await?;

    assert_eq!(
        response.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "Journal entries endpoint must require mTLS"
    );

    ctx.stop_server().await?;
    Ok(())
}

#[actix_web::test]
async fn test_journal_entries_endpoint_allows_disable_authentication_without_cert() -> AttResult<()>
{
    let mut server_params = make_test_server_params(true, "test");
    // Journal must be enabled so that the journal handler has its Data<DynJournalStore>.
    server_params.journal_config.enabled = true;
    let ctx = start_test_server(server_params).await?;
    let client = TestClient::new(&ctx.base_url())?;

    let response = client.get_raw("/ewqwe_api/journal/test/entries").await?;

    // Since there are no journal entries yet, state may be 200 empty list.
    assert_eq!(response.status(), reqwest::StatusCode::OK);

    ctx.stop_server().await?;
    Ok(())
}

#[actix_web::test]
async fn test_journal_verify_endpoint_requires_tls() -> AttResult<()> {
    let ctx = start_journal_test_server().await?;
    let client = TestClient::new(&ctx.base_url())?;

    let response = client
        .get_raw("/ewqwe_api/journal/user1.acme.com/verify")
        .await?;

    assert_eq!(
        response.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "Journal verify endpoint must require mTLS"
    );

    ctx.stop_server().await?;
    Ok(())
}

#[actix_web::test]
async fn test_journal_download_endpoint_requires_tls() -> AttResult<()> {
    let ctx = start_journal_test_server().await?;
    let client = TestClient::new(&ctx.base_url())?;

    let response = client
        .get_raw("/ewqwe_api/journal/user1.acme.com/download")
        .await?;

    assert_eq!(
        response.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "Journal download endpoint must require mTLS"
    );

    ctx.stop_server().await?;
    Ok(())
}

#[actix_web::test]
async fn test_journal_entries_empty_for_new_user() -> AttResult<()> {
    let ctx = start_journal_test_server().await?;
    // user1.acme.com is the CN of ewqwe.user1.cert.pem
    let client = TestClient::new_with_user1_cert(&ctx.base_url())?;

    let response = client
        .get_raw("/ewqwe_api/journal/user1.acme.com/entries")
        .await?;

    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "Authenticated user should be able to query their own empty journal"
    );

    let body: serde_json::Value = response.json().await.map_err(|e| {
        crate::AttError::Generic(format!("Failed to deserialize journal response: {e}"))
    })?;
    assert!(
        body.as_array().map(|a| a.is_empty()).unwrap_or(false),
        "New user journal should be an empty array, got: {body}"
    );

    ctx.stop_server().await?;
    Ok(())
}

#[actix_web::test]
async fn test_journal_access_denied_for_other_user() -> AttResult<()> {
    log_init(None);
    let ctx = start_journal_test_server().await?;
    // Authenticated as user1 but trying to access user2's journal.
    let client = TestClient::new_with_user1_cert(&ctx.base_url())?;

    let response = client
        .get_raw("/ewqwe_api/journal/user2.acme.com/entries")
        .await?;

    assert_eq!(
        response.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "User should not be able to access another user's journal"
    );

    ctx.stop_server().await?;
    Ok(())
}

#[actix_web::test]
async fn test_journal_chain_verify_empty() -> AttResult<()> {
    let ctx = start_journal_test_server().await?;
    let client = TestClient::new_with_user1_cert(&ctx.base_url())?;

    let response = client
        .get_raw("/ewqwe_api/journal/user1.acme.com/verify")
        .await?;

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = response.json().await.map_err(|e| {
        crate::AttError::Generic(format!("Failed to deserialize verify response: {e}"))
    })?;
    assert_eq!(
        body["valid"].as_bool(),
        Some(true),
        "Empty journal should report valid chain"
    );
    assert_eq!(
        body["entries_verified"].as_u64(),
        Some(0),
        "Empty journal should have 0 entries verified"
    );

    ctx.stop_server().await?;
    Ok(())
}

#[actix_web::test]
async fn test_journal_download_returns_json_file() -> AttResult<()> {
    let ctx = start_journal_test_server().await?;
    let client = TestClient::new_with_user1_cert(&ctx.base_url())?;

    let response = client
        .get_raw("/ewqwe_api/journal/user1.acme.com/download")
        .await?;

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let content_disposition = response
        .headers()
        .get("content-disposition")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    assert!(
        content_disposition.contains("attachment"),
        "Download endpoint must set Content-Disposition: attachment"
    );
    assert!(
        content_disposition.contains("journal_user1.acme.com.json"),
        "Download filename should match username: {content_disposition}"
    );

    ctx.stop_server().await?;
    Ok(())
}
