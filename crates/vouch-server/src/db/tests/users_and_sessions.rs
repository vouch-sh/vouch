// SPDX-License-Identifier: Apache-2.0 OR MIT
//! User CRUD (`db::users`) and browser-session lifecycle (`db::sessions`).
#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable; cast bounds are obvious in test fixtures"
)]

use super::*;

#[tokio::test]
async fn test_upsert_and_get_user() {
    let (store, _audit) = test_db().await;

    // Create a user
    let (user_id, created) = upsert_user(&store, "test@example.com", Some("Test User"))
        .await
        .expect("Failed to create user");

    assert!(!user_id.is_empty());
    assert!(created);

    // Get the full user to check fields
    let user = get_user_by_id(&store, &user_id)
        .await
        .expect("Failed to get user")
        .expect("User should exist");
    assert_eq!(user.email, "test@example.com");
    assert_eq!(user.name.as_deref(), Some("Test User"));

    // Get the user by email
    let fetched = get_user_by_email(&store, "test@example.com")
        .await
        .expect("Failed to get user")
        .expect("User should exist");

    assert_eq!(fetched.id, user_id);
    assert_eq!(fetched.email, "test@example.com");
}

#[tokio::test]
async fn test_upsert_idempotent() {
    let (store, _audit) = test_db().await;

    // First call creates user
    let (user_id1, created1) = upsert_user(&store, "new@example.com", Some("New User"))
        .await
        .expect("Failed to upsert user");
    assert!(created1);

    // Second call returns same user
    let (user_id2, created2) = upsert_user(&store, "new@example.com", Some("Different Name"))
        .await
        .expect("Failed to upsert user");
    assert!(!created2);

    assert_eq!(user_id1, user_id2);
}

#[tokio::test]
async fn test_user_not_found() {
    let (store, _audit) = test_db().await;

    let user = get_user_by_email(&store, "nonexistent@example.com")
        .await
        .expect("Query should succeed");

    assert!(user.is_none());
}

#[tokio::test]
async fn test_get_users_by_ids_multiple_found_and_some_missing() {
    let (store, _audit) = test_db().await;

    let (id1, _) = upsert_user(&store, "alice@example.com", Some("Alice"))
        .await
        .expect("Failed to create user");
    let (id2, _) = upsert_user(&store, "bob@example.com", Some("Bob"))
        .await
        .expect("Failed to create user");

    let ids = vec![id1.clone(), id2.clone(), "nonexistent-id".to_string()];
    let users = get_users_by_ids(&store, &ids)
        .await
        .expect("Query should succeed");

    assert_eq!(
        users.len(),
        2,
        "a missing id should simply be absent, not an error"
    );
    assert_eq!(
        users.get(&id1).map(|u| u.email.as_str()),
        Some("alice@example.com")
    );
    assert_eq!(
        users.get(&id2).map(|u| u.email.as_str()),
        Some("bob@example.com")
    );
    assert!(!users.contains_key("nonexistent-id"));
}

#[tokio::test]
async fn test_get_users_by_ids_empty_input_returns_empty_map() {
    let (store, _audit) = test_db().await;

    let users = get_users_by_ids(&store, &[])
        .await
        .expect("Query should succeed");

    assert!(users.is_empty());
}

#[tokio::test]
async fn test_session_lifecycle() {
    let (store, _audit) = test_db().await;

    // Create user
    let (user_id, _) = upsert_user(&store, "session@example.com", None)
        .await
        .expect("Failed to create user");

    // Create authenticator (with user_email parameter)
    let auth_id = create_authenticator(
        &store,
        &CreateAuthenticatorParams {
            user_id: &user_id,
            user_email: "session@example.com",
            name: "Test Key",
            credential_id: b"test-cred-id",
            public_key: &[0u8; 32],
            aaguid: None,
            user_handle: Some(user_id.as_bytes()),
            attestation_verified: false,
        },
    )
    .await
    .expect("Failed to create authenticator");

    // Create session (with user_email parameter)
    let token_hash = "test_token_hash_123";
    let session_id = create_session(
        &store,
        &CreateSessionParams {
            user_id: &user_id,
            user_email: "session@example.com",
            token_hash,
            authenticator_id: Some(&auth_id),
            expires_at: "2099-12-31T23:59:59Z".parse().unwrap(),
            session_type: SessionPurpose::OAuthAccessToken,
            authorization_details: None,
            hardware_aaguid: None,
            org_domain: None,
            client_id: None,
            source_code_hash: None,
        },
    )
    .await
    .expect("Failed to create session");

    assert!(!session_id.is_empty());

    // Get session
    let session = get_session_by_token_hash(&store, token_hash, jiff::Timestamp::now())
        .await
        .expect("Failed to get session")
        .expect("Session should exist");

    assert_eq!(session.user_id, user_id);

    // Delete session
    let deleted = delete_session_by_token_hash(&store, token_hash)
        .await
        .expect("Failed to delete session");

    assert!(deleted);

    // Session should no longer exist
    let session = get_session_by_token_hash(&store, token_hash, jiff::Timestamp::now())
        .await
        .expect("Failed to get session");

    assert!(session.is_none());
}

/// Deterministic expiry boundary (issue #661): a session is valid the
/// instant before `expires_at` and gone the instant at/after it, using fixed
/// timestamps instead of a real-clock wait.
#[tokio::test]
async fn test_session_expiry_boundary() {
    let (store, _audit) = test_db().await;

    let (user_id, _) = upsert_user(&store, "expiry-boundary@example.com", None)
        .await
        .expect("Failed to create user");

    let expires_at: jiff::Timestamp = "2030-01-01T00:00:00Z".parse().unwrap();
    let token_hash = "expiry_boundary_token";
    create_session(
        &store,
        &CreateSessionParams {
            user_id: &user_id,
            user_email: "expiry-boundary@example.com",
            token_hash,
            authenticator_id: None,
            expires_at,
            session_type: SessionPurpose::OAuthAccessToken,
            authorization_details: None,
            hardware_aaguid: None,
            org_domain: None,
            client_id: None,
            source_code_hash: None,
        },
    )
    .await
    .expect("Failed to create session");

    // One second before expiry: still valid (`expires_at > now`).
    let just_before = expires_at
        .checked_sub(jiff::Span::new().seconds(1))
        .unwrap();
    let session = get_session_by_token_hash(&store, token_hash, just_before)
        .await
        .expect("query should succeed");
    assert!(session.is_some(), "session must be valid 1s before expiry");

    // Exactly at expiry: no longer valid (`expires_at > now` is strict).
    let session = get_session_by_token_hash(&store, token_hash, expires_at)
        .await
        .expect("query should succeed");
    assert!(session.is_none(), "session must be expired at expires_at");

    // One second after expiry: still no longer valid.
    let just_after = expires_at
        .checked_add(jiff::Span::new().seconds(1))
        .unwrap();
    let session = get_session_by_token_hash(&store, token_hash, just_after)
        .await
        .expect("query should succeed");
    assert!(session.is_none(), "session must be expired 1s after expiry");
}

/// Helper: create an OAuth access-token session for `user_id` with a given
/// `token_hash` and optional `source_code_hash`, returning the session id.
async fn create_oauth_session(
    store: &DocumentStore,
    user_id: &str,
    email: &str,
    token_hash: &str,
    source_code_hash: Option<&str>,
) -> String {
    create_session(
        store,
        &CreateSessionParams {
            user_id,
            user_email: email,
            token_hash,
            authenticator_id: None,
            expires_at: "2099-12-31T23:59:59Z".parse().unwrap(),
            session_type: SessionPurpose::OAuthAccessToken,
            authorization_details: None,
            hardware_aaguid: None,
            org_domain: None,
            client_id: None,
            source_code_hash,
        },
    )
    .await
    .expect("create session")
}

/// RFC 6749 Section 10.5: "the authorization server SHOULD attempt to revoke
/// all access tokens already granted based on the compromised authorization
/// code." Revocation deletes only the sessions issued from the replayed code,
/// leaving the user's other sessions — from other codes, and from grants with
/// no single-use code — intact.
#[tokio::test]
async fn test_replay_revocation_targets_only_the_replayed_code() {
    let (store, _audit) = test_db().await;
    let (user_id, _) = upsert_user(&store, "replay@example.com", None)
        .await
        .expect("create user");

    // Two sessions issued from authorization code A.
    let s_a1 = create_oauth_session(
        &store,
        &user_id,
        "replay@example.com",
        "hash-a1",
        Some("code-A"),
    )
    .await;
    let _s_a2 = create_oauth_session(
        &store,
        &user_id,
        "replay@example.com",
        "hash-a2",
        Some("code-A"),
    )
    .await;
    // A session issued from a different authorization code B.
    let _s_b = create_oauth_session(
        &store,
        &user_id,
        "replay@example.com",
        "hash-b",
        Some("code-B"),
    )
    .await;
    // A session from a grant with no single-use code (FIDO2 / browser login).
    let _s_none =
        create_oauth_session(&store, &user_id, "replay@example.com", "hash-none", None).await;

    // Replay detection for code A revokes only the code-A sessions.
    let revoked = delete_sessions_for_code_replay(&store, "code-A")
        .await
        .expect("replay revocation");
    assert_eq!(
        revoked.len(),
        2,
        "only the two sessions issued from code-A must be returned: {revoked:?}"
    );
    assert!(
        revoked.contains(&"hash-a1".to_string()) && revoked.contains(&"hash-a2".to_string()),
        "returned token hashes must be exactly the code-A sessions: {revoked:?}"
    );

    // Code-A sessions are gone.
    assert!(
        get_session_by_token_hash(&store, "hash-a1", jiff::Timestamp::now())
            .await
            .expect("lookup a1")
            .is_none(),
        "code-A session a1 must be revoked"
    );
    assert!(
        get_session_by_token_hash(&store, "hash-a2", jiff::Timestamp::now())
            .await
            .expect("lookup a2")
            .is_none(),
        "code-A session a2 must be revoked"
    );

    // Code-B session survives — a replay of one code must not log the user
    // out of tokens issued from unrelated codes.
    assert!(
        get_session_by_token_hash(&store, "hash-b", jiff::Timestamp::now())
            .await
            .expect("lookup b")
            .is_some(),
        "code-B session must survive a code-A replay"
    );

    // The no-code session survives — grants without a single-use code are
    // never targeted by replay-based revocation.
    assert!(
        get_session_by_token_hash(&store, "hash-none", jiff::Timestamp::now())
            .await
            .expect("lookup none")
            .is_some(),
        "no-code session must survive a code replay"
    );

    // Deleting the code-A sessions again is a no-op (already gone), not an error.
    let again = delete_sessions_for_code_replay(&store, "code-A")
        .await
        .expect("idempotent replay revocation");
    assert!(
        again.is_empty(),
        "second revocation of code-A must find nothing"
    );
    let _ = s_a1; // suppress unused binding warning
}

/// A replay of a code that no session was issued from (e.g., the legitimate
/// exchange failed after consuming the code) revokes nothing and does not
/// touch unrelated sessions.
#[tokio::test]
async fn test_replay_revocation_for_unknown_code_is_noop() {
    let (store, _audit) = test_db().await;
    let (user_id, _) = upsert_user(&store, "noop-replay@example.com", None)
        .await
        .expect("create user");
    let _s = create_oauth_session(
        &store,
        &user_id,
        "noop-replay@example.com",
        "hash-x",
        Some("code-X"),
    )
    .await;

    let revoked = delete_sessions_for_code_replay(&store, "never-issued")
        .await
        .expect("revocation lookup");
    assert!(revoked.is_empty(), "no sessions match an unknown code");

    assert!(
        get_session_by_token_hash(&store, "hash-x", jiff::Timestamp::now())
            .await
            .expect("lookup")
            .is_some(),
        "unrelated session must be untouched"
    );
}

/// Regression test for the cache/DB desync fixed by making
/// `delete_sessions_for_code_replay` best-effort.
///
/// When at least two OAuth sessions share a `source_code_hash` (the
/// ≥2-session shape produced by RFC 8693 token exchange at
/// `services/oidc/exchange.rs`) and a per-session delete fails partway through
/// the revocation loop, the committed deletes' token hashes must still be
/// returned on the `Ok` arm so the caller's `Ok`-arm cache invalidation runs.
/// The old code propagated `Err` on the failing delete and discarded the
/// already-committed deletes' hashes, so the caller's log-only `Err` arm left a
/// DB-deleted session cached as a stale `Hit` for up to the cache TTL — a
/// request presenting that token then authenticated against a row the server
/// had already deleted.
///
/// `set_delete_remaining_successes(1)` faults the *second* `store.delete` in
/// the loop, exercising the "one delete commits, a later delete fails before
/// committing" control-flow shape without a real DB outage. The assertions
/// below pin the post-fix behavior; under the old code this test fails at
/// `result.is_ok()` (the function used to return `Err`).
#[tokio::test]
async fn test_replay_revocation_partial_failure_still_invalidates_committed_deletes() {
    let (mut store, _audit) = test_db().await;
    let (user_id, _) = upsert_user(&store, "partial-replay@example.com", None)
        .await
        .expect("create user");

    // Two OAuth access-token sessions issued from the same replayed code "code-P"
    // — the ≥2-session shape that makes a mid-loop delete failure observable.
    create_oauth_session(
        &store,
        &user_id,
        "partial-replay@example.com",
        "hash-p1",
        Some("code-P"),
    )
    .await;
    create_oauth_session(
        &store,
        &user_id,
        "partial-replay@example.com",
        "hash-p2",
        Some("code-P"),
    )
    .await;

    // Populate the session cache with `Hit`s for both, mirroring the
    // precondition an RFC 8693 exchange establishes when it looks up the
    // subject token: that lookup freshly populates the subject session's
    // cache entry at the instant the second session is created.
    let cache = SessionCache::new(100, 30);
    assert!(
        cache
            .get_session_by_token_hash(&store, "hash-p1")
            .await
            .expect("cache lookup p1")
            .is_some(),
        "hash-p1 must start as a cache Hit"
    );
    assert!(
        cache
            .get_session_by_token_hash(&store, "hash-p2")
            .await
            .expect("cache lookup p2")
            .is_some(),
        "hash-p2 must start as a cache Hit"
    );

    // Fault the second `store.delete` so the first delete commits and the
    // second returns a non-retryable `Err` before opening its transaction.
    store.set_delete_remaining_successes(1);

    // Run the real caller match logic from `services/oidc/token.rs`: invalidate
    // each returned hash on `Ok`, log only on `Err`.
    let result = delete_sessions_for_code_replay(&store, "code-P").await;
    assert!(
        result.is_ok(),
        "best-effort revocation must return Ok on partial delete failure, not \
         discard the already-committed deletes' hashes: {result:?}"
    );
    let token_hashes = result.expect("checked Ok above");
    assert_eq!(
        token_hashes.len(),
        1,
        "only the one successfully-deleted session's hash is returned: {token_hashes:?}"
    );
    let committed_hash = token_hashes
        .first()
        .expect("len == 1 checked above")
        .as_str();
    let surviving_hash = if committed_hash == "hash-p1" {
        "hash-p2"
    } else {
        "hash-p1"
    };

    // The committed-deleted session is gone from the DB; the session whose
    // delete failed is still present.
    assert!(
        get_session_by_token_hash(&store, committed_hash, jiff::Timestamp::now())
            .await
            .expect("db lookup committed")
            .is_none(),
        "the committed delete must be gone from the DB"
    );
    assert!(
        get_session_by_token_hash(&store, surviving_hash, jiff::Timestamp::now())
            .await
            .expect("db lookup surviving")
            .is_some(),
        "the session whose delete failed must remain in the DB"
    );

    // Run the caller's `Ok`-arm cache invalidation against the returned hash.
    cache.invalidate(committed_hash);

    // The committed-deleted session is no longer served as a stale `Hit`: the
    // cache misses through to the DB, which returns `None`. Under the old code
    // the function returned `Err` and the caller never invalidated, so this
    // lookup would return `Some` from the stale `Hit` (the bug).
    assert!(
        cache
            .get_session_by_token_hash(&store, committed_hash)
            .await
            .expect("cache re-lookup committed")
            .is_none(),
        "a DB-deleted session must not be served from a stale cache Hit"
    );

    // The session whose delete failed stays cached — it is still a valid row.
    assert!(
        cache
            .get_session_by_token_hash(&store, surviving_hash)
            .await
            .expect("cache re-lookup surviving")
            .is_some(),
        "the session whose delete failed must remain a cache Hit"
    );
}

/// A per-session delete failure on the *first* iteration (budget 0) deletes
/// nothing, returns an empty `Ok`, and leaves both sessions cached + in the
/// DB — the no-progress extreme of the best-effort loop, mirroring the
/// "replay of a code whose sessions were never enumerated before the fault"
/// edge of the contract.
#[tokio::test]
async fn test_replay_revocation_first_delete_fails_is_empty_ok() {
    let (mut store, _audit) = test_db().await;
    let (user_id, _) = upsert_user(&store, "first-fail@example.com", None)
        .await
        .expect("create user");
    create_oauth_session(
        &store,
        &user_id,
        "first-fail@example.com",
        "hash-f1",
        Some("code-F"),
    )
    .await;
    create_oauth_session(
        &store,
        &user_id,
        "first-fail@example.com",
        "hash-f2",
        Some("code-F"),
    )
    .await;

    // Fault every delete (budget 0): no delete commits.
    store.set_delete_remaining_successes(0);

    let result = delete_sessions_for_code_replay(&store, "code-F").await;
    assert!(
        result.is_ok(),
        "best-effort revocation must return Ok even when no delete succeeds: {result:?}"
    );
    assert!(
        result.as_ref().expect("Ok").is_empty(),
        "no successful deletes means no hashes returned"
    );

    // Both sessions survive in the DB.
    assert!(
        get_session_by_token_hash(&store, "hash-f1", jiff::Timestamp::now())
            .await
            .expect("lookup f1")
            .is_some(),
        "no deletes committed, so hash-f1 must remain"
    );
    assert!(
        get_session_by_token_hash(&store, "hash-f2", jiff::Timestamp::now())
            .await
            .expect("lookup f2")
            .is_some(),
        "no deletes committed, so hash-f2 must remain"
    );
}

/// `delete_sessions_for_oauth_client` deletes only sessions tagged with the
/// given `client_id`, leaving other clients' sessions and pre-migration rows
/// (whose `client_id` deserialized to `None`) intact. This is the db-level
/// half of `revoke_tokens_api`'s user-issued-token revocation.
#[tokio::test]
async fn test_delete_sessions_for_oauth_client_targets_only_that_client() {
    let (store, _audit) = test_db().await;
    let (user_id, _) = upsert_user(&store, "revoke-client@example.com", None)
        .await
        .expect("create user");

    async fn mk(
        store: &crate::db::store::DocumentStore,
        user_id: &str,
        client_id: Option<&str>,
        hash: &str,
    ) {
        create_session(
            store,
            &CreateSessionParams {
                user_id,
                user_email: "revoke-client@example.com",
                token_hash: hash,
                authenticator_id: None,
                expires_at: "2099-12-31T23:59:59Z".parse().unwrap(),
                session_type: SessionPurpose::OAuthAccessToken,
                authorization_details: None,
                hardware_aaguid: None,
                org_domain: None,
                client_id,
                source_code_hash: None,
            },
        )
        .await
        .expect("create session");
    }
    // Two sessions for the primary client, one for a different client, and a
    // pre-migration row (no `client_id` tag, as if issued before the index).
    mk(&store, &user_id, Some("client-primary"), "hash-primary1").await;
    mk(&store, &user_id, Some("client-primary"), "hash-primary2").await;
    mk(&store, &user_id, Some("client-other"), "hash-other").await;
    mk(&store, &user_id, None, "hash-legacy").await;

    let deleted = delete_sessions_for_oauth_client(&store, "client-primary")
        .await
        .expect("delete for client-primary");
    assert_eq!(
        deleted, 2,
        "exactly the two client-primary sessions should be deleted"
    );

    // The primary client's sessions are gone.
    assert!(
        get_session_by_token_hash(&store, "hash-primary1", jiff::Timestamp::now())
            .await
            .expect("lookup primary1")
            .is_none(),
        "client-primary session hash-primary1 must be deleted"
    );
    assert!(
        get_session_by_token_hash(&store, "hash-primary2", jiff::Timestamp::now())
            .await
            .expect("lookup primary2")
            .is_none(),
        "client-primary session hash-primary2 must be deleted"
    );

    // Other clients and pre-migration rows survive.
    assert!(
        get_session_by_token_hash(&store, "hash-other", jiff::Timestamp::now())
            .await
            .expect("lookup other")
            .is_some(),
        "other client's session must survive revoking client-primary"
    );
    assert!(
        get_session_by_token_hash(&store, "hash-legacy", jiff::Timestamp::now())
            .await
            .expect("lookup legacy")
            .is_some(),
        "pre-migration session (no client_id) must survive client-scoped revocation"
    );

    // A second call is a no-op (idempotent): nothing left to delete.
    let deleted_again = delete_sessions_for_oauth_client(&store, "client-primary")
        .await
        .expect("delete for client-primary again");
    assert_eq!(deleted_again, 0, "re-deleting an empty index is a no-op");
}
