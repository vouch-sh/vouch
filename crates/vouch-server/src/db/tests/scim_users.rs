// SPDX-License-Identifier: Apache-2.0 OR MIT
//! SCIM user CRUD, list/filter behavior, deactivation, and SCIM audit records.
#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable; cast bounds are obvious in test fixtures"
)]

use super::*;

// ========================================================================
// SCIM User Tests (RFC 7643/7644)
// ========================================================================

#[tokio::test]
async fn test_scim_user_crud() {
    let (store, _audit) = test_db().await;
    seed_test_org(&store).await;

    // Create SCIM user
    let user = create_scim_user(
        &store,
        Some(TEST_ORG_ID),
        "scim@example.com",
        Some("SCIM User"),
        Some("ext-123"),
        true,
    )
    .await
    .expect("Failed to create SCIM user");

    assert!(!user.id.is_empty());
    assert_eq!(user.email, "scim@example.com");
    assert_eq!(user.name, Some("SCIM User".to_string()));
    assert_eq!(user.external_id, Some("ext-123".to_string()));
    assert!(user.active);

    // Get SCIM user
    let fetched = get_scim_user(&store, &user.id, TEST_ORG_ID)
        .await
        .expect("Failed to get SCIM user")
        .expect("User should exist");
    assert_eq!(fetched.email, "scim@example.com");

    // Update SCIM user
    let _ = update_scim_user(
        &store,
        &user.id,
        TEST_ORG_ID,
        Some("Updated Name"),
        Some("ext-456"),
        false,
    )
    .await
    .expect("Failed to update SCIM user");

    let updated = get_scim_user(&store, &user.id, TEST_ORG_ID)
        .await
        .expect("Failed to get user")
        .expect("User should exist");
    assert_eq!(updated.name, Some("Updated Name".to_string()));
    assert_eq!(updated.external_id, Some("ext-456".to_string()));
    assert!(!updated.active);
}

#[tokio::test]
async fn test_scim_user_list_and_filter() {
    let (store, _audit) = test_db().await;
    seed_test_org(&store).await;

    // Create multiple users
    for i in 0..5 {
        create_scim_user(
            &store,
            Some(TEST_ORG_ID),
            &format!("user{}@example.com", i),
            None,
            None,
            true,
        )
        .await
        .expect("Failed to create user");
    }

    // List all users
    let (users, total) = list_scim_users(&store, TEST_ORG_ID, None, 1, 100)
        .await
        .expect("Failed to list users");
    assert_eq!(users.len(), 5);
    assert_eq!(total, 5);

    // Filter by userName (email)
    let (users, _) = list_scim_users(
        &store,
        TEST_ORG_ID,
        Some("userName eq \"user2@example.com\""),
        1,
        100,
    )
    .await
    .expect("Failed to filter users");
    assert_eq!(users.len(), 1);
    assert_eq!(users[0].email, "user2@example.com");

    // Pagination
    let (page1, _) = list_scim_users(&store, TEST_ORG_ID, None, 1, 2)
        .await
        .expect("Failed to paginate");
    assert_eq!(page1.len(), 2);

    let (page2, _) = list_scim_users(&store, TEST_ORG_ID, None, 3, 2)
        .await
        .expect("Failed to paginate");
    assert_eq!(page2.len(), 2);
}

// ===========================================================================
// SCIM user lookup — case-insensitive eq on userName / email
//
// `userName` and `email` are `caseExact: false` per RFC 7643, and emails are
// stored ASCII-lowercase. `eq` filters must therefore match regardless of the
// casing supplied by the client. See `try_indexed_user_lookup`.
// ===========================================================================

#[tokio::test]
async fn test_scim_filter_user_name_eq_is_case_insensitive() {
    let (store, _audit) = test_db().await;
    seed_test_org(&store).await;

    create_scim_user(
        &store,
        Some(TEST_ORG_ID),
        "alice@example.com",
        None,
        None,
        true,
    )
    .await
    .expect("Failed to create user");

    let (users, total) = list_scim_users(
        &store,
        TEST_ORG_ID,
        Some("userName eq \"Alice@Example.com\""),
        1,
        100,
    )
    .await
    .expect("Failed to filter users");

    assert_eq!(total, 1, "should find 1 user via case-insensitive filter");
    assert_eq!(users.len(), 1);
    assert_eq!(users[0].email, "alice@example.com");
}

#[tokio::test]
async fn test_scim_filter_email_eq_is_case_insensitive() {
    let (store, _audit) = test_db().await;
    seed_test_org(&store).await;

    create_scim_user(
        &store,
        Some(TEST_ORG_ID),
        "bob@example.com",
        None,
        None,
        true,
    )
    .await
    .expect("Failed to create user");

    // The `email` attribute path uses the same indexed lookup as `userName`.
    let (users, total) = list_scim_users(
        &store,
        TEST_ORG_ID,
        Some("email eq \"BOB@example.com\""),
        1,
        100,
    )
    .await
    .expect("Failed to filter users");

    assert_eq!(
        total, 1,
        "should find 1 user via case-insensitive email filter"
    );
    assert_eq!(users.len(), 1);
    assert_eq!(users[0].email, "bob@example.com");
}

#[tokio::test]
async fn test_scim_filter_user_name_eq_case_insensitive_is_org_scoped() {
    // User IDs are derived deterministically from email, so an email is
    // globally unique to one user. The indexed lookup combines the email
    // index with the `org_id` index, so a case-insensitive match must still
    // honor the org scope: a user in `other-org` must not be returned when
    // querying `TEST_ORG_ID`.
    let (store, _audit) = test_db().await;
    seed_test_org(&store).await;
    // `other-org` also needs an org doc because `create_scim_user` validates
    // domain ownership in-transaction; both orgs own `example.com` in this
    // test fixture (the test exercises org scoping, not domain isolation).
    store
        .insert_with_id("other-org", &test_org_doc(TEST_ORG_DOMAIN))
        .await
        .expect("seed other-org");

    create_scim_user(
        &store,
        Some(TEST_ORG_ID),
        "carol@example.com",
        None,
        None,
        true,
    )
    .await
    .expect("Failed to create user in TEST_ORG_ID");
    create_scim_user(
        &store,
        Some("other-org"),
        "carol-other@example.com",
        None,
        None,
        true,
    )
    .await
    .expect("Failed to create user in other-org");

    // Mixed-case filter resolves to the lowercase `carol@example.com` in
    // TEST_ORG_ID only.
    let (users, total) = list_scim_users(
        &store,
        TEST_ORG_ID,
        Some("userName eq \"Carol@Example.com\""),
        1,
        100,
    )
    .await
    .expect("Failed to filter users");

    assert_eq!(total, 1, "case-insensitive lookup must stay org-scoped");
    assert_eq!(users.len(), 1);
    assert_eq!(users[0].email, "carol@example.com");

    // Querying the other org with a mixed-case filter for its user must
    // find that user and not the TEST_ORG_ID one.
    let (users, total) = list_scim_users(
        &store,
        "other-org",
        Some("userName eq \"Carol-Other@Example.com\""),
        1,
        100,
    )
    .await
    .expect("Failed to filter users");
    assert_eq!(
        total, 1,
        "case-insensitive lookup must find the other-org user"
    );
    assert_eq!(users.len(), 1);
    assert_eq!(users[0].email, "carol-other@example.com");
}

#[tokio::test]
async fn test_scim_filter_external_id_eq_is_case_sensitive() {
    // `externalId` is `caseExact: true` per RFC 7643 Section 3.1, so the
    // indexed lookup must NOT be lowercased. This guards against the fix for
    // userName/email being over-applied to externalId.
    let (store, _audit) = test_db().await;
    seed_test_org(&store).await;

    create_scim_user(
        &store,
        Some(TEST_ORG_ID),
        "erin@example.com",
        None,
        Some("Ext-Case-123"),
        true,
    )
    .await
    .expect("Failed to create user");

    // Exact case matches.
    let (users, total) = list_scim_users(
        &store,
        TEST_ORG_ID,
        Some(r#"externalId eq "Ext-Case-123""#),
        1,
        100,
    )
    .await
    .expect("Failed to filter users");
    assert_eq!(total, 1, "exact-case externalId should match");
    assert_eq!(users.len(), 1);
    assert_eq!(users[0].email, "erin@example.com");

    // Wrong case must NOT match.
    let (users, total) = list_scim_users(
        &store,
        TEST_ORG_ID,
        Some(r#"externalId eq "ext-case-123""#),
        1,
        100,
    )
    .await
    .expect("Failed to filter users");
    assert_eq!(
        total, 0,
        "externalId is caseExact: wrong case must not match"
    );
    assert!(users.is_empty());
}

#[tokio::test]
async fn test_scim_filter_external_id_co_is_case_sensitive() {
    // `externalId` is `caseExact: true` per RFC 7643 Section 3.1, so the
    // "co" operator must also be case-sensitive (RFC 7644 Section 3.4.2.2).
    // This guards the in-memory `co` path against the bug where
    // `match_filter_value` lowercased all attributes unconditionally.
    let (store, _audit) = test_db().await;
    seed_test_org(&store).await;

    create_scim_user(
        &store,
        Some(TEST_ORG_ID),
        "test-co@example.com",
        None,
        Some("CaseSensitive-ID-123"),
        true,
    )
    .await
    .expect("Failed to create user");

    // Exact-case "co" matches.
    let (users, total) = list_scim_users(
        &store,
        TEST_ORG_ID,
        Some(r#"externalId co "CaseSensitive""#),
        1,
        100,
    )
    .await
    .expect("Failed to filter users");
    assert_eq!(total, 1, "exact-case co should match");
    assert_eq!(users.len(), 1);
    assert_eq!(users[0].email, "test-co@example.com");

    // Wrong-case "co" must NOT match.
    let (users, total) = list_scim_users(
        &store,
        TEST_ORG_ID,
        Some(r#"externalId co "casesensitive""#),
        1,
        100,
    )
    .await
    .expect("Failed to filter users");
    assert_eq!(
        total, 0,
        "externalId is caseExact: lowercase co should not match"
    );
    assert!(users.is_empty());
}

#[tokio::test]
async fn test_scim_filter_user_name_co_remains_case_insensitive() {
    // `userName` and `email` are `caseExact: false` per RFC 7643, so "co"
    // must remain case-insensitive. Guards against the fix being
    // over-applied to case-insensitive attributes.
    let (store, _audit) = test_db().await;
    seed_test_org(&store).await;

    create_scim_user(
        &store,
        Some(TEST_ORG_ID),
        "swcase@example.com",
        None,
        None,
        true,
    )
    .await
    .expect("Failed to create user");

    let (users, total) =
        list_scim_users(&store, TEST_ORG_ID, Some(r#"userName co "SWCASE""#), 1, 100)
            .await
            .expect("Failed to filter users");
    assert_eq!(
        total, 1,
        "userName is caseExact: false; co must stay case-insensitive"
    );
    assert_eq!(users.len(), 1);
    assert_eq!(users[0].email, "swcase@example.com");
}

#[tokio::test]
async fn test_scim_session_invalidation_on_deactivation() {
    let (store, _audit) = test_db().await;
    seed_test_org(&store).await;

    // Create user with session
    let user = create_scim_user(
        &store,
        Some(TEST_ORG_ID),
        "invalidate@example.com",
        None,
        None,
        true,
    )
    .await
    .expect("Failed to create user");

    // Create authenticator (with user_email parameter)
    let auth_id = create_authenticator(
        &store,
        &CreateAuthenticatorParams {
            user_id: &user.id,
            user_email: "invalidate@example.com",
            name: "SCIM Key",
            credential_id: b"scim-cred-id",
            public_key: &[0u8; 32],
            aaguid: None,
            user_handle: Some(user.id.as_bytes()),
            attestation_verified: false,
        },
    )
    .await
    .expect("Failed to create authenticator");

    // Create session (with user_email parameter)
    create_session(
        &store,
        &CreateSessionParams {
            user_id: &user.id,
            user_email: "invalidate@example.com",
            token_hash: "scim_token_hash",
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

    // Verify session exists
    let session = get_session_by_token_hash(&store, "scim_token_hash", jiff::Timestamp::now())
        .await
        .expect("Failed to get session");
    assert!(session.is_some());

    // Delete all sessions for user (as SCIM would do on deactivation)
    let deleted = delete_sessions_for_user(&store, &user.id)
        .await
        .expect("Failed to delete sessions");
    assert_eq!(deleted, 1);

    // Verify session deleted
    let session = get_session_by_token_hash(&store, "scim_token_hash", jiff::Timestamp::now())
        .await
        .expect("Failed to get session");
    assert!(session.is_none());
}

#[tokio::test]
async fn test_scim_audit_logging() {
    let (_store, audit) = test_db().await;

    record_scim_audit(
        &audit,
        "CREATE",
        "User",
        "user-123",
        Some("token-123"),
        Some("Created user via SCIM"),
        Some("example.com"),
    )
    .await;

    // Record another audit log without token or org domain (None is valid)
    record_scim_audit(&audit, "DELETE", "User", "user-789", None, None, None).await;

    // The write is best-effort (failures are swallowed), so assert both
    // rows landed by querying them back.
    let events = audit
        .query_events(&AuditEventFilter {
            event_types: Some(vec!["scim_operation".to_string()]),
            ..AuditEventFilter::default()
        })
        .await
        .expect("query audit events");
    assert_eq!(events.len(), 2, "both SCIM audit rows must be stored");
    assert_ne!(events[0].id, events[1].id);
}
