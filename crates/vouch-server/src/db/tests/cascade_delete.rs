// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Cascade deletion of users and OAuth clients with their dependent rows.
#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable; cast bounds are obvious in test fixtures"
)]

use super::*;
use crate::crypto::alg::JwsAlgorithm;
use crate::test_utils::test_arrival;

// ========================================================================
// Cascade Delete Tests
// ========================================================================

#[tokio::test]
async fn test_user_cascade_delete() {
    let (store, _audit) = test_db().await;

    // Create user with authenticators and sessions
    let (user_id, _) = upsert_user(&store, "cascade@example.com", None)
        .await
        .expect("Failed to create user");

    let auth_id = create_authenticator(
        &store,
        &CreateAuthenticatorParams {
            user_id: &user_id,
            user_email: "cascade@example.com",
            name: "Cascade Key",
            credential_id: &[99u8; 10],
            public_key: &[0u8; 32],
            aaguid: None,
            user_handle: None,
            attestation_verified: false,
        },
    )
    .await
    .expect("Failed to create authenticator");

    create_session(
        &store,
        &CreateSessionParams {
            user_id: &user_id,
            user_email: "cascade@example.com",
            token_hash: "cascade_token",
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

    // Verify everything exists
    assert!(
        get_authenticator_by_id(&store, &auth_id)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        get_session_by_token_hash(&store, "cascade_token", jiff::Timestamp::now())
            .await
            .unwrap()
            .is_some()
    );

    // Delete user
    delete_user(&store, &user_id)
        .await
        .expect("Failed to delete user");

    // Verify cascade (authenticators and sessions should be deleted)
    assert!(
        get_authenticator_by_id(&store, &auth_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        get_session_by_token_hash(&store, "cascade_token", jiff::Timestamp::now())
            .await
            .unwrap()
            .is_none()
    );
    assert!(get_user_by_id(&store, &user_id).await.unwrap().is_none());
}

/// `delete_user` returns `Result<bool>`: it must return `false` when the
/// user document does not exist (so handlers can surface 404 and skip the
/// audit event) and `true` when the user is deleted. Mirrors the contract
/// already implemented by `delete_scim_group` / `delete_custom_policy`.
///
/// Without the existence check, `delete_user` always returned `Ok(true)`,
/// making the handler-side `member_gone()` defense dead code and allowing a
/// fraudulent audit event when the target vanished mid-operation.
#[tokio::test]
async fn test_delete_user_returns_false_when_missing() {
    let (store, _audit) = test_db().await;

    // A valid UUID that was never inserted.
    let missing_id = "00000000-0000-7000-0000-000000000001";
    let deleted = delete_user(&store, missing_id)
        .await
        .expect("delete_user must not error on a missing user");
    assert!(
        !deleted,
        "delete_user must return false when the user does not exist"
    );

    // Sanity: deleting a real user returns true and removes the document.
    let (user_id, _) = upsert_user(&store, "delete-bool@example.com", None)
        .await
        .expect("create user");
    let deleted = delete_user(&store, &user_id)
        .await
        .expect("delete_user should succeed");
    assert!(deleted, "delete_user must return true for an existing user");
    assert!(
        get_user_by_id(&store, &user_id)
            .await
            .expect("query failed")
            .is_none(),
        "user should be gone after delete"
    );

    // Deleting the same user again returns false (idempotent miss).
    let deleted_again = delete_user(&store, &user_id)
        .await
        .expect("delete_user must not error on a missing user");
    assert!(
        !deleted_again,
        "delete_user must return false on the second delete of the same user"
    );
}

/// Regression test for GH#249 / PR#262: SSH revocation records must
/// survive user deletion so they remain visible in the KRL.
#[tokio::test]
async fn test_user_delete_preserves_ssh_revocations() {
    let (store, _audit) = test_db().await;

    let (user_id, _) = upsert_user(&store, "revoke-preserve@example.com", None)
        .await
        .expect("Failed to create user");

    let serial: u64 = 4_242_424;
    let expires_at: jiff::Timestamp = "2099-12-31T23:59:59Z".parse().unwrap();

    record_ssh_certificate_issuance(
        &store,
        serial,
        &user_id,
        "revoke-preserve@example.com",
        &["revoke-preserve@example.com".to_string()],
        expires_at,
    )
    .await
    .expect("Failed to record issued SSH certificate");

    crate::db::credentials::revoke_all_ssh_certificates_for_user(
        &store,
        &user_id,
        Some("User deleted by admin"),
        Some("admin-user-id"),
    )
    .await
    .expect("Failed to revoke SSH certificates");

    delete_user(&store, &user_id).await.expect("delete failed");

    // User should be gone
    assert!(
        get_user_by_id(&store, &user_id)
            .await
            .expect("query failed")
            .is_none()
    );

    // Revocation record must persist after user deletion
    assert!(
        is_ssh_certificate_revoked(&store, &serial.to_string())
            .await
            .expect("revocation check failed"),
        "revoked serial must remain after deleting the user"
    );
}

#[tokio::test]
async fn test_oauth_client_cascade_delete() {
    let (store, audit) = test_db().await;

    let (user_id, _) = upsert_user(&store, "oauth_cascade@example.com", None)
        .await
        .expect("Failed to create user");

    let (client, _) = create_oauth_client(
        &store,
        &CreateOAuthClientParams {
            user_id: Some(&user_id),
            name: "Cascade App",
            description: None,
            application_type: OAuthClientType::Web,
            redirect_uris: &[],
            access_scope: AccessScope::default(),
            org_id: None,
            resource_uris: &[],
            token_endpoint_auth_method: TokenEndpointAuthMethod::ClientSecretBasic,
            keys: None,
            fapi_profile: None,
            dpop_bound_access_tokens: None,
            grant_types: None,
            response_types: None,
            software_id: None,
            software_version: None,
            registration_source: RegistrationSource::Manual,
            registration_access_token_hash: None,
            registration_metadata: None,
            id_token_signed_response_alg: JwsAlgorithm::Rs256,
            tls_client_auth_subject_dn: None,
            tls_client_auth_san_dns: None,
            tls_client_auth_san_uri: None,
            tls_client_auth_san_ip: None,
            tls_client_auth_san_email: None,
            tls_client_certificate_bound_access_tokens: None,
            authorization_signed_response_alg: None,
            introspection_signed_response_alg: None,
            request_object_signing_alg: None,
            require_signed_request_object: None,
            userinfo_signed_response_alg: None,
            request_uris: None,
            post_logout_redirect_uris: None,
        },
    )
    .await
    .expect("Failed to create client");

    // Add secrets and usage events
    create_oauth_client_secret(&store, &client.id, "secret_hash", None, None)
        .await
        .expect("Failed to create secret");

    record_oauth_event(
        &audit,
        &store,
        &RecordOAuthEventParams {
            oauth_client_id: &client.id,
            event_type: OAuthEventType::TokenIssued,
            user_id: None,
            ip_address: None,
            user_agent: None,
            details: None,
            org_domain: RecordedOrgDomain::Unresolved,
        },
    )
    .await;

    // Delete client
    delete_oauth_client(&store, &client.id)
        .await
        .expect("Failed to delete client");

    // Verify cascade (secrets should be deleted)
    let secrets = get_oauth_client_secrets(&store, &client.id)
        .await
        .expect("Failed to get secrets");
    assert!(secrets.is_empty());

    // Verify JWKS cache row is also deleted
    let cache = get_jwks_cache(&store, &client.id)
        .await
        .expect("Failed to query JWKS cache");
    assert!(
        cache.is_none(),
        "JWKS cache must be deleted with the client"
    );
}

// ========================================================================
// Org-scoped application ownership transfer on user deletion
// ========================================================================

/// Build an OAuth client owned by `user_id` with the given access scope.
async fn create_scoped_client(
    store: &DocumentStore,
    user_id: &str,
    name: &str,
    access_scope: AccessScope,
    org_id: Option<&str>,
) -> String {
    create_test_client(
        store,
        user_id,
        TestClientSpec {
            name: name.to_string(),
            redirect_uris: vec![],
            access_scope,
            org_id: org_id.map(String::from),
            with_secret: false,
            ..Default::default()
        },
    )
    .await
    .app_id
}

/// Deleting an org-scoped application's creator transfers the application to
/// an active org admin. Management is creator-only, so leaving `user_id`
/// empty would strand the application with no one able to manage it.
#[tokio::test]
async fn test_delete_user_transfers_org_scoped_apps_to_org_admin() {
    let (store, _audit) = test_db().await;
    seed_test_org(&store).await;

    let (creator_id, _) = upsert_user_with_org(
        &store,
        "org-app-creator@example.com",
        None,
        Some(TEST_ORG_ID),
        false,
    )
    .await
    .expect("create creator");
    let (admin_id, _) = upsert_user_with_org(
        &store,
        "org-app-admin@example.com",
        None,
        Some(TEST_ORG_ID),
        true,
    )
    .await
    .expect("create admin");

    let org_app = create_scoped_client(
        &store,
        &creator_id,
        "Org App",
        AccessScope::Organization,
        Some(TEST_ORG_ID),
    )
    .await;
    let personal_app = create_scoped_client(
        &store,
        &creator_id,
        "Personal App",
        AccessScope::Personal,
        Some(TEST_ORG_ID),
    )
    .await;

    assert!(
        delete_user(&store, &creator_id).await.expect("delete_user"),
        "creator must be deleted"
    );

    let org_client = get_oauth_client_by_id(&store, &org_app)
        .await
        .expect("lookup org app")
        .expect("org app still exists");
    assert_eq!(
        org_client.user_id.as_deref(),
        Some(admin_id.as_str()),
        "org-scoped app must transfer to the org admin so it stays manageable"
    );

    let personal_client = get_oauth_client_by_id(&store, &personal_app)
        .await
        .expect("lookup personal app")
        .expect("personal app still exists");
    assert_eq!(
        personal_client.user_id, None,
        "personal app has no other legitimate owner and stays unlinked"
    );
}

/// With no other active org admin to inherit it, an org-scoped application
/// is unlinked as before — there is no one to transfer it to.
#[tokio::test]
async fn test_delete_user_unlinks_org_app_when_no_admin_remains() {
    let (store, _audit) = test_db().await;
    seed_test_org(&store).await;

    let (creator_id, _) = upsert_user_with_org(
        &store,
        "sole-admin@example.com",
        None,
        Some(TEST_ORG_ID),
        true,
    )
    .await
    .expect("create creator");

    let org_app = create_scoped_client(
        &store,
        &creator_id,
        "Sole Org App",
        AccessScope::Organization,
        Some(TEST_ORG_ID),
    )
    .await;

    assert!(
        delete_user(&store, &creator_id).await.expect("delete_user"),
        "creator must be deleted"
    );

    let org_client = get_oauth_client_by_id(&store, &org_app)
        .await
        .expect("lookup org app")
        .expect("org app still exists");
    assert_eq!(
        org_client.user_id, None,
        "with no successor admin the app is unlinked"
    );
}

/// A deactivated org admin must not inherit applications — they cannot
/// authenticate, so the transfer would strand the app just as surely.
#[tokio::test]
async fn test_delete_user_skips_deactivated_org_admin_as_successor() {
    let (store, _audit) = test_db().await;
    seed_test_org(&store).await;

    let (creator_id, _) = upsert_user_with_org(
        &store,
        "transfer-creator@example.com",
        None,
        Some(TEST_ORG_ID),
        false,
    )
    .await
    .expect("create creator");
    let (inactive_admin_id, _) = upsert_user_with_org(
        &store,
        "inactive-admin@example.com",
        None,
        Some(TEST_ORG_ID),
        true,
    )
    .await
    .expect("create inactive admin");
    update_user_active_status(&store, &inactive_admin_id, false)
        .await
        .expect("deactivate admin");

    let org_app = create_scoped_client(
        &store,
        &creator_id,
        "Org App",
        AccessScope::Organization,
        Some(TEST_ORG_ID),
    )
    .await;

    assert!(
        delete_user(&store, &creator_id).await.expect("delete_user"),
        "creator must be deleted"
    );

    let org_client = get_oauth_client_by_id(&store, &org_app)
        .await
        .expect("lookup org app")
        .expect("org app still exists");
    assert_eq!(
        org_client.user_id, None,
        "a deactivated admin must not inherit the application"
    );
}

/// Two org admins deleted at the same time must not leave the organization's
/// applications owned by a user that no longer exists.
///
/// Both deletions read the org's members to choose a successor, and a
/// predicate read is what concurrent transactions do not conflict on: each
/// would otherwise pick the other, and both rows would then be removed.
/// Writing the org row makes the loser re-read and pick a survivor — or,
/// when it is the last admin, unlink.
///
/// This asserts the invariant; it does not reproduce the skew. SQLite
/// serializes writers, so the interleaving that produces it cannot occur
/// here — the same reason
/// `test_enroll_user_with_org_same_domain_converges_on_one_org` exercises
/// its property sequentially. The guarantee under READ COMMITTED comes from
/// the org-row write in `delete_user`, which is the pattern enrollment uses
/// to claim its admin slot.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_concurrent_admin_deletes_never_strand_org_apps() {
    let (store, _audit) = test_db().await;
    seed_test_org(&store).await;
    let store = std::sync::Arc::new(store);

    let (admin_a, _) = upsert_user_with_org(
        &store,
        "race-admin-a@example.com",
        None,
        Some(TEST_ORG_ID),
        true,
    )
    .await
    .expect("create admin a");
    let (admin_b, _) = upsert_user_with_org(
        &store,
        "race-admin-b@example.com",
        None,
        Some(TEST_ORG_ID),
        true,
    )
    .await
    .expect("create admin b");

    let app_a = create_scoped_client(
        &store,
        &admin_a,
        "App A",
        AccessScope::Organization,
        Some(TEST_ORG_ID),
    )
    .await;
    let app_b = create_scoped_client(
        &store,
        &admin_b,
        "App B",
        AccessScope::Organization,
        Some(TEST_ORG_ID),
    )
    .await;

    let (r1, r2) = tokio::join!(
        {
            let s = std::sync::Arc::clone(&store);
            let id = admin_a.clone();
            async move { delete_user(&s, &id).await }
        },
        {
            let s = std::sync::Arc::clone(&store);
            let id = admin_b.clone();
            async move { delete_user(&s, &id).await }
        },
    );
    assert!(r1.expect("delete a"), "admin a must be deleted");
    assert!(r2.expect("delete b"), "admin b must be deleted");

    // Whatever order they ran in, no application may reference a deleted user.
    for app_id in [&app_a, &app_b] {
        let client = get_oauth_client_by_id(&store, app_id)
            .await
            .expect("lookup app")
            .expect("app still exists");
        if let Some(owner) = client.user_id.as_deref() {
            let owner_exists = get_user_by_id(&store, owner)
                .await
                .expect("lookup owner")
                .is_some();
            assert!(
                owner_exists,
                "application {app_id} is owned by deleted user {owner}"
            );
        }
    }
}

/// Step-6 client reassignment in `delete_user` must write under the OCC
/// version guard: `OAuthClientDoc`'s version is the serialization point for
/// all secret-set mutations (`update_oauth_client` /
/// `update_oauth_client_registration` write via `compare_and_update`), and a
/// blind `UPDATE ... version = version + 1` between a `find_all` read and
/// the write would silently overwrite a concurrently-committed client
/// update with the stale doc — the same lost-update anomaly the
/// authenticator-deletion cascade had for `DeviceAuthRequestDoc`. The guard
/// lives in `update_by_index` itself, whose lost write is a retryable
/// `VersionConflict` that the entry-point `with_dsql_retry!` re-runs from a
/// fresh read.
///
/// This sequential test pins the reassignment against a doc whose version
/// has already advanced past the initial insert (several prior committed
/// updates), asserting it lands on the LATEST doc state with every
/// non-`user_id` field intact. The guard itself is pinned at the store level
/// by `store::tests::tx_update_by_index_rejects_row_changed_since_read`.
#[tokio::test]
async fn test_delete_user_client_reassignment_writes_against_latest_version() {
    let (store, _audit) = test_db().await;
    seed_test_org(&store).await;

    let (creator_id, _) = upsert_user_with_org(
        &store,
        "occ-app-creator@example.com",
        None,
        Some(TEST_ORG_ID),
        false,
    )
    .await
    .expect("create creator");
    let (admin_id, _) = upsert_user_with_org(
        &store,
        "occ-app-admin@example.com",
        None,
        Some(TEST_ORG_ID),
        true,
    )
    .await
    .expect("create admin");

    let org_app = create_scoped_client(
        &store,
        &creator_id,
        "OCC Org App",
        AccessScope::Organization,
        Some(TEST_ORG_ID),
    )
    .await;

    // Advance the client doc's version with committed OCC updates — the
    // reassignment must read and re-write the LATEST state, not version 1.
    let occ_redirects = vec!["https://occ.example.com/callback".to_string()];
    for name in ["OCC Org App v2", "OCC Org App v3"] {
        update_oauth_client(
            &store,
            &UpdateOAuthClientParams {
                id: &org_app,
                name,
                description: Some("occ regression fixture"),
                redirect_uris: &occ_redirects,
                access_scope: None,
                org_id: None,
                resource_uris: &[],
                token_endpoint_auth_method: crate::db::TokenEndpointAuthMethod::default(),
                keys: None,
                fapi_profile: crate::db::FapiProfile::None,
                dpop_bound_access_tokens: false,
                post_logout_redirect_uris: None,
            },
        )
        .await
        .expect("update client");
    }

    assert!(
        delete_user(&store, &creator_id).await.expect("delete_user"),
        "creator must be deleted"
    );

    let org_client = get_oauth_client_by_id(&store, &org_app)
        .await
        .expect("lookup org app")
        .expect("org app still exists");
    assert_eq!(
        org_client.user_id.as_deref(),
        Some(admin_id.as_str()),
        "org-scoped app must transfer to the org admin"
    );
    // The reassignment modified ONLY user_id: the latest committed name and
    // redirect URIs survive. Under the pre-fix blind update a stale doc
    // (read before a concurrent update committed) would have clobbered them.
    assert_eq!(
        org_client.name, "OCC Org App v3",
        "reassignment must write against the latest doc state"
    );
    assert_eq!(
        org_client.redirect_uris, occ_redirects,
        "non-user_id fields must be preserved by the reassignment"
    );
}

// ========================================================================
// delete_oauth_client_and_revoke_sessions: cache/DB consistency on partial
// failure (regression for the (A)-OK / (B)-Err arm)
// ========================================================================

/// Helper: create an OAuth access-token session with the given keying and a
/// far-future expiry, so it is live for the duration of the test. Directly
/// mirrors the `create_oauth_session` helper in `users_and_sessions.rs` but
/// adds the `client_id` index, which the chokepoint's client-scoped delete
/// matches on.
async fn create_client_session(
    store: &DocumentStore,
    user_id: &str,
    email: &str,
    token_hash: &str,
    client_id: Option<&str>,
) {
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
            client_id,
            source_code_hash: None,
        },
    )
    .await
    .expect("create session");
}

/// Regression test for the cache/DB desync in
/// [`delete_oauth_client_and_revoke_sessions`].
///
/// The chokepoint used to run both `delete_by_index` calls (the
/// `user_id`-indexed M2M delete, then the `client_id`-indexed user-issued
/// delete) before either cache invalidation. If the second delete surfaced
/// `Err`, the `?` skipped `invalidate_for_user`/`invalidate_for_client`, so
/// the M2M rows the first delete already committed remained cached as `Hit`s
/// — and `SessionCache::get` serves a `Hit` without re-reading the DB, so
/// those tokens kept authenticating until the cache TTL elapsed.
///
/// `set_delete_by_index_remaining_successes(1)` faults the *second*
/// `delete_by_index` (the client-scoped one) while letting the first
/// (the `user_id`-scoped M2M delete) commit, exercising the (A)-OK / (B)-Err
/// arm. With the fix, `invalidate_for_user` runs between the two deletes and
/// evicts the committed-deleted M2M entry, so a subsequent cache lookup misses
/// through to the DB and returns `None`. Under the bug both invalidations are
/// skipped and the lookup returns `Some` from the stale `Hit`.
#[tokio::test]
async fn test_delete_client_partial_failure_evicts_committed_m2m_from_cache() {
    let (mut store, _audit) = test_db().await;

    let (user_id, _) = upsert_user(&store, "partial-cache@example.com", None)
        .await
        .expect("create user");

    let client = create_test_client(
        &store,
        &user_id,
        TestClientSpec {
            name: "Partial Cache App".to_string(),
            with_secret: false,
            ..Default::default()
        },
    )
    .await;

    // M2M (client_credentials) session: user_id == client_id (RFC 9068 §2.2),
    // also tagged with client_id on its own index. This is the half step (A)
    // commits and must be evicted from the cache before step (B) can fault.
    create_client_session(
        &store,
        &client.client_id,
        &format!("{}@clients", client.client_id),
        "m2m-hash",
        Some(&client.client_id),
    )
    .await;

    // User-issued access-token session: keyed by the real resource owner's
    // user_id, tagged with the issuing client_id. Step (B) would delete this
    // but faults before committing, so it must survive in DB and cache.
    create_client_session(
        &store,
        &user_id,
        "partial-cache@example.com",
        "user-hash",
        Some(&client.client_id),
    )
    .await;

    // Warm the session cache with `Hit`s for both tokens — the precondition
    // the exploit requires: the attacker used the token against a resource
    // endpoint within the cache TTL before the admin's delete.
    let cache = SessionCache::new(100, 30);
    assert!(
        cache
            .get_session_by_token_hash(&store, "m2m-hash", test_arrival())
            .await
            .expect("cache lookup m2m")
            .is_some(),
        "m2m token must start as a cache Hit"
    );
    assert!(
        cache
            .get_session_by_token_hash(&store, "user-hash", test_arrival())
            .await
            .expect("cache lookup user")
            .is_some(),
        "user-issued token must start as a cache Hit"
    );

    // Fault the *second* `delete_by_index`: the `user_id`-scoped M2M delete
    // (step A) consumes the single unit and commits; the client-scoped delete
    // (step B) faults before opening its transaction.
    store.set_delete_by_index_remaining_successes(1);

    // The chokepoint must surface the (B)-failure as `Err` to the caller (so
    // the admin sees a 500 and can retry) — the fix changes only *when* the
    // cache is invalidated, not the error-propagation contract.
    let result =
        delete_oauth_client_and_revoke_sessions(&store, &cache, &client.app_id, &client.client_id)
            .await;
    assert!(
        result.is_err(),
        "chokepoint must surface the (B)-delete failure as Err: {result:?}"
    );

    // The client row is NOT deleted on this arm: step (E) only runs after
    // both invalidations succeed, and step (B) faulted before it. Pinning this
    // confirms the fix preserved the error-propagation contract (the admin
    // sees the error and retries; the row is still there to retry against).
    assert!(
        get_oauth_client_by_id(&store, &client.app_id)
            .await
            .expect("lookup client")
            .is_some(),
        "the client row must survive when step (E) is unreachable"
    );

    // The committed-deleted M2M session is gone from the DB; the user-issued
    // session whose delete faulted is still present.
    let now = jiff::Timestamp::now();
    assert!(
        get_session_by_token_hash(&store, "m2m-hash", now)
            .await
            .expect("db lookup m2m")
            .is_none(),
        "the committed M2M delete must be gone from the DB"
    );
    assert!(
        get_session_by_token_hash(&store, "user-hash", now)
            .await
            .expect("db lookup user")
            .is_some(),
        "the session whose delete faulted must remain in the DB"
    );

    // The distinguishing assertion: a DB-deleted M2M session must NOT be
    // served from a stale cache `Hit`. With the fix `invalidate_for_user`
    // evicted it between the two deletes, so this lookup misses through to
    // the DB and returns `None`. Under the bug both invalidations are skipped
    // and the stale `Hit` keeps authenticating the revoked M2M token until
    // the TTL.
    assert!(
        cache
            .get_session_by_token_hash(&store, "m2m-hash", test_arrival())
            .await
            .expect("cache re-lookup m2m")
            .is_none(),
        "a DB-deleted M2M session must not be served from a stale cache Hit \
         after the chokepoint returned Err on the second delete"
    );

    // The user-issued session whose delete faulted stays cached — it is still
    // a valid row, and `invalidate_for_user` correctly retained it (its
    // `user_id` is the real user, not the client). `invalidate_for_client`
    // never ran (step B faulted before it), which is consistent: the row is
    // still in the DB, so serving it is correct, not a stale `Hit`.
    assert!(
        cache
            .get_session_by_token_hash(&store, "user-hash", test_arrival())
            .await
            .expect("cache re-lookup user")
            .is_some(),
        "the session whose delete faulted must remain a cache Hit (still in DB)"
    );
}

/// The (A)-errors arm: when the *first* `delete_by_index` faults, no DB write
/// committed and no invalidation is needed — both halves stay consistent
/// (cache and DB untouched). Pins the contract that faulting step (A) evicts
/// nothing and leaves both sessions live, so a retry of the whole chokepoint
/// starts from a clean state.
#[tokio::test]
async fn test_delete_client_first_delete_failure_changes_nothing() {
    let (mut store, _audit) = test_db().await;

    let (user_id, _) = upsert_user(&store, "first-fail-client@example.com", None)
        .await
        .expect("create user");

    let client = create_test_client(
        &store,
        &user_id,
        TestClientSpec {
            name: "First Fail App".to_string(),
            with_secret: false,
            ..Default::default()
        },
    )
    .await;

    create_client_session(
        &store,
        &client.client_id,
        &format!("{}@clients", client.client_id),
        "m2m-f",
        Some(&client.client_id),
    )
    .await;
    create_client_session(
        &store,
        &user_id,
        "first-fail-client@example.com",
        "user-f",
        Some(&client.client_id),
    )
    .await;

    let cache = SessionCache::new(100, 30);
    assert!(
        cache
            .get_session_by_token_hash(&store, "m2m-f", test_arrival())
            .await
            .expect("warm m2m")
            .is_some()
    );
    assert!(
        cache
            .get_session_by_token_hash(&store, "user-f", test_arrival())
            .await
            .expect("warm user")
            .is_some()
    );

    // Fault every `delete_by_index`: step (A) faults before committing, so
    // neither delete runs and neither invalidation runs.
    store.set_delete_by_index_remaining_successes(0);

    let result =
        delete_oauth_client_and_revoke_sessions(&store, &cache, &client.app_id, &client.client_id)
            .await;
    assert!(
        result.is_err(),
        "chokepoint must surface the (A)-delete failure as Err: {result:?}"
    );

    // Nothing committed: both sessions remain in the DB.
    let now = jiff::Timestamp::now();
    assert!(
        get_session_by_token_hash(&store, "m2m-f", now)
            .await
            .expect("db m2m")
            .is_some(),
        "no delete committed, so the M2M session must remain"
    );
    assert!(
        get_session_by_token_hash(&store, "user-f", now)
            .await
            .expect("db user")
            .is_some(),
        "no delete committed, so the user-issued session must remain"
    );

    // No invalidation ran, so both stay cached — consistent with the DB, and
    // a retry of the chokepoint starts from a clean state.
    assert!(
        cache
            .get_session_by_token_hash(&store, "m2m-f", test_arrival())
            .await
            .expect("cache m2m")
            .is_some(),
        "no invalidation ran, so the M2M session must stay cached (still valid)"
    );
    assert!(
        cache
            .get_session_by_token_hash(&store, "user-f", test_arrival())
            .await
            .expect("cache user")
            .is_some(),
        "no invalidation ran, so the user-issued session must stay cached (still valid)"
    );
}
