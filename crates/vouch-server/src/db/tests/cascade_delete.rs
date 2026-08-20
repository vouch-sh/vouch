// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Cascade deletion of users and OAuth clients with their dependent rows.
#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable; cast bounds are obvious in test fixtures"
)]

use super::*;

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
            token_endpoint_auth_method: None,
            jwks: None,
            jwks_uri: None,
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
