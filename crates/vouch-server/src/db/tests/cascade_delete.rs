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

    revoke_all_ssh_certificates_for_user(
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
