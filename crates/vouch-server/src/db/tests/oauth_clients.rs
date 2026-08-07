// SPDX-License-Identifier: Apache-2.0 OR MIT
//! OAuth client application CRUD, client types, secret validity.
#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable; cast bounds are obvious in test fixtures"
)]

use super::*;

// ========================================================================
// OAuth Client Application Tests (Phase 7)
// ========================================================================

#[tokio::test]
async fn test_oauth_client_crud() {
    let (store, _audit) = test_db().await;

    // Create user
    let (user_id, _) = upsert_user(&store, "developer@example.com", Some("Developer"))
        .await
        .expect("Failed to create user");

    // Create OAuth client
    let redirect_uris = vec!["https://example.com/callback".to_string()];
    let (client, client_id) = create_oauth_client(
        &store,
        &CreateOAuthClientParams {
            user_id: Some(&user_id),
            name: "My App",
            description: Some("A test application"),
            application_type: OAuthClientType::Web,
            redirect_uris: &redirect_uris,
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
    .expect("Failed to create OAuth client");

    assert!(!client_id.is_empty());
    assert_eq!(client.name, "My App");
    assert_eq!(client.application_type, OAuthClientType::Web);
    assert!(client.active);

    // Get by ID
    let fetched = get_oauth_client_by_id(&store, &client.id)
        .await
        .expect("Failed to get client")
        .expect("Client should exist");
    assert_eq!(fetched.client_id, client_id);

    // Get by client_id
    let fetched = get_oauth_client_by_client_id(&store, &client_id)
        .await
        .expect("Failed to get client")
        .expect("Client should exist");
    assert_eq!(fetched.name, "My App");

    // Update client
    let new_redirect_uris = vec![
        "https://example.com/callback".to_string(),
        "https://example.com/callback2".to_string(),
    ];
    update_oauth_client(
        &store,
        &UpdateOAuthClientParams {
            id: &client.id,
            name: "My Updated App",
            description: Some("Updated desc"),
            redirect_uris: &new_redirect_uris,
            access_scope: None,
            org_id: None,
            resource_uris: &[],
            token_endpoint_auth_method: client.token_endpoint_auth_method,
            jwks: client.jwks.as_ref(),
            jwks_uri: client.jwks_uri.as_deref(),
            fapi_profile: client.fapi_profile,
            dpop_bound_access_tokens: client.dpop_bound_access_tokens,
            post_logout_redirect_uris: None,
        },
    )
    .await
    .expect("Failed to update client");

    let updated = get_oauth_client_by_id(&store, &client.id)
        .await
        .expect("Failed to get client")
        .expect("Client should exist");
    assert_eq!(updated.name, "My Updated App");
    assert_eq!(updated.redirect_uris.len(), 2);

    // Delete client
    let deleted = delete_oauth_client(&store, &client.id)
        .await
        .expect("Failed to delete client");
    assert_eq!(deleted, 1);

    // Verify deleted
    let client = get_oauth_client_by_id(&store, &client.id)
        .await
        .expect("Query should succeed");
    assert!(client.is_none());
}

#[tokio::test]
async fn test_oauth_client_types() {
    let (store, _audit) = test_db().await;

    let (user_id, _) = upsert_user(&store, "types@example.com", None)
        .await
        .expect("Failed to create user");

    // Test all application types
    for app_type in [
        OAuthClientType::Web,
        OAuthClientType::Native,
        OAuthClientType::Spa,
        OAuthClientType::Service,
    ] {
        let (client, _) = create_oauth_client(
            &store,
            &CreateOAuthClientParams {
                user_id: Some(&user_id),
                name: &format!("{:?} App", app_type),
                description: None,
                application_type: app_type,
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

        assert_eq!(client.application_type, app_type);

        // Check requires_secret
        let requires_secret = app_type.requires_secret();
        match app_type {
            OAuthClientType::Web | OAuthClientType::Service => assert!(requires_secret),
            OAuthClientType::Native | OAuthClientType::Spa => assert!(!requires_secret),
        }
    }
}

#[tokio::test]
async fn test_oauth_client_list_for_user() {
    let (store, _audit) = test_db().await;

    let (user_id1, _) = upsert_user(&store, "user1@example.com", None)
        .await
        .expect("Failed to create user");
    let (user_id2, _) = upsert_user(&store, "user2@example.com", None)
        .await
        .expect("Failed to create user");

    // Create clients for user1
    for i in 0..3 {
        create_oauth_client(
            &store,
            &CreateOAuthClientParams {
                user_id: Some(&user_id1),
                name: &format!("App {}", i),
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
    }

    // Create client for user2
    create_oauth_client(
        &store,
        &CreateOAuthClientParams {
            user_id: Some(&user_id2),
            name: "Other App",
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

    // Get user1's clients
    let clients = get_oauth_clients_for_user(&store, &user_id1)
        .await
        .expect("Failed to get clients");
    assert_eq!(clients.len(), 3);

    // Get user2's clients
    let clients = get_oauth_clients_for_user(&store, &user_id2)
        .await
        .expect("Failed to get clients");
    assert_eq!(clients.len(), 1);
}

#[tokio::test]
async fn test_oauth_client_secret_management() {
    let (store, _audit) = test_db().await;

    let (user_id, _) = upsert_user(&store, "secrets@example.com", None)
        .await
        .expect("Failed to create user");

    let (client, _) = create_oauth_client(
        &store,
        &CreateOAuthClientParams {
            user_id: Some(&user_id),
            name: "Secret App",
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

    // Create a secret
    let secret_hash = "hashed_secret_12345";
    let secret = create_oauth_client_secret(
        &store,
        &client.id,
        secret_hash,
        Some("Initial secret"),
        None,
    )
    .await
    .expect("Failed to create secret");

    assert!(!secret.id.is_empty());
    assert_eq!(secret.oauth_client_id, client.id);
    assert!(secret.revoked_at.is_none());

    // Get secrets
    let secrets = get_oauth_client_secrets(&store, &client.id)
        .await
        .expect("Failed to get secrets");
    assert_eq!(secrets.len(), 1);

    // Revoke all secrets
    let revoked_count = revoke_all_oauth_client_secrets(&store, &client.id)
        .await
        .expect("Failed to revoke secrets");
    assert_eq!(revoked_count, 1);

    // Verify revoked
    let secrets = get_oauth_client_secrets(&store, &client.id)
        .await
        .expect("Failed to get secrets");
    assert!(secrets[0].revoked_at.is_some());
}

#[tokio::test]
async fn test_oauth_usage_recording() {
    let (store, audit) = test_db().await;

    let (user_id, _) = upsert_user(&store, "usage@example.com", None)
        .await
        .expect("Failed to create user");

    let (client, _) = create_oauth_client(
        &store,
        &CreateOAuthClientParams {
            user_id: Some(&user_id),
            name: "Usage App",
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

    // Record some events (now uses AuditStore)
    record_oauth_event(
        &audit,
        &store,
        &RecordOAuthEventParams {
            oauth_client_id: &client.id,
            event_type: OAuthEventType::TokenIssued,
            user_id: Some(&user_id),
            ip_address: None,
            user_agent: None,
            details: None,
        },
    )
    .await;
    record_oauth_event(
        &audit,
        &store,
        &RecordOAuthEventParams {
            oauth_client_id: &client.id,
            event_type: OAuthEventType::TokenIssued,
            user_id: Some(&user_id),
            ip_address: None,
            user_agent: None,
            details: None,
        },
    )
    .await;
    record_oauth_event(
        &audit,
        &store,
        &RecordOAuthEventParams {
            oauth_client_id: &client.id,
            event_type: OAuthEventType::TokenRevoked,
            user_id: Some(&user_id),
            ip_address: None,
            user_agent: None,
            details: None,
        },
    )
    .await;

    let stats = get_oauth_usage_stats(&audit, &client.id, None)
        .await
        .expect("Failed to get stats");

    // Should have 2 token_issued and 1 token_revoked
    let issued_count: i64 = stats
        .iter()
        .filter(|s| s.event_type == "oauth_token_issued")
        .map(|s| s.count)
        .sum();
    assert_eq!(issued_count, 2);
    let revoked_count: i64 = stats
        .iter()
        .filter(|s| s.event_type == "oauth_token_revoked")
        .map(|s| s.count)
        .sum();
    assert_eq!(revoked_count, 1);
}

// ========================================================================
// OAuthClientSecret — is_valid edge cases
// ========================================================================

#[test]
fn test_oauth_client_secret_is_valid_revoked() {
    let now = jiff::Timestamp::now();
    let secret = OAuthClientSecret {
        id: "s1".into(),
        oauth_client_id: "c1".into(),
        secret_hash: "h1".into(),
        description: None,
        created_at: now,
        expires_at: None,
        revoked_at: Some(now), // revoked
    };
    assert!(!secret.is_valid(&now), "Revoked secret must be invalid");
}

#[test]
fn test_oauth_client_secret_is_valid_expired() {
    let now = jiff::Timestamp::now();
    let past: jiff::Timestamp = "2020-01-01T00:00:00Z".parse().unwrap();
    let secret = OAuthClientSecret {
        id: "s2".into(),
        oauth_client_id: "c1".into(),
        secret_hash: "h2".into(),
        description: None,
        created_at: past,
        expires_at: Some(past), // already expired
        revoked_at: None,
    };
    assert!(!secret.is_valid(&now), "Expired secret must be invalid");
}

#[test]
fn test_oauth_client_secret_is_valid_not_expired() {
    let now = jiff::Timestamp::now();
    let future: jiff::Timestamp = "2099-01-01T00:00:00Z".parse().unwrap();
    let secret = OAuthClientSecret {
        id: "s3".into(),
        oauth_client_id: "c1".into(),
        secret_hash: "h3".into(),
        description: None,
        created_at: now,
        expires_at: Some(future),
        revoked_at: None,
    };
    assert!(
        secret.is_valid(&now),
        "Non-expired, non-revoked secret must be valid"
    );
}

#[test]
fn test_oauth_client_secret_is_valid_no_expiry() {
    let now = jiff::Timestamp::now();
    let secret = OAuthClientSecret {
        id: "s4".into(),
        oauth_client_id: "c1".into(),
        secret_hash: "h4".into(),
        description: None,
        created_at: now,
        expires_at: None,
        revoked_at: None,
    };
    assert!(
        secret.is_valid(&now),
        "Secret with no expiry and not revoked must be valid"
    );
}
