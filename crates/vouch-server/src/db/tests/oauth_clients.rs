// SPDX-License-Identifier: Apache-2.0 OR MIT
//! OAuth client application CRUD, client types, secret validity.
#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable; cast bounds are obvious in test fixtures"
)]

use super::*;
use crate::crypto::alg::JwsAlgorithm;

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
            keys: client.keys.as_ref(),
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
                token_endpoint_auth_method: if app_type.requires_secret() {
                    TokenEndpointAuthMethod::ClientSecretBasic
                } else {
                    TokenEndpointAuthMethod::None
                },
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

        assert_eq!(client.application_type, app_type);

        // Check requires_secret
        let requires_secret = app_type.requires_secret();
        match app_type {
            OAuthClientType::Web | OAuthClientType::Service => assert!(requires_secret),
            OAuthClientType::Native | OAuthClientType::Spa => assert!(!requires_secret),
        }
    }
}

/// Rows persisted before secretless client types were stored as public
/// carry `client_secret_basic`; `normalize_stored_auth_method` reads them
/// as `none`.
#[tokio::test]
async fn test_legacy_public_client_rows_read_as_auth_method_none() {
    let (store, _audit) = test_db().await;

    let (user_id, _) = upsert_user(&store, "legacy-public@example.com", None)
        .await
        .expect("Failed to create user");

    for app_type in [OAuthClientType::Spa, OAuthClientType::Native] {
        let client = create_test_client(
            &store,
            &user_id,
            TestClientSpec {
                name: format!("Legacy {app_type:?}"),
                application_type: app_type,
                token_endpoint_auth_method: Some(TokenEndpointAuthMethod::ClientSecretBasic),
                with_secret: false,
                ..TestClientSpec::default()
            },
        )
        .await;

        let loaded = get_oauth_client_by_client_id(&store, &client.client_id)
            .await
            .expect("Failed to get client")
            .expect("Client should exist");
        assert_eq!(
            loaded.token_endpoint_auth_method,
            TokenEndpointAuthMethod::None,
            "{app_type:?} + client_secret_basic must normalize to none on read"
        );
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
            org_domain: RecordedOrgDomain::Unresolved,
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
            org_domain: RecordedOrgDomain::Unresolved,
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
            org_domain: RecordedOrgDomain::Unresolved,
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

// ─────────────────────────────────────────────────────────────────────────
// Redirect URI validation — the one rule shared by every write path
// ─────────────────────────────────────────────────────────────────────────

use crate::db::{OAuthClientType, RedirectUriError, validate_redirect_uri};

/// RFC 6749 §3.1.2: "The endpoint URI MUST NOT include a fragment component."
/// Rejected for every client kind, which is the change here — the self-service
/// path had no fragment check at all.
#[test]
fn redirect_uri_with_a_fragment_is_rejected_for_every_client_kind() {
    for kind in [
        OAuthClientType::Web,
        OAuthClientType::Native,
        OAuthClientType::Spa,
        OAuthClientType::Service,
    ] {
        assert_eq!(
            validate_redirect_uri("https://app.example/cb#x", kind),
            Err(RedirectUriError::HasFragment),
            "{kind:?} must not be able to register a fragment"
        );
    }
}

/// OIDC Registration §2: "Native Clients MUST only register "redirect_uris"
/// using custom URI schemes or loopback URLs using the "http" scheme".
/// Dynamic client registration accepted a custom scheme for any client and
/// self-service rejected it for all of them; the rule is per client kind.
#[test]
fn custom_scheme_is_registrable_only_by_native_clients() {
    assert_eq!(
        validate_redirect_uri("com.example.app://cb", OAuthClientType::Native),
        Ok(())
    );
    for kind in [
        OAuthClientType::Web,
        OAuthClientType::Spa,
        OAuthClientType::Service,
    ] {
        assert_eq!(
            validate_redirect_uri("com.example.app://cb", kind),
            Err(RedirectUriError::CustomSchemeNotNative),
            "{kind:?} is not a native client"
        );
    }
}

/// RFC 8252 §7.1's reverse-domain scheme format is a MUST on the app, not on
/// the authorization server, so a scheme that does not follow it still
/// registers.
#[test]
fn a_custom_scheme_is_not_required_to_be_reverse_domain() {
    assert_eq!(
        validate_redirect_uri("myapp://cb", OAuthClientType::Native),
        Ok(())
    );
}

/// The loopback set is exactly what OIDC Registration §2 and OIDC Core
/// §3.1.2.1 enumerate — notably not `host.docker.internal`, which
/// `vouch_common::is_loopback_host` accepts and which resolves off-device.
#[test]
fn http_is_registrable_only_for_the_three_loopback_hosts() {
    for accepted in [
        "http://localhost:8080/cb",
        "http://127.0.0.1:8080/cb",
        "http://[::1]:8080/cb",
    ] {
        assert_eq!(
            validate_redirect_uri(accepted, OAuthClientType::Native),
            Ok(()),
            "{accepted} is a loopback redirect"
        );
    }
    for rejected in [
        "http://app.example/cb",
        "http://127.0.0.2:8080/cb",
        "http://host.docker.internal/cb",
    ] {
        assert_eq!(
            validate_redirect_uri(rejected, OAuthClientType::Native),
            Err(RedirectUriError::HttpNonLoopback),
            "{rejected} is not a loopback redirect"
        );
    }
}

#[test]
fn a_relative_uri_is_not_a_redirect_uri() {
    assert_eq!(
        validate_redirect_uri("/callback", OAuthClientType::Web),
        Err(RedirectUriError::NotAbsolute)
    );
}

// ─────────────────────────────────────────────────────────────────────────
// Redirect URI matching at the authorization endpoint
// ─────────────────────────────────────────────────────────────────────────

/// Persist a client with these redirect URIs and hand back the stored record,
/// so matching is exercised against a real row rather than a literal.
async fn client_with_redirect_uris(uris: &[&str]) -> OAuthClient {
    let (store, _audit) = test_db().await;
    let (user_id, _) = upsert_user(&store, "redirect-match@example.com", None)
        .await
        .expect("create user");
    let redirect_uris: Vec<String> = uris.iter().map(|u| (*u).to_string()).collect();
    let (client, _) = create_oauth_client(
        &store,
        &CreateOAuthClientParams {
            user_id: Some(&user_id),
            name: "Redirect Match",
            description: None,
            application_type: OAuthClientType::Native,
            redirect_uris: &redirect_uris,
            access_scope: AccessScope::default(),
            org_id: None,
            resource_uris: &[],
            token_endpoint_auth_method: TokenEndpointAuthMethod::None,
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
    .expect("create client");
    client
}

/// RFC 8252 §7.3: "The authorization server MUST allow any port to be
/// specified at the time of the request for loopback IP redirect URIs, to
/// accommodate clients that obtain an available ephemeral port from the
/// operating system at the time of the request."
#[tokio::test]
async fn a_loopback_ip_redirect_matches_on_any_port() {
    let client = client_with_redirect_uris(&["http://127.0.0.1:51004/cb"]).await;
    assert!(client.is_valid_redirect_uri("http://127.0.0.1:61023/cb"));
    assert!(client.is_valid_redirect_uri("http://127.0.0.1:51004/cb"));

    let client = client_with_redirect_uris(&["http://[::1]:51004/cb"]).await;
    assert!(client.is_valid_redirect_uri("http://[::1]:61023/cb"));
}

/// The any-port rule is scoped to what §7.3 calls "loopback IP redirect URIs".
/// `localhost` is a name, not an IP literal, so it keeps exact matching.
#[tokio::test]
async fn localhost_does_not_get_the_any_port_exemption() {
    let client = client_with_redirect_uris(&["http://localhost:51004/cb"]).await;
    assert!(client.is_valid_redirect_uri("http://localhost:51004/cb"));
    assert!(!client.is_valid_redirect_uri("http://localhost:61023/cb"));
}

/// Everything but the port must still match: the exemption cannot be used to
/// reach a different path, host, or scheme.
#[tokio::test]
async fn the_any_port_exemption_relaxes_only_the_port() {
    let client = client_with_redirect_uris(&["http://127.0.0.1:51004/cb"]).await;
    assert!(!client.is_valid_redirect_uri("http://127.0.0.1:61023/other"));
    assert!(!client.is_valid_redirect_uri("http://127.0.0.1:61023/cb?x=1"));
    assert!(!client.is_valid_redirect_uri("https://127.0.0.1:61023/cb"));
    assert!(!client.is_valid_redirect_uri("http://[::1]:61023/cb"));
}

/// OIDC Core §3.1.2.1 keeps simple string comparison for everything else.
#[tokio::test]
async fn a_non_loopback_redirect_still_matches_exactly() {
    let client = client_with_redirect_uris(&["https://app.example/cb"]).await;
    assert!(client.is_valid_redirect_uri("https://app.example/cb"));
    assert!(!client.is_valid_redirect_uri("https://app.example/cb2"));
    assert!(!client.is_valid_redirect_uri("https://app.example:8443/cb"));
}

/// A fragment can never be a legitimate redirect target (RFC 6749 §3.1.2), so
/// it is refused at the endpoint too rather than only at registration.
#[tokio::test]
async fn a_requested_uri_with_a_fragment_is_never_matched() {
    let client = client_with_redirect_uris(&["https://app.example/cb"]).await;
    assert!(!client.is_valid_redirect_uri("https://app.example/cb#x"));
}

// ===========================================================================
// Concurrent client_credentials mint during application deletion
// ===========================================================================
//
// Bug report (delete OAuth app leaves a surviving client_credentials access
// token): `delete_oauth_client_and_revoke_sessions` previously swept the
// client's sessions and *then* deleted the client row, without first
// revoking the client's secrets. During the window between the session-sweep
// commits and `delete_oauth_client`'s secret hard-delete, a concurrent
// `POST /oauth/token` (`grant_type=client_credentials`) request whose
// `validate_oauth_client_credentials` already passed could still mint an
// access token whose `SessionDoc` was out of scope of both sweeps. The fix
// adds a `revoke_all_oauth_client_secrets` step *before* the session sweeps,
// mirroring `revoke_tokens_api`, so any *new* validation reads a revoked
// secret and returns `None`, closing the issuance commit for new validations
// at the moment the secret-revoke commits.
//
// The two tests below pin the two halves of that contract: the
// issuance-blocking precondition `revoke_all_oauth_client_secrets` provides,
// and the ordering inside `delete_oauth_client_and_revoke_sessions` (the
// revoke must run *before* the session sweeps; a `#[cfg(test)]` seam invoked
// after the revoke commit lets the test inject a `validate_oauth_client_credentials`
// call at that exact instant and assert it returns `None`).

/// After `revoke_all_oauth_client_secrets` commits, every *new*
/// `validate_oauth_client_credentials` call's auto-commit `find_one` reads the
/// secret with `revoked_at == Some(...)`, so `is_valid` is false and the
/// validator returns `None`. This is the issuance-blocking contract that the
/// delete path's secret-revoke-first ordering relies on; without it, the
/// revoke-secrets step would not block new validations and the concurrent-mint
/// window during application deletion would re-open. The delete path shares
/// this contract with `revoke_tokens_api` (which has relied on it since #539).
#[tokio::test]
async fn test_revoke_all_oauth_client_secrets_blocks_subsequent_credential_validation() {
    let (store, _audit) = test_db().await;
    let app = create_test_client(
        &store,
        "revoke-blocks-validation",
        TestClientSpec::default(),
    )
    .await;

    let secret_hash = crate::crypto::hash_token(&app.client_secret);

    // Sanity: validate succeeds before revoke_all_oauth_client_secrets. If
    // this fails, the test fixture did not seed a usable secret and the
    // assertion below would pass vacuously.
    let pre = validate_oauth_client_credentials(
        &store,
        &app.client_id,
        &secret_hash,
        jiff::Timestamp::now(),
    )
    .await
    .expect("validate before revoke must not error");
    assert!(
        pre.is_some(),
        "secret must validate before revoke_all_oauth_client_secrets — \
         fixture mis-seeded the secret"
    );

    // Revoke all secrets for the client (the durable issuance-blocking step).
    let revoked_count = revoke_all_oauth_client_secrets(&store, &app.app_id)
        .await
        .expect("revoke_all_oauth_client_secrets");
    assert_eq!(
        revoked_count, 1,
        "exactly one secret (minted by create_test_client) must be revoked"
    );

    // After the revoke commit, validation must fail (return None). This is
    // what closes the concurrent-mint window the delete path's
    // secret-revoke-first ordering exploits.
    let post = validate_oauth_client_credentials(
        &store,
        &app.client_id,
        &secret_hash,
        jiff::Timestamp::now(),
    )
    .await
    .expect("validate after revoke must not error");
    assert!(
        post.is_none(),
        "validate_oauth_client_credentials must return None after \
         revoke_all_oauth_client_secrets commits — this is the issuance-blocking \
         contract the delete path's secret-revoke-first ordering relies on"
    );
}

/// Pins the ordering inside `delete_oauth_client_and_revoke_sessions`: the
/// `revoke_all_oauth_client_secrets` step must commit *before* the session
/// sweeps run. The `set_post_secret_revoke_test_hook` seam fires at the exact
/// instant between the secret-revoke commit and the first session sweep, so a
/// test-installed hook can inject the §2a interleaving's read-side
/// (`validate_oauth_client_credentials`) at that instant and observe its
/// outcome. With the fix in place the secret is already revoked, so the
/// validation returns `None` (issuance blocked); without the secret-revoke
/// step (or with it moved to after the sweeps) the secret would still be valid
/// at this point and the validation would return `Some(client)`, re-opening
/// the survival window.
///
/// The seam is `#[cfg(test)]`-only and compiled out of non-test builds, so the
/// production ordering is unchanged. Driven on SQLite, which serializes
/// writes via `busy_timeout`; the seam provides the deterministic
/// inter-step interleaving the single-threaded suite cannot produce by
/// task-scheduling races alone — the same rationale as
/// `delete_user`'s `set_delete_test_hook`.
#[tokio::test]
async fn test_delete_oauth_client_revokes_secrets_before_sweeps_closes_concurrent_mint_window() {
    use std::sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    };

    use crate::db::documents::session::SessionDoc;

    let (mut store, _audit) = test_db().await;
    let app = create_test_client(&store, "delete-revoke-order", TestClientSpec::default()).await;
    let app_id = app.app_id.clone();
    let client_id = app.client_id.clone();
    let secret_hash = crate::crypto::hash_token(&app.client_secret);

    // Pre-existing M2M (`client_credentials`) session for this client, so the
    // user_id sweep has something to delete. Mirrors the existing handler-tier
    // regression tests' mint-before-delete fixtures.
    let expires_at: jiff::Timestamp = "2099-12-31T23:59:59Z"
        .parse()
        .expect("far-future expiry parses");
    create_session(
        &store,
        &CreateSessionParams {
            user_id: &client_id,
            user_email: &format!("{client_id}@clients"),
            token_hash: "delete-revoke-order-m2m-existing",
            authenticator_id: None,
            expires_at,
            session_type: SessionPurpose::M2MAccessToken,
            authorization_details: None,
            hardware_aaguid: None,
            org_domain: None,
            client_id: Some(&client_id),
            source_code_hash: None,
        },
    )
    .await
    .expect("seed m2m session");

    let fired = Arc::new(AtomicBool::new(false));
    // The captured outcome of the hook's validate call:
    // * `Some(Ok(None))` — validation blocked (secret revoked): the fix's invariant.
    // * `Some(Ok(Some(_)))` — validation succeeded at the injection point
    //   (issuance window still open): the fix regressed (secret revoke absent
    //   or moved to after the sweeps).
    // * `None` — the hook ran but did not record (test bug).
    let outcome: Arc<Mutex<Option<anyhow::Result<Option<OAuthClient>>>>> =
        Arc::new(Mutex::new(None));

    let store_for_hook = store.clone();
    let secret_hash_for_hook = secret_hash.clone();
    let client_id_for_hook = client_id.clone();
    let fired_for_hook = Arc::clone(&fired);
    let outcome_for_hook = Arc::clone(&outcome);
    store.set_post_secret_revoke_test_hook(Arc::new(move |_client_id: &str| {
        let store = store_for_hook.clone();
        let client_id = client_id_for_hook.clone();
        let secret_hash = secret_hash_for_hook.clone();
        let fired = Arc::clone(&fired_for_hook);
        let outcome = Arc::clone(&outcome_for_hook);
        Box::pin(async move {
            fired.store(true, Ordering::SeqCst);
            // Concurrent client_credentials mint attempt — the read-side of the
            // §2a interleaving: `validate_oauth_client_credentials` running at
            // the precise instant between `revoke_all_oauth_client_secrets`'s
            // commit and the first session sweep's commit.
            let r = validate_oauth_client_credentials(
                &store,
                &client_id,
                &secret_hash,
                jiff::Timestamp::now(),
            )
            .await;
            *outcome.lock().expect("outcome lock") = Some(r);
        })
    }));

    let cache = SessionCache::new(100, 30);
    delete_oauth_client_and_revoke_sessions(&store, &cache, &app_id, &client_id)
        .await
        .expect("delete_oauth_client_and_revoke_sessions");

    // The seam fired — the secret-revoke step ran before the session sweeps.
    // Combined with the outcome assertion below, this pins the secret-revoke-
    // first ordering: the seam is invoked only by the fixed function, and only
    // after `revoke_all_oauth_client_secrets` commits.
    assert!(
        fired.load(Ordering::SeqCst),
        "the post-secret-revoke test seam must fire — \
         delete_oauth_client_and_revoke_sessions must call revoke_all_oauth_client_secrets \
         before the session sweeps and then invoke the seam"
    );

    // The injection's validate returned None — issuance was blocked at the
    // secret level. Without the secret-revoke-first step (or with it moved to
    // after the sweeps), validate would read a still-valid secret at this
    // point and return `Some(client)`, re-opening the survival window.
    let captured = outcome
        .lock()
        .expect("outcome lock")
        .take()
        .expect("hook must record outcome");
    let captured_client =
        captured.expect("validate_oauth_client_credentials must not error at the seam");
    assert!(
        captured_client.is_none(),
        "validate_oauth_client_credentials at the post-secret-revoke seam must return None \
         — the delete path's secret-revoke-first ordering regressed (secrets not revoked \
         before the session sweeps, or revoked after); got: {captured_client:?}"
    );

    // No surviving sessions for the deleted client — the existing
    // mint-before-delete regression coverage must hold under the new ordering.
    assert_eq!(
        store
            .count::<SessionDoc>("user_id", &client_id)
            .await
            .expect("count user_id"),
        0,
        "M2M (user_id == client_id) sessions must be gone"
    );
    assert_eq!(
        store
            .count::<SessionDoc>("client_id", &client_id)
            .await
            .expect("count client_id"),
        0,
        "user-issued (client_id index) sessions must be gone"
    );

    // The OAuth client and its secrets are hard-deleted (existing
    // functionality preserved — delete_oauth_client's hard-delete of secrets is
    // unaffected by the prior secret-revoke commit).
    assert!(
        get_oauth_client_by_id(&store, &app_id)
            .await
            .expect("get_oauth_client_by_id")
            .is_none(),
        "OAuthClientDoc must be hard-deleted"
    );
    assert_eq!(
        get_oauth_client_secrets(&store, &app_id)
            .await
            .expect("get_oauth_client_secrets")
            .len(),
        0,
        "OAuthClientSecretDocs must be hard-deleted"
    );
}
