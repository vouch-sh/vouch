// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Database module tests.

#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "test code: panic on assertion failure is acceptable; cast bounds are obvious in test fixtures"
)]

use std::sync::Arc;

use super::*;
use crate::crypto::document_crypto::PlaintextDocumentCrypto;
use crate::db::audit::AuditStore;
use crate::db::store::DocumentStore;

/// Create an in-memory SQLite database for testing.
///
/// Returns a `(DocumentStore, AuditStore)` pair backed by the same
/// in-memory pool with migrations applied.
async fn test_db() -> (DocumentStore, AuditStore) {
    let pool = Pool::connect("sqlite::memory:", &pool::PoolConfig::default())
        .await
        .expect("Failed to create test database");

    // Run migrations based on database type
    match &pool {
        Pool::Sqlite(p) => sqlx::migrate!("./migrations/sqlite")
            .run(p)
            .await
            .expect("Failed to run migrations"),
        Pool::Postgres(p) => sqlx::migrate!("./migrations/postgres")
            .run(p)
            .await
            .expect("Failed to run migrations"),
    }

    let crypto: Arc<dyn crate::crypto::document_crypto::DocumentCrypto> =
        Arc::new(PlaintextDocumentCrypto);
    let store = DocumentStore::new(pool.clone(), crypto.clone());
    let audit = AuditStore::new(pool, crypto);
    (store, audit)
}

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
async fn test_session_lifecycle() {
    let (store, _audit) = test_db().await;

    // Create user
    let (user_id, _) = upsert_user(&store, "session@example.com", None)
        .await
        .expect("Failed to create user");

    // Create authenticator (with user_email parameter)
    let auth_id = create_authenticator(
        &store,
        &user_id,
        "session@example.com",
        "Test Key",
        b"test-cred-id",
        &[0u8; 32],
        None,
        Some(user_id.as_bytes()),
        false,
    )
    .await
    .expect("Failed to create authenticator");

    // Create session (with user_email parameter)
    let token_hash = "test_token_hash_123";
    let session_id = create_session(
        &store,
        &user_id,
        "session@example.com",
        token_hash,
        Some(&auth_id),
        "2099-12-31T23:59:59Z".parse().unwrap(),
        SessionPurpose::OAuthAccessToken,
        None,
    )
    .await
    .expect("Failed to create session");

    assert!(!session_id.is_empty());

    // Get session
    let session = get_session_by_token_hash(&store, token_hash)
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
    let session = get_session_by_token_hash(&store, token_hash)
        .await
        .expect("Failed to get session");

    assert!(session.is_none());
}

// ========================================================================
// RFC 8628 - Device Authorization Grant Tests
// ========================================================================

#[tokio::test]
async fn test_device_auth_request_lifecycle() {
    let (store, _audit) = test_db().await;

    // Create device auth request
    let device_code_hash = "hashed_device_code_123";
    let user_code = "ABCD-1234";
    let expires_at: jiff::Timestamp = "2099-12-31T23:59:59Z".parse().unwrap();
    let interval = 5;

    let id = create_device_auth_request(
        &store,
        device_code_hash,
        user_code,
        None,
        expires_at,
        interval,
    )
    .await
    .expect("Failed to create device auth request");

    assert!(!id.is_empty());

    // Get by device code hash
    let request = get_device_auth_by_code_hash(&store, device_code_hash)
        .await
        .expect("Failed to get device auth")
        .expect("Device auth should exist");

    assert_eq!(request.user_code, user_code);
    assert_eq!(request.status, DeviceAuthStatus::Pending);
    assert!(request.user_id.is_none());

    // Get by user code
    let request = get_device_auth_by_user_code(&store, user_code)
        .await
        .expect("Failed to get device auth by user code")
        .expect("Should find by user code");

    assert_eq!(request.device_code_hash, device_code_hash);

    // Get by ID
    let request = get_device_auth_by_id(&store, &id)
        .await
        .expect("Failed to get device auth by ID")
        .expect("Should find by ID");

    assert_eq!(request.interval_seconds, interval);
}

#[tokio::test]
async fn test_device_auth_authorization_flow() {
    let (store, _audit) = test_db().await;

    // Create user first
    let (user_id, _) = upsert_user(&store, "device@example.com", Some("Device User"))
        .await
        .expect("Failed to create user");
    let user = get_user_by_id(&store, &user_id)
        .await
        .expect("Failed to get user")
        .expect("User should exist");

    // Create authenticator
    let auth_id = create_authenticator(
        &store,
        &user_id,
        "device@example.com",
        "Test Key",
        b"test-cred-id-device",
        &[0u8; 32],
        None,
        Some(user_id.as_bytes()),
        false,
    )
    .await
    .expect("Failed to create authenticator");

    // Create pending device auth request
    let device_code_hash = "hashed_device_code_456";
    let user_code = "EFGH-5678";
    let id = create_device_auth_request(
        &store,
        device_code_hash,
        user_code,
        None,
        "2099-12-31T23:59:59Z".parse().unwrap(),
        5,
    )
    .await
    .expect("Failed to create device auth request");

    // Verify initially pending
    let request = get_device_auth_by_id(&store, &id)
        .await
        .expect("Failed to get request")
        .expect("Should exist");
    assert_eq!(request.status, DeviceAuthStatus::Pending);

    // Authorize the request
    authorize_device_auth(&store, &id, &user_id, &user.email, &auth_id)
        .await
        .expect("Failed to authorize");

    // Verify status changed to authorized
    let request = get_device_auth_by_id(&store, &id)
        .await
        .expect("Failed to get request")
        .expect("Should exist");
    assert_eq!(request.status, DeviceAuthStatus::Authorized);
    assert_eq!(request.user_id, Some(user_id.clone()));
    assert_eq!(request.user_email, Some(user.email.clone()));
    assert_eq!(request.authenticator_id, Some(auth_id));
}

#[tokio::test]
async fn test_device_auth_polling_rate_limit() {
    let (store, _audit) = test_db().await;

    let device_code_hash = "rate_limit_test";
    let user_code = "RATE-1234";
    let interval = 5; // 5 seconds

    let id = create_device_auth_request(
        &store,
        device_code_hash,
        user_code,
        None,
        "2099-12-31T23:59:59Z".parse().unwrap(),
        interval,
    )
    .await
    .expect("Failed to create device auth request");

    // First poll should succeed
    let allowed = update_device_auth_poll_time(&store, &id, interval)
        .await
        .expect("Failed to update poll time");
    assert!(allowed, "First poll should be allowed");

    // Immediate second poll should be rate limited
    let allowed = update_device_auth_poll_time(&store, &id, interval)
        .await
        .expect("Failed to update poll time");
    assert!(!allowed, "Immediate second poll should be rate limited");
}

#[tokio::test]
async fn test_device_auth_not_found() {
    let (store, _audit) = test_db().await;

    // Get nonexistent device auth
    let request = get_device_auth_by_code_hash(&store, "nonexistent")
        .await
        .expect("Query should succeed");
    assert!(request.is_none());

    let request = get_device_auth_by_user_code(&store, "XXXX-0000")
        .await
        .expect("Query should succeed");
    assert!(request.is_none());
}

// ========================================================================
// Device Auth Consumption Tests (RFC 8628 Section 3.5)
// ========================================================================

#[tokio::test]
async fn test_try_consume_device_auth_authorized_succeeds() {
    let (store, _audit) = test_db().await;

    let device_code_hash = "consume_success_hash";
    let user_code = "CNSM-SUCC";
    let expires_at: jiff::Timestamp = "2099-12-31T23:59:59Z".parse().unwrap();

    let id = create_device_auth_request(&store, device_code_hash, user_code, None, expires_at, 5)
        .await
        .expect("create");

    // Authorize it first
    let (user_id, _) = upsert_user(&store, "consume@example.com", Some("Test"))
        .await
        .expect("user");
    let auth_id = create_authenticator(
        &store,
        &user_id,
        "consume@example.com",
        "Key",
        b"cred-consume",
        &[0u8; 32],
        None,
        None,
        false,
    )
    .await
    .expect("auth");

    authorize_device_auth(&store, &id, &user_id, "consume@example.com", &auth_id)
        .await
        .expect("authorize");

    // Consume
    let consumed = try_consume_device_auth(&store, device_code_hash)
        .await
        .expect("consume");
    assert!(consumed, "First consumption should succeed");

    // Verify status and consumed_at
    let request = get_device_auth_by_code_hash(&store, device_code_hash)
        .await
        .expect("get")
        .expect("should exist");
    assert_eq!(request.status, DeviceAuthStatus::Consumed);
    assert!(request.consumed_at.is_some(), "consumed_at should be set");
}

#[tokio::test]
async fn test_try_consume_device_auth_already_consumed_returns_false() {
    let (store, _audit) = test_db().await;

    let device_code_hash = "double_consume_hash";
    let id = create_device_auth_request(
        &store,
        device_code_hash,
        "DBLC-CODE",
        None,
        "2099-12-31T23:59:59Z".parse().unwrap(),
        5,
    )
    .await
    .expect("create");

    let (user_id, _) = upsert_user(&store, "double@example.com", Some("Test"))
        .await
        .expect("user");
    let auth_id = create_authenticator(
        &store,
        &user_id,
        "double@example.com",
        "Key",
        b"cred-double",
        &[0u8; 32],
        None,
        None,
        false,
    )
    .await
    .expect("auth");

    authorize_device_auth(&store, &id, &user_id, "double@example.com", &auth_id)
        .await
        .expect("authorize");

    let first = try_consume_device_auth(&store, device_code_hash)
        .await
        .expect("first consume");
    assert!(first, "First consumption should succeed");

    let second = try_consume_device_auth(&store, device_code_hash)
        .await
        .expect("second consume");
    assert!(!second, "Second consumption must return false");
}

#[tokio::test]
async fn test_try_consume_device_auth_pending_returns_false() {
    let (store, _audit) = test_db().await;

    let device_code_hash = "pending_consume_hash";
    create_device_auth_request(
        &store,
        device_code_hash,
        "PEND-CODE",
        None,
        "2099-12-31T23:59:59Z".parse().unwrap(),
        5,
    )
    .await
    .expect("create");

    // Attempt to consume a Pending request (never authorized)
    let consumed = try_consume_device_auth(&store, device_code_hash)
        .await
        .expect("consume");
    assert!(!consumed, "Pending device code must not be consumable");
}

#[tokio::test]
async fn test_try_consume_device_auth_expired_returns_false() {
    let (store, _audit) = test_db().await;

    let device_code_hash = "expired_consume_hash";
    // Already expired
    let expired_at: jiff::Timestamp = "2020-01-01T00:00:00Z".parse().unwrap();
    let id = create_device_auth_request(&store, device_code_hash, "EXPD-CNSM", None, expired_at, 5)
        .await
        .expect("create");

    let (user_id, _) = upsert_user(&store, "expired@example.com", Some("Test"))
        .await
        .expect("user");
    let auth_id = create_authenticator(
        &store,
        &user_id,
        "expired@example.com",
        "Key",
        b"cred-expired",
        &[0u8; 32],
        None,
        None,
        false,
    )
    .await
    .expect("auth");

    authorize_device_auth(&store, &id, &user_id, "expired@example.com", &auth_id)
        .await
        .expect("authorize");

    let consumed = try_consume_device_auth(&store, device_code_hash)
        .await
        .expect("consume");
    assert!(!consumed, "Expired device code must not be consumable");
}

#[tokio::test]
async fn test_try_consume_device_auth_not_found_returns_false() {
    let (store, _audit) = test_db().await;

    let consumed = try_consume_device_auth(&store, "nonexistent_hash")
        .await
        .expect("consume");
    assert!(!consumed, "Nonexistent hash must return false");
}

#[tokio::test]
async fn test_device_auth_request_doc_consumed_at_defaults_to_none() {
    // Pre-fix documents without consumed_at should deserialize cleanly
    let json = r#"{
        "device_code_hash": "test",
        "user_code": "TEST-CODE",
        "status": "pending",
        "user_id": null,
        "user_email": null,
        "authenticator_id": null,
        "expires_at": "2099-12-31T23:59:59Z",
        "interval_seconds": 5,
        "last_poll_at": null
    }"#;

    let doc: super::documents::device_auth::DeviceAuthRequestDoc =
        serde_json::from_str(json).expect("should deserialize without consumed_at");
    assert!(
        doc.consumed_at.is_none(),
        "consumed_at should default to None"
    );
    assert_eq!(doc.status, DeviceAuthStatus::Pending);
}

// ========================================================================
// Device Auth Single-Use Semantics (GH#254)
// ========================================================================

#[tokio::test]
async fn test_double_authorization_should_fail() {
    let (store, _audit) = test_db().await;

    let id = create_device_auth_request(
        &store,
        "dbl_auth_hash",
        "DBLA-0001",
        None,
        "2099-12-31T23:59:59Z".parse().unwrap(),
        5,
    )
    .await
    .expect("create");

    authorize_device_auth(&store, &id, "user_a", "a@example.com", "auth_a")
        .await
        .expect("first authorization should succeed");

    let result = authorize_device_auth(&store, &id, "user_b", "b@example.com", "auth_b").await;
    assert!(result.is_err(), "second authorization should fail");

    // Original user must be preserved
    let req = get_device_auth_by_id(&store, &id)
        .await
        .expect("get")
        .expect("exists");
    assert_eq!(req.status, DeviceAuthStatus::Authorized);
    assert_eq!(req.user_id.as_deref(), Some("user_a"));
}

#[tokio::test]
async fn test_authorize_after_deny_should_fail() {
    let (store, _audit) = test_db().await;

    let id = create_device_auth_request(
        &store,
        "deny_then_auth",
        "DNYA-0001",
        None,
        "2099-12-31T23:59:59Z".parse().unwrap(),
        5,
    )
    .await
    .expect("create");

    deny_device_auth(&store, &id).await.expect("deny succeeds");

    let result = authorize_device_auth(&store, &id, "user_a", "a@example.com", "auth_a").await;
    assert!(result.is_err(), "authorize after deny should fail");

    let req = get_device_auth_by_id(&store, &id)
        .await
        .expect("get")
        .expect("exists");
    assert_eq!(req.status, DeviceAuthStatus::Denied);
    assert!(req.user_id.is_none());
}

#[tokio::test]
async fn test_deny_after_authorize_should_fail() {
    let (store, _audit) = test_db().await;

    let id = create_device_auth_request(
        &store,
        "auth_then_deny",
        "ATDN-0001",
        None,
        "2099-12-31T23:59:59Z".parse().unwrap(),
        5,
    )
    .await
    .expect("create");

    authorize_device_auth(&store, &id, "user_a", "a@example.com", "auth_a")
        .await
        .expect("authorize succeeds");

    let result = deny_device_auth(&store, &id).await;
    assert!(result.is_err(), "deny after authorize should fail");

    let req = get_device_auth_by_id(&store, &id)
        .await
        .expect("get")
        .expect("exists");
    assert_eq!(req.status, DeviceAuthStatus::Authorized);
    assert_eq!(req.user_id.as_deref(), Some("user_a"));
}

#[tokio::test]
async fn test_double_deny_should_fail() {
    let (store, _audit) = test_db().await;

    let id = create_device_auth_request(
        &store,
        "dbl_deny_hash",
        "DBLD-0001",
        None,
        "2099-12-31T23:59:59Z".parse().unwrap(),
        5,
    )
    .await
    .expect("create");

    deny_device_auth(&store, &id)
        .await
        .expect("first deny should succeed");

    let result = deny_device_auth(&store, &id).await;
    assert!(result.is_err(), "second deny should fail");

    let req = get_device_auth_by_id(&store, &id)
        .await
        .expect("get")
        .expect("exists");
    assert_eq!(req.status, DeviceAuthStatus::Denied);
}

// ========================================================================
// OIDC State Tests
// ========================================================================

#[tokio::test]
async fn test_oidc_state_lifecycle() {
    let (store, _audit) = test_db().await;

    // Create device auth request first (FK reference)
    let device_auth_id = create_device_auth_request(
        &store,
        "device_hash_for_oidc",
        "OIDC-1234",
        None,
        "2099-12-31T23:59:59Z".parse().unwrap(),
        5,
    )
    .await
    .expect("Failed to create device auth");

    // Create OIDC state
    let state = "random_state_12345";
    let nonce = "nonce_67890";
    let expires_at: jiff::Timestamp = "2099-12-31T23:59:59Z".parse().unwrap();

    let id = create_oidc_state(&store, state, &device_auth_id, nonce, "", expires_at, "")
        .await
        .expect("Failed to create OIDC state");
    assert!(!id.is_empty());

    // Get OIDC state
    let oidc_state = get_oidc_state(&store, state)
        .await
        .expect("Failed to get OIDC state")
        .expect("Should exist");

    assert_eq!(oidc_state.state, state);
    assert_eq!(oidc_state.device_auth_id, device_auth_id);
    assert_eq!(oidc_state.nonce, nonce);

    // Delete OIDC state
    delete_oidc_state(&store, state)
        .await
        .expect("Failed to delete OIDC state");

    // Verify deleted
    let oidc_state = get_oidc_state(&store, state)
        .await
        .expect("Query should succeed");
    assert!(oidc_state.is_none());
}

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
        },
    )
    .await
    .expect("Failed to create client");

    // Record some events (now uses AuditStore)
    record_oauth_event(
        &audit,
        &client.id,
        OAuthEventType::TokenIssued,
        Some(&user_id),
        None,
        None,
        None,
    )
    .await
    .expect("Failed to record event");
    record_oauth_event(
        &audit,
        &client.id,
        OAuthEventType::TokenIssued,
        Some(&user_id),
        None,
        None,
        None,
    )
    .await
    .expect("Failed to record event");
    record_oauth_event(
        &audit,
        &client.id,
        OAuthEventType::TokenRevoked,
        Some(&user_id),
        None,
        None,
        None,
    )
    .await
    .expect("Failed to record event");

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
// SCIM User Tests (RFC 7643/7644)
// ========================================================================

const TEST_ORG_ID: &str = "test-org";

#[tokio::test]
async fn test_scim_user_crud() {
    let (store, _audit) = test_db().await;

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

#[tokio::test]
async fn test_scim_session_invalidation_on_deactivation() {
    let (store, _audit) = test_db().await;

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
        &user.id,
        "invalidate@example.com",
        "SCIM Key",
        b"scim-cred-id",
        &[0u8; 32],
        None,
        Some(user.id.as_bytes()),
        false,
    )
    .await
    .expect("Failed to create authenticator");

    // Create session (with user_email parameter)
    create_session(
        &store,
        &user.id,
        "invalidate@example.com",
        "scim_token_hash",
        Some(&auth_id),
        "2099-12-31T23:59:59Z".parse().unwrap(),
        SessionPurpose::OAuthAccessToken,
        None,
    )
    .await
    .expect("Failed to create session");

    // Verify session exists
    let session = get_session_by_token_hash(&store, "scim_token_hash")
        .await
        .expect("Failed to get session");
    assert!(session.is_some());

    // Delete all sessions for user (as SCIM would do on deactivation)
    let deleted = delete_sessions_for_user(&store, &user.id)
        .await
        .expect("Failed to delete sessions");
    assert_eq!(deleted, 1);

    // Verify session deleted
    let session = get_session_by_token_hash(&store, "scim_token_hash")
        .await
        .expect("Failed to get session");
    assert!(session.is_none());
}

#[tokio::test]
async fn test_scim_audit_logging() {
    let (_store, audit) = test_db().await;

    // Insert audit log (insert_scim_audit now uses AuditStore directly)
    let audit_id = insert_scim_audit(
        &audit,
        "CREATE",
        "User",
        "user-123",
        Some("token-123"),
        Some("Created user via SCIM"),
    )
    .await
    .expect("Failed to insert audit log");

    assert!(!audit_id.is_empty());

    // Insert another audit log without token (None is valid)
    let audit_id2 = insert_scim_audit(&audit, "DELETE", "User", "user-789", None, None)
        .await
        .expect("Failed to insert audit log");

    assert!(!audit_id2.is_empty());
    assert_ne!(audit_id, audit_id2);
}

// ========================================================================
// Authentication Event Tests
// ========================================================================

#[tokio::test]
async fn test_auth_event_logging() {
    let (store, audit) = test_db().await;

    let (user_id, _) = upsert_user(&store, "events@example.com", None)
        .await
        .expect("Failed to create user");

    // Log successful login (insert_auth_event now uses AuditStore)
    let event_id = insert_auth_event(
        &audit,
        &AuthEventParams {
            user_id: user_id.clone(),
            event_type: AuthEventType::LoginSuccess,
            authenticator_id: Some("auth-123".to_string()),
            client_ip: Some("192.168.1.1".parse().unwrap()),
            user_agent: Some("Mozilla/5.0".to_string()),
            success: true,
            ..Default::default()
        },
        Some("events@example.com"),
    )
    .await
    .expect("Failed to insert auth event");

    assert!(!event_id.is_empty());

    // Log failed login
    insert_auth_event(
        &audit,
        &AuthEventParams {
            user_id: user_id.clone(),
            event_type: AuthEventType::LoginFailed,
            client_ip: Some("192.168.1.1".parse().unwrap()),
            success: false,
            failure_reason: Some("Invalid credential".to_string()),
            ..Default::default()
        },
        Some("events@example.com"),
    )
    .await
    .expect("Failed to insert auth event");
}

// ========================================================================
// Authenticator Tests
// ========================================================================

#[tokio::test]
async fn test_authenticator_crud() {
    let (store, _audit) = test_db().await;

    let (user_id, _) = upsert_user(&store, "auth@example.com", None)
        .await
        .expect("Failed to create user");

    // Create authenticator (with user_email parameter)
    let credential_id = vec![1u8, 2, 3, 4, 5];
    let public_key = vec![10u8; 65];
    let user_handle = vec![20u8; 32];

    let auth_id = create_authenticator(
        &store,
        &user_id,
        "auth@example.com",
        "YubiKey 5C",
        &credential_id,
        &public_key,
        Some("2fc0579f-8113-47ea-b116-bb5a8db9202a"),
        Some(&user_handle),
        false,
    )
    .await
    .expect("Failed to create authenticator");

    assert!(!auth_id.is_empty());

    // Get by ID
    let auth = get_authenticator_by_id(&store, &auth_id)
        .await
        .expect("Failed to get authenticator")
        .expect("Authenticator should exist");

    assert_eq!(auth.name, "YubiKey 5C");
    assert_eq!(auth.credential_id, credential_id);
    assert_eq!(auth.counter, 0);

    // Get by credential ID
    let auth = get_authenticator_by_credential_id(&store, &credential_id)
        .await
        .expect("Failed to get authenticator")
        .expect("Authenticator should exist");

    assert_eq!(auth.id, auth_id);

    // Get all for user
    let auths = get_authenticators_for_user(&store, &user_id)
        .await
        .expect("Failed to get authenticators");

    assert_eq!(auths.len(), 1);

    // Update counter
    update_authenticator_counter(&store, &auth_id, 42)
        .await
        .expect("Failed to update counter");

    let auth = get_authenticator_by_id(&store, &auth_id)
        .await
        .expect("Failed to get authenticator")
        .expect("Authenticator should exist");

    assert_eq!(auth.counter, 42);

    // Delete authenticator
    let deleted = delete_authenticator(&store, &auth_id)
        .await
        .expect("Failed to delete authenticator");

    assert_eq!(deleted, 1);

    // Verify deleted
    let auth = get_authenticator_by_id(&store, &auth_id)
        .await
        .expect("Query should succeed");

    assert!(auth.is_none());
}

#[tokio::test]
async fn test_authenticator_count() {
    let (store, _audit) = test_db().await;

    let (user_id, _) = upsert_user(&store, "count@example.com", None)
        .await
        .expect("Failed to create user");

    // Initially 0 authenticators
    let count = count_authenticators_for_user(&store, &user_id)
        .await
        .expect("Failed to count");
    assert_eq!(count, 0);

    // Add authenticators (with user_email parameter)
    for i in 0..3 {
        create_authenticator(
            &store,
            &user_id,
            "count@example.com",
            &format!("Key {}", i),
            &[i as u8; 10],
            &[0u8; 32],
            None,
            None,
            false,
        )
        .await
        .expect("Failed to create authenticator");
    }

    let count = count_authenticators_for_user(&store, &user_id)
        .await
        .expect("Failed to count");
    assert_eq!(count, 3);
}

// ========================================================================
// SCIM Token Tests
// ========================================================================

#[tokio::test]
async fn test_scim_token_management() {
    let (store, _audit) = test_db().await;

    // Create org for SCIM token (new signature: domain, name, created_by_user_id)
    let org = create_organization(&store, "test.com", Some("Test Org"), None)
        .await
        .expect("Failed to create org");
    let org_id = &org.id;

    // Create SCIM token with org
    let token_hash = "hashed_scim_token";
    let token_id = create_scim_token(
        &store,
        token_hash,
        Some("Admin token"),
        None,
        Some(org_id),
        None,
    )
    .await
    .expect("Failed to create SCIM token");

    assert!(!token_id.is_empty());

    // Get by hash
    let token = get_scim_token_by_hash(&store, token_hash)
        .await
        .expect("Failed to get token")
        .expect("Token should exist");

    assert_eq!(token.description, Some("Admin token".to_string()));
    assert!(token.last_used_at.is_none());

    // Update last used
    update_scim_token_last_used(&store, &token.id)
        .await
        .expect("Failed to update last used");

    let token = get_scim_token_by_hash(&store, token_hash)
        .await
        .expect("Failed to get token")
        .expect("Token should exist");

    assert!(token.last_used_at.is_some());

    // List tokens
    let tokens = list_scim_tokens(&store, None)
        .await
        .expect("Failed to list tokens");

    assert_eq!(tokens.len(), 1);

    // Attempt delete with wrong org (should not delete)
    let deleted = delete_scim_token(&store, &token_id, "wrong-org")
        .await
        .expect("Query should succeed");
    assert!(
        !deleted,
        "Should not delete token belonging to different org"
    );

    // Verify token still exists
    let token = get_scim_token_by_hash(&store, token_hash)
        .await
        .expect("Query should succeed");
    assert!(
        token.is_some(),
        "Token should still exist after wrong-org delete"
    );

    // Delete token with correct org
    let deleted = delete_scim_token(&store, &token_id, org_id)
        .await
        .expect("Failed to delete token");
    assert!(deleted, "Should delete token belonging to correct org");

    let token = get_scim_token_by_hash(&store, token_hash)
        .await
        .expect("Query should succeed");

    assert!(token.is_none());
}

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
        &user_id,
        "cascade@example.com",
        "Cascade Key",
        &[99u8; 10],
        &[0u8; 32],
        None,
        None,
        false,
    )
    .await
    .expect("Failed to create authenticator");

    create_session(
        &store,
        &user_id,
        "cascade@example.com",
        "cascade_token",
        Some(&auth_id),
        "2099-12-31T23:59:59Z".parse().unwrap(),
        SessionPurpose::OAuthAccessToken,
        None,
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
        get_session_by_token_hash(&store, "cascade_token")
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
        get_session_by_token_hash(&store, "cascade_token")
            .await
            .unwrap()
            .is_none()
    );
    assert!(get_user_by_id(&store, &user_id).await.unwrap().is_none());
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
        &client.id,
        OAuthEventType::TokenIssued,
        None,
        None,
        None,
        None,
    )
    .await
    .expect("Failed to record event");

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
// SCIM Scope Tests
// ========================================================================

#[test]
fn test_scim_scope_round_trip() {
    for scope in [
        ScimScope::UsersRead,
        ScimScope::UsersWrite,
        ScimScope::GroupsRead,
        ScimScope::GroupsWrite,
    ] {
        let s = scope.as_str();
        let parsed = ScimScope::parse(s).expect("Should parse valid scope");
        assert_eq!(parsed, scope);
    }
}

#[test]
fn test_scim_scope_parse_invalid() {
    assert!(ScimScope::parse("invalid").is_none());
    assert!(ScimScope::parse("").is_none());
    assert!(ScimScope::parse("users:admin").is_none());
    assert!(ScimScope::parse("Users:Read").is_none());
}

#[test]
fn test_scim_scope_set_round_trip() {
    let set = ScimScopeSet::all();
    let db_string = set.as_db_string();
    let parsed = ScimScopeSet::parse(&db_string).expect("Should parse valid scope set");
    assert_eq!(parsed, set);
}

#[test]
fn test_scim_scope_set_parse_subset() {
    let parsed = ScimScopeSet::parse("users:read,groups:write").expect("Should parse valid subset");
    assert!(parsed.contains(ScimScope::UsersRead));
    assert!(!parsed.contains(ScimScope::UsersWrite));
    assert!(!parsed.contains(ScimScope::GroupsRead));
    assert!(parsed.contains(ScimScope::GroupsWrite));
}

#[test]
fn test_scim_scope_set_parse_rejects_invalid() {
    assert!(ScimScopeSet::parse("users:read,invalid").is_none());
    assert!(ScimScopeSet::parse("bad").is_none());
    assert!(ScimScopeSet::parse("").is_none());
}

#[test]
fn test_scim_scope_set_contains() {
    let all = ScimScopeSet::all();
    assert!(all.contains(ScimScope::UsersRead));
    assert!(all.contains(ScimScope::UsersWrite));
    assert!(all.contains(ScimScope::GroupsRead));
    assert!(all.contains(ScimScope::GroupsWrite));

    let partial = ScimScopeSet::parse("users:read").expect("valid");
    assert!(partial.contains(ScimScope::UsersRead));
    assert!(!partial.contains(ScimScope::UsersWrite));
}

#[test]
fn test_scim_scope_set_default_is_all() {
    assert_eq!(ScimScopeSet::default(), ScimScopeSet::all());
}

// ========================================================================
// DocumentStore — gaps in store.rs tests
// ========================================================================

#[tokio::test]
async fn test_store_get_many_empty_slice() {
    let (store, _audit) = test_db().await;

    // get_many with an empty id slice must return an empty vec, not error
    let result = store
        .list_all::<crate::db::documents::user::UserDoc>()
        .await
        .expect("list_all should succeed");
    assert!(result.is_empty());
}

#[tokio::test]
async fn test_store_count_zero_for_no_matches() {
    let (store, _audit) = test_db().await;

    // Newly-initialised DB has no sessions; count should be 0
    let count = store
        .count::<crate::db::documents::session::SessionDoc>("token_hash", "nonexistent")
        .await
        .expect("count should not error");
    assert_eq!(count, 0);
}

#[tokio::test]
async fn test_store_delete_cleans_up_indexes() {
    let (store, _audit) = test_db().await;

    // Create a user so we have something with index entries
    let (user_id, _) = upsert_user(&store, "index-cleanup@example.com", None)
        .await
        .expect("upsert failed");

    // The document is findable by its email index
    let found = get_user_by_email(&store, "index-cleanup@example.com")
        .await
        .expect("query failed");
    assert!(found.is_some());

    // Delete the document
    delete_user(&store, &user_id).await.expect("delete failed");

    // Document is gone
    assert!(
        get_user_by_id(&store, &user_id)
            .await
            .expect("query failed")
            .is_none()
    );

    // Index entry is also gone: find_one should return None
    let found_after = get_user_by_email(&store, "index-cleanup@example.com")
        .await
        .expect("query failed");
    assert!(
        found_after.is_none(),
        "index entry should be deleted with the document"
    );
}

#[tokio::test]
async fn test_store_delete_expired_cleans_up_indexes() {
    let (store, _audit) = test_db().await;

    // Create a device-auth request with a past expiry (expired)
    let id = create_device_auth_request(
        &store,
        "expired-code-hash",
        "EXPR-0001",
        None,
        "2020-01-01T00:00:00Z".parse().unwrap(), // past
        5,
    )
    .await
    .expect("create failed");

    // Confirm it is findable by its user-code index
    let found = get_device_auth_by_user_code(&store, "EXPR-0001")
        .await
        .expect("query failed");
    assert!(found.is_some());

    // Run the cleanup
    let now_str = jiff::Timestamp::now().to_string();
    let deleted = delete_expired_device_auth_requests(&store, &now_str)
        .await
        .expect("cleanup failed");
    assert!(deleted >= 1);

    // Now the document should be gone
    assert!(
        get_device_auth_by_id(&store, &id)
            .await
            .expect("query failed")
            .is_none()
    );

    // And the index entry should also be gone
    let found_after = get_device_auth_by_user_code(&store, "EXPR-0001")
        .await
        .expect("query failed");
    assert!(
        found_after.is_none(),
        "index entry should be cleaned up after delete_expired"
    );
}

// ========================================================================
// SCIM — application-level uniqueness check
// ========================================================================

#[tokio::test]
async fn test_create_scim_user_duplicate_email_rejected() {
    let (store, _audit) = test_db().await;

    // First creation succeeds
    create_scim_user(
        &store,
        Some(TEST_ORG_ID),
        "dup@example.com",
        Some("Original"),
        None,
        true,
    )
    .await
    .expect("First creation should succeed");

    // Second creation with the same email must fail with a UNIQUE error
    let result = create_scim_user(
        &store,
        Some(TEST_ORG_ID),
        "dup@example.com",
        Some("Duplicate"),
        None,
        true,
    )
    .await;
    assert!(result.is_err(), "Duplicate email should be rejected");
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("UNIQUE"),
        "Error message should mention UNIQUE; got: {err}"
    );
}

// ========================================================================
// SCIM groups — full lifecycle
// ========================================================================

#[tokio::test]
async fn test_scim_group_lifecycle() {
    let (store, _audit) = test_db().await;

    // Create
    let group = create_scim_group(&store, TEST_ORG_ID, "Engineering", Some("ext-grp-1"))
        .await
        .expect("create_scim_group failed");
    assert!(!group.id.is_empty());
    assert_eq!(group.display_name, "Engineering");
    assert_eq!(group.external_id.as_deref(), Some("ext-grp-1"));

    // Get by ID
    let fetched = get_scim_group(&store, &group.id, TEST_ORG_ID)
        .await
        .expect("get_scim_group failed")
        .expect("group should exist");
    assert_eq!(fetched.display_name, "Engineering");

    // Get by display name
    let by_name = get_scim_group_by_name(&store, TEST_ORG_ID, "Engineering")
        .await
        .expect("get_scim_group_by_name failed")
        .expect("should find by name");
    assert_eq!(by_name.id, group.id);

    // Update
    let _ = update_scim_group(
        &store,
        &group.id,
        TEST_ORG_ID,
        Some("Platform"),
        Some("ext-grp-2"),
    )
    .await
    .expect("update_scim_group failed");
    let updated = get_scim_group(&store, &group.id, TEST_ORG_ID)
        .await
        .expect("get_scim_group failed")
        .expect("group should still exist");
    assert_eq!(updated.display_name, "Platform");
    assert_eq!(updated.external_id.as_deref(), Some("ext-grp-2"));

    // List
    let (groups, total) = list_scim_groups(&store, TEST_ORG_ID, None, 1, 100)
        .await
        .expect("list_scim_groups failed");
    assert_eq!(groups.len(), 1);
    assert_eq!(total, 1);

    // Delete
    let deleted = delete_scim_group(&store, &group.id, TEST_ORG_ID)
        .await
        .expect("delete_scim_group failed");
    assert!(deleted);

    // Gone
    let missing = get_scim_group(&store, &group.id, TEST_ORG_ID)
        .await
        .expect("query should succeed");
    assert!(missing.is_none());

    // Delete again returns false
    let deleted_again = delete_scim_group(&store, &group.id, TEST_ORG_ID)
        .await
        .expect("delete should not error");
    assert!(!deleted_again);
}

#[tokio::test]
async fn test_scim_group_member_add_remove() {
    let (store, _audit) = test_db().await;

    let group = create_scim_group(&store, TEST_ORG_ID, "Beta", None)
        .await
        .expect("create group");
    let user = create_scim_user(
        &store,
        Some(TEST_ORG_ID),
        "member@example.com",
        None,
        None,
        true,
    )
    .await
    .expect("create user");

    // Add member
    let _ = add_scim_group_member(&store, &group.id, TEST_ORG_ID, &user.id)
        .await
        .expect("add_scim_group_member failed");

    // Member appears in group
    let members = get_scim_group_members(&store, &group.id, TEST_ORG_ID)
        .await
        .expect("get_scim_group_members failed")
        .unwrap_or_default();
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].id, user.id);

    // Add again is idempotent
    let _ = add_scim_group_member(&store, &group.id, TEST_ORG_ID, &user.id)
        .await
        .expect("idempotent add failed");
    let members_after = get_scim_group_members(&store, &group.id, TEST_ORG_ID)
        .await
        .expect("get members")
        .unwrap_or_default();
    assert_eq!(
        members_after.len(),
        1,
        "idempotent add should not duplicate"
    );

    // User's groups
    let user_groups = get_user_scim_groups(&store, &user.id, TEST_ORG_ID)
        .await
        .expect("get_user_scim_groups failed");
    assert_eq!(user_groups.len(), 1);
    assert_eq!(user_groups[0].id, group.id);

    // Remove member
    let removed = remove_scim_group_member(&store, &group.id, TEST_ORG_ID, &user.id)
        .await
        .expect("remove_scim_group_member failed");
    assert!(removed);

    // Group is now empty
    let members_final = get_scim_group_members(&store, &group.id, TEST_ORG_ID)
        .await
        .expect("get members after remove")
        .unwrap_or_default();
    assert!(members_final.is_empty());

    // Remove again returns false
    let removed_again = remove_scim_group_member(&store, &group.id, TEST_ORG_ID, &user.id)
        .await
        .expect("remove should not error");
    assert!(!removed_again);
}

#[tokio::test]
async fn test_scim_group_replace_members() {
    let (store, _audit) = test_db().await;

    let group = create_scim_group(&store, TEST_ORG_ID, "Gamma", None)
        .await
        .expect("create group");
    let user1 = create_scim_user(
        &store,
        Some(TEST_ORG_ID),
        "u1@example.com",
        None,
        None,
        true,
    )
    .await
    .expect("create user1");
    let user2 = create_scim_user(
        &store,
        Some(TEST_ORG_ID),
        "u2@example.com",
        None,
        None,
        true,
    )
    .await
    .expect("create user2");
    let user3 = create_scim_user(
        &store,
        Some(TEST_ORG_ID),
        "u3@example.com",
        None,
        None,
        true,
    )
    .await
    .expect("create user3");

    // Start with user1 and user2
    let _ = replace_scim_group_members(
        &store,
        &group.id,
        TEST_ORG_ID,
        &[user1.id.clone(), user2.id.clone()],
    )
    .await
    .expect("replace members");
    let members = get_scim_group_members(&store, &group.id, TEST_ORG_ID)
        .await
        .expect("get members")
        .unwrap_or_default();
    assert_eq!(members.len(), 2);

    // Replace with just user3
    let _ = replace_scim_group_members(
        &store,
        &group.id,
        TEST_ORG_ID,
        std::slice::from_ref(&user3.id),
    )
    .await
    .expect("replace members");
    let members_after = get_scim_group_members(&store, &group.id, TEST_ORG_ID)
        .await
        .expect("get members")
        .unwrap_or_default();
    assert_eq!(members_after.len(), 1);
    assert_eq!(members_after[0].id, user3.id);

    // Replace with empty list
    let _ = replace_scim_group_members(&store, &group.id, TEST_ORG_ID, &[])
        .await
        .expect("replace with empty");
    let empty = get_scim_group_members(&store, &group.id, TEST_ORG_ID)
        .await
        .expect("get members")
        .unwrap_or_default();
    assert!(empty.is_empty());
}

#[tokio::test]
async fn test_scim_group_delete_cascades_members() {
    let (store, _audit) = test_db().await;

    let group = create_scim_group(&store, TEST_ORG_ID, "ToBeCascaded", None)
        .await
        .expect("create group");
    let user = create_scim_user(
        &store,
        Some(TEST_ORG_ID),
        "cascade-member@example.com",
        None,
        None,
        true,
    )
    .await
    .expect("create user");

    let _ = add_scim_group_member(&store, &group.id, TEST_ORG_ID, &user.id)
        .await
        .expect("add member");

    // Delete the group
    let _ = delete_scim_group(&store, &group.id, TEST_ORG_ID)
        .await
        .expect("delete group");

    // User should still exist
    let user_exists = get_scim_user(&store, &user.id, TEST_ORG_ID)
        .await
        .expect("query user");
    assert!(
        user_exists.is_some(),
        "user should not be deleted when group is deleted"
    );

    // User's group memberships should be cleaned up
    let user_groups = get_user_scim_groups(&store, &user.id, TEST_ORG_ID)
        .await
        .expect("get user groups");
    assert!(
        user_groups.is_empty(),
        "group membership should be cascade-deleted with the group"
    );
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

// ========================================================================
// JWT assertion JTI — replay prevention and expiry cleanup
// ========================================================================

#[tokio::test]
async fn test_store_jwt_assertion_jti_replay_prevention() {
    use crate::db::claim::ClaimError;
    let (store, _audit) = test_db().await;

    let expires: jiff::Timestamp = "2099-01-01T00:00:00Z".parse().unwrap();

    // First use returns the witness
    let _claim = store_jwt_assertion_jti(&store, "jti-abc", "client-1", expires)
        .await
        .expect("First use of a JTI should be accepted");

    // Replay with same jti + client_id returns AlreadyConsumed
    let replayed = store_jwt_assertion_jti(&store, "jti-abc", "client-1", expires).await;
    assert!(
        matches!(replayed, Err(ClaimError::AlreadyConsumed)),
        "Replay of same JTI+client_id should be rejected: got {replayed:?}"
    );

    // Same JTI from a different client_id is allowed
    let _different_client = store_jwt_assertion_jti(&store, "jti-abc", "client-2", expires)
        .await
        .expect("Same JTI from a different client should be accepted");
}

#[tokio::test]
async fn test_store_jwt_assertion_jti_too_long() {
    use crate::db::claim::ClaimError;
    let (store, _audit) = test_db().await;

    // JTI longer than MAX_JTI_LENGTH (256) must be rejected immediately
    let long_jti = "x".repeat(257);
    let result = store_jwt_assertion_jti(
        &store,
        &long_jti,
        "client-1",
        "2099-01-01T00:00:00Z".parse().unwrap(),
    )
    .await;
    assert!(
        matches!(result, Err(ClaimError::Database(_))),
        "JTI exceeding max length must return a Database error: got {result:?}"
    );
}

#[tokio::test]
async fn test_store_jwt_assertion_jti_at_max_length() {
    use crate::db::claim::ClaimError;
    let (store, _audit) = test_db().await;

    // Exactly MAX_JTI_LENGTH (256) must be accepted
    let max_jti = "j".repeat(256);
    let _claim = store_jwt_assertion_jti(
        &store,
        &max_jti,
        "client-1",
        "2099-01-01T00:00:00Z".parse().unwrap(),
    )
    .await
    .expect("JTI at max length should be accepted");

    // Replay still detected
    let replayed = store_jwt_assertion_jti(
        &store,
        &max_jti,
        "client-1",
        "2099-01-01T00:00:00Z".parse().unwrap(),
    )
    .await;
    assert!(
        matches!(replayed, Err(ClaimError::AlreadyConsumed)),
        "Replay of max-length JTI should be rejected: got {replayed:?}"
    );
}

#[tokio::test]
async fn test_store_jwt_assertion_jti_client_isolation() {
    use crate::db::claim::ClaimError;
    let (store, _audit) = test_db().await;

    let expires: jiff::Timestamp = "2099-01-01T00:00:00Z".parse().unwrap();

    // Three independent (jti, client_id) pairs must all succeed
    let _a = store_jwt_assertion_jti(&store, "jti-xyz", "client-A", expires)
        .await
        .expect("First pair should be accepted");
    let _b = store_jwt_assertion_jti(&store, "jti-xyz", "client-B", expires)
        .await
        .expect("Same JTI, different client should be accepted");
    let _c = store_jwt_assertion_jti(&store, "jti-pqr", "client-A", expires)
        .await
        .expect("Different JTI, same client should be accepted");

    // Each pair replays to AlreadyConsumed independently
    let a2 = store_jwt_assertion_jti(&store, "jti-xyz", "client-A", expires).await;
    let b2 = store_jwt_assertion_jti(&store, "jti-xyz", "client-B", expires).await;
    let c2 = store_jwt_assertion_jti(&store, "jti-pqr", "client-A", expires).await;
    assert!(matches!(a2, Err(ClaimError::AlreadyConsumed)));
    assert!(matches!(b2, Err(ClaimError::AlreadyConsumed)));
    assert!(matches!(c2, Err(ClaimError::AlreadyConsumed)));
}

#[tokio::test]
async fn test_delete_expired_jwt_assertion_jtis() {
    use crate::db::claim::ClaimError;
    let (store, _audit) = test_db().await;

    let past_expires: jiff::Timestamp = "2020-01-01T00:00:00Z".parse().unwrap();
    let future_expires: jiff::Timestamp = "2099-01-01T00:00:00Z".parse().unwrap();

    // Insert one expired and one valid JTI
    let _expired_claim = store_jwt_assertion_jti(&store, "expired-jti", "c1", past_expires)
        .await
        .expect("insert expired");
    let _valid_claim = store_jwt_assertion_jti(&store, "valid-jti", "c1", future_expires)
        .await
        .expect("insert valid");

    let deleted = delete_expired_jwt_assertion_jtis(&store)
        .await
        .expect("delete_expired should not error");
    assert!(deleted >= 1, "Should delete at least the expired JTI");

    // The valid one is still in place — replay returns AlreadyConsumed
    let still_stored = store_jwt_assertion_jti(&store, "valid-jti", "c1", future_expires).await;
    assert!(
        matches!(still_stored, Err(ClaimError::AlreadyConsumed)),
        "Valid JTI should still block replay: got {still_stored:?}"
    );

    // The expired one was deleted and can be reused
    let _reused = store_jwt_assertion_jti(&store, "expired-jti", "c1", future_expires)
        .await
        .expect("Expired+deleted JTI should be accepted again after cleanup");
}

// ========================================================================
// DPoP JTI replay prevention
// ========================================================================

#[tokio::test]
async fn test_dpop_jti_replay_prevention() {
    let (store, _audit) = test_db().await;

    // First use returns true
    let stored = check_and_store_dpop_jti(&store, "dpop-jti-1", 600)
        .await
        .expect("first store should not error");
    assert!(stored, "First use of a JTI should be accepted");

    // Replay returns false
    let replayed = check_and_store_dpop_jti(&store, "dpop-jti-1", 600)
        .await
        .expect("replay check should not error");
    assert!(!replayed, "Replay of same JTI should be rejected");

    // Different JTI succeeds
    let different = check_and_store_dpop_jti(&store, "dpop-jti-2", 600)
        .await
        .expect("different JTI should not error");
    assert!(different, "Different JTI should be accepted");
}

#[tokio::test]
async fn test_dpop_jti_empty() {
    let (store, _audit) = test_db().await;

    let result = check_and_store_dpop_jti(&store, "", 600).await;
    assert!(result.is_err(), "Empty JTI must return an error");
}

#[tokio::test]
async fn test_dpop_jti_too_long() {
    let (store, _audit) = test_db().await;

    let long_jti = "x".repeat(257);
    let result = check_and_store_dpop_jti(&store, &long_jti, 600).await;
    assert!(
        result.is_err(),
        "JTI exceeding max length must return an error"
    );
}

#[tokio::test]
async fn test_dpop_jti_at_max_length() {
    let (store, _audit) = test_db().await;

    let max_jti = "d".repeat(256);
    let stored = check_and_store_dpop_jti(&store, &max_jti, 600)
        .await
        .expect("256-char JTI should not error");
    assert!(stored, "JTI at max length should be accepted");

    let replayed = check_and_store_dpop_jti(&store, &max_jti, 600)
        .await
        .expect("replay check should not error");
    assert!(!replayed, "Replay of max-length JTI should be rejected");
}

#[tokio::test]
async fn test_dpop_jti_concurrent_insert_rejects_duplicates() {
    let (store, _audit) = test_db().await;
    let store = Arc::new(store);

    let num_tasks = 20;
    let mut handles = Vec::with_capacity(num_tasks);

    for _ in 0..num_tasks {
        let s = Arc::clone(&store);
        handles.push(tokio::spawn(async move {
            check_and_store_dpop_jti(&s, "same-jti", 600).await
        }));
    }

    let mut successes = 0u32;
    for handle in handles {
        let result = handle.await.expect("task should not panic");
        if let Ok(true) = result {
            successes += 1;
        }
    }

    assert_eq!(
        successes, 1,
        "Exactly one concurrent insert should succeed, got {successes}"
    );
}

#[tokio::test]
async fn test_delete_expired_dpop_jtis() {
    let (store, _audit) = test_db().await;

    // Insert one with past expiry (validity_seconds=0 won't work since
    // it computes from now; instead insert directly with short validity
    // and rely on the fact that we can test cleanup.)
    check_and_store_dpop_jti(&store, "valid-dpop-jti", 3600)
        .await
        .expect("insert valid");

    // Cleanup should not delete the valid one
    let deleted = delete_expired_dpop_jtis(&store, "")
        .await
        .expect("delete_expired should not error");
    assert_eq!(deleted, 0, "No expired JTIs to delete");

    // The valid one should still block replay
    let still_blocked = check_and_store_dpop_jti(&store, "valid-dpop-jti", 3600)
        .await
        .expect("check");
    assert!(!still_blocked, "Valid JTI should still block replay");
}

// ========================================================================
// SCIM filter parsing — co / sw operators and error path
// ========================================================================

#[test]
fn test_scim_filter_parse_co_operator() {
    use crate::db::scim::{ScimFilterOp, parse_scim_filter};

    let result =
        parse_scim_filter(r#"userName co "smith""#, "userName").expect("parse should succeed");
    let filter = result.expect("filter should be present");
    assert_eq!(filter.op, ScimFilterOp::Co);
    assert_eq!(filter.value, "smith");
}

#[test]
fn test_scim_filter_parse_sw_operator() {
    use crate::db::scim::{ScimFilterOp, parse_scim_filter};

    let result =
        parse_scim_filter(r#"userName sw "alice""#, "userName").expect("parse should succeed");
    let filter = result.expect("filter should be present");
    assert_eq!(filter.op, ScimFilterOp::Sw);
    assert_eq!(filter.value, "alice");
}

#[test]
fn test_scim_filter_parse_unsupported_operator_returns_error() {
    use crate::db::scim::parse_scim_filter;

    let result = parse_scim_filter(r#"userName gt "alice""#, "userName");
    assert!(result.is_err(), "Unsupported operator should return Err");
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("gt"),
        "Error should mention the unsupported operator"
    );
}

#[test]
fn test_scim_filter_parse_no_match_for_other_attribute() {
    use crate::db::scim::parse_scim_filter;

    let result =
        parse_scim_filter(r#"externalId eq "ext-1""#, "userName").expect("parse should not error");
    assert!(
        result.is_none(),
        "Filter for different attribute should return None"
    );
}

// ========================================================================
// SCIM list — co / sw filter operators applied in app code
// ========================================================================

#[tokio::test]
async fn test_scim_user_list_filter_co_operator() {
    let (store, _audit) = test_db().await;

    create_scim_user(
        &store,
        Some(TEST_ORG_ID),
        "alice@example.com",
        None,
        None,
        true,
    )
    .await
    .expect("create alice");
    create_scim_user(
        &store,
        Some(TEST_ORG_ID),
        "bob@example.com",
        None,
        None,
        true,
    )
    .await
    .expect("create bob");
    create_scim_user(
        &store,
        Some(TEST_ORG_ID),
        "alicia@example.com",
        None,
        None,
        true,
    )
    .await
    .expect("create alicia");

    // "userName co \"alic\"" should match alice and alicia
    let (results, _) = list_scim_users(&store, TEST_ORG_ID, Some(r#"userName co "alic""#), 1, 100)
        .await
        .expect("list_scim_users failed");
    assert_eq!(
        results.len(),
        2,
        "co filter should match two users; got {}",
        results.len()
    );
    let emails: Vec<&str> = results.iter().map(|u| u.email.as_str()).collect();
    assert!(emails.contains(&"alice@example.com"));
    assert!(emails.contains(&"alicia@example.com"));
}

#[tokio::test]
async fn test_scim_user_list_filter_sw_operator() {
    let (store, _audit) = test_db().await;

    create_scim_user(
        &store,
        Some(TEST_ORG_ID),
        "zara@example.com",
        None,
        None,
        true,
    )
    .await
    .expect("create zara");
    create_scim_user(
        &store,
        Some(TEST_ORG_ID),
        "zebra@example.com",
        None,
        None,
        true,
    )
    .await
    .expect("create zebra");
    create_scim_user(
        &store,
        Some(TEST_ORG_ID),
        "anna@example.com",
        None,
        None,
        true,
    )
    .await
    .expect("create anna");

    // "userName sw \"ze\"" should match zara? no — "ze" prefix: zebra matches, zara does not.
    let (results, _) = list_scim_users(&store, TEST_ORG_ID, Some(r#"userName sw "ze""#), 1, 100)
        .await
        .expect("list_scim_users failed");
    assert_eq!(results.len(), 1, "sw filter should match zebra only");
    assert_eq!(results[0].email, "zebra@example.com");
}

// ========================================================================
// SCIM filter — multibyte / CJK character handling
// ========================================================================

#[test]
fn test_scim_filter_parse_cjk_value() {
    use crate::db::scim::{ScimFilterOp, parse_scim_filter};

    let result = parse_scim_filter(r#"displayName eq "山田太郎""#, "displayName")
        .expect("parse should succeed");
    let filter = result.expect("filter should be present");
    assert_eq!(filter.op, ScimFilterOp::Eq);
    assert_eq!(filter.value, "山田太郎");
}

#[test]
fn test_scim_filter_parse_cjk_co_operator() {
    use crate::db::scim::{ScimFilterOp, parse_scim_filter};

    let result =
        parse_scim_filter(r#"displayName co "田中""#, "displayName").expect("parse should succeed");
    let filter = result.expect("filter should be present");
    assert_eq!(filter.op, ScimFilterOp::Co);
    assert_eq!(filter.value, "田中");
}

#[test]
fn test_scim_filter_parse_emoji_value() {
    use crate::db::scim::{ScimFilterOp, parse_scim_filter};

    let result = parse_scim_filter(r#"displayName eq "Test 🔑 Key""#, "displayName")
        .expect("parse should succeed");
    let filter = result.expect("filter should be present");
    assert_eq!(filter.op, ScimFilterOp::Eq);
    assert_eq!(filter.value, "Test 🔑 Key");
}

// ========================================================================
// FIDO2 Challenge State Single-Use Tests
// ========================================================================

#[tokio::test]
async fn test_challenge_state_mark_used() {
    let (store, _audit) = test_db().await;

    let state_jwt = "test-jwt-mark-used";
    let expires_at = jiff::Timestamp::now()
        .checked_add(jiff::SignedDuration::from_secs(300))
        .unwrap();

    // First use should succeed
    let used = try_mark_challenge_used(&store, state_jwt, expires_at)
        .await
        .expect("Failed to mark challenge used");
    assert!(used, "First use should succeed");
}

#[tokio::test]
async fn test_challenge_state_replay_rejected() {
    let (store, _audit) = test_db().await;

    let state_jwt = "test-jwt-replay";
    let expires_at = jiff::Timestamp::now()
        .checked_add(jiff::SignedDuration::from_secs(300))
        .unwrap();

    // First use succeeds
    let first = try_mark_challenge_used(&store, state_jwt, expires_at)
        .await
        .expect("Failed on first use");
    assert!(first, "First use should succeed");

    // Second use must fail (replay)
    let second = try_mark_challenge_used(&store, state_jwt, expires_at)
        .await
        .expect("Failed on second use");
    assert!(!second, "Second use (replay) should be rejected");
}

#[tokio::test]
async fn test_challenge_state_new_hash_succeeds() {
    let (store, _audit) = test_db().await;

    // A never-seen hash should succeed on first use
    let used = try_mark_challenge_used(
        &store,
        "never_seen_hash",
        jiff::Timestamp::now()
            .checked_add(jiff::SignedDuration::from_secs(300))
            .unwrap(),
    )
    .await
    .expect("Failed to mark challenge used");
    assert!(used, "New challenge hash should succeed");
}

#[tokio::test]
async fn test_challenge_state_concurrent_calls_produce_one_row() {
    // Two concurrent calls with the same state_jwt must produce exactly one
    // document row — deterministic ID ensures they collide on the PRIMARY KEY
    // rather than creating two rows.
    let (store, _audit) = test_db().await;

    let state_jwt = "concurrent-state-jwt-test-value";
    let expires_at = jiff::Timestamp::now()
        .checked_add(jiff::SignedDuration::from_secs(300))
        .unwrap();

    let store_a = store.clone();
    let store_b = store.clone();
    let (result_a, result_b) = tokio::join!(
        try_mark_challenge_used(&store_a, state_jwt, expires_at),
        try_mark_challenge_used(&store_b, state_jwt, expires_at),
    );

    let a = result_a.expect("first concurrent call must not error");
    let b = result_b.expect("second concurrent call must not error");

    // Exactly one winner and one loser — the sum of the two booleans is 1.
    assert!(
        a ^ b,
        "exactly one concurrent call should return true (winner), got a={a}, b={b}"
    );
}

#[test]
fn test_scim_filter_parse_korean_value() {
    use crate::db::scim::{ScimFilterOp, parse_scim_filter};

    let result = parse_scim_filter(r#"userName eq "사용자@example.com""#, "userName")
        .expect("parse should succeed");
    let filter = result.expect("filter should be present");
    assert_eq!(filter.op, ScimFilterOp::Eq);
    assert_eq!(filter.value, "사용자@example.com");
}

// ========================================================================
// JWKS cache — behavioral invariants
// ========================================================================

#[tokio::test]
async fn test_update_oauth_client_jwks_uri_clears_cache() {
    let (store, _audit) = test_db().await;

    let (user_id, _) = upsert_user(&store, "jwks-uri-clear@example.com", None)
        .await
        .expect("upsert_user failed");

    let (client, _) = create_oauth_client(
        &store,
        &CreateOAuthClientParams {
            user_id: Some(&user_id),
            name: "JWKS URI Clear Test",
            description: None,
            application_type: OAuthClientType::Web,
            redirect_uris: &[],
            access_scope: AccessScope::default(),
            org_id: None,
            resource_uris: &[],
            token_endpoint_auth_method: None,
            jwks: None,
            jwks_uri: Some("https://original.example.com/jwks"),
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
        },
    )
    .await
    .expect("create_oauth_client failed");

    let jwks = serde_json::json!({"keys": [{"kty": "EC", "kid": "k1"}]});
    upsert_jwks_cache(&store, &client.id, &jwks)
        .await
        .expect("upsert_jwks_cache failed");

    assert!(
        get_jwks_cache(&store, &client.id)
            .await
            .expect("get_jwks_cache failed")
            .is_some(),
        "cache should be populated before URI change"
    );

    update_oauth_client_registration(
        &store,
        &client.id,
        &UpdateClientRegistrationParams {
            redirect_uris: &[],
            grant_types: None,
            response_types: None,
            jwks: None,
            jwks_uri: Some("https://rotated.example.com/jwks"),
            registration_access_token_hash: "hash",
            registration_metadata: None,
            userinfo_signed_response_alg: None,
            request_uris: None,
        },
    )
    .await
    .expect("update_oauth_client_registration failed");

    let cache = get_jwks_cache(&store, &client.id)
        .await
        .expect("get_jwks_cache failed");
    assert!(
        cache.is_none(),
        "cache must be cleared when jwks_uri changes"
    );
}

#[tokio::test]
async fn test_jwks_refresh_does_not_modify_oauth_client_doc() {
    let (store, _audit) = test_db().await;

    let (user_id, _) = upsert_user(&store, "jwks-parent-immutable@example.com", None)
        .await
        .expect("upsert_user failed");

    let (client, _) = create_oauth_client(
        &store,
        &CreateOAuthClientParams {
            user_id: Some(&user_id),
            name: "Parent Immutable Test",
            description: None,
            application_type: OAuthClientType::Web,
            redirect_uris: &[],
            access_scope: AccessScope::default(),
            org_id: None,
            resource_uris: &[],
            token_endpoint_auth_method: None,
            jwks: None,
            jwks_uri: Some("https://immutable.example.com/jwks"),
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
        },
    )
    .await
    .expect("create_oauth_client failed");

    let snapshot_updated_at = client.updated_at;

    let jwks = serde_json::json!({"keys": [{"kty": "EC", "kid": "p1"}]});
    upsert_jwks_cache(&store, &client.id, &jwks)
        .await
        .expect("upsert_jwks_cache failed");

    let after = get_oauth_client_by_id(&store, &client.id)
        .await
        .expect("get_oauth_client_by_id failed")
        .expect("client must still exist");

    assert_eq!(
        after.updated_at, snapshot_updated_at,
        "upsert_jwks_cache must not change parent updated_at"
    );
}
