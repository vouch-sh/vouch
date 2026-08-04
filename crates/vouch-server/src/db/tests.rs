// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Database module tests.

#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::panic,
    reason = "test code: panic on assertion failure is acceptable; cast bounds are obvious in test fixtures"
)]

use std::sync::Arc;

use super::*;
use crate::crypto::document_crypto::PlaintextDocumentCrypto;
use crate::db::audit::AuditStore;
use crate::db::store::DocumentStore;
use crate::test_utils::{TestClientSpec, create_test_client};

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
        &CreateAuthenticatorParams {
            user_id: &user_id,
            user_email: "device@example.com",
            name: "Test Key",
            credential_id: b"test-cred-id-device",
            public_key: &[0u8; 32],
            aaguid: None,
            user_handle: Some(user_id.as_bytes()),
            attestation_verified: false,
        },
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
        &CreateAuthenticatorParams {
            user_id: &user_id,
            user_email: "consume@example.com",
            name: "Key",
            credential_id: b"cred-consume",
            public_key: &[0u8; 32],
            aaguid: None,
            user_handle: None,
            attestation_verified: false,
        },
    )
    .await
    .expect("auth");

    authorize_device_auth(&store, &id, &user_id, "consume@example.com", &auth_id)
        .await
        .expect("authorize");

    // Consume — claim binding satisfies #[must_use].
    let _claim = try_consume_device_auth(&store, device_code_hash)
        .await
        .expect("First consumption should succeed");

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
        &CreateAuthenticatorParams {
            user_id: &user_id,
            user_email: "double@example.com",
            name: "Key",
            credential_id: b"cred-double",
            public_key: &[0u8; 32],
            aaguid: None,
            user_handle: None,
            attestation_verified: false,
        },
    )
    .await
    .expect("auth");

    authorize_device_auth(&store, &id, &user_id, "double@example.com", &auth_id)
        .await
        .expect("authorize");

    let _first = try_consume_device_auth(&store, device_code_hash)
        .await
        .expect("First consumption should succeed");

    let second = try_consume_device_auth(&store, device_code_hash).await;
    assert!(
        matches!(second, Err(crate::db::claim::ClaimError::AlreadyConsumed)),
        "Second consumption must fail with AlreadyConsumed, got: {second:?}"
    );
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
    let consumed = try_consume_device_auth(&store, device_code_hash).await;
    assert!(
        matches!(consumed, Err(crate::db::claim::ClaimError::AlreadyConsumed)),
        "Pending device code must not be consumable, got: {consumed:?}"
    );
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
        &CreateAuthenticatorParams {
            user_id: &user_id,
            user_email: "expired@example.com",
            name: "Key",
            credential_id: b"cred-expired",
            public_key: &[0u8; 32],
            aaguid: None,
            user_handle: None,
            attestation_verified: false,
        },
    )
    .await
    .expect("auth");

    authorize_device_auth(&store, &id, &user_id, "expired@example.com", &auth_id)
        .await
        .expect("authorize");

    let consumed = try_consume_device_auth(&store, device_code_hash).await;
    assert!(
        matches!(consumed, Err(crate::db::claim::ClaimError::AlreadyConsumed)),
        "Expired device code must not be consumable, got: {consumed:?}"
    );
}

#[tokio::test]
async fn test_try_consume_device_auth_not_found_returns_false() {
    let (store, _audit) = test_db().await;

    let consumed = try_consume_device_auth(&store, "nonexistent_hash").await;
    assert!(
        matches!(consumed, Err(crate::db::claim::ClaimError::AlreadyConsumed)),
        "Nonexistent hash must fail with AlreadyConsumed, got: {consumed:?}"
    );
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

    let id = create_oidc_state(
        &store,
        state,
        Some(&device_auth_id),
        nonce,
        "",
        expires_at,
        "",
    )
    .await
    .expect("Failed to create OIDC state");
    assert!(!id.is_empty());

    // Get OIDC state
    let oidc_state = get_oidc_state(&store, state)
        .await
        .expect("Failed to get OIDC state")
        .expect("Should exist");

    assert_eq!(oidc_state.state, state);
    assert_eq!(
        oidc_state.device_auth_id.as_deref(),
        Some(device_auth_id.as_str())
    );
    assert_eq!(oidc_state.nonce, nonce);
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

    // Insert audit log (insert_scim_audit now uses AuditStore directly)
    let audit_id = insert_scim_audit(
        &audit,
        "CREATE",
        "User",
        "user-123",
        Some("token-123"),
        Some("Created user via SCIM"),
        Some("example.com"),
    )
    .await
    .expect("Failed to insert audit log");

    assert!(!audit_id.is_empty());

    // Insert another audit log without token or org domain (None is valid)
    let audit_id2 = insert_scim_audit(&audit, "DELETE", "User", "user-789", None, None, None)
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
    let event_id = config::insert_auth_event(
        &audit,
        &AuthEventParams {
            user_id: user_id.clone(),
            event_type: AuthEventType::LoginSuccess,
            authenticator_id: Some("auth-123".to_string()),
            client: ClientInfo {
                client_ip: Some("192.168.1.1".parse().unwrap()),
                user_agent: Some("Mozilla/5.0".to_string()),
                ..Default::default()
            },
            success: true,
            ..Default::default()
        },
        Some("events@example.com"),
    )
    .await
    .expect("Failed to insert auth event");

    assert!(!event_id.is_empty());

    // Log failed login
    config::insert_auth_event(
        &audit,
        &AuthEventParams {
            user_id: user_id.clone(),
            event_type: AuthEventType::LoginFailed,
            client: ClientInfo {
                client_ip: Some("192.168.1.1".parse().unwrap()),
                ..Default::default()
            },
            success: false,
            failure_reason: Some("Invalid credential".to_string()),
            ..Default::default()
        },
        Some("events@example.com"),
    )
    .await
    .expect("Failed to insert auth event");
}

#[tokio::test]
async fn test_key_and_device_auth_events_round_trip_and_expire() {
    let (store, audit) = test_db().await;

    let (user_id, _) = upsert_user(&store, "key-events@example.com", None)
        .await
        .expect("Failed to create user");

    // Insert one event per key/device-auth lifecycle variant.
    let variants = [
        AuthEventType::KeyRegistered,
        AuthEventType::KeyRemoved,
        AuthEventType::DeviceAuthApproved,
    ];
    for event_type in variants {
        config::insert_auth_event(
            &audit,
            &AuthEventParams {
                user_id: user_id.clone(),
                event_type,
                authenticator_id: Some("auth-123".to_string()),
                success: true,
                ..Default::default()
            },
            Some("key-events@example.com"),
        )
        .await
        .expect("Failed to insert auth event");
    }

    // Each variant is queryable under its expected event_type string.
    for expected in ["key_registered", "key_removed", "device_auth_approved"] {
        let events = audit
            .query_events(&AuditEventFilter {
                event_types: Some(vec![expected.to_string()]),
                ..AuditEventFilter::default()
            })
            .await
            .expect("query events");
        assert_eq!(events.len(), 1, "expected one {expected} event");
        assert_eq!(
            events[0].email_domain.as_deref(),
            Some("example.com"),
            "email must be masked to domain-only"
        );
    }

    // Retention must cover the new variants: the sweep derives coverage from
    // each variant's registry kind, so this fails if a kind loses its
    // AuthEvents retention class.
    let cutoff = jiff::Timestamp::now()
        .checked_add(jiff::Span::new().hours(1))
        .unwrap();
    let deleted = audit
        .delete_expired_events(Some(cutoff), None)
        .await
        .expect("delete old auth events");
    assert!(
        deleted >= 3,
        "expected the 3 lifecycle events to be deleted, got {deleted}"
    );
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
        &CreateAuthenticatorParams {
            user_id: &user_id,
            user_email: "auth@example.com",
            name: "YubiKey 5C",
            credential_id: &credential_id,
            public_key: &public_key,
            aaguid: Some("2fc0579f-8113-47ea-b116-bb5a8db9202a"),
            user_handle: Some(&user_handle),
            attestation_verified: false,
        },
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
            &CreateAuthenticatorParams {
                user_id: &user_id,
                user_email: "count@example.com",
                name: &format!("Key {}", i),
                credential_id: &[i as u8; 10],
                public_key: &[0u8; 32],
                aaguid: None,
                user_handle: None,
                attestation_verified: false,
            },
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
        &CreateScimTokenParams {
            org_id,
            token_hash,
            description: Some("Admin token"),
            expires_at: None,
            scope: ScimScopeSet::default(),
        },
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

/// Expired SCIM tokens cannot authenticate, so they must not count
/// toward the per-org creation limit, and cleanup must purge them (#715).
#[tokio::test]
async fn test_expired_scim_tokens_excluded_from_active_count() {
    let (store, _audit) = test_db().await;

    let org = create_organization(&store, "test.com", Some("Test Org"), None)
        .await
        .expect("Failed to create org");
    let org_id = &org.id;

    let past = jiff::Timestamp::now() - jiff::Span::new().hours(1);
    let future = jiff::Timestamp::now() + jiff::Span::new().hours(1);

    // Two expired tokens and one active token
    for (hash, expiry) in [
        ("expired-1", Some(past)),
        ("expired-2", Some(past)),
        ("active-1", Some(future)),
    ] {
        create_scim_token(
            &store,
            &CreateScimTokenParams {
                org_id,
                token_hash: hash,
                description: None,
                expires_at: expiry,
                scope: ScimScopeSet::default(),
            },
        )
        .await
        .expect("Failed to create SCIM token");
    }

    // list returns everything, expired rows included
    let all = list_scim_tokens(&store, Some(org_id))
        .await
        .expect("Failed to list tokens");
    assert_eq!(all.len(), 3);

    // An expired token cannot authenticate...
    assert!(
        get_scim_token_by_hash(&store, "expired-1")
            .await
            .expect("lookup expired token")
            .is_none(),
        "an expired token must not authenticate"
    );
    assert!(
        get_scim_token_by_hash(&store, "active-1")
            .await
            .expect("lookup active token")
            .is_some(),
        "an unexpired token must authenticate"
    );

    // ...so it must not consume a slot either. Only `active-1` counts against
    // the cap of 2, leaving room for one more. A token with no expiration is
    // always active, so the one after that is refused.
    create_scim_token(
        &store,
        &CreateScimTokenParams {
            org_id,
            token_hash: "no-expiry",
            description: None,
            expires_at: None,
            scope: ScimScopeSet::default(),
        },
    )
    .await
    .expect("a second active token must be allowed alongside 2 expired ones");

    match create_scim_token(
        &store,
        &CreateScimTokenParams {
            org_id,
            token_hash: "third-active",
            description: None,
            expires_at: Some(future),
            scope: ScimScopeSet::default(),
        },
    )
    .await
    {
        Err(crate::error::ServiceError::Api { ref code, .. }) if code == "token_limit_reached" => {}
        other => panic!("a third active token must hit the cap; got {other:?}"),
    }

    // Cleanup purges only the expired tokens
    let deleted = delete_expired_scim_tokens(&store)
        .await
        .expect("Failed to delete expired tokens");
    assert_eq!(deleted, 2);
    let remaining = list_scim_tokens(&store, Some(org_id))
        .await
        .expect("Failed to list tokens");
    assert_eq!(remaining.len(), 2);
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
    let user = create_scim_user(
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

    // The created user must be addressable by its deterministic ID: the
    // SCIM handler's `validate_resource_id` only accepts `uuid::Uuid`-parseable
    // IDs, so a deterministic ID that isn't a valid UUID would make the user
    // unreachable via GET/PATCH/PUT/DELETE.
    use crate::db::documents::user::UserDoc;
    let by_id = store
        .get::<UserDoc>(&user.id)
        .await
        .expect("query by id")
        .expect("user must be findable by its deterministic ID");
    assert_eq!(by_id.data.email, "dup@example.com");
    assert!(
        uuid::Uuid::try_parse(&user.id).is_ok(),
        "deterministic user ID must parse as a UUID; got {}",
        user.id
    );
}

/// Regression for the SCIM concurrent-create race: two concurrent
/// `create_scim_user` calls with the same email must produce exactly one
/// user row, not two. Before the deterministic-ID fix, each call generated
/// a fresh random UUID v7 primary key, so neither insert conflicted with the
/// other and both committed — producing duplicate accounts for the same email.
///
/// The fix derives the user ID from the email (a version-5 name-based UUID),
/// so the two inserts collide on the `documents` PRIMARY KEY. The losing
/// insert fails with a unique/primary-key violation, which
/// `is_unique_violation` maps to the same "UNIQUE constraint failed" error
/// returned by the explicit pre-check; the SCIM handler then returns
/// `409 Conflict` for the loser.
///
/// Mirrors `test_dpop_jti_concurrent_insert_rejects_duplicates`. Uses
/// `multi_thread` for defensive OS-level parallelism (SQLite `busy_timeout`
/// waits happen inside sqlx-sqlite's dedicated OS thread and don't block
/// tokio worker threads). Under DSQL's optimistic concurrency the loser
/// first receives a serialization error (`40001`), `with_dsql_retry!`
/// retries, and the retried insert then collides with the winner's
/// committed row (`23505`) — `23505` is not retryable, so the loser surfaces
/// as `Err`. This SQLite test exercises the post-retry collision path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_create_scim_user_concurrent_same_email_produces_one_user() {
    use crate::db::documents::user::UserDoc;
    let (store, _audit) = test_db().await;
    let store = std::sync::Arc::new(store);
    let email = "race@example.com";

    let num_tasks = 20;
    let mut handles = Vec::with_capacity(num_tasks);
    for _ in 0..num_tasks {
        let s = std::sync::Arc::clone(&store);
        handles.push(tokio::spawn(async move {
            create_scim_user(&s, Some(TEST_ORG_ID), email, Some("Racer"), None, true).await
        }));
    }

    let mut successes = 0u32;
    let mut unique_errors = 0u32;
    for handle in handles {
        let result = handle.await.expect("task should not panic");
        match result {
            Ok(_) => successes += 1,
            Err(ref e) if e.to_string().contains("UNIQUE") => unique_errors += 1,
            Err(ref e) => panic!("unexpected error from create_scim_user: {e}"),
        }
    }

    assert_eq!(
        successes, 1,
        "exactly one concurrent create should succeed; got {successes}"
    );
    assert_eq!(
        unique_errors,
        u32::try_from(num_tasks - 1).expect("num_tasks - 1 fits in u32"),
        "every other concurrent create should be rejected with a UNIQUE error"
    );

    // Verify at the DB level: exactly one user row for the email, and exactly
    // one row with the deterministic ID. No duplicate accounts can exist.
    let by_email = store
        .find_one::<UserDoc>("email", email)
        .await
        .expect("query by email")
        .expect("exactly one user must exist for the email");
    let all_for_email = store
        .find_all::<UserDoc>("email", email)
        .await
        .expect("find_all by email");
    assert_eq!(
        all_for_email.len(),
        1,
        "exactly one user row must exist for the email; got {}",
        all_for_email.len()
    );
    // The row found by email must be the same row found by the deterministic ID.
    let by_id = store
        .get::<UserDoc>(&by_email.id)
        .await
        .expect("query by id")
        .expect("user must be findable by its deterministic ID");
    assert_eq!(by_id.id, by_email.id);
    assert_eq!(by_id.data.email, email);
    // And the ID must be a valid UUID (SCIM resource ID contract).
    assert!(
        uuid::Uuid::try_parse(&by_email.id).is_ok(),
        "the winning user's ID must be a valid UUID; got {}",
        by_email.id
    );
}

/// Concurrent creates for the same email in DIFFERENT casings must still
/// collide on one row: `create_scim_user` lowercases the email before
/// deriving the deterministic ID, so `Alice@…`, `ALICE@…`, and `alice@…`
/// all compute the same primary key. Deriving from the verbatim email
/// instead would give each casing its own ID, letting cross-case concurrent
/// creates commit distinct rows — reopening the duplicate-user bug the
/// deterministic ID exists to close.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_create_scim_user_concurrent_mixed_case_same_email_produces_one_user() {
    use crate::db::documents::user::UserDoc;
    let (store, _audit) = test_db().await;
    let store = std::sync::Arc::new(store);

    let casings = [
        "Case.Race@Example.com",
        "case.race@example.com",
        "CASE.RACE@EXAMPLE.COM",
        "case.Race@example.COM",
    ];
    let num_tasks = 20;
    let mut handles = Vec::with_capacity(num_tasks);
    for &email in casings.iter().cycle().take(num_tasks) {
        let s = std::sync::Arc::clone(&store);
        handles.push(tokio::spawn(async move {
            create_scim_user(&s, Some(TEST_ORG_ID), email, Some("Racer"), None, true).await
        }));
    }

    let mut successes = 0u32;
    let mut unique_errors = 0u32;
    for handle in handles {
        let result = handle.await.expect("task should not panic");
        match result {
            Ok(record) => {
                successes += 1;
                assert_eq!(
                    record.email, "case.race@example.com",
                    "the stored email must be the lowercase normalization"
                );
            }
            Err(ref e) if e.to_string().contains("UNIQUE") => unique_errors += 1,
            Err(ref e) => panic!("unexpected error from create_scim_user: {e}"),
        }
    }

    assert_eq!(
        successes, 1,
        "exactly one mixed-case concurrent create should succeed; got {successes}"
    );
    assert_eq!(
        unique_errors,
        u32::try_from(num_tasks - 1).expect("num_tasks - 1 fits in u32"),
        "every other mixed-case concurrent create should be rejected with a UNIQUE error"
    );

    // Exactly one row exists, stored under the lowercase email, with the
    // deterministic ID derived from that lowercase form.
    let all_for_email = store
        .find_all::<UserDoc>("email", "case.race@example.com")
        .await
        .expect("find_all by lowercase email");
    assert_eq!(
        all_for_email.len(),
        1,
        "exactly one user row must exist across all casings; got {}",
        all_for_email.len()
    );
    let expected_id = crate::db::documents::user::deterministic_user_id("case.race@example.com");
    let winner = all_for_email.first().expect("one row exists");
    assert_eq!(
        winner.id, expected_id,
        "the winning row's ID must derive from the lowercase email"
    );
}

/// The deterministic user ID is stable across calls and across process
/// restarts (it is a pure function of the email). A user created by
/// `create_scim_user`, deleted, then re-created with the same email must
/// receive the same ID — confirming the derivation has no per-process
/// randomness and that the `documents` PRIMARY KEY collision behaviour is
/// not an arte fact of a single test run.
#[tokio::test]
async fn test_create_scim_user_deterministic_id_is_stable_across_recreate() {
    use crate::db::documents::user::UserDoc;
    let (store, _audit) = test_db().await;
    let email = "recreate@example.com";

    let first = create_scim_user(&store, Some(TEST_ORG_ID), email, Some("First"), None, true)
        .await
        .expect("first create");
    let first_id = first.id.clone();

    // Delete the user (and any associated data) so the email is free again.
    store.delete(&first.id).await.expect("delete user");

    // Re-create with the same email — must get the same ID.
    let second = create_scim_user(&store, Some(TEST_ORG_ID), email, Some("Second"), None, true)
        .await
        .expect("re-create after delete");
    assert_eq!(
        second.id, first_id,
        "re-creating a user with the same email must produce the same deterministic ID"
    );

    // Only one row exists for the email.
    let all_for_email = store
        .find_all::<UserDoc>("email", email)
        .await
        .expect("find_all by email");
    assert_eq!(all_for_email.len(), 1);
}

/// A pre-existing user created by a *different* code path that does not use
/// the deterministic ID (e.g. `enroll_user_with_org`, which still generates a
/// random UUID v7) must still block a subsequent `create_scim_user` for the
/// same email. The `find_one` pre-check catches this before the insert is
/// attempted, so the deterministic ID never collides with the random one —
/// the user sees the existing-user `UNIQUE` error, not a silent duplicate.
#[tokio::test]
async fn test_create_scim_user_blocked_by_preexisting_random_id_user() {
    use crate::db::documents::user::UserDoc;
    let (store, _audit) = test_db().await;
    let email = "preexisting@example.com";

    // Seed a user with a random UUID v7 ID, as `enroll_user_with_org` does.
    let seeded = UserDoc {
        email: email.to_string(),
        name: Some("Seeded".to_string()),
        org_id: Some(TEST_ORG_ID.to_string()),
        is_org_admin: false,
        active: true,
        external_id: None,
        github_id: None,
        github_login: None,
        github_refresh_token: None,
    };
    let seeded_doc = store.insert(&seeded).await.expect("seed random-id user");
    assert!(
        uuid::Uuid::try_parse(&seeded_doc.id).is_ok(),
        "seeded user should have a valid UUID v7 id"
    );

    // SCIM create for the same email must be rejected with a UNIQUE error,
    // even though the seeded user's ID differs from the deterministic one.
    let result = create_scim_user(&store, Some(TEST_ORG_ID), email, Some("SCIM"), None, true).await;
    assert!(result.is_err(), "create should be rejected");
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("UNIQUE"),
        "error should mention UNIQUE; got: {err}"
    );

    // Exactly one user row exists — no duplicate created.
    let all_for_email = store
        .find_all::<UserDoc>("email", email)
        .await
        .expect("find_all by email");
    assert_eq!(
        all_for_email.len(),
        1,
        "no duplicate user should be created"
    );
    assert_eq!(all_for_email[0].id, seeded_doc.id);
}

/// Snapshot-isolation verification of the SCIM concurrent-create fix.
///
/// The SQLite `test_create_scim_user_concurrent_same_email_produces_one_user`
/// test confirms the post-retry collision path and the DB-level invariant, but
/// SQLite serializes writers so it cannot reproduce the original race (two
/// transactions both reading "no user exists" from the same snapshot and both
/// attempting to commit distinct rows). This test runs the same scenario
/// against a real PostgreSQL backend when `VOUCH_TEST_POSTGRES_URL` is set,
/// exercising true snapshot isolation where the deterministic-ID collision is
/// the only thing preventing duplicate accounts.
///
/// To run:
///   VOUCH_TEST_POSTGRES_URL="postgres://user:pass@localhost/db" \
///     cargo test -p vouch-server --all-features --lib -- \
///     test_create_scim_user_concurrent_same_email_produces_one_user_postgres --nocapture
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_create_scim_user_concurrent_same_email_produces_one_user_postgres() {
    use crate::db::documents::user::UserDoc;
    use crate::db::pool::{Pool, PoolConfig};

    let url = match std::env::var("VOUCH_TEST_POSTGRES_URL") {
        Ok(u) if !u.is_empty() => u,
        _ => {
            eprintln!("skipping Postgres snapshot-isolation test: VOUCH_TEST_POSTGRES_URL not set");
            return;
        }
    };

    let pool = Pool::connect(&url, &PoolConfig::default())
        .await
        .expect("connect to Postgres test DB");
    let crate::db::pool::Pool::Postgres(p) = &pool else {
        panic!("VOUCH_TEST_POSTGRES_URL must point to a Postgres database");
    };

    // The bundled Postgres migrations use `CREATE INDEX ASYNC`, which is
    // DSQL-specific syntax. For vanilla PostgreSQL we create the schema
    // inline with standard `CREATE INDEX`. This mirrors the migration files
    // in `migrations/postgres/` with the `ASYNC` keyword removed.
    sqlx::raw_sql(
        r#"
        CREATE TABLE IF NOT EXISTS documents (
            id TEXT PRIMARY KEY,
            doc_type TEXT NOT NULL,
            schema_version INTEGER NOT NULL DEFAULT 1,
            encapped_key TEXT,
            data TEXT NOT NULL,
            expires_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            version INTEGER NOT NULL DEFAULT 1,
            last_used_at TEXT
        );
        CREATE TABLE IF NOT EXISTS document_indexes (
            id TEXT PRIMARY KEY,
            document_id TEXT NOT NULL,
            index_field TEXT NOT NULL,
            index_value TEXT NOT NULL,
            UNIQUE(document_id, index_field, index_value)
        );
        CREATE INDEX IF NOT EXISTS idx_documents_doc_type ON documents(doc_type);
        CREATE INDEX IF NOT EXISTS idx_documents_expires_at ON documents(expires_at);
        CREATE INDEX IF NOT EXISTS idx_documents_doc_type_created ON documents(doc_type, created_at);
        CREATE INDEX IF NOT EXISTS idx_document_indexes_lookup ON document_indexes(index_field, index_value);
        CREATE INDEX IF NOT EXISTS idx_document_indexes_document_id ON document_indexes(document_id);
        CREATE INDEX IF NOT EXISTS idx_document_indexes_covering ON document_indexes(index_field, index_value, document_id);
        CREATE INDEX IF NOT EXISTS idx_documents_cleanup ON documents(doc_type, expires_at);
        "#,
    )
    .execute(p)
    .await
    .expect("create Postgres schema");

    let crypto: std::sync::Arc<dyn crate::crypto::document_crypto::DocumentCrypto> =
        std::sync::Arc::new(crate::crypto::document_crypto::PlaintextDocumentCrypto);
    let store = crate::db::store::DocumentStore::new(pool.clone(), crypto.clone());

    let email = "pg-race@example.com";

    // Clean up any leftover row from a previous run.
    if let Some(existing) = store
        .find_one::<UserDoc>("email", email)
        .await
        .expect("find_one before test")
    {
        store.delete(&existing.id).await.expect("delete leftover");
    }

    let store = std::sync::Arc::new(store);
    let num_tasks = 20;
    let mut handles = Vec::with_capacity(num_tasks);
    for _ in 0..num_tasks {
        let s = std::sync::Arc::clone(&store);
        handles.push(tokio::spawn(async move {
            create_scim_user(&s, Some("pg-test-org"), email, Some("Racer"), None, true).await
        }));
    }

    let mut successes = 0u32;
    let mut unique_errors = 0u32;
    let mut other_errors = Vec::new();
    for handle in handles {
        let result = handle.await.expect("task should not panic");
        match result {
            Ok(_) => successes += 1,
            Err(ref e) if e.to_string().contains("UNIQUE") => unique_errors += 1,
            Err(ref e) => other_errors.push(format!("{e:#}")),
        }
    }

    assert!(
        other_errors.is_empty(),
        "unexpected non-UNIQUE errors: {other_errors:?}"
    );
    assert_eq!(
        successes, 1,
        "exactly one concurrent create should succeed on Postgres; got {successes}"
    );
    assert_eq!(
        unique_errors,
        u32::try_from(num_tasks - 1).expect("num_tasks - 1 fits in u32"),
        "every other concurrent create should be rejected with a UNIQUE error on Postgres"
    );

    // Verify at the DB level: exactly one user row for the email.
    let all_for_email = store
        .find_all::<UserDoc>("email", email)
        .await
        .expect("find_all by email");
    assert_eq!(
        all_for_email.len(),
        1,
        "exactly one user row must exist for the email on Postgres; got {}",
        all_for_email.len()
    );
    assert!(
        uuid::Uuid::try_parse(&all_for_email[0].id).is_ok(),
        "the winning user's ID must be a valid UUID; got {}",
        all_for_email[0].id
    );

    // Clean up.
    store
        .delete(&all_for_email[0].id)
        .await
        .expect("cleanup after test");
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
        matches!(result, Err(ClaimError::InvalidInput(_))),
        "JTI exceeding max length must return InvalidInput (client error, \
         not Database — a Database error would tell well-behaved clients to \
         retry the oversized JTI): got {result:?}"
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
    use crate::db::claim::ClaimError;
    let (store, _audit) = test_db().await;

    // First use returns the witness
    let _claim = check_and_store_dpop_jti(&store, "dpop-jti-1", 600)
        .await
        .expect("First use of a JTI should be accepted");

    // Replay returns AlreadyConsumed
    let replayed = check_and_store_dpop_jti(&store, "dpop-jti-1", 600).await;
    assert!(
        matches!(replayed, Err(ClaimError::AlreadyConsumed)),
        "Replay of same JTI should be AlreadyConsumed, got: {replayed:?}"
    );

    // Different JTI succeeds
    let _different = check_and_store_dpop_jti(&store, "dpop-jti-2", 600)
        .await
        .expect("Different JTI should be accepted");
}

#[tokio::test]
async fn test_dpop_jti_empty() {
    use crate::db::claim::ClaimError;
    let (store, _audit) = test_db().await;

    let result = check_and_store_dpop_jti(&store, "", 600).await;
    assert!(
        matches!(result, Err(ClaimError::InvalidInput(_))),
        "Empty JTI must return InvalidInput, got: {result:?}"
    );
}

#[tokio::test]
async fn test_dpop_jti_too_long() {
    use crate::db::claim::ClaimError;
    let (store, _audit) = test_db().await;

    let long_jti = "x".repeat(257);
    let result = check_and_store_dpop_jti(&store, &long_jti, 600).await;
    assert!(
        matches!(result, Err(ClaimError::InvalidInput(_))),
        "JTI exceeding max length must return InvalidInput, got: {result:?}"
    );
}

#[tokio::test]
async fn test_dpop_jti_at_max_length() {
    use crate::db::claim::ClaimError;
    let (store, _audit) = test_db().await;

    let max_jti = "d".repeat(256);
    let _stored = check_and_store_dpop_jti(&store, &max_jti, 600)
        .await
        .expect("JTI at max length should be accepted");

    let replayed = check_and_store_dpop_jti(&store, &max_jti, 600).await;
    assert!(
        matches!(replayed, Err(ClaimError::AlreadyConsumed)),
        "Replay of max-length JTI should be AlreadyConsumed, got: {replayed:?}"
    );
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
        if result.is_ok() {
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
    let _valid = check_and_store_dpop_jti(&store, "valid-dpop-jti", 3600)
        .await
        .expect("insert valid");

    // Cleanup should not delete the valid one
    let deleted = delete_expired_dpop_jtis(&store, "")
        .await
        .expect("delete_expired should not error");
    assert_eq!(deleted, 0, "No expired JTIs to delete");

    // The valid one should still block replay
    use crate::db::claim::ClaimError;
    let result = check_and_store_dpop_jti(&store, "valid-dpop-jti", 3600).await;
    assert!(
        matches!(result, Err(ClaimError::AlreadyConsumed)),
        "Valid JTI should still block replay, got: {result:?}"
    );
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

    // First use should succeed and return a witness
    let _claim = try_consume_challenge_state(&store, state_jwt, expires_at)
        .await
        .expect("First use should succeed");
}

#[tokio::test]
async fn test_challenge_state_replay_rejected() {
    use crate::db::claim::ClaimError;
    let (store, _audit) = test_db().await;

    let state_jwt = "test-jwt-replay";
    let expires_at = jiff::Timestamp::now()
        .checked_add(jiff::SignedDuration::from_secs(300))
        .unwrap();

    // First use succeeds
    let _first = try_consume_challenge_state(&store, state_jwt, expires_at)
        .await
        .expect("First use should succeed");

    // Second use must fail (replay)
    let second = try_consume_challenge_state(&store, state_jwt, expires_at).await;
    assert!(
        matches!(second, Err(ClaimError::AlreadyConsumed)),
        "Second use (replay) should be rejected, got: {second:?}"
    );
}

#[tokio::test]
async fn test_challenge_state_new_hash_succeeds() {
    let (store, _audit) = test_db().await;

    // A never-seen hash should succeed on first use
    let _claim = try_consume_challenge_state(
        &store,
        "never_seen_hash",
        jiff::Timestamp::now()
            .checked_add(jiff::SignedDuration::from_secs(300))
            .unwrap(),
    )
    .await
    .expect("New challenge hash should succeed");
}

#[tokio::test]
async fn test_challenge_state_concurrent_calls_produce_one_row() {
    use crate::db::claim::ClaimError;
    // Two concurrent calls with the same state_jwt must produce exactly one
    // winner — deterministic ID ensures they collide on the PRIMARY KEY
    // rather than creating two rows.
    let (store, _audit) = test_db().await;

    let state_jwt = "concurrent-state-jwt-test-value";
    let expires_at = jiff::Timestamp::now()
        .checked_add(jiff::SignedDuration::from_secs(300))
        .unwrap();

    let store_a = store.clone();
    let store_b = store.clone();
    let (result_a, result_b) = tokio::join!(
        try_consume_challenge_state(&store_a, state_jwt, expires_at),
        try_consume_challenge_state(&store_b, state_jwt, expires_at),
    );

    let a_won = result_a.is_ok();
    let b_won = result_b.is_ok();
    assert!(
        a_won ^ b_won,
        "exactly one concurrent call should win, got a={a_won}, b={b_won}"
    );
    // The loser must report AlreadyConsumed (not a database error).
    for r in [result_a, result_b] {
        if let Err(e) = r {
            assert!(
                matches!(e, ClaimError::AlreadyConsumed),
                "loser must be AlreadyConsumed, got: {e:?}"
            );
        }
    }
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
            post_logout_redirect_uris: None,
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
            post_logout_redirect_uris: None,
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
            post_logout_redirect_uris: None,
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

// ========================================================================
// OIDC state — atomic consume + concurrent-replay regression coverage
// ========================================================================

/// Seed a fresh OIDC state row tied to a fresh device-auth row.
async fn seed_oidc_state(
    store: &DocumentStore,
    state_value: &str,
    expires_at: jiff::Timestamp,
) -> String {
    let device_auth_id = create_device_auth_request(
        store,
        &format!("device_hash_for_{state_value}"),
        &format!("UC-{state_value}"),
        None,
        expires_at,
        5,
    )
    .await
    .expect("create_device_auth_request");

    create_oidc_state(
        store,
        state_value,
        Some(&device_auth_id),
        "nonce-value",
        "",
        expires_at,
        "",
    )
    .await
    .expect("create_oidc_state");

    device_auth_id
}

#[tokio::test]
async fn test_oidc_state_consume_happy_path() {
    let (store, _audit) = test_db().await;
    let expires_at: jiff::Timestamp = "2099-12-31T23:59:59Z".parse().unwrap();
    let device_auth_id = seed_oidc_state(&store, "happy-state", expires_at).await;

    let (data, _claim) = try_consume_oidc_state(&store, "happy-state")
        .await
        .expect("first consume must succeed");

    assert_eq!(data.state, "happy-state");
    assert_eq!(
        data.device_auth_id.as_deref(),
        Some(device_auth_id.as_str())
    );
    assert_eq!(data.nonce, "nonce-value");
}

#[tokio::test]
async fn test_oidc_state_consume_replay_rejected() {
    use crate::db::claim::ClaimError;
    let (store, _audit) = test_db().await;
    let expires_at: jiff::Timestamp = "2099-12-31T23:59:59Z".parse().unwrap();
    seed_oidc_state(&store, "replay-state", expires_at).await;

    let _first = try_consume_oidc_state(&store, "replay-state")
        .await
        .expect("first consume must succeed");

    let replayed = try_consume_oidc_state(&store, "replay-state").await;
    assert!(
        matches!(replayed, Err(ClaimError::AlreadyConsumed)),
        "second consume must be rejected as AlreadyConsumed, got: {replayed:?}"
    );
}

#[tokio::test]
async fn test_oidc_state_consume_expired_rejected() {
    use crate::db::claim::ClaimError;
    let (store, _audit) = test_db().await;
    // Past expiry.
    let expires_at: jiff::Timestamp = "2000-01-01T00:00:00Z".parse().unwrap();
    seed_oidc_state(&store, "expired-state", expires_at).await;

    let result = try_consume_oidc_state(&store, "expired-state").await;
    assert!(
        matches!(result, Err(ClaimError::AlreadyConsumed)),
        "expired state must be reported as AlreadyConsumed (indistinguishable \
         from replay so the caller cannot probe state existence): got {result:?}"
    );
}

#[tokio::test]
async fn test_oidc_state_consume_not_found_rejected() {
    use crate::db::claim::ClaimError;
    let (store, _audit) = test_db().await;

    let result = try_consume_oidc_state(&store, "never-existed").await;
    assert!(
        matches!(result, Err(ClaimError::AlreadyConsumed)),
        "missing state must be reported as AlreadyConsumed: got {result:?}"
    );
}

#[tokio::test]
async fn test_oidc_state_consume_concurrent() {
    use crate::db::claim::ClaimError;
    let (store, _audit) = test_db().await;
    let expires_at: jiff::Timestamp = "2099-12-31T23:59:59Z".parse().unwrap();
    seed_oidc_state(&store, "race-state", expires_at).await;

    let store_a = store.clone();
    let store_b = store.clone();
    let (result_a, result_b) = tokio::join!(
        try_consume_oidc_state(&store_a, "race-state"),
        try_consume_oidc_state(&store_b, "race-state"),
    );

    let a_won = result_a.is_ok();
    let b_won = result_b.is_ok();
    assert!(
        a_won ^ b_won,
        "exactly one concurrent consume must win, got a={a_won}, b={b_won}"
    );
    for r in [result_a, result_b] {
        if let Err(e) = r {
            assert!(
                matches!(e, ClaimError::AlreadyConsumed),
                "loser must be AlreadyConsumed (not Database), got: {e:?}"
            );
        }
    }
}

// ========================================================================
// Concurrent-replay regression coverage for single-use primitives:
// `tokio::join` two consume calls, assert exactly one wins and the loser
// is AlreadyConsumed. SQLite-only; the underlying OCC patterns are
// race-safe by construction on the other backends as well, but these
// tests guard against accidental regressions in the helper functions
// themselves.
// ========================================================================

#[tokio::test]
async fn test_authorization_code_consume_concurrent() {
    use crate::db::claim::ClaimError;
    let (store, _audit) = test_db().await;

    let expires_at: jiff::Timestamp = "2099-12-31T23:59:59Z".parse().unwrap();
    store_authorization_code(
        &store,
        "race-code-hash",
        "client-race",
        "user-race",
        expires_at,
        None,
    )
    .await
    .expect("seed authorization code");

    let store_a = store.clone();
    let store_b = store.clone();
    let (result_a, result_b) = tokio::join!(
        try_consume_authorization_code(&store_a, "race-code-hash"),
        try_consume_authorization_code(&store_b, "race-code-hash"),
    );

    let a_won = result_a.is_ok();
    let b_won = result_b.is_ok();
    assert!(
        a_won ^ b_won,
        "exactly one auth-code consume must win, got a={a_won}, b={b_won}"
    );
    for r in [result_a, result_b] {
        if let Err(e) = r {
            assert!(
                matches!(e, ClaimError::AlreadyConsumed),
                "loser must be AlreadyConsumed, got: {e:?}"
            );
        }
    }
}

#[tokio::test]
async fn test_device_auth_consume_concurrent() {
    use crate::db::claim::ClaimError;
    let (store, _audit) = test_db().await;

    let expires_at: jiff::Timestamp = "2099-12-31T23:59:59Z".parse().unwrap();
    let device_code_hash = "race-device-hash";
    let id = create_device_auth_request(&store, device_code_hash, "RACE-DC", None, expires_at, 5)
        .await
        .expect("create device auth");
    let (user_id, _) = upsert_user(&store, "race-device@example.com", Some("Test"))
        .await
        .expect("upsert user");
    let auth_id = create_authenticator(
        &store,
        &CreateAuthenticatorParams {
            user_id: &user_id,
            user_email: "race-device@example.com",
            name: "Key",
            credential_id: b"cred-race-device",
            public_key: &[0u8; 32],
            aaguid: None,
            user_handle: None,
            attestation_verified: false,
        },
    )
    .await
    .expect("create authenticator");
    authorize_device_auth(&store, &id, &user_id, "race-device@example.com", &auth_id)
        .await
        .expect("authorize");

    let store_a = store.clone();
    let store_b = store.clone();
    let (result_a, result_b) = tokio::join!(
        try_consume_device_auth(&store_a, device_code_hash),
        try_consume_device_auth(&store_b, device_code_hash),
    );

    let a_won = result_a.is_ok();
    let b_won = result_b.is_ok();
    assert!(
        a_won ^ b_won,
        "exactly one device-auth consume must win, got a={a_won}, b={b_won}"
    );
    for r in [result_a, result_b] {
        if let Err(e) = r {
            assert!(
                matches!(e, ClaimError::AlreadyConsumed),
                "loser must be AlreadyConsumed, got: {e:?}"
            );
        }
    }
}

#[tokio::test]
async fn test_dpop_nonce_consume_concurrent() {
    use crate::db::claim::ClaimError;
    let (store, _audit) = test_db().await;

    // Seed a fresh nonce; the function returns the nonce string.
    let nonce = generate_dpop_nonce(&store, 300)
        .await
        .expect("generate_dpop_nonce");

    let store_a = store.clone();
    let store_b = store.clone();
    let nonce_a = nonce.clone();
    let nonce_b = nonce.clone();
    let (result_a, result_b) = tokio::join!(
        async move { validate_and_consume_dpop_nonce(&store_a, &nonce_a).await },
        async move { validate_and_consume_dpop_nonce(&store_b, &nonce_b).await },
    );

    let a_won = result_a.is_ok();
    let b_won = result_b.is_ok();
    assert!(
        a_won ^ b_won,
        "exactly one DPoP-nonce consume must win, got a={a_won}, b={b_won}"
    );
    for r in [result_a, result_b] {
        if let Err(e) = r {
            assert!(
                matches!(e, ClaimError::AlreadyConsumed),
                "loser must be AlreadyConsumed, got: {e:?}"
            );
        }
    }
}

#[tokio::test]
async fn test_pending_oauth_consume_concurrent() {
    use crate::db::claim::ClaimError;
    let (store, _audit) = test_db().await;

    let id = create_pending_oauth_authorization(
        &store,
        CreatePendingOAuthParams {
            client_id: "race-pending-client",
            redirect_uri: "https://example.com/cb",
            response_type: "code",
            state: None,
            scope: Some("openid"),
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            resource: None,
            acr_values: None,
            max_age: None,
            prompt: None,
            dpop_jkt: None,
            authorization_details: None,
            response_mode: Default::default(),
            par_request_uri: None,
        },
    )
    .await
    .expect("create pending_oauth");

    let store_a = store.clone();
    let store_b = store.clone();
    let id_a = id.clone();
    let id_b = id.clone();
    let (result_a, result_b) = tokio::join!(
        async move { consume_pending_oauth_authorization(&store_a, &id_a).await },
        async move { consume_pending_oauth_authorization(&store_b, &id_b).await },
    );

    let a_won = result_a.is_ok();
    let b_won = result_b.is_ok();
    assert!(
        a_won ^ b_won,
        "exactly one pending_oauth consume must win, got a={a_won}, b={b_won}"
    );
    for r in [result_a, result_b] {
        if let Err(e) = r {
            assert!(
                matches!(e, ClaimError::AlreadyConsumed),
                "loser must be AlreadyConsumed, got: {e:?}"
            );
        }
    }
}

// ============================================================================
// Concurrent CAS regression tests for state-transition helpers
// (non-consume helpers that share the same outer-tx + read + compare_and_update
// pattern — included to empirically confirm whether each site exhibits the
// SQLite shared-cache deadlock or not).
// ============================================================================

#[tokio::test]
async fn test_authorize_device_auth_concurrent() {
    let (store, _audit) = test_db().await;

    let expires_at: jiff::Timestamp = "2099-12-31T23:59:59Z".parse().unwrap();
    let device_code_hash = "race-authorize-hash";
    let id = create_device_auth_request(&store, device_code_hash, "RACE-AUTH", None, expires_at, 5)
        .await
        .expect("create device auth");
    let (user_id, _) = upsert_user(&store, "race-authorize@example.com", Some("Test"))
        .await
        .expect("upsert user");
    let auth_id = create_authenticator(
        &store,
        &CreateAuthenticatorParams {
            user_id: &user_id,
            user_email: "race-authorize@example.com",
            name: "Key",
            credential_id: b"cred-race-authorize",
            public_key: &[0u8; 32],
            aaguid: None,
            user_handle: None,
            attestation_verified: false,
        },
    )
    .await
    .expect("create authenticator");

    let store_a = store.clone();
    let store_b = store.clone();
    let id_a = id.clone();
    let id_b = id.clone();
    let uid_a = user_id.clone();
    let uid_b = user_id.clone();
    let aid_a = auth_id.clone();
    let aid_b = auth_id.clone();
    let (result_a, result_b) = tokio::join!(
        async move {
            authorize_device_auth(
                &store_a,
                &id_a,
                &uid_a,
                "race-authorize@example.com",
                &aid_a,
            )
            .await
        },
        async move {
            authorize_device_auth(
                &store_b,
                &id_b,
                &uid_b,
                "race-authorize@example.com",
                &aid_b,
            )
            .await
        },
    );

    for (label, r) in [("a", &result_a), ("b", &result_b)] {
        if let Err(e) = r {
            let msg = format!("{e:#}");
            assert!(
                !msg.contains("deadlock"),
                "task {label} should not fail with a DB deadlock: {msg}"
            );
        }
    }
    let a_won = result_a.is_ok();
    let b_won = result_b.is_ok();
    assert!(
        a_won ^ b_won,
        "exactly one authorize must win, got a={a_won}, b={b_won}"
    );
}

#[tokio::test]
async fn test_deny_device_auth_concurrent() {
    let (store, _audit) = test_db().await;

    let expires_at: jiff::Timestamp = "2099-12-31T23:59:59Z".parse().unwrap();
    let device_code_hash = "race-deny-hash";
    let id = create_device_auth_request(&store, device_code_hash, "RACE-DENY", None, expires_at, 5)
        .await
        .expect("create device auth");

    let store_a = store.clone();
    let store_b = store.clone();
    let id_a = id.clone();
    let id_b = id.clone();
    let (result_a, result_b) = tokio::join!(
        async move { deny_device_auth(&store_a, &id_a).await },
        async move { deny_device_auth(&store_b, &id_b).await },
    );

    for (label, r) in [("a", &result_a), ("b", &result_b)] {
        if let Err(e) = r {
            let msg = format!("{e:#}");
            assert!(
                !msg.contains("deadlock"),
                "task {label} should not fail with a DB deadlock: {msg}"
            );
        }
    }
    let a_won = result_a.is_ok();
    let b_won = result_b.is_ok();
    assert!(
        a_won ^ b_won,
        "exactly one deny must win, got a={a_won}, b={b_won}"
    );
}

#[tokio::test]
async fn test_remove_additional_domain_concurrent() {
    use crate::db::organizations::{
        add_additional_domain, mark_additional_domain_verified, remove_additional_domain,
    };

    let (store, _audit) = test_db().await;
    let org = create_organization(&store, "race-remove.com", Some("Race Org"), None)
        .await
        .expect("create org");
    let (uid, _) = upsert_user(&store, "race-remove-admin@race-remove.com", Some("Admin"))
        .await
        .expect("upsert admin");
    add_additional_domain(
        &store,
        &org.id,
        "extra-remove.com",
        &uid,
        "race-remove-admin@race-remove.com",
    )
    .await
    .expect("add additional domain");
    mark_additional_domain_verified(&store, &org.id, "extra-remove.com")
        .await
        .expect("verify additional domain");

    let store_a = store.clone();
    let store_b = store.clone();
    let org_a = org.id.clone();
    let org_b = org.id.clone();
    let (result_a, result_b) = tokio::join!(
        async move { remove_additional_domain(&store_a, &org_a, "extra-remove.com").await },
        async move { remove_additional_domain(&store_b, &org_b, "extra-remove.com").await },
    );

    for (label, r) in [("a", &result_a), ("b", &result_b)] {
        if let Err(e) = r {
            let msg = format!("{e:#}");
            assert!(
                !msg.contains("deadlock"),
                "task {label} should not fail with a DB deadlock: {msg}"
            );
        }
    }
    let some_count = [&result_a, &result_b]
        .iter()
        .filter(|r| matches!(r, Ok(Some(_))))
        .count();
    assert!(
        some_count == 1,
        "exactly one remove must return Ok(Some), got a={result_a:?}, b={result_b:?}"
    );
}

#[tokio::test]
async fn test_record_recheck_result_concurrent() {
    use crate::db::organizations::{
        RecheckOutcome, add_additional_domain, mark_additional_domain_verified,
        record_recheck_result,
    };

    let (store, _audit) = test_db().await;
    let org = create_organization(&store, "race-recheck.com", Some("Race Org"), None)
        .await
        .expect("create org");
    let (uid, _) = upsert_user(&store, "race-recheck-admin@race-recheck.com", Some("Admin"))
        .await
        .expect("upsert admin");
    add_additional_domain(
        &store,
        &org.id,
        "extra-recheck.com",
        &uid,
        "race-recheck-admin@race-recheck.com",
    )
    .await
    .expect("add additional domain");
    mark_additional_domain_verified(&store, &org.id, "extra-recheck.com")
        .await
        .expect("verify additional domain");

    let store_a = store.clone();
    let store_b = store.clone();
    let org_a = org.id.clone();
    let org_b = org.id.clone();
    let (result_a, result_b) = tokio::join!(
        async move {
            record_recheck_result(
                &store_a,
                &org_a,
                "extra-recheck.com",
                RecheckOutcome::Success,
            )
            .await
        },
        async move {
            record_recheck_result(
                &store_b,
                &org_b,
                "extra-recheck.com",
                RecheckOutcome::Success,
            )
            .await
        },
    );

    for (label, r) in [("a", &result_a), ("b", &result_b)] {
        if let Err(e) = r {
            let msg = format!("{e:#}");
            assert!(
                !msg.contains("deadlock"),
                "task {label} should not fail with a DB deadlock: {msg}"
            );
        }
    }
    assert!(
        result_a.is_ok() && result_b.is_ok(),
        "both record_recheck_result calls must succeed (CAS loser returns Ok(StillVerified))"
    );
}

// Regression for #389: two enrollments for the same domain must converge
// on a single organization. `enroll_user_with_org` derives a deterministic
// org ID from the domain, so concurrent enrollees collide on the same
// primary key instead of inserting distinct orgs.
//
// This test exercises the "second enrollee converges on first's org"
// property sequentially because multi-step transactions on SQLite WAL
// deadlock under real `tokio::join!` contention; the under-contention
// property is guaranteed by `store.insert_with_id`'s atomic primary-key
// behavior (covered by `test_dpop_jti_concurrent_insert_rejects_duplicates`)
// combined with the deterministic ID.
#[tokio::test]
async fn test_enroll_user_with_org_same_domain_converges_on_one_org() {
    use crate::db::documents::organization::OrganizationDoc;
    use crate::db::enroll_user_with_org;

    let (store, _audit) = test_db().await;
    let domain = "shared-domain.example";

    let alice = enroll_user_with_org(&store, "alice@shared-domain.example", None, Some(domain))
        .await
        .expect("alice enrollment");
    let bob = enroll_user_with_org(&store, "bob@shared-domain.example", None, Some(domain))
        .await
        .expect("bob enrollment");

    assert_eq!(
        alice.org_id, bob.org_id,
        "both enrollees must share the same org_id"
    );
    assert!(alice.org_id.is_some());

    let org_count = store
        .count::<OrganizationDoc>("domain", domain)
        .await
        .expect("count orgs by domain");
    assert_eq!(
        org_count, 1,
        "exactly one organization must exist for the domain; got {org_count}"
    );

    assert!(alice.is_org_admin, "first enrollee should be admin");
    assert!(!bob.is_org_admin, "second enrollee must not be admin");
}

// Enrolling into an existing org that has no admin must promote the
// enrollee to admin — this exercises the `compare_and_update` repair
// path in `enroll_user_with_org`.
#[tokio::test]
async fn test_enroll_promotes_admin_for_org_without_one() {
    use crate::db::documents::organization::OrganizationDoc;
    use crate::db::enroll_user_with_org;

    let (store, _audit) = test_db().await;
    let domain = "orphaned-org.example";

    // Seed an org row with no admin (e.g. previous enrollee crashed
    // mid-flow before Step 4 ran).
    let seed_doc = OrganizationDoc {
        domain: domain.to_string(),
        name: None,
        created_by_user_id: None,
        additional_domains: Vec::new(),
        subdomain: None,
    };
    store.insert(&seed_doc).await.expect("seed org row");

    let user = enroll_user_with_org(&store, "rescuer@orphaned-org.example", None, Some(domain))
        .await
        .expect("enrollment");

    assert!(
        user.is_org_admin,
        "an org with no admin must promote the next enrollee"
    );

    // The promotion must be persisted on the user doc, not just reported in
    // the return value — authorization reads `UserDoc.is_org_admin`.
    let persisted = store
        .find_one::<crate::db::documents::user::UserDoc>("email", "rescuer@orphaned-org.example")
        .await
        .expect("find enrolled user")
        .expect("enrolled user exists");
    assert!(persisted.data.is_org_admin);

    let org_count = store
        .count::<OrganizationDoc>("domain", domain)
        .await
        .expect("count orgs by domain");
    assert_eq!(
        org_count, 1,
        "no duplicate org may be created when one already exists"
    );
}

// Regression for #742: a user who already belongs to one org must not claim
// a different org's admin slot by enrolling through that org's domain. The
// slot has to stay open for that org's own first enrollee.
#[tokio::test]
async fn test_enroll_cross_org_user_does_not_claim_admin_slot() {
    use crate::db::documents::organization::OrganizationDoc;
    use crate::db::enroll_user_with_org;

    let (store, _audit) = test_db().await;
    let domain_a = "org-a.example";
    let domain_b = "org-b.example";

    // Alice belongs to org A, and is its admin.
    let alice = enroll_user_with_org(&store, "alice@org-a.example", None, Some(domain_a))
        .await
        .expect("alice enrollment");
    let org_a = alice.org_id.clone().expect("org a id");
    assert!(alice.is_org_admin, "alice is org A's first enrollee");

    // Alice now enrolls through org B's domain. Her user row keeps org A, so
    // she is not a member of B and must not take B's admin slot.
    let alice_again = enroll_user_with_org(&store, "alice@org-a.example", None, Some(domain_b))
        .await
        .expect("alice cross-org enrollment");
    assert_eq!(
        alice_again.org_id,
        Some(org_a),
        "enrolling via another domain must not move an existing user's org"
    );

    let org_b_doc = store
        .find_one::<OrganizationDoc>("domain", domain_b)
        .await
        .expect("find org b")
        .expect("org b exists");
    assert_eq!(
        org_b_doc.data.created_by_user_id, None,
        "a non-member must leave org B's admin slot unclaimed"
    );

    // ...and org B's own first enrollee still gets promoted.
    let bob = enroll_user_with_org(&store, "bob@org-b.example", None, Some(domain_b))
        .await
        .expect("bob enrollment");
    assert!(
        bob.is_org_admin,
        "org B's first genuine enrollee must still become admin"
    );

    let org_b_doc = store
        .find_one::<OrganizationDoc>("domain", domain_b)
        .await
        .expect("find org b")
        .expect("org b exists");
    assert_eq!(
        org_b_doc.data.created_by_user_id,
        Some(bob.id),
        "org B's admin slot must record its own first enrollee"
    );
}

// A retrying CAS loser must re-derive its admin decision from fresh state:
// with the winner's user row committed and the org's created_by_user_id
// still unset (the state a loser observes when it re-runs after aborting
// on the org-row conflict), the second enrollee must come out non-admin.
#[tokio::test]
async fn test_enroll_second_user_after_winner_commit_is_not_admin() {
    use crate::db::documents::organization::OrganizationDoc;
    use crate::db::enroll_user_with_org;

    let (store, _audit) = test_db().await;
    let domain = "retry-loser.example";

    let winner = enroll_user_with_org(&store, "winner@retry-loser.example", None, Some(domain))
        .await
        .expect("winner enrollment");
    assert!(winner.is_org_admin);

    // Simulate the winner having committed its user row but NOT yet the org
    // admin slot (crash between the two would leave this state; a retrying
    // loser sees it after aborting on the org-row conflict).
    let org_id = winner.org_id.expect("org id");
    let org = store
        .get::<OrganizationDoc>(&org_id)
        .await
        .expect("get org")
        .expect("org exists");
    let mut data = org.data;
    data.created_by_user_id = None;
    store
        .update(&org_id, &data)
        .await
        .expect("clear admin slot");

    let loser = enroll_user_with_org(&store, "loser@retry-loser.example", None, Some(domain))
        .await
        .expect("second enrollment");
    assert!(
        !loser.is_org_admin,
        "an enrollee joining an org that already has users must not become admin"
    );
}

// ========================================================================
// OCC read-modify-write conversions: blind get+update → store.modify()
// ========================================================================

// ---- update_authenticator_name ----

/// After `update_authenticator_name`, only the `name` field changes; the
/// `credential_id`, `counter`, and other fields are untouched, and the
/// document version is incremented.
#[tokio::test]
async fn test_update_authenticator_name_only_name_changes() {
    use crate::db::documents::authenticator::AuthenticatorDoc;

    let (store, _audit) = test_db().await;

    let (user_id, _) = upsert_user(&store, "rename@example.com", None)
        .await
        .expect("upsert user");

    let auth_id = create_authenticator(
        &store,
        &CreateAuthenticatorParams {
            user_id: &user_id,
            user_email: "rename@example.com",
            name: "OldName",
            credential_id: b"cred-rename",
            public_key: &[1u8; 32],
            aaguid: Some("aaguid-rename"),
            user_handle: None,
            attestation_verified: true,
        },
    )
    .await
    .expect("create authenticator");

    let before = store
        .get::<AuthenticatorDoc>(&auth_id)
        .await
        .expect("get before")
        .expect("must exist");
    let version_before = before.version;

    let found = update_authenticator_name(&store, &auth_id, "NewName")
        .await
        .expect("update name");
    assert!(found, "update must report found=true");

    let after = store
        .get::<AuthenticatorDoc>(&auth_id)
        .await
        .expect("get after")
        .expect("must exist");

    assert_eq!(after.data.name, "NewName", "name must be updated");
    assert_eq!(
        after.data.credential_id, before.data.credential_id,
        "credential_id must be unchanged"
    );
    assert_eq!(
        after.data.counter, before.data.counter,
        "counter must be unchanged"
    );
    assert_eq!(
        after.data.aaguid, before.data.aaguid,
        "aaguid must be unchanged"
    );
    assert!(
        after.version > version_before,
        "document version must increment after update"
    );
}

/// `update_authenticator_name` on a non-existent authenticator returns `Ok(false)`.
#[tokio::test]
async fn test_update_authenticator_name_not_found() {
    let (store, _audit) = test_db().await;
    let found = update_authenticator_name(&store, "does-not-exist", "AnyName")
        .await
        .expect("query must not error");
    assert!(!found, "missing authenticator must return false");
}

// ---- suspend/unsuspend/update_github_installation_repos ----

/// Helper: create a minimal GitHub installation for tests.
async fn create_test_github_installation(
    store: &DocumentStore,
    installation_id: i64,
    org_id: &str,
) -> String {
    create_github_installation(
        store,
        &CreateGitHubInstallationParams {
            org_id,
            installation_id,
            github_account_login: "test-account",
            github_account_type: "Organization",
            permissions: &std::collections::HashMap::new(),
            repository_selection: "all",
            installed_by_user_id: None,
        },
    )
    .await
    .expect("create_github_installation")
}

/// After `suspend_github_installation`, only `suspended_at` is set; other fields
/// are unchanged and the document version increments.
#[tokio::test]
async fn test_suspend_github_installation_only_suspended_at_changes() {
    use crate::db::documents::github::GitHubInstallationDoc;

    let (store, _audit) = test_db().await;
    let doc_id = create_test_github_installation(&store, 10_001, "org-suspend").await;

    let before = store
        .get::<GitHubInstallationDoc>(&doc_id)
        .await
        .expect("get before")
        .expect("must exist");
    assert!(
        before.data.suspended_at.is_none(),
        "fresh installation must not be suspended"
    );
    let version_before = before.version;

    let found = suspend_github_installation(&store, 10_001)
        .await
        .expect("suspend");
    assert!(found, "suspend must return true");

    let after = store
        .get::<GitHubInstallationDoc>(&doc_id)
        .await
        .expect("get after")
        .expect("must exist");
    assert!(
        after.data.suspended_at.is_some(),
        "suspended_at must be set after suspend"
    );
    assert_eq!(
        after.data.installation_id, before.data.installation_id,
        "installation_id must be unchanged"
    );
    assert_eq!(
        after.data.org_id, before.data.org_id,
        "org_id must be unchanged"
    );
    assert!(
        after.version > version_before,
        "document version must increment after suspend"
    );
}

/// After `unsuspend_github_installation`, `suspended_at` is cleared; version increments.
#[tokio::test]
async fn test_unsuspend_github_installation_only_suspended_at_changes() {
    use crate::db::documents::github::GitHubInstallationDoc;

    let (store, _audit) = test_db().await;
    let doc_id = create_test_github_installation(&store, 10_002, "org-unsuspend").await;

    // First suspend, then unsuspend.
    suspend_github_installation(&store, 10_002)
        .await
        .expect("suspend");

    let before = store
        .get::<GitHubInstallationDoc>(&doc_id)
        .await
        .expect("get before unsuspend")
        .expect("must exist");
    let version_before = before.version;

    let found = unsuspend_github_installation(&store, 10_002)
        .await
        .expect("unsuspend");
    assert!(found, "unsuspend must return true");

    let after = store
        .get::<GitHubInstallationDoc>(&doc_id)
        .await
        .expect("get after unsuspend")
        .expect("must exist");
    assert!(
        after.data.suspended_at.is_none(),
        "suspended_at must be cleared after unsuspend"
    );
    assert_eq!(
        after.data.installation_id, before.data.installation_id,
        "installation_id must be unchanged"
    );
    assert!(
        after.version > version_before,
        "document version must increment after unsuspend"
    );
}

/// After `update_github_installation_repos`, only `repositories` changes; version increments.
#[tokio::test]
async fn test_update_github_installation_repos_only_repos_change() {
    use crate::db::documents::github::GitHubInstallationDoc;

    let (store, _audit) = test_db().await;
    let doc_id = create_test_github_installation(&store, 10_003, "org-repos").await;

    let repos = vec!["owner/repo-a".to_string(), "owner/repo-b".to_string()];

    let before = store
        .get::<GitHubInstallationDoc>(&doc_id)
        .await
        .expect("get before")
        .expect("must exist");
    let version_before = before.version;

    let found = update_github_installation_repos(&store, 10_003, &repos)
        .await
        .expect("update repos");
    assert!(found, "update must return true");

    let after = store
        .get::<GitHubInstallationDoc>(&doc_id)
        .await
        .expect("get after")
        .expect("must exist");
    assert_eq!(
        after.data.repositories.as_deref(),
        Some(repos.as_slice()),
        "repositories must be updated"
    );
    assert_eq!(
        after.data.suspended_at, before.data.suspended_at,
        "suspended_at must be unchanged"
    );
    assert!(
        after.version > version_before,
        "document version must increment after repo update"
    );
}

/// Concurrent suspend+unsuspend on the same installation converge without lost updates.
/// At least one write must win and be reflected in the final state.
#[tokio::test]
async fn test_github_installation_concurrent_suspend_unsuspend_no_lost_update() {
    let (store, _audit) = test_db().await;
    create_test_github_installation(&store, 20_001, "org-concurrent-suspend").await;

    let store_a = store.clone();
    let store_b = store.clone();
    let handles: Vec<_> = [
        tokio::spawn(async move { suspend_github_installation(&store_a, 20_001).await }),
        tokio::spawn(async move { unsuspend_github_installation(&store_b, 20_001).await }),
    ]
    .into_iter()
    .collect();

    for h in handles {
        h.await
            .expect("task must not panic")
            .expect("operation must succeed");
    }

    // Smoke check: both concurrent writes complete without error, and the
    // record still exists with both increments applied (version ≥ 2). This does
    // not by itself distinguish OCC from a blind `store.update` — the blind path
    // also bumps the version unconditionally — so it only proves concurrent
    // access doesn't error or corrupt. The lost-update regression (a sibling
    // field being clobbered) is caught by the `*_only_*_changes` tests above.
    use crate::db::documents::github::GitHubInstallationDoc;
    let doc_after = store
        .get::<GitHubInstallationDoc>(&{
            let d = store
                .find_one::<GitHubInstallationDoc>("installation_id", "20001")
                .await
                .expect("find_one")
                .expect("must exist after concurrent writes");
            d.id
        })
        .await
        .expect("get after concurrent writes")
        .expect("installation must still exist after concurrent suspend/unsuspend");
    assert!(
        doc_after.version >= 2,
        "both concurrent writes must land (version ≥2); got version {}",
        doc_after.version
    );
}

/// Two concurrent delta updates with disjoint adds must both land: the merge
/// runs inside the `modify` closure, so an OCC retry re-reads fresh state and
/// re-applies the delta instead of losing the other webhook's update.
#[tokio::test]
async fn test_update_github_installation_repos_delta_concurrent_deltas_both_land() {
    let (store, _audit) = test_db().await;
    create_test_github_installation(&store, 20_002, "org-concurrent-delta").await;
    let seeded = update_github_installation_repos(&store, 20_002, &["seed".to_string()])
        .await
        .expect("seed repos");
    assert!(seeded, "seeding must find the installation");

    let store_a = store.clone();
    let store_b = store.clone();
    let add_a = vec!["alpha".to_string()];
    let add_b = vec!["bravo".to_string()];
    let (a, b) = tokio::join!(
        update_github_installation_repos_delta(&store_a, 20_002, &add_a, &[]),
        update_github_installation_repos_delta(&store_b, 20_002, &add_b, &[]),
    );
    assert!(
        a.expect("delta a must not error"),
        "delta a must find the installation"
    );
    assert!(
        b.expect("delta b must not error"),
        "delta b must find the installation"
    );

    let after = get_github_installation_by_installation_id(&store, 20_002)
        .await
        .expect("lookup after concurrent deltas")
        .expect("installation must still exist");
    assert_eq!(
        after.repositories.as_deref(),
        Some(&["alpha".to_string(), "bravo".to_string(), "seed".to_string()][..]),
        "both concurrent deltas must land (no lost update)"
    );
}

/// Deterministic companion to the concurrent-delta test above (whose
/// `tokio::join!` contention depends on scheduling): the modify test seam
/// applies a second delta inside the OCC window, guaranteeing the retry path
/// runs and asserting the retried merge re-reads the fresh repo list.
#[tokio::test]
async fn test_update_github_installation_repos_delta_occ_retry_merges_fresh_state() {
    let (store, _audit) = test_db().await;
    create_test_github_installation(&store, 20_004, "org-delta-seam").await;
    let seeded = update_github_installation_repos(&store, 20_004, &["seed".to_string()])
        .await
        .expect("seed repos");
    assert!(seeded, "seeding must find the installation");

    let writer = store.clone();
    let mut hooked = store.clone();
    hooked.set_modify_test_hook(Arc::new(move |_doc_id: &str, attempt: u32| {
        let writer = writer.clone();
        Box::pin(async move {
            if attempt != 0 {
                return;
            }
            let bravo = vec!["bravo".to_string()];
            let found = update_github_installation_repos_delta(&writer, 20_004, &bravo, &[])
                .await
                .expect("hook delta must not error");
            assert!(found, "hook delta must find the installation");
        })
    }));

    let alpha = vec!["alpha".to_string()];
    let found = update_github_installation_repos_delta(&hooked, 20_004, &alpha, &[])
        .await
        .expect("delta must not error");
    assert!(found, "delta must find the installation");

    let after = get_github_installation_by_installation_id(&store, 20_004)
        .await
        .expect("lookup after deltas")
        .expect("installation must still exist");
    assert_eq!(
        after.repositories.as_deref(),
        Some(&["alpha".to_string(), "bravo".to_string(), "seed".to_string()][..]),
        "the delta applied inside the OCC window must survive the retried merge"
    );
}

/// If an installation is deleted between the index-resolve and the `modify` call
/// (race with an uninstall webhook), `modify` returns `Ok(false)` rather than
/// updating a stale document.
#[tokio::test]
async fn test_github_installation_deleted_between_resolve_and_modify() {
    // This test exercises the edge case described in the plan: the resolve step
    // maps installation_id → doc.id, then the doc is deleted before `modify`
    // runs. `modify` re-reads by id, finds nothing, and returns Ok(false).
    let (store, _audit) = test_db().await;
    create_test_github_installation(&store, 30_001, "org-delete-race").await;

    // Step 1: resolve the doc_id (simulates what suspend_github_installation does).
    let doc = store
        .find_one::<crate::db::documents::github::GitHubInstallationDoc>("installation_id", "30001")
        .await
        .expect("find_one")
        .expect("must exist after create");
    let doc_id = doc.id.clone();

    // Step 2: delete the installation (simulates a concurrent uninstall webhook).
    delete_github_installation_by_installation_id(&store, 30_001)
        .await
        .expect("delete");

    // Step 3: call modify directly on the now-deleted id — must return Ok(false).
    let found = store
        .modify::<crate::db::documents::github::GitHubInstallationDoc, _>(&doc_id, |data| {
            data.suspended_at = Some(jiff::Timestamp::now());
        })
        .await
        .expect("modify must not error");
    assert!(!found, "modify on deleted doc must return Ok(false)");
}

// ---- update_scim_group ----

/// After `update_scim_group`, only the updated fields change and version increments.
#[tokio::test]
async fn test_update_scim_group_only_intended_fields_change() {
    use crate::db::documents::scim::ScimGroupDoc;

    let (store, _audit) = test_db().await;

    let group = create_scim_group(&store, TEST_ORG_ID, "OriginalName", Some("ext-123"))
        .await
        .expect("create_scim_group");

    let before = store
        .get::<ScimGroupDoc>(&group.id)
        .await
        .expect("get before")
        .expect("must exist");
    let version_before = before.version;

    let found = update_scim_group(
        &store,
        &group.id,
        TEST_ORG_ID,
        Some("UpdatedName"),
        Some("ext-456"),
    )
    .await
    .expect("update_scim_group");
    assert!(found, "update must return true");

    let after = store
        .get::<ScimGroupDoc>(&group.id)
        .await
        .expect("get after")
        .expect("must exist");
    assert_eq!(after.data.display_name, "UpdatedName", "name must update");
    assert_eq!(
        after.data.external_id.as_deref(),
        Some("ext-456"),
        "external_id must update"
    );
    assert_eq!(
        after.data.org_id, before.data.org_id,
        "org_id must be unchanged"
    );
    assert!(
        after.version > version_before,
        "document version must increment"
    );
}

/// `update_scim_group` with a wrong `org_id` returns `Ok(false)` without modifying the doc.
#[tokio::test]
async fn test_update_scim_group_wrong_org_returns_false() {
    let (store, _audit) = test_db().await;

    let group = create_scim_group(&store, TEST_ORG_ID, "GroupToProtect", None)
        .await
        .expect("create_scim_group");

    let found = update_scim_group(&store, &group.id, "wrong-org", Some("HackedName"), None)
        .await
        .expect("update_scim_group query must not error");
    assert!(!found, "cross-org update must return false");

    // Original name must be unchanged.
    let unchanged = get_scim_group(&store, &group.id, TEST_ORG_ID)
        .await
        .expect("get_scim_group")
        .expect("must exist");
    assert_eq!(
        unchanged.display_name, "GroupToProtect",
        "name must be unchanged after cross-org rejection"
    );
}

// ---- update_custom_policy ----

/// After `update_custom_policy`, only the updated fields change and version increments.
#[tokio::test]
async fn test_update_custom_policy_only_intended_fields_change() {
    use crate::db::documents::posture_policy::CustomPosturePolicyDoc;

    let (store, _audit) = test_db().await;

    let policy = create_custom_policy(
        &store,
        CreateCustomPolicyParams {
            name: "OriginalPolicy",
            description: Some("orig desc"),
            cel_expression: "true",
            org_id: "org-policy-test",
        },
    )
    .await
    .expect("create_custom_policy");

    let before = store
        .get::<CustomPosturePolicyDoc>(&policy.id)
        .await
        .expect("get before")
        .expect("must exist");
    let version_before = before.version;

    let updated = update_custom_policy(
        &store,
        &policy.id,
        "org-policy-test",
        UpdateCustomPolicyParams {
            name: Some("UpdatedPolicy"),
            description: FieldUpdate::Set("new desc"),
            cel_expression: Some("false"),
            active: Some(true),
        },
    )
    .await
    .expect("update_custom_policy")
    .expect("must return updated record");

    assert_eq!(updated.name, "UpdatedPolicy", "name must update");
    assert_eq!(
        updated.description.as_deref(),
        Some("new desc"),
        "description must update"
    );
    assert_eq!(
        updated.cel_expression, "false",
        "cel_expression must update"
    );
    assert!(updated.active, "active must be set to true");

    let after = store
        .get::<CustomPosturePolicyDoc>(&policy.id)
        .await
        .expect("get after")
        .expect("must exist");
    assert_eq!(
        after.data.org_id, before.data.org_id,
        "org_id must be unchanged"
    );
    assert!(
        after.version > version_before,
        "document version must increment"
    );
}

/// `FieldUpdate::Keep` leaves the description unchanged.
#[tokio::test]
async fn test_update_custom_policy_field_update_keep() {
    let (store, _audit) = test_db().await;

    let policy = create_custom_policy(
        &store,
        CreateCustomPolicyParams {
            name: "KeepDescPolicy",
            description: Some("original desc"),
            cel_expression: "true",
            org_id: "org-keep-test",
        },
    )
    .await
    .expect("create_custom_policy");

    let updated = update_custom_policy(
        &store,
        &policy.id,
        "org-keep-test",
        UpdateCustomPolicyParams {
            name: None,
            description: FieldUpdate::Keep,
            cel_expression: None,
            active: None,
        },
    )
    .await
    .expect("update_custom_policy")
    .expect("must return record");

    assert_eq!(
        updated.description.as_deref(),
        Some("original desc"),
        "Keep must leave description unchanged"
    );
}

/// `FieldUpdate::Clear` sets the description to None.
#[tokio::test]
async fn test_update_custom_policy_field_update_clear() {
    let (store, _audit) = test_db().await;

    let policy = create_custom_policy(
        &store,
        CreateCustomPolicyParams {
            name: "ClearDescPolicy",
            description: Some("will be cleared"),
            cel_expression: "true",
            org_id: "org-clear-test",
        },
    )
    .await
    .expect("create_custom_policy");

    let updated = update_custom_policy(
        &store,
        &policy.id,
        "org-clear-test",
        UpdateCustomPolicyParams {
            name: None,
            description: FieldUpdate::Clear,
            cel_expression: None,
            active: None,
        },
    )
    .await
    .expect("update_custom_policy")
    .expect("must return record");

    assert!(
        updated.description.is_none(),
        "Clear must set description to None"
    );
}

/// `update_custom_policy` with wrong `org_id` returns `Ok(None)`.
#[tokio::test]
async fn test_update_custom_policy_wrong_org_returns_none() {
    let (store, _audit) = test_db().await;

    let policy = create_custom_policy(
        &store,
        CreateCustomPolicyParams {
            name: "ProtectedPolicy",
            description: None,
            cel_expression: "true",
            org_id: "real-org",
        },
    )
    .await
    .expect("create_custom_policy");

    let result = update_custom_policy(
        &store,
        &policy.id,
        "wrong-org",
        UpdateCustomPolicyParams {
            name: Some("HackedName"),
            description: FieldUpdate::Keep,
            cel_expression: None,
            active: None,
        },
    )
    .await
    .expect("query must not error");
    assert!(result.is_none(), "cross-org update must return None");

    let unchanged = get_custom_policy(&store, &policy.id)
        .await
        .expect("get_custom_policy")
        .expect("must exist");
    assert_eq!(
        unchanged.name, "ProtectedPolicy",
        "name must be unchanged after cross-org rejection"
    );
}

/// `update_custom_policy` with an id that does not exist returns `None`.
///
/// The pre-check at the top of `update_custom_policy` fast-paths to `Ok(None)`
/// when `store.get` finds no document. This path is distinct from the wrong-org
/// rejection and needs its own coverage.
#[tokio::test]
async fn test_update_custom_policy_not_found_returns_none() {
    let (store, _audit) = test_db().await;

    let result = update_custom_policy(
        &store,
        "does-not-exist",
        TEST_ORG_ID,
        UpdateCustomPolicyParams {
            name: Some("Anything"),
            description: FieldUpdate::Keep,
            cel_expression: None,
            active: None,
        },
    )
    .await
    .expect("query must not error");
    assert!(result.is_none(), "absent policy id must return None");
}

// ---- OCC applied-flag reset (uses the `modify` test seam) ----

/// Regression: a concurrent org-ownership change landing between `modify`'s
/// internal read and its compare-and-update must be reported as not-applied.
/// Without the applied-flag reset at the top of each attempt, the stale
/// `applied = true` from the failed first attempt leaks a false success.
#[tokio::test]
async fn test_update_scim_user_concurrent_org_change_reports_not_applied() {
    use crate::db::documents::user::UserDoc;

    let (store, _audit) = test_db().await;
    let user = create_scim_user(
        &store,
        Some(TEST_ORG_ID),
        "occ-race@example.com",
        Some("Before"),
        None,
        true,
    )
    .await
    .expect("create_scim_user");

    // Hookless clone for the concurrent write: the hook must not re-enter
    // itself when it writes through the store.
    let writer = store.clone();
    let mut hooked = store.clone();
    hooked.set_modify_test_hook(Arc::new(move |doc_id: &str, attempt: u32| {
        let writer = writer.clone();
        let doc_id = doc_id.to_string();
        Box::pin(async move {
            if attempt != 0 {
                return;
            }
            // Concurrent writer: move the user to another org after modify's
            // read (stale version captured) but before its CAS, so the first
            // attempt loses the version race and the loop retries.
            let doc = writer
                .get::<UserDoc>(&doc_id)
                .await
                .expect("hook get")
                .expect("hook doc must exist");
            let mut data = doc.data;
            data.org_id = Some("other-org".to_string());
            writer.update(&doc_id, &data).await.expect("hook update");
        })
    }));

    let applied = update_scim_user(&hooked, &user.id, TEST_ORG_ID, Some("Hacked"), None, false)
        .await
        .expect("update_scim_user must not error");
    assert!(
        !applied,
        "org changed mid-flight: update must report not-applied"
    );

    let after = store
        .get::<UserDoc>(&user.id)
        .await
        .expect("get after")
        .expect("must exist");
    assert_eq!(
        after.data.org_id.as_deref(),
        Some("other-org"),
        "the concurrent org change must not be clobbered"
    );
    assert_eq!(
        after.data.name.as_deref(),
        Some("Before"),
        "the cross-org name mutation must not land"
    );
    assert!(after.data.active, "active must be unchanged");
}

/// Regression: same race as
/// [`test_update_scim_user_concurrent_org_change_reports_not_applied`],
/// for `update_scim_group`.
#[tokio::test]
async fn test_update_scim_group_concurrent_org_change_reports_not_applied() {
    use crate::db::documents::scim::ScimGroupDoc;

    let (store, _audit) = test_db().await;
    let group = create_scim_group(&store, TEST_ORG_ID, "GroupBefore", None)
        .await
        .expect("create_scim_group");

    let writer = store.clone();
    let mut hooked = store.clone();
    hooked.set_modify_test_hook(Arc::new(move |doc_id: &str, attempt: u32| {
        let writer = writer.clone();
        let doc_id = doc_id.to_string();
        Box::pin(async move {
            if attempt != 0 {
                return;
            }
            let doc = writer
                .get::<ScimGroupDoc>(&doc_id)
                .await
                .expect("hook get")
                .expect("hook doc must exist");
            let mut data = doc.data;
            data.org_id = "other-org".to_string();
            writer.update(&doc_id, &data).await.expect("hook update");
        })
    }));

    let applied = update_scim_group(&hooked, &group.id, TEST_ORG_ID, Some("Hacked"), None)
        .await
        .expect("update_scim_group must not error");
    assert!(
        !applied,
        "org changed mid-flight: update must report not-applied"
    );

    let after = store
        .get::<ScimGroupDoc>(&group.id)
        .await
        .expect("get after")
        .expect("must exist");
    assert_eq!(
        after.data.org_id, "other-org",
        "the concurrent org change must not be clobbered"
    );
    assert_eq!(
        after.data.display_name, "GroupBefore",
        "the cross-org name mutation must not land"
    );
}

/// Regression: same race as
/// [`test_update_scim_user_concurrent_org_change_reports_not_applied`],
/// for `update_custom_policy` (which reports not-applied as `None`).
#[tokio::test]
async fn test_update_custom_policy_concurrent_org_change_returns_none() {
    use crate::db::documents::posture_policy::CustomPosturePolicyDoc;

    let (store, _audit) = test_db().await;
    let policy = create_custom_policy(
        &store,
        CreateCustomPolicyParams {
            name: "PolicyBefore",
            description: None,
            cel_expression: "true",
            org_id: "org-occ-race",
        },
    )
    .await
    .expect("create_custom_policy");

    let writer = store.clone();
    let mut hooked = store.clone();
    hooked.set_modify_test_hook(Arc::new(move |doc_id: &str, attempt: u32| {
        let writer = writer.clone();
        let doc_id = doc_id.to_string();
        Box::pin(async move {
            if attempt != 0 {
                return;
            }
            let doc = writer
                .get::<CustomPosturePolicyDoc>(&doc_id)
                .await
                .expect("hook get")
                .expect("hook doc must exist");
            let mut data = doc.data;
            data.org_id = "other-org".to_string();
            writer.update(&doc_id, &data).await.expect("hook update");
        })
    }));

    let result = update_custom_policy(
        &hooked,
        &policy.id,
        "org-occ-race",
        UpdateCustomPolicyParams {
            name: Some("Hacked"),
            description: FieldUpdate::Keep,
            cel_expression: None,
            active: None,
        },
    )
    .await
    .expect("update_custom_policy must not error");
    assert!(
        result.is_none(),
        "org changed mid-flight: update must return None"
    );

    let after = store
        .get::<CustomPosturePolicyDoc>(&policy.id)
        .await
        .expect("get after")
        .expect("must exist");
    assert_eq!(
        after.data.org_id, "other-org",
        "the concurrent org change must not be clobbered"
    );
    assert_eq!(
        after.data.name, "PolicyBefore",
        "the cross-org name mutation must not land"
    );
}

/// `suspend_github_installation` with an `installation_id` that was never
/// created returns `Ok(false)`.
#[tokio::test]
async fn test_suspend_github_installation_not_found_returns_false() {
    let (store, _audit) = test_db().await;

    let found = suspend_github_installation(&store, 99_001)
        .await
        .expect("query must not error");
    assert!(
        !found,
        "missing installation must return false from suspend"
    );
}

/// `unsuspend_github_installation` with an `installation_id` that was never
/// created returns `Ok(false)`.
#[tokio::test]
async fn test_unsuspend_github_installation_not_found_returns_false() {
    let (store, _audit) = test_db().await;

    let found = unsuspend_github_installation(&store, 99_002)
        .await
        .expect("query must not error");
    assert!(
        !found,
        "missing installation must return false from unsuspend"
    );
}

/// `update_github_installation_repos` with an `installation_id` that was never
/// created returns `Ok(false)`.
#[tokio::test]
async fn test_update_github_installation_repos_not_found_returns_false() {
    let (store, _audit) = test_db().await;

    let found = update_github_installation_repos(&store, 99_003, &["owner/repo".to_string()])
        .await
        .expect("query must not error");
    assert!(
        !found,
        "missing installation must return false from update_repos"
    );
}

// ========================================================================
// Regression tests for DB concurrency fixes (#537, #545, #543)
// ========================================================================

/// #537 — A concurrent `update_user_github_identity` must NOT revert a
/// demotion performed by a concurrent `update_user_admin_status`.
///
/// Both paths go through `store.modify`, which re-reads the document at
/// write time, so a GitHub-identity update applied after a demotion must
/// preserve `is_org_admin = false` rather than writing back a stale
/// pre-demotion snapshot.
#[tokio::test]
async fn test_user_update_lost_update_race() {
    let (store, _audit) = test_db().await;

    // Create an admin user.
    let (user_id, _) = upsert_user_with_org(
        &store,
        "race@example.com",
        Some("Race User"),
        Some("org-race"),
        true, // starts as admin
    )
    .await
    .expect("upsert admin user");

    // Demote the user — this must win regardless of ordering.
    update_user_admin_status(&store, &user_id, false)
        .await
        .expect("admin status update");

    // Update the GitHub identity. `modify` re-reads the post-demotion doc,
    // so is_org_admin must stay false.
    update_user_github_identity(&store, &user_id, 42, "gh-user", Some("refresh-tok"))
        .await
        .expect("github identity update");

    let user = get_user_by_id(&store, &user_id)
        .await
        .expect("get user")
        .expect("user must exist");

    assert!(
        !user.is_org_admin,
        "demotion must survive a concurrent github identity update"
    );
    assert_eq!(user.github_id, Some(42), "github_id must be set");
    assert_eq!(
        user.github_login.as_deref(),
        Some("gh-user"),
        "github_login must be set"
    );
}

/// #545 — Counter updates must never regress: after setting 50,
/// applying values 1..=49 must leave the counter at 50 (max semantics).
///
/// The sequential descent test verifies the `max(stored, incoming)` logic
/// in `update_authenticator_counter`. A small concurrent burst (4 tasks,
/// well within the 3-retry budget for in-memory SQLite) additionally
/// confirms the optimistic-concurrency path does not regress the counter.
#[tokio::test]
async fn test_update_authenticator_counter_high_concurrency_no_lost_update() {
    let (store, _audit) = test_db().await;

    let (user_id, _) = upsert_user(&store, "counter@example.com", None)
        .await
        .expect("upsert user");

    let auth_id = create_authenticator(
        &store,
        &CreateAuthenticatorParams {
            user_id: &user_id,
            user_email: "counter@example.com",
            name: "Counter Key",
            credential_id: b"cred-counter-race",
            public_key: &[0u8; 32],
            aaguid: None,
            user_handle: None,
            attestation_verified: false,
        },
    )
    .await
    .expect("create authenticator");

    // Part 1 — sequential regression guard.
    // Set the counter to 50, then apply lower values and confirm no regression.
    update_authenticator_counter(&store, &auth_id, 50)
        .await
        .expect("set counter to 50");

    for lower in (1_i32..50).rev() {
        update_authenticator_counter(&store, &auth_id, lower)
            .await
            .expect("apply lower value");
    }

    let auth = get_authenticator_by_id(&store, &auth_id)
        .await
        .expect("get authenticator")
        .expect("authenticator must exist");

    assert_eq!(
        auth.counter, 50,
        "counter must not regress after applying values < 50"
    );

    // Part 2 — concurrent burst (4 tasks, within the 3-retry budget for
    // in-memory SQLite). Each task tries to set a value; the stored result
    // must equal the maximum attempted value.
    let target = 100_i32;
    let handles: Vec<_> = [target, 51, 52, 53]
        .iter()
        .map(|&i| {
            let store = store.clone();
            let auth_id = auth_id.clone();
            tokio::spawn(async move {
                update_authenticator_counter(&store, &auth_id, i)
                    .await
                    .expect("concurrent counter update")
            })
        })
        .collect();

    for h in handles {
        h.await.expect("task must not panic");
    }

    let auth = get_authenticator_by_id(&store, &auth_id)
        .await
        .expect("get authenticator after burst")
        .expect("authenticator must exist");

    assert_eq!(
        auth.counter, target,
        "counter must equal the max value applied in the concurrent burst"
    );
}

/// Deterministic companion to the #545 burst test above (whose contention
/// depends on scheduling): a higher counter written inside the OCC window via
/// the modify test seam must win over the in-flight lower value — the retry
/// re-reads the fresh counter and `max()` keeps it. A blind write would
/// regress the counter to 50.
#[tokio::test]
async fn test_update_authenticator_counter_concurrent_higher_value_wins() {
    use crate::db::documents::authenticator::AuthenticatorDoc;

    let (store, _audit) = test_db().await;
    let (user_id, _) = upsert_user(&store, "counter-seam@example.com", None)
        .await
        .expect("upsert user");
    let auth_id = create_authenticator(
        &store,
        &CreateAuthenticatorParams {
            user_id: &user_id,
            user_email: "counter-seam@example.com",
            name: "Counter Seam Key",
            credential_id: b"cred-counter-seam",
            public_key: &[0u8; 32],
            aaguid: None,
            user_handle: None,
            attestation_verified: false,
        },
    )
    .await
    .expect("create authenticator");

    let writer = store.clone();
    let mut hooked = store.clone();
    hooked.set_modify_test_hook(Arc::new(move |doc_id: &str, attempt: u32| {
        let writer = writer.clone();
        let doc_id = doc_id.to_string();
        Box::pin(async move {
            if attempt != 0 {
                return;
            }
            let doc = writer
                .get::<AuthenticatorDoc>(&doc_id)
                .await
                .expect("hook get")
                .expect("hook doc must exist");
            let mut data = doc.data;
            data.counter = 100;
            writer.update(&doc_id, &data).await.expect("hook update");
        })
    }));

    update_authenticator_counter(&hooked, &auth_id, 50)
        .await
        .expect("counter update must not error");

    let auth = get_authenticator_by_id(&store, &auth_id)
        .await
        .expect("get authenticator")
        .expect("authenticator must exist");
    assert_eq!(
        auth.counter, 100,
        "the concurrent higher counter must survive the retried max()"
    );
}

/// The concurrent suspend/unsuspend test cannot distinguish OCC from a blind
/// write (its own comment says so — both bump the version). This
/// deterministic variant proves the re-read: a sibling-field write
/// (repositories) landing inside the OCC window must survive the suspend
/// that retries over it.
#[tokio::test]
async fn test_suspend_github_installation_preserves_concurrent_sibling_write() {
    use crate::db::documents::github::GitHubInstallationDoc;

    let (store, _audit) = test_db().await;
    let doc_id = create_test_github_installation(&store, 20_005, "org-sibling-preserve").await;

    let writer = store.clone();
    let mut hooked = store.clone();
    hooked.set_modify_test_hook(Arc::new(move |_doc_id: &str, attempt: u32| {
        let writer = writer.clone();
        Box::pin(async move {
            if attempt != 0 {
                return;
            }
            let found =
                update_github_installation_repos(&writer, 20_005, &["hook/repo".to_string()])
                    .await
                    .expect("hook repos update must not error");
            assert!(found, "hook must find the installation");
        })
    }));

    let found = suspend_github_installation(&hooked, 20_005)
        .await
        .expect("suspend must not error");
    assert!(found, "suspend must find the installation");

    let after = store
        .get::<GitHubInstallationDoc>(&doc_id)
        .await
        .expect("get after")
        .expect("must exist");
    assert!(after.data.suspended_at.is_some(), "suspend must land");
    assert_eq!(
        after.data.repositories.as_deref(),
        Some(&["hook/repo".to_string()][..]),
        "the concurrent repositories write must not be clobbered by the suspend"
    );
}

/// Deterministic companion to the #537 sequential test above: an admin
/// demotion landing inside the OCC window (not merely before the call) must
/// survive `update_user_github_identity`'s retry — the doc comment on that
/// function promises exactly this.
#[tokio::test]
async fn test_update_user_github_identity_preserves_concurrent_admin_change() {
    let (store, _audit) = test_db().await;
    let (user_id, _) = upsert_user_with_org(
        &store,
        "seam-race@example.com",
        Some("Seam Race User"),
        Some("org-seam-race"),
        true, // starts as admin
    )
    .await
    .expect("upsert admin user");

    let writer = store.clone();
    let demote_user_id = user_id.clone();
    let mut hooked = store.clone();
    hooked.set_modify_test_hook(Arc::new(move |_doc_id: &str, attempt: u32| {
        let writer = writer.clone();
        let demote_user_id = demote_user_id.clone();
        Box::pin(async move {
            if attempt != 0 {
                return;
            }
            let found = update_user_admin_status(&writer, &demote_user_id, false)
                .await
                .expect("hook demotion must not error");
            assert!(found, "hook must find the user");
        })
    }));

    update_user_github_identity(&hooked, &user_id, 42, "gh-user", None)
        .await
        .expect("github identity update must not error");

    let user = get_user_by_id(&store, &user_id)
        .await
        .expect("get user")
        .expect("user must exist");
    assert!(
        !user.is_org_admin,
        "the demotion inside the OCC window must survive the identity update"
    );
    assert_eq!(user.github_id, Some(42), "github_id must be set");
    assert_eq!(
        user.github_login.as_deref(),
        Some("gh-user"),
        "github_login must be set"
    );
}

/// #543 — Deleting an authenticator must cascade to clear
/// `authenticator_id` on `DeviceAuthRequestDoc`, which requires the
/// `authenticator_id` index to be emitted by `DeviceAuthRequestDoc::index_entries`.
///
/// Note: this index only covers docs written *after* the fix is deployed.
/// Pre-existing device_auth_request rows lack the index entry and will not
/// be cleared on authenticator delete. This is acceptable because
/// device_auth_request docs are short-lived (minutes), so any pre-fix
/// rows will have expired before the fix is deployed in production.
#[tokio::test]
async fn test_delete_authenticator_clears_device_auth_reference() {
    let (store, _audit) = test_db().await;

    // Create user + authenticator.
    let (user_id, _) = upsert_user(&store, "cascade@example.com", None)
        .await
        .expect("upsert user");

    let auth_id = create_authenticator(
        &store,
        &CreateAuthenticatorParams {
            user_id: &user_id,
            user_email: "cascade@example.com",
            name: "Cascade Key",
            credential_id: b"cred-cascade",
            public_key: &[0u8; 32],
            aaguid: None,
            user_handle: None,
            attestation_verified: false,
        },
    )
    .await
    .expect("create authenticator");

    // Create a device_auth_request that references the authenticator.
    let device_code_hash = "cascade_device_code";
    let user_code = "CSCD-1234";
    let request_id = create_device_auth_request(
        &store,
        device_code_hash,
        user_code,
        None,
        "2099-12-31T23:59:59Z".parse().unwrap(),
        5,
    )
    .await
    .expect("create device auth request");

    // Authorize to bind the authenticator_id.
    authorize_device_auth(
        &store,
        &request_id,
        &user_id,
        "cascade@example.com",
        &auth_id,
    )
    .await
    .expect("authorize device auth");

    // Verify the authenticator_id is set before the cascade.
    let before = get_device_auth_by_id(&store, &request_id)
        .await
        .expect("get device auth")
        .expect("must exist before cascade");
    assert_eq!(
        before.authenticator_id.as_deref(),
        Some(auth_id.as_str()),
        "authenticator_id must be set before cascade delete"
    );

    // Delete the authenticator — this triggers the cascade.
    delete_authenticator(&store, &auth_id)
        .await
        .expect("delete authenticator");

    // The device_auth_request must now have authenticator_id cleared.
    let after = get_device_auth_by_id(&store, &request_id)
        .await
        .expect("get device auth")
        .expect("device auth request must still exist after cascade");
    assert!(
        after.authenticator_id.is_none(),
        "authenticator_id must be cleared by cascade delete"
    );
}

// ============================================================================
// OAuth secret cap (≤2) / floor (≥1) OCC invariant tests (#551)
// ============================================================================

/// 4 concurrent adds → exactly 2 `Ok`, rest `409 max_secrets_reached`.
/// Mirrors `test_update_authenticator_counter_high_concurrency_no_lost_update`.
/// Uses multi_thread for defensive OS-level parallelism; busy_timeout waits happen
/// inside sqlx-sqlite's dedicated OS thread and do not block tokio worker threads,
/// so a single-thread runtime would also work correctly here.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_concurrent_secret_add_never_exceeds_two() {
    let (store, _audit) = test_db().await;
    let app_id = create_test_client(
        &store,
        "occ-test-user",
        TestClientSpec {
            with_secret: false,
            ..Default::default()
        },
    )
    .await
    .app_id;

    let handles: Vec<_> = (0_u8..4)
        .map(|i| {
            let store = store.clone();
            let app_id = app_id.clone();
            tokio::spawn(async move {
                create_oauth_client_secret(
                    &store,
                    &app_id,
                    &format!("hash_concurrent_{i}"),
                    None,
                    None,
                )
                .await
            })
        })
        .collect();

    let mut ok_count: usize = 0;
    let mut max_reached_count: usize = 0;
    for h in handles {
        match h.await.expect("task must not panic") {
            Ok(_) => ok_count = ok_count.saturating_add(1),
            Err(crate::error::ServiceError::Api { ref code, .. })
                if code == "max_secrets_reached" =>
            {
                max_reached_count = max_reached_count.saturating_add(1);
            }
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    assert_eq!(ok_count, 2, "exactly 2 adds must succeed");
    assert_eq!(max_reached_count, 2, "exactly 2 adds must be rejected");

    // Verify at the DB level.
    let now = jiff::Timestamp::now();
    let secrets = get_oauth_client_secrets(&store, &app_id)
        .await
        .expect("list secrets");
    let active = secrets.iter().filter(|s| s.is_valid(&now)).count();
    assert_eq!(active, 2, "exactly 2 active secrets must exist");
}

/// Regression for #744: 4 concurrent SCIM token creates → exactly 2 `Ok`, rest
/// `409 token_limit_reached`. Counting in the handler and inserting afterwards
/// let every concurrent request pass the check; the count now happens inside the
/// insert's transaction, with the organization document's version as the
/// serialization point. Mirrors `test_concurrent_secret_add_never_exceeds_two`.
///
/// Scope note: this runs on SQLite, which serializes writers, so moving the
/// count inside the transaction is by itself sufficient here — the test still
/// passes if the `compare_and_update` version guard is removed. That guard
/// exists for PostgreSQL and DSQL, where two transactions can read the same
/// snapshot and neither conflicts on a predicate read. Proving it therefore
/// requires a snapshot-isolated backend, not this test.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_concurrent_scim_token_create_never_exceeds_two() {
    use crate::db::create_scim_token;

    let (store, _audit) = test_db().await;
    let org = create_organization(&store, "scim-cap.example", Some("Cap Org"), None)
        .await
        .expect("create org");

    let handles: Vec<_> = (0_u8..4)
        .map(|i| {
            let store = store.clone();
            let org_id = org.id.clone();
            tokio::spawn(async move {
                create_scim_token(
                    &store,
                    &CreateScimTokenParams {
                        org_id: &org_id,
                        token_hash: &format!("scim_hash_{i}"),
                        description: None,
                        expires_at: None,
                        scope: ScimScopeSet::default(),
                    },
                )
                .await
            })
        })
        .collect();

    let mut ok_count: usize = 0;
    let mut limit_count: usize = 0;
    for h in handles {
        match h.await.expect("task must not panic") {
            Ok(_) => ok_count = ok_count.saturating_add(1),
            Err(crate::error::ServiceError::Api { ref code, .. })
                if code == "token_limit_reached" =>
            {
                limit_count = limit_count.saturating_add(1);
            }
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    assert_eq!(ok_count, 2, "exactly 2 creates must succeed");
    assert_eq!(limit_count, 2, "exactly 2 creates must be rejected");

    // Verify at the DB level — the cap must hold in storage, not just in the
    // return values. None of these carry an expiry, so every stored row counts.
    let stored = list_scim_tokens(&store, Some(&org.id))
        .await
        .expect("list tokens");
    assert_eq!(stored.len(), 2, "exactly 2 SCIM tokens must be stored");
}

/// Seed 2 active secrets, 4 concurrent revokes → at least 1 active always remains.
/// Uses multi_thread for defensive OS-level parallelism (see add test for rationale).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_concurrent_secret_revoke_never_drops_below_one() {
    let (store, _audit) = test_db().await;
    let app_id = create_test_client(
        &store,
        "occ-test-user",
        TestClientSpec {
            with_secret: false,
            ..Default::default()
        },
    )
    .await
    .app_id;

    // Seed exactly 2 active secrets.
    let s1 = create_oauth_client_secret(&store, &app_id, "hash_s1", None, None)
        .await
        .expect("seed s1");
    let s2 = create_oauth_client_secret(&store, &app_id, "hash_s2", None, None)
        .await
        .expect("seed s2");

    let secret_ids = [s1.id, s2.id];

    // 4 concurrent revoke attempts on s1 and s2 (two each).
    let handles: Vec<_> = secret_ids
        .iter()
        .flat_map(|sid| [sid.clone(), sid.clone()])
        .map(|sid| {
            let store = store.clone();
            let app_id = app_id.clone();
            tokio::spawn(async move { revoke_oauth_client_secret(&store, &sid, &app_id).await })
        })
        .collect();

    for h in handles {
        let result = h.await.expect("task must not panic");
        // Acceptable outcomes: Ok (revoked), last_secret (floor guard),
        // ServiceError::NotFound (already revoked — idempotent path),
        // or conflict (exhausted OCC budget).  Anything else is a bug.
        // Note: the already-revoked path returns ServiceError::NotFound, not
        // ServiceError::Api { code: "not_found" }, so there is no Api "not_found" arm.
        match result {
            Ok(()) => {}
            Err(crate::error::ServiceError::Api { ref code, .. })
                if code == "last_secret" || code == "conflict" => {}
            Err(crate::error::ServiceError::NotFound(_)) => {}
            Err(e) => panic!("unexpected error from concurrent revoke: {e}"),
        }
    }

    // Invariant: at least 1 active secret must remain.
    let now = jiff::Timestamp::now();
    let secrets = get_oauth_client_secrets(&store, &app_id)
        .await
        .expect("list secrets");
    let active = secrets.iter().filter(|s| s.is_valid(&now)).count();
    assert!(
        active >= 1,
        "at least 1 active secret must remain; got {active}"
    );
}

/// Revoke 1 of 2, then add back to 2, confirming the cap counts `is_valid` not total rows.
#[tokio::test]
async fn test_revoke_then_add_back_to_two() {
    let (store, _audit) = test_db().await;
    let app_id = create_test_client(
        &store,
        "occ-test-user",
        TestClientSpec {
            with_secret: false,
            ..Default::default()
        },
    )
    .await
    .app_id;

    // Seed 2 active secrets.
    let s1 = create_oauth_client_secret(&store, &app_id, "hash_rtb_s1", None, None)
        .await
        .expect("seed s1");
    let _s2 = create_oauth_client_secret(&store, &app_id, "hash_rtb_s2", None, None)
        .await
        .expect("seed s2");

    // Revoke s1 (1 active remains).
    revoke_oauth_client_secret(&store, &s1.id, &app_id)
        .await
        .expect("revoke s1");

    // Now 1 active, 1 soft-deleted row.  A new add should succeed (not
    // triggered by the soft-deleted row's count).
    let _s3 = create_oauth_client_secret(&store, &app_id, "hash_rtb_s3", None, None)
        .await
        .expect("add s3 after revoke");

    // Now 2 active (s2 + s3).  A further add must be rejected.
    let cap_result = create_oauth_client_secret(&store, &app_id, "hash_rtb_s4", None, None).await;
    assert!(
        matches!(
            cap_result,
            Err(crate::error::ServiceError::Api { ref code, .. }) if code == "max_secrets_reached"
        ),
        "third add must fail with max_secrets_reached; got: {cap_result:?}"
    );

    // Verify counts at DB level.
    let now = jiff::Timestamp::now();
    let secrets = get_oauth_client_secrets(&store, &app_id)
        .await
        .expect("list secrets");
    let total = secrets.len();
    let active = secrets.iter().filter(|s| s.is_valid(&now)).count();
    assert_eq!(active, 2, "exactly 2 active secrets; got {active}");
    assert_eq!(
        total, 3,
        "3 total rows (1 soft-deleted, 2 active); got {total}"
    );
}

/// Revoking the sole active secret returns `Api(409 "last_secret")`.
/// Complements the handler-layer `test_delete_last_secret_rejected` with a
/// faster, db-level signal that the floor guard fires.
#[tokio::test]
async fn test_revoke_last_secret_rejected() {
    let (store, _audit) = test_db().await;
    let app_id = create_test_client(
        &store,
        "occ-test-user",
        TestClientSpec {
            with_secret: false,
            ..Default::default()
        },
    )
    .await
    .app_id;

    let secret = create_oauth_client_secret(&store, &app_id, "hash_only_one", None, None)
        .await
        .expect("create sole secret");

    let result = revoke_oauth_client_secret(&store, &secret.id, &app_id).await;

    assert!(
        matches!(
            result,
            Err(crate::error::ServiceError::Api { ref code, .. }) if code == "last_secret"
        ),
        "revoking the last secret must fail with last_secret; got: {result:?}"
    );
}

/// Revoking an expired-but-unrevoked secret must succeed while another valid
/// secret remains: the floor counts *other* active secrets, not the target.
/// Without excluding the target, the expired row drops `active_count` to 1 and
/// the revoke is wrongly rejected with `last_secret` (#557).
#[tokio::test]
async fn test_revoke_expired_secret_allowed_when_valid_remains() {
    let (store, _audit) = test_db().await;
    let app_id = create_test_client(
        &store,
        "occ-test-user",
        TestClientSpec {
            with_secret: false,
            ..Default::default()
        },
    )
    .await
    .app_id;

    // One valid secret (no expiry) plus one expired-but-unrevoked secret.
    let _valid = create_oauth_client_secret(&store, &app_id, "hash_valid", None, None)
        .await
        .expect("create valid secret");
    let past: jiff::Timestamp = "2020-01-01T00:00:00Z".parse().unwrap();
    let expired = create_oauth_client_secret(&store, &app_id, "hash_expired", None, Some(past))
        .await
        .expect("create expired secret");

    // Revoking the expired secret must be allowed — a valid secret still remains.
    revoke_oauth_client_secret(&store, &expired.id, &app_id)
        .await
        .expect("revoking an expired secret must succeed while a valid secret remains");

    // The valid secret is untouched and still active.
    let now = jiff::Timestamp::now();
    let secrets = get_oauth_client_secrets(&store, &app_id)
        .await
        .expect("list secrets");
    let active = secrets.iter().filter(|s| s.is_valid(&now)).count();
    assert_eq!(
        active, 1,
        "the valid secret must remain active; got {active}"
    );
}

// ========================================================================
// Email case normalization across SCIM and OIDC enrollment
// ========================================================================
//
// Regression for the duplicate-user bug: a user pre-provisioned via SCIM
// with `Alice@example.com` must be found (not duplicated) when the same
// person enrolls via OIDC with `alice@example.com`. Both `create_scim_user`
// and `enroll_user_with_org` now normalize email to ASCII lowercase before
// lookup and storage, matching the existing domain-normalization contract
// documented on `get_or_create_org`.

/// SCIM provisioning with a mixed-case email stores the row with the
/// email lowercased, and a subsequent OIDC enrollment for the same
/// person (with different casing) reuses the existing user row instead
/// of creating a duplicate.
#[tokio::test]
async fn test_enroll_finds_scim_user_with_different_email_casing() {
    use crate::db::documents::organization::OrganizationDoc;
    use crate::db::{create_scim_user, enroll_user_with_org};

    let (store, _audit) = test_db().await;
    let domain = "case-example.com";

    // Org is required for SCIM token binding and is the one OIDC enrollment
    // will resolve to via the (lowercased) domain.
    let org_id = {
        let org_doc = OrganizationDoc {
            domain: domain.to_string(),
            name: None,
            created_by_user_id: None,
            additional_domains: Vec::new(),
            subdomain: None,
        };
        store.insert(&org_doc).await.expect("org insert").id
    };

    // 1. SCIM creates a user with a mixed-case email, as an IdP directory
    //    API might return it.
    let scim_user = create_scim_user(
        &store,
        Some(&org_id),
        "Alice@Case-Example.com",
        Some("Alice Smith"),
        None,
        true,
    )
    .await
    .expect("SCIM user creation should succeed");

    // The stored email must be normalized to lowercase so that future
    // case-insensitive lookups match.
    assert_eq!(
        scim_user.email, "alice@case-example.com",
        "SCIM must store the email lowercased"
    );

    // 2. The same person enrolls via OIDC; the IdP returns the email in
    //    a different casing. The domain is lowercased by OIDC callers.
    let oidc_user = enroll_user_with_org(
        &store,
        "ALICE@Case-Example.com",
        Some("Alice Smith"),
        Some(domain),
    )
    .await
    .expect("OIDC enrollment should succeed");

    // The fix: the existing SCIM user is found — no duplicate user row.
    assert_eq!(
        scim_user.id, oidc_user.id,
        "SCIM and OIDC must resolve to the same user id"
    );
    assert_eq!(
        oidc_user.email, "alice@case-example.com",
        "OIDC enrollment must report the normalized (lowercase) email"
    );
    assert_eq!(
        oidc_user.org_id,
        Some(org_id.clone()),
        "OIDC user must be bound to the same org as the SCIM user"
    );

    // No duplicate user row exists in the store.
    let user_count = store
        .count::<crate::db::documents::user::UserDoc>("email", "alice@case-example.com")
        .await
        .expect("count users by email");
    assert_eq!(
        user_count, 1,
        "exactly one user row must exist for the email; got {user_count}"
    );
}

/// SCIM duplicate-email check is case-insensitive: provisioning
/// `Alice@example.com` after `alice@example.com` must be rejected
/// rather than producing a second row.
#[tokio::test]
async fn test_scim_duplicate_email_rejected_across_case() {
    let (store, _audit) = test_db().await;

    // First provisioning with lowercase email succeeds.
    create_scim_user(
        &store,
        Some(TEST_ORG_ID),
        "dup@example.com",
        Some("Original"),
        None,
        true,
    )
    .await
    .expect("first SCIM provisioning should succeed");

    // Second provisioning with the same email in a different case must
    // fail with the UNIQUE error — the application-level uniqueness
    // check uses the normalized (lowercase) email.
    let result = create_scim_user(
        &store,
        Some(TEST_ORG_ID),
        "DUP@example.com",
        Some("Duplicate"),
        None,
        true,
    )
    .await;
    assert!(
        result.is_err(),
        "SCIM provisioning with a different-case duplicate email must be rejected"
    );
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("UNIQUE"),
        "Error message should mention UNIQUE; got: {err}"
    );

    // And no second row was inserted.
    let count = store
        .count::<crate::db::documents::user::UserDoc>("email", "dup@example.com")
        .await
        .expect("count");
    assert_eq!(count, 1, "only one user row should exist; got {count}");
}

/// A user enrolling twice via OIDC with different email casing reuses
/// the same user row (no duplicate, no admin-claim regression).
#[tokio::test]
async fn test_enroll_twice_with_different_email_casing_reuses_user() {
    use crate::db::enroll_user_with_org;

    let (store, _audit) = test_db().await;
    let domain = "twice.example";

    let first = enroll_user_with_org(&store, "Bob@Twice.Example", Some("Bob"), Some(domain))
        .await
        .expect("first enrollment");
    assert!(first.is_org_admin, "first enrollee is admin");

    let second = enroll_user_with_org(&store, "bob@twice.example", Some("Bob"), Some(domain))
        .await
        .expect("second enrollment");

    assert_eq!(
        first.id, second.id,
        "second enrollment with different casing must reuse the same user"
    );
    assert_eq!(
        second.email, "bob@twice.example",
        "returned email must be normalized"
    );
    assert!(
        second.is_org_admin,
        "returning user must keep their admin status"
    );
}

/// `get_user_by_email` is case-insensitive: looking up a user by an
/// email with different casing than was stored returns the user.
#[tokio::test]
async fn test_get_user_by_email_is_case_insensitive() {
    let (store, _audit) = test_db().await;

    // Store via the test helper with a lowercase email.
    let (user_id, _) = upsert_user(&store, "Carol@example.com", Some("Carol"))
        .await
        .expect("upsert user");

    // Look up with the same email in a different case.
    let fetched = get_user_by_email(&store, "CAROL@EXAMPLE.COM")
        .await
        .expect("query")
        .expect("user should be found via case-insensitive lookup");
    assert_eq!(fetched.id, user_id);
    assert_eq!(fetched.email, "carol@example.com");
}
