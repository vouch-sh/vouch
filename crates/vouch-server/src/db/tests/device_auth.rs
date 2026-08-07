// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Device authorization grant (RFC 8628): request lifecycle, polling, atomic consumption, single-use semantics.
#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable; cast bounds are obvious in test fixtures"
)]

use super::*;

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
