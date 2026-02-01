// SPDX-License-Identifier: BUSL-1.1
//! Database module tests.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]

use super::*;

/// Create an in-memory SQLite database for testing.
async fn test_db() -> Pool {
    let pool = Pool::connect("sqlite::memory:")
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

    pool
}

#[tokio::test]
async fn test_upsert_and_get_user() {
    let pool = test_db().await;

    // Create a user
    let user = upsert_user(&pool, "test@example.com", Some("Test User"))
        .await
        .expect("Failed to create user");

    assert!(!user.id.is_empty());
    assert_eq!(user.email, "test@example.com");
    assert_eq!(user.name.as_deref(), Some("Test User"));

    // Get the user
    let fetched = get_user_by_email(&pool, "test@example.com")
        .await
        .expect("Failed to get user")
        .expect("User should exist");

    assert_eq!(fetched.id, user.id);
    assert_eq!(fetched.email, "test@example.com");
}

#[tokio::test]
async fn test_upsert_idempotent() {
    let pool = test_db().await;

    // First call creates user
    let user1 = upsert_user(&pool, "new@example.com", Some("New User"))
        .await
        .expect("Failed to upsert user");

    // Second call returns same user
    let user2 = upsert_user(&pool, "new@example.com", Some("Different Name"))
        .await
        .expect("Failed to upsert user");

    assert_eq!(user1.id, user2.id);
}

#[tokio::test]
async fn test_user_not_found() {
    let pool = test_db().await;

    let user = get_user_by_email(&pool, "nonexistent@example.com")
        .await
        .expect("Query should succeed");

    assert!(user.is_none());
}

#[tokio::test]
async fn test_session_lifecycle() {
    let pool = test_db().await;

    // Create user
    let user = upsert_user(&pool, "session@example.com", None)
        .await
        .expect("Failed to create user");
    let user_id = user.id;

    // Create authenticator (simplified - normally needs more fields)
    let auth_id = create_authenticator(
        &pool,
        &user_id,
        "Test Key",
        b"test-cred-id",
        &[0u8; 32],
        None,
        Some(user_id.as_bytes()),
    )
    .await
    .expect("Failed to create authenticator");

    // Create session
    let token_hash = "test_token_hash_123";
    let session_id = create_session(
        &pool,
        &user_id,
        token_hash,
        Some(&auth_id),
        "2099-12-31T23:59:59Z",
    )
    .await
    .expect("Failed to create session");

    assert!(!session_id.is_empty());

    // Get session
    let session = get_session_by_token_hash(&pool, token_hash)
        .await
        .expect("Failed to get session")
        .expect("Session should exist");

    assert_eq!(session.user_id, user_id);

    // Delete session
    let deleted = delete_session_by_token_hash(&pool, token_hash)
        .await
        .expect("Failed to delete session");

    assert!(deleted);

    // Session should no longer exist
    let session = get_session_by_token_hash(&pool, token_hash)
        .await
        .expect("Failed to get session");

    assert!(session.is_none());
}

#[tokio::test]
async fn test_config_storage() {
    let pool = test_db().await;

    // Initially no config
    let value = get_config(&pool, "test_key")
        .await
        .expect("Failed to get config");
    assert!(value.is_none());

    // Set config
    set_config(&pool, "test_key", "test_value")
        .await
        .expect("Failed to set config");

    // Get config
    let value = get_config(&pool, "test_key")
        .await
        .expect("Failed to get config")
        .expect("Config should exist");

    assert_eq!(value, "test_value");

    // Update config
    set_config(&pool, "test_key", "updated_value")
        .await
        .expect("Failed to update config");

    let value = get_config(&pool, "test_key")
        .await
        .expect("Failed to get config")
        .expect("Config should exist");

    assert_eq!(value, "updated_value");
}

// ========================================================================
// RFC 8628 - Device Authorization Grant Tests
// ========================================================================

#[tokio::test]
async fn test_device_auth_request_lifecycle() {
    let pool = test_db().await;

    // Create device auth request
    let device_code_hash = "hashed_device_code_123";
    let user_code = "ABCD-1234";
    let expires_at = "2099-12-31T23:59:59Z";
    let interval = 5;

    let id = create_device_auth_request(&pool, device_code_hash, user_code, expires_at, interval)
        .await
        .expect("Failed to create device auth request");

    assert!(!id.is_empty());

    // Get by device code hash
    let request = get_device_auth_by_code_hash(&pool, device_code_hash)
        .await
        .expect("Failed to get device auth")
        .expect("Device auth should exist");

    assert_eq!(request.user_code, user_code);
    assert_eq!(request.status, "pending");
    assert!(request.user_id.is_none());

    // Get by user code
    let request = get_device_auth_by_user_code(&pool, user_code)
        .await
        .expect("Failed to get device auth by user code")
        .expect("Should find by user code");

    assert_eq!(request.device_code_hash, device_code_hash);

    // Get by ID
    let request = get_device_auth_by_id(&pool, &id)
        .await
        .expect("Failed to get device auth by ID")
        .expect("Should find by ID");

    assert_eq!(request.interval_seconds, interval);
}

#[tokio::test]
async fn test_device_auth_authorization_flow() {
    let pool = test_db().await;

    // Create user first
    let user = upsert_user(&pool, "device@example.com", Some("Device User"))
        .await
        .expect("Failed to create user");

    // Create authenticator
    let auth_id = create_authenticator(
        &pool,
        &user.id,
        "Test Key",
        b"test-cred-id-device",
        &[0u8; 32],
        None,
        Some(user.id.as_bytes()),
    )
    .await
    .expect("Failed to create authenticator");

    // Create pending device auth request
    let device_code_hash = "hashed_device_code_456";
    let user_code = "EFGH-5678";
    let id = create_device_auth_request(
        &pool,
        device_code_hash,
        user_code,
        "2099-12-31T23:59:59Z",
        5,
    )
    .await
    .expect("Failed to create device auth request");

    // Verify initially pending
    let request = get_device_auth_by_id(&pool, &id)
        .await
        .expect("Failed to get request")
        .expect("Should exist");
    assert_eq!(request.status, "pending");

    // Authorize the request
    authorize_device_auth(&pool, &id, &user.id, &user.email, &auth_id)
        .await
        .expect("Failed to authorize");

    // Verify status changed to authorized
    let request = get_device_auth_by_id(&pool, &id)
        .await
        .expect("Failed to get request")
        .expect("Should exist");
    assert_eq!(request.status, "authorized");
    assert_eq!(request.user_id, Some(user.id.clone()));
    assert_eq!(request.user_email, Some(user.email.clone()));
    assert_eq!(request.authenticator_id, Some(auth_id));
}

#[tokio::test]
async fn test_device_auth_polling_rate_limit() {
    let pool = test_db().await;

    let device_code_hash = "rate_limit_test";
    let user_code = "RATE-1234";
    let interval = 5; // 5 seconds

    let id = create_device_auth_request(
        &pool,
        device_code_hash,
        user_code,
        "2099-12-31T23:59:59Z",
        interval,
    )
    .await
    .expect("Failed to create device auth request");

    // First poll should succeed
    let allowed = update_device_auth_poll_time(&pool, &id, interval)
        .await
        .expect("Failed to update poll time");
    assert!(allowed, "First poll should be allowed");

    // Immediate second poll should be rate limited
    let allowed = update_device_auth_poll_time(&pool, &id, interval)
        .await
        .expect("Failed to update poll time");
    assert!(!allowed, "Immediate second poll should be rate limited");
}

#[tokio::test]
async fn test_device_auth_not_found() {
    let pool = test_db().await;

    // Get nonexistent device auth
    let request = get_device_auth_by_code_hash(&pool, "nonexistent")
        .await
        .expect("Query should succeed");
    assert!(request.is_none());

    let request = get_device_auth_by_user_code(&pool, "XXXX-0000")
        .await
        .expect("Query should succeed");
    assert!(request.is_none());
}

// ========================================================================
// OIDC State Tests
// ========================================================================

#[tokio::test]
async fn test_oidc_state_lifecycle() {
    let pool = test_db().await;

    // Create device auth request first (FK reference)
    let device_auth_id = create_device_auth_request(
        &pool,
        "device_hash_for_oidc",
        "OIDC-1234",
        "2099-12-31T23:59:59Z",
        5,
    )
    .await
    .expect("Failed to create device auth");

    // Create OIDC state
    let state = "random_state_12345";
    let nonce = "nonce_67890";
    let expires_at = "2099-12-31T23:59:59Z";

    let id = create_oidc_state(&pool, state, &device_auth_id, nonce, expires_at)
        .await
        .expect("Failed to create OIDC state");
    assert!(!id.is_empty());

    // Get OIDC state
    let oidc_state = get_oidc_state(&pool, state)
        .await
        .expect("Failed to get OIDC state")
        .expect("Should exist");

    assert_eq!(oidc_state.state, state);
    assert_eq!(oidc_state.device_auth_id, device_auth_id);
    assert_eq!(oidc_state.nonce, nonce);

    // Delete OIDC state
    delete_oidc_state(&pool, state)
        .await
        .expect("Failed to delete OIDC state");

    // Verify deleted
    let oidc_state = get_oidc_state(&pool, state)
        .await
        .expect("Query should succeed");
    assert!(oidc_state.is_none());
}

// ========================================================================
// OAuth Client Application Tests (Phase 7)
// ========================================================================

#[tokio::test]
async fn test_oauth_client_crud() {
    let pool = test_db().await;

    // Create user
    let user = upsert_user(&pool, "developer@example.com", Some("Developer"))
        .await
        .expect("Failed to create user");

    // Create OAuth client
    let redirect_uris = vec!["https://example.com/callback".to_string()];
    let (client, client_id) = create_oauth_client(
        &pool,
        &user.id,
        "My App",
        Some("A test application"),
        OAuthClientType::Web,
        &redirect_uris,
        AccessScope::default(),
        None,
    )
    .await
    .expect("Failed to create OAuth client");

    assert!(!client_id.is_empty());
    assert_eq!(client.name, "My App");
    assert_eq!(client.application_type, "web");
    assert!(client.is_active());

    // Get by ID
    let fetched = get_oauth_client_by_id(&pool, &client.id)
        .await
        .expect("Failed to get client")
        .expect("Client should exist");
    assert_eq!(fetched.client_id, client_id);

    // Get by client_id
    let fetched = get_oauth_client_by_client_id(&pool, &client_id)
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
        &pool,
        &client.id,
        "My Updated App",
        Some("Updated desc"),
        &new_redirect_uris,
        None,
        None,
    )
    .await
    .expect("Failed to update client");

    let updated = get_oauth_client_by_id(&pool, &client.id)
        .await
        .expect("Failed to get client")
        .expect("Client should exist");
    assert_eq!(updated.name, "My Updated App");
    assert_eq!(updated.get_redirect_uris().len(), 2);

    // Delete client
    let deleted = delete_oauth_client(&pool, &client.id)
        .await
        .expect("Failed to delete client");
    assert_eq!(deleted, 1);

    // Verify deleted
    let client = get_oauth_client_by_id(&pool, &client.id)
        .await
        .expect("Query should succeed");
    assert!(client.is_none());
}

#[tokio::test]
async fn test_oauth_client_types() {
    let pool = test_db().await;

    let user = upsert_user(&pool, "types@example.com", None)
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
            &pool,
            &user.id,
            &format!("{:?} App", app_type),
            None,
            app_type,
            &[],
            AccessScope::default(),
            None,
        )
        .await
        .expect("Failed to create client");

        assert_eq!(client.client_type(), Some(app_type));

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
    let pool = test_db().await;

    let user1 = upsert_user(&pool, "user1@example.com", None)
        .await
        .expect("Failed to create user");
    let user2 = upsert_user(&pool, "user2@example.com", None)
        .await
        .expect("Failed to create user");

    // Create clients for user1
    for i in 0..3 {
        create_oauth_client(
            &pool,
            &user1.id,
            &format!("App {}", i),
            None,
            OAuthClientType::Web,
            &[],
            AccessScope::default(),
            None,
        )
        .await
        .expect("Failed to create client");
    }

    // Create client for user2
    create_oauth_client(
        &pool,
        &user2.id,
        "Other App",
        None,
        OAuthClientType::Web,
        &[],
        AccessScope::default(),
        None,
    )
    .await
    .expect("Failed to create client");

    // Get user1's clients
    let clients = get_oauth_clients_for_user(&pool, &user1.id)
        .await
        .expect("Failed to get clients");
    assert_eq!(clients.len(), 3);

    // Get user2's clients
    let clients = get_oauth_clients_for_user(&pool, &user2.id)
        .await
        .expect("Failed to get clients");
    assert_eq!(clients.len(), 1);
}

#[tokio::test]
async fn test_oauth_client_secret_management() {
    let pool = test_db().await;

    let user = upsert_user(&pool, "secrets@example.com", None)
        .await
        .expect("Failed to create user");

    let (client, _) = create_oauth_client(
        &pool,
        &user.id,
        "Secret App",
        None,
        OAuthClientType::Web,
        &[],
        AccessScope::default(),
        None,
    )
    .await
    .expect("Failed to create client");

    // Create a secret
    let secret_hash = "hashed_secret_12345";
    let secret =
        create_oauth_client_secret(&pool, &client.id, secret_hash, Some("Initial secret"), None)
            .await
            .expect("Failed to create secret");

    assert!(!secret.id.is_empty());
    assert_eq!(secret.oauth_client_id, client.id);
    assert!(secret.revoked_at.is_none());

    // Get secrets
    let secrets = get_oauth_client_secrets(&pool, &client.id)
        .await
        .expect("Failed to get secrets");
    assert_eq!(secrets.len(), 1);

    // Revoke all secrets
    let revoked_count = revoke_all_oauth_client_secrets(&pool, &client.id)
        .await
        .expect("Failed to revoke secrets");
    assert_eq!(revoked_count, 1);

    // Verify revoked
    let secrets = get_oauth_client_secrets(&pool, &client.id)
        .await
        .expect("Failed to get secrets");
    assert!(secrets[0].revoked_at.is_some());
}

#[tokio::test]
async fn test_oauth_client_deactivation() {
    let pool = test_db().await;

    let user = upsert_user(&pool, "deactivate@example.com", None)
        .await
        .expect("Failed to create user");

    let (client, _) = create_oauth_client(
        &pool,
        &user.id,
        "Deactivate App",
        None,
        OAuthClientType::Web,
        &[],
        AccessScope::default(),
        None,
    )
    .await
    .expect("Failed to create client");

    assert!(client.is_active());

    // Deactivate
    deactivate_oauth_client(&pool, &client.id)
        .await
        .expect("Failed to deactivate");

    let client = get_oauth_client_by_id(&pool, &client.id)
        .await
        .expect("Failed to get client")
        .expect("Client should exist");
    assert!(!client.is_active());

    // Reactivate
    reactivate_oauth_client(&pool, &client.id)
        .await
        .expect("Failed to reactivate");

    let client = get_oauth_client_by_id(&pool, &client.id)
        .await
        .expect("Failed to get client")
        .expect("Client should exist");
    assert!(client.is_active());
}

#[tokio::test]
async fn test_oauth_usage_recording() {
    let pool = test_db().await;

    let user = upsert_user(&pool, "usage@example.com", None)
        .await
        .expect("Failed to create user");

    let (client, _) = create_oauth_client(
        &pool,
        &user.id,
        "Usage App",
        None,
        OAuthClientType::Web,
        &[],
        AccessScope::default(),
        None,
    )
    .await
    .expect("Failed to create client");

    // Record some events
    record_oauth_event(
        &pool,
        &client.id,
        OAuthEventType::TokenIssued,
        Some(&user.id),
        None,
        None,
        None,
    )
    .await
    .expect("Failed to record event");
    record_oauth_event(
        &pool,
        &client.id,
        OAuthEventType::TokenIssued,
        Some(&user.id),
        None,
        None,
        None,
    )
    .await
    .expect("Failed to record event");
    record_oauth_event(
        &pool,
        &client.id,
        OAuthEventType::TokenRevoked,
        Some(&user.id),
        None,
        None,
        None,
    )
    .await
    .expect("Failed to record event");

    // Get usage stats
    let stats = get_oauth_usage_stats(&pool, &client.id, None)
        .await
        .expect("Failed to get stats");

    assert_eq!(stats.len(), 2); // token_issued and token_revoked

    let token_issued = stats
        .iter()
        .find(|s| s.event_type == "token_issued")
        .unwrap();
    assert_eq!(token_issued.count, 2);

    let token_revoked = stats
        .iter()
        .find(|s| s.event_type == "token_revoked")
        .unwrap();
    assert_eq!(token_revoked.count, 1);
}

// ========================================================================
// SCIM User Tests (RFC 7643/7644)
// ========================================================================

#[tokio::test]
async fn test_scim_user_crud() {
    let pool = test_db().await;

    // Create SCIM user
    let user = create_scim_user(
        &pool,
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
    let fetched = get_scim_user(&pool, &user.id)
        .await
        .expect("Failed to get SCIM user")
        .expect("User should exist");
    assert_eq!(fetched.email, "scim@example.com");

    // Update SCIM user
    update_scim_user(
        &pool,
        &user.id,
        Some("Updated Name"),
        Some("ext-456"),
        false,
    )
    .await
    .expect("Failed to update SCIM user");

    let updated = get_scim_user(&pool, &user.id)
        .await
        .expect("Failed to get user")
        .expect("User should exist");
    assert_eq!(updated.name, Some("Updated Name".to_string()));
    assert_eq!(updated.external_id, Some("ext-456".to_string()));
    assert!(!updated.active);
}

#[tokio::test]
async fn test_scim_user_list_and_filter() {
    let pool = test_db().await;

    // Create multiple users
    for i in 0..5 {
        create_scim_user(&pool, &format!("user{}@example.com", i), None, None, true)
            .await
            .expect("Failed to create user");
    }

    // List all users
    let users = list_scim_users(&pool, None, 1, 100)
        .await
        .expect("Failed to list users");
    assert_eq!(users.len(), 5);

    // Count users
    let count = count_scim_users(&pool, None)
        .await
        .expect("Failed to count users");
    assert_eq!(count, 5);

    // Filter by userName (email)
    let users = list_scim_users(&pool, Some("userName eq \"user2@example.com\""), 1, 100)
        .await
        .expect("Failed to filter users");
    assert_eq!(users.len(), 1);
    assert_eq!(users[0].email, "user2@example.com");

    // Pagination
    let page1 = list_scim_users(&pool, None, 1, 2)
        .await
        .expect("Failed to paginate");
    assert_eq!(page1.len(), 2);

    let page2 = list_scim_users(&pool, None, 3, 2)
        .await
        .expect("Failed to paginate");
    assert_eq!(page2.len(), 2);
}

#[tokio::test]
async fn test_scim_session_invalidation_on_deactivation() {
    let pool = test_db().await;

    // Create user with session
    let user = create_scim_user(&pool, "invalidate@example.com", None, None, true)
        .await
        .expect("Failed to create user");

    // Create authenticator
    let auth_id = create_authenticator(
        &pool,
        &user.id,
        "SCIM Key",
        b"scim-cred-id",
        &[0u8; 32],
        None,
        Some(user.id.as_bytes()),
    )
    .await
    .expect("Failed to create authenticator");

    // Create session
    create_session(
        &pool,
        &user.id,
        "scim_token_hash",
        Some(&auth_id),
        "2099-12-31T23:59:59Z",
    )
    .await
    .expect("Failed to create session");

    // Verify session exists
    let session = get_session_by_token_hash(&pool, "scim_token_hash")
        .await
        .expect("Failed to get session");
    assert!(session.is_some());

    // Delete all sessions for user (as SCIM would do on deactivation)
    let deleted = delete_sessions_for_user(&pool, &user.id)
        .await
        .expect("Failed to delete sessions");
    assert_eq!(deleted, 1);

    // Verify session deleted
    let session = get_session_by_token_hash(&pool, "scim_token_hash")
        .await
        .expect("Failed to get session");
    assert!(session.is_none());
}

#[tokio::test]
async fn test_scim_audit_logging() {
    let pool = test_db().await;

    // Create a SCIM token first (required for foreign key constraint)
    let token_id = create_scim_token(&pool, "test_token_hash", Some("Test token"), None, None)
        .await
        .expect("Failed to create SCIM token");

    // Insert audit log with token reference
    let audit_id = insert_scim_audit(
        &pool,
        "CREATE",
        "User",
        "user-123",
        Some(&token_id),
        Some("Created user via SCIM"),
    )
    .await
    .expect("Failed to insert audit log");

    assert!(!audit_id.is_empty());

    // Insert another audit log without token (None is valid)
    let audit_id2 = insert_scim_audit(&pool, "DELETE", "User", "user-789", None, None)
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
    let pool = test_db().await;

    let user = upsert_user(&pool, "events@example.com", None)
        .await
        .expect("Failed to create user");

    // Log successful login
    let event_id = insert_auth_event(
        &pool,
        &AuthEventParams {
            user_id: user.id.clone(),
            event_type: AuthEventType::LoginSuccess,
            authenticator_id: Some("auth-123".to_string()),
            client_ip: Some("192.168.1.1".to_string()),
            user_agent: Some("Mozilla/5.0".to_string()),
            success: true,
            ..Default::default()
        },
    )
    .await
    .expect("Failed to insert auth event");

    assert!(!event_id.is_empty());

    // Log failed login
    insert_auth_event(
        &pool,
        &AuthEventParams {
            user_id: user.id.clone(),
            event_type: AuthEventType::LoginFailed,
            client_ip: Some("192.168.1.1".to_string()),
            success: false,
            failure_reason: Some("Invalid credential".to_string()),
            ..Default::default()
        },
    )
    .await
    .expect("Failed to insert auth event");

    // Query events for user
    let events = get_auth_events(
        &pool,
        &AuthEventQuery {
            user_id: Some(user.id.clone()),
            limit: Some(10),
            ..Default::default()
        },
    )
    .await
    .expect("Failed to get events");

    assert_eq!(events.len(), 2);

    // Query by event type
    let events = get_auth_events(
        &pool,
        &AuthEventQuery {
            event_type: Some("login_success".to_string()),
            limit: Some(10),
            ..Default::default()
        },
    )
    .await
    .expect("Failed to get events");

    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type, "login_success");
}

// ========================================================================
// Authenticator Tests
// ========================================================================

#[tokio::test]
async fn test_authenticator_crud() {
    let pool = test_db().await;

    let user = upsert_user(&pool, "auth@example.com", None)
        .await
        .expect("Failed to create user");

    // Create authenticator
    let credential_id = vec![1u8, 2, 3, 4, 5];
    let public_key = vec![10u8; 65];
    let user_handle = vec![20u8; 32];

    let auth_id = create_authenticator(
        &pool,
        &user.id,
        "YubiKey 5C",
        &credential_id,
        &public_key,
        Some("2fc0579f-8113-47ea-b116-bb5a8db9202a"),
        Some(&user_handle),
    )
    .await
    .expect("Failed to create authenticator");

    assert!(!auth_id.is_empty());

    // Get by ID
    let auth = get_authenticator_by_id(&pool, &auth_id)
        .await
        .expect("Failed to get authenticator")
        .expect("Authenticator should exist");

    assert_eq!(auth.name, "YubiKey 5C");
    assert_eq!(auth.credential_id, credential_id);
    assert_eq!(auth.counter, 0);

    // Get by credential ID
    let auth = get_authenticator_by_credential_id(&pool, &credential_id)
        .await
        .expect("Failed to get authenticator")
        .expect("Authenticator should exist");

    assert_eq!(auth.id, auth_id);

    // Get all for user
    let auths = get_authenticators_for_user(&pool, &user.id)
        .await
        .expect("Failed to get authenticators");

    assert_eq!(auths.len(), 1);

    // Update counter
    update_authenticator_counter(&pool, &auth_id, 42)
        .await
        .expect("Failed to update counter");

    let auth = get_authenticator_by_id(&pool, &auth_id)
        .await
        .expect("Failed to get authenticator")
        .expect("Authenticator should exist");

    assert_eq!(auth.counter, 42);

    // Delete authenticator
    let deleted = delete_authenticator(&pool, &auth_id)
        .await
        .expect("Failed to delete authenticator");

    assert_eq!(deleted, 1);

    // Verify deleted
    let auth = get_authenticator_by_id(&pool, &auth_id)
        .await
        .expect("Query should succeed");

    assert!(auth.is_none());
}

#[tokio::test]
async fn test_authenticator_count() {
    let pool = test_db().await;

    let user = upsert_user(&pool, "count@example.com", None)
        .await
        .expect("Failed to create user");

    // Initially 0 authenticators
    let count = count_authenticators_for_user(&pool, &user.id)
        .await
        .expect("Failed to count");
    assert_eq!(count, 0);

    // Add authenticators
    for i in 0..3 {
        create_authenticator(
            &pool,
            &user.id,
            &format!("Key {}", i),
            &[i as u8; 10],
            &[0u8; 32],
            None,
            None,
        )
        .await
        .expect("Failed to create authenticator");
    }

    let count = count_authenticators_for_user(&pool, &user.id)
        .await
        .expect("Failed to count");
    assert_eq!(count, 3);
}

// ========================================================================
// SCIM Token Tests
// ========================================================================

#[tokio::test]
async fn test_scim_token_management() {
    let pool = test_db().await;

    // Create SCIM token
    let token_hash = "hashed_scim_token";
    let token_id = create_scim_token(&pool, token_hash, Some("Admin token"), None, None)
        .await
        .expect("Failed to create SCIM token");

    assert!(!token_id.is_empty());

    // Get by hash
    let token = get_scim_token_by_hash(&pool, token_hash)
        .await
        .expect("Failed to get token")
        .expect("Token should exist");

    assert_eq!(token.description, Some("Admin token".to_string()));
    assert!(token.last_used_at.is_none());

    // Update last used
    update_scim_token_last_used(&pool, &token.id)
        .await
        .expect("Failed to update last used");

    let token = get_scim_token_by_hash(&pool, token_hash)
        .await
        .expect("Failed to get token")
        .expect("Token should exist");

    assert!(token.last_used_at.is_some());

    // List tokens
    let tokens = list_scim_tokens(&pool, None)
        .await
        .expect("Failed to list tokens");

    assert_eq!(tokens.len(), 1);

    // Delete token
    delete_scim_token(&pool, &token_id)
        .await
        .expect("Failed to delete token");

    let token = get_scim_token_by_hash(&pool, token_hash)
        .await
        .expect("Query should succeed");

    assert!(token.is_none());
}

// ========================================================================
// Cascade Delete Tests
// ========================================================================

#[tokio::test]
async fn test_user_cascade_delete() {
    let pool = test_db().await;

    // Create user with authenticators and sessions
    let user = upsert_user(&pool, "cascade@example.com", None)
        .await
        .expect("Failed to create user");

    let auth_id = create_authenticator(
        &pool,
        &user.id,
        "Cascade Key",
        &[99u8; 10],
        &[0u8; 32],
        None,
        None,
    )
    .await
    .expect("Failed to create authenticator");

    create_session(
        &pool,
        &user.id,
        "cascade_token",
        Some(&auth_id),
        "2099-12-31T23:59:59Z",
    )
    .await
    .expect("Failed to create session");

    // Verify everything exists
    assert!(
        get_authenticator_by_id(&pool, &auth_id)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        get_session_by_token_hash(&pool, "cascade_token")
            .await
            .unwrap()
            .is_some()
    );

    // Delete user
    delete_user(&pool, &user.id)
        .await
        .expect("Failed to delete user");

    // Verify cascade (authenticators and sessions should be deleted)
    assert!(
        get_authenticator_by_id(&pool, &auth_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        get_session_by_token_hash(&pool, "cascade_token")
            .await
            .unwrap()
            .is_none()
    );
    assert!(get_user_by_id(&pool, &user.id).await.unwrap().is_none());
}

#[tokio::test]
async fn test_oauth_client_cascade_delete() {
    let pool = test_db().await;

    let user = upsert_user(&pool, "oauth_cascade@example.com", None)
        .await
        .expect("Failed to create user");

    let (client, _) = create_oauth_client(
        &pool,
        &user.id,
        "Cascade App",
        None,
        OAuthClientType::Web,
        &[],
        AccessScope::default(),
        None,
    )
    .await
    .expect("Failed to create client");

    // Add secrets and usage events
    create_oauth_client_secret(&pool, &client.id, "secret_hash", None, None)
        .await
        .expect("Failed to create secret");

    record_oauth_event(
        &pool,
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
    delete_oauth_client(&pool, &client.id)
        .await
        .expect("Failed to delete client");

    // Verify cascade (secrets should be deleted due to ON DELETE CASCADE)
    let secrets = get_oauth_client_secrets(&pool, &client.id)
        .await
        .expect("Failed to get secrets");
    assert!(secrets.is_empty());
}

// ========================================================================
// Cloud Integration Tests
// ========================================================================

#[tokio::test]
async fn test_cloud_integration_crud() {
    let pool = test_db().await;

    // Create an organization first
    let org = create_organization(&pool, "test.com", Some("Test Org"), None)
        .await
        .expect("Failed to create org");

    // Create a user in the org
    let user = upsert_user_with_org(&pool, "admin@test.com", None, Some(&org.id), true)
        .await
        .expect("Failed to create user");

    // Initially no GCP config
    let config = get_cloud_integration(&pool, &org.id, "gcp")
        .await
        .expect("Failed to get config");
    assert!(config.is_none());

    // Create GCP config
    let gcp_config =
        r#"{"project_number":"123456789","pool_id":"vouch-pool","provider_id":"vouch-provider"}"#;
    let integration = upsert_cloud_integration(&pool, &org.id, "gcp", gcp_config, &user.id)
        .await
        .expect("Failed to create config");

    assert_eq!(integration.org_id, org.id);
    assert_eq!(integration.provider, "gcp");
    assert_eq!(integration.config, gcp_config);
    assert_eq!(integration.created_by_user_id, Some(user.id.clone()));

    // Get the config back
    let config = get_cloud_integration(&pool, &org.id, "gcp")
        .await
        .expect("Failed to get config")
        .expect("Config should exist");

    assert_eq!(config.org_id, org.id);
    assert_eq!(config.provider, "gcp");
    assert_eq!(config.config, gcp_config);

    // Update the config
    let updated_config =
        r#"{"project_number":"987654321","pool_id":"new-pool","provider_id":"new-provider"}"#;
    let updated = upsert_cloud_integration(&pool, &org.id, "gcp", updated_config, &user.id)
        .await
        .expect("Failed to update config");

    assert_eq!(updated.config, updated_config);

    // Delete the config
    let deleted = delete_cloud_integration(&pool, &org.id, "gcp")
        .await
        .expect("Failed to delete config");
    assert!(deleted);

    // Config should be gone
    let config = get_cloud_integration(&pool, &org.id, "gcp")
        .await
        .expect("Failed to get config");
    assert!(config.is_none());

    // Delete non-existent should return false
    let deleted_again = delete_cloud_integration(&pool, &org.id, "gcp")
        .await
        .expect("Failed to delete config");
    assert!(!deleted_again);
}

#[tokio::test]
async fn test_cloud_integration_multiple_providers() {
    let pool = test_db().await;

    // Create an organization
    let org = create_organization(&pool, "multi.com", Some("Multi Org"), None)
        .await
        .expect("Failed to create org");

    let user = upsert_user_with_org(&pool, "admin@multi.com", None, Some(&org.id), true)
        .await
        .expect("Failed to create user");

    // Create both GCP and AWS configs
    let gcp_config = r#"{"project_number":"111","pool_id":"pool","provider_id":"provider"}"#;
    let aws_config = r#"{"default_role_arn":"arn:aws:iam::123:role/Test"}"#;

    upsert_cloud_integration(&pool, &org.id, "gcp", gcp_config, &user.id)
        .await
        .expect("Failed to create GCP config");

    upsert_cloud_integration(&pool, &org.id, "aws", aws_config, &user.id)
        .await
        .expect("Failed to create AWS config");

    // Both should exist independently
    let gcp = get_cloud_integration(&pool, &org.id, "gcp")
        .await
        .expect("Failed to get GCP config")
        .expect("GCP config should exist");
    assert_eq!(gcp.config, gcp_config);

    let aws = get_cloud_integration(&pool, &org.id, "aws")
        .await
        .expect("Failed to get AWS config")
        .expect("AWS config should exist");
    assert_eq!(aws.config, aws_config);

    // Delete GCP should not affect AWS
    delete_cloud_integration(&pool, &org.id, "gcp")
        .await
        .expect("Failed to delete GCP config");

    let gcp = get_cloud_integration(&pool, &org.id, "gcp")
        .await
        .expect("Failed to get GCP config");
    assert!(gcp.is_none());

    let aws = get_cloud_integration(&pool, &org.id, "aws")
        .await
        .expect("Failed to get AWS config")
        .expect("AWS config should still exist");
    assert_eq!(aws.config, aws_config);
}

#[tokio::test]
async fn test_cloud_integration_org_isolation() {
    let pool = test_db().await;

    // Create two organizations
    let org1 = create_organization(&pool, "org1.com", Some("Org 1"), None)
        .await
        .expect("Failed to create org1");
    let org2 = create_organization(&pool, "org2.com", Some("Org 2"), None)
        .await
        .expect("Failed to create org2");

    let user1 = upsert_user_with_org(&pool, "admin@org1.com", None, Some(&org1.id), true)
        .await
        .expect("Failed to create user1");
    let user2 = upsert_user_with_org(&pool, "admin@org2.com", None, Some(&org2.id), true)
        .await
        .expect("Failed to create user2");

    // Create GCP config for org1
    let config1 = r#"{"project_number":"111","pool_id":"pool1","provider_id":"provider1"}"#;
    upsert_cloud_integration(&pool, &org1.id, "gcp", config1, &user1.id)
        .await
        .expect("Failed to create config for org1");

    // Create GCP config for org2
    let config2 = r#"{"project_number":"222","pool_id":"pool2","provider_id":"provider2"}"#;
    upsert_cloud_integration(&pool, &org2.id, "gcp", config2, &user2.id)
        .await
        .expect("Failed to create config for org2");

    // Each org should only see its own config
    let gcp1 = get_cloud_integration(&pool, &org1.id, "gcp")
        .await
        .expect("Failed to get config for org1")
        .expect("Config should exist");
    assert_eq!(gcp1.config, config1);

    let gcp2 = get_cloud_integration(&pool, &org2.id, "gcp")
        .await
        .expect("Failed to get config for org2")
        .expect("Config should exist");
    assert_eq!(gcp2.config, config2);

    // Deleting org1's config should not affect org2
    delete_cloud_integration(&pool, &org1.id, "gcp")
        .await
        .expect("Failed to delete config for org1");

    let gcp1 = get_cloud_integration(&pool, &org1.id, "gcp")
        .await
        .expect("Failed to get config");
    assert!(gcp1.is_none());

    let gcp2 = get_cloud_integration(&pool, &org2.id, "gcp")
        .await
        .expect("Failed to get config")
        .expect("Org2 config should still exist");
    assert_eq!(gcp2.config, config2);
}
