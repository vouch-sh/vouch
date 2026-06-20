// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Authentication flow tests — session-key binding, key lifecycle, and cross-flow interactions.
//!
//! These tests verify the relationship between sessions and authenticators:
//! - Sessions are bound to specific authenticators via `authenticator_id`
//! - Deleting a key cascades to all sessions bound to it
//! - Key deletion requires fresh authentication (step-up)
//! - Cannot delete last key
//! - Token revocation is independent of key deletion

use super::helpers::*;

// ========================================================================
// Group A: Session-Key Binding Verification
// ========================================================================

#[tokio::test]
async fn test_session_bound_to_authenticator() {
    // Session should report the correct authenticator as is_current_session
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "bind-a1@example.com").await;
    let auth_a = create_test_authenticator(&state.store, &user.id).await;
    let auth_b = create_test_authenticator(&state.store, &user.id).await;

    let token = create_test_session(&state, &user.id, &user.email, &auth_a).await;

    let (status, body) = http_get(
        &app,
        "/v1/keys",
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;

    assert_eq!(status, StatusCode::OK, "List keys should succeed: {body}");

    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let keys = response["keys"].as_array().expect("keys array");
    assert_eq!(keys.len(), 2, "User should have 2 keys");

    let key_a = keys.iter().find(|k| k["id"].as_str() == Some(&auth_a));
    let key_b = keys.iter().find(|k| k["id"].as_str() == Some(&auth_b));

    assert!(
        key_a.expect("Key A present")["is_current_session"]
            .as_bool()
            .unwrap_or(false),
        "Key A should be marked as current session"
    );
    assert!(
        !key_b.expect("Key B present")["is_current_session"]
            .as_bool()
            .unwrap_or(true),
        "Key B should NOT be marked as current session"
    );
}

#[tokio::test]
async fn test_session_valid_after_registering_new_key() {
    // Adding a new key should not affect existing sessions
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "bind-a2@example.com").await;
    let auth_a = create_test_authenticator(&state.store, &user.id).await;

    let token = create_test_session(&state, &user.id, &user.email, &auth_a).await;

    // Verify session works
    let (status, _) = http_get(
        &app,
        "/v1/keys",
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "Session should work before new key");

    // Add a second key
    let _auth_b = create_test_authenticator(&state.store, &user.id).await;

    // Session should still work
    let (status, body) = http_get(
        &app,
        "/v1/keys",
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "Session should survive new key registration: {body}"
    );

    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let keys = response["keys"].as_array().expect("keys array");
    assert_eq!(keys.len(), 2, "User should now have 2 keys");
}

#[tokio::test]
async fn test_multiple_sessions_different_keys() {
    // Two sessions bound to different keys should both work independently
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "bind-a3@example.com").await;
    let auth_a = create_test_authenticator(&state.store, &user.id).await;
    let auth_b = create_test_authenticator(&state.store, &user.id).await;

    let token_a = create_test_session(&state, &user.id, &user.email, &auth_a).await;
    let token_b = create_test_session(&state, &user.id, &user.email, &auth_b).await;

    let (status_a, _) = http_get(
        &app,
        "/v1/keys",
        &[("Authorization", &format!("Bearer {token_a}"))],
    )
    .await;
    let (status_b, _) = http_get(
        &app,
        "/v1/keys",
        &[("Authorization", &format!("Bearer {token_b}"))],
    )
    .await;

    assert_eq!(status_a, StatusCode::OK, "Session A should work");
    assert_eq!(status_b, StatusCode::OK, "Session B should work");
}

// ========================================================================
// Group B: Key Deletion Cascades
// ========================================================================

#[tokio::test]
async fn test_delete_non_session_key_preserves_session() {
    // Deleting a key NOT bound to the current session should leave
    // the session intact.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "del-b1@example.com").await;
    let auth_a = create_test_authenticator(&state.store, &user.id).await;
    let auth_b = create_test_authenticator(&state.store, &user.id).await;

    let token = create_test_session(&state, &user.id, &user.email, &auth_a).await;

    // Delete Key B (not the session key)
    let (status, body) = http_delete(
        &app,
        &format!("/v1/keys/{auth_b}"),
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "Deleting non-session key should succeed: {body}"
    );

    // Session should still work
    let (status, body) = http_get(
        &app,
        "/v1/keys",
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "Session should survive after deleting non-session key: {body}"
    );

    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let keys = response["keys"].as_array().expect("keys array");
    assert_eq!(keys.len(), 1, "Only Key A should remain");
    assert_eq!(
        keys[0]["id"].as_str(),
        Some(auth_a.as_str()),
        "Remaining key should be Key A"
    );
}

#[tokio::test]
async fn test_delete_session_key_invalidates_session() {
    // Deleting the key bound to the current session should cascade-delete
    // the session, making subsequent requests fail with 401.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "del-b2@example.com").await;
    let auth_a = create_test_authenticator(&state.store, &user.id).await;
    let _auth_b = create_test_authenticator(&state.store, &user.id).await;

    let token = create_test_session(&state, &user.id, &user.email, &auth_a).await;

    // Delete Key A (the session key) — this should succeed for the delete
    // itself but cascade-delete the session
    let (status, body) = http_delete(
        &app,
        &format!("/v1/keys/{auth_a}"),
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "Self-deletion should succeed: {body}"
    );

    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert!(
        response["sessions_revoked"].as_u64().unwrap_or(0) >= 1,
        "At least 1 session should be revoked: {body}"
    );

    // Now the token should be invalid
    let (status, _) = http_get(
        &app,
        "/v1/keys",
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "Session should be invalidated after deleting its authenticator"
    );
}

#[tokio::test]
async fn test_delete_key_revokes_all_sessions_for_that_key() {
    // Deleting a key should revoke ALL sessions bound to it, even if
    // the delete is performed using a session bound to a different key.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "del-b3@example.com").await;
    let auth_a = create_test_authenticator(&state.store, &user.id).await;
    let auth_b = create_test_authenticator(&state.store, &user.id).await;

    // Create two sessions bound to Key A
    let token_a1 = create_test_session(&state, &user.id, &user.email, &auth_a).await;
    let token_a2 = create_test_session(&state, &user.id, &user.email, &auth_a).await;
    // One session bound to Key B (the "admin" session that performs the delete)
    let token_b = create_test_session(&state, &user.id, &user.email, &auth_b).await;

    // Delete Key A using session bound to Key B
    let (status, body) = http_delete(
        &app,
        &format!("/v1/keys/{auth_a}"),
        &[("Authorization", &format!("Bearer {token_b}"))],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "Delete Key A via Key B session should succeed: {body}"
    );

    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert!(
        response["sessions_revoked"].as_u64().unwrap_or(0) >= 2,
        "At least 2 sessions should be revoked (token_a1 + token_a2): {body}"
    );

    // Both Key A sessions should be invalid
    let (status_a1, _) = http_get(
        &app,
        "/v1/keys",
        &[("Authorization", &format!("Bearer {token_a1}"))],
    )
    .await;
    let (status_a2, _) = http_get(
        &app,
        "/v1/keys",
        &[("Authorization", &format!("Bearer {token_a2}"))],
    )
    .await;
    assert_eq!(
        status_a1,
        StatusCode::UNAUTHORIZED,
        "Session A1 should be revoked"
    );
    assert_eq!(
        status_a2,
        StatusCode::UNAUTHORIZED,
        "Session A2 should be revoked"
    );

    // Key B session should still work
    let (status_b, _) = http_get(
        &app,
        "/v1/keys",
        &[("Authorization", &format!("Bearer {token_b}"))],
    )
    .await;
    assert_eq!(status_b, StatusCode::OK, "Session B should still be valid");
}

#[tokio::test]
async fn test_cannot_delete_last_key() {
    // Attempting to delete the user's only key should fail
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "del-b4@example.com").await;
    let auth_a = create_test_authenticator(&state.store, &user.id).await;

    let token = create_test_session(&state, &user.id, &user.email, &auth_a).await;

    let (status, body) = http_delete(
        &app,
        &format!("/v1/keys/{auth_a}"),
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Deleting last key should fail: {body}"
    );

    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        response["code"].as_str(),
        Some("last_key"),
        "Error code should be last_key: {body}"
    );
}

#[tokio::test]
async fn test_delete_returns_revoked_session_count() {
    // The delete response should include the number of revoked sessions
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "del-b5@example.com").await;
    let auth_a = create_test_authenticator(&state.store, &user.id).await;
    let auth_b = create_test_authenticator(&state.store, &user.id).await;

    // Create 3 sessions bound to Key A
    let _t1 = create_test_session(&state, &user.id, &user.email, &auth_a).await;
    let _t2 = create_test_session(&state, &user.id, &user.email, &auth_a).await;
    let _t3 = create_test_session(&state, &user.id, &user.email, &auth_a).await;
    // Use Key B to perform the delete
    let token_b = create_test_session(&state, &user.id, &user.email, &auth_b).await;

    let (status, body) = http_delete(
        &app,
        &format!("/v1/keys/{auth_a}"),
        &[("Authorization", &format!("Bearer {token_b}"))],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "Delete should succeed: {body}");

    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        response["sessions_revoked"].as_u64(),
        Some(3),
        "Should report 3 revoked sessions: {body}"
    );
}

// ========================================================================
// Group C: Step-Up Authentication (Key Deletion Freshness)
// ========================================================================

#[tokio::test]
async fn test_stale_session_cannot_delete_key() {
    // A session older than KEY_DELETE_MAX_AGE_SECS (60s) should be rejected
    // with 401 and WWW-Authenticate containing insufficient_user_authentication
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "step-c1@example.com").await;
    let auth_a = create_test_authenticator(&state.store, &user.id).await;
    let auth_b = create_test_authenticator(&state.store, &user.id).await;

    let stale_iat = jiff::Timestamp::now().as_second() - 600;
    let token =
        create_test_session_with_iat(&state, &user.id, &user.email, &auth_a, stale_iat).await;

    let response = http_delete_full(
        &app,
        &format!("/v1/keys/{auth_b}"),
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;

    assert_eq!(
        response.status,
        StatusCode::UNAUTHORIZED,
        "Stale session should be rejected: {}",
        response.body
    );

    let www_auth = response
        .headers
        .get("www-authenticate")
        .expect("Must have WWW-Authenticate")
        .to_str()
        .expect("Valid UTF-8");
    assert!(
        www_auth.contains("insufficient_user_authentication"),
        "WWW-Authenticate must signal step-up required: {www_auth}"
    );
    assert!(
        www_auth.contains("max_age="),
        "WWW-Authenticate must include max_age: {www_auth}"
    );
}

#[tokio::test]
async fn test_fresh_session_can_delete_key() {
    // A session created just now (iat=now) should pass the freshness check
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "step-c2@example.com").await;
    let auth_a = create_test_authenticator(&state.store, &user.id).await;
    let auth_b = create_test_authenticator(&state.store, &user.id).await;

    let token = create_test_session(&state, &user.id, &user.email, &auth_a).await;

    let (status, body) = http_delete(
        &app,
        &format!("/v1/keys/{auth_b}"),
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "Fresh session should allow deletion: {body}"
    );
}

#[tokio::test]
async fn test_boundary_exactly_at_max_age() {
    // A session exactly at the 60-second boundary should succeed
    // (require_fresh_timestamp uses > not >=)
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "step-c3@example.com").await;
    let auth_a = create_test_authenticator(&state.store, &user.id).await;
    let auth_b = create_test_authenticator(&state.store, &user.id).await;

    let boundary_iat = jiff::Timestamp::now().as_second() - 60;
    let token =
        create_test_session_with_iat(&state, &user.id, &user.email, &auth_a, boundary_iat).await;

    let (status, body) = http_delete(
        &app,
        &format!("/v1/keys/{auth_b}"),
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "Session exactly at max_age boundary should succeed: {body}"
    );
}

#[tokio::test]
async fn test_one_second_over_max_age() {
    // A session 61 seconds old should fail the freshness check
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "step-c4@example.com").await;
    let auth_a = create_test_authenticator(&state.store, &user.id).await;
    let auth_b = create_test_authenticator(&state.store, &user.id).await;

    let over_iat = jiff::Timestamp::now().as_second() - 61;
    let token =
        create_test_session_with_iat(&state, &user.id, &user.email, &auth_a, over_iat).await;

    let response = http_delete_full(
        &app,
        &format!("/v1/keys/{auth_b}"),
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;

    assert_eq!(
        response.status,
        StatusCode::UNAUTHORIZED,
        "Session 1s over max_age should be rejected: {}",
        response.body
    );

    let body: serde_json::Value = serde_json::from_str(&response.body).expect("Valid JSON");
    assert_eq!(
        body["error"].as_str(),
        Some("insufficient_user_authentication"),
        "Error should be insufficient_user_authentication: {}",
        response.body
    );
}

// ========================================================================
// Group D: Token Revocation and Session Lifecycle
// ========================================================================

#[tokio::test]
async fn test_revoked_token_cannot_access_resources() {
    // After RFC 7009 revocation, the token should be rejected by resource endpoints
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "rev-d1@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    // The token's client must hold the shared test signing key so the
    // transparently-signed /v1/* request verifies.
    attach_test_signing_key(&state.store, &client.app_id).await;

    let (access_token, _) = issue_oauth_access_token(&app, &state, &user, &auth_id, &client).await;

    // Verify token works before revocation
    let (status, _) = http_get(
        &app,
        "/v1/keys",
        &[("Authorization", &format!("Bearer {access_token}"))],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "Token should work before revocation"
    );

    // Revoke the token
    let auth_header = client.basic_auth_header();
    let (status, _) = http_post_form(
        &app,
        "/oauth/revoke",
        &format!("token={access_token}"),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "Revocation should return 200");

    // Token should now fail on resource endpoint
    let (status, _) = http_get(
        &app,
        "/v1/keys",
        &[("Authorization", &format!("Bearer {access_token}"))],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "Revoked token should be rejected by /v1/keys"
    );
}

#[tokio::test]
async fn test_revoke_kills_all_user_sessions() {
    // Revoking any token revokes ALL sessions for that user
    // (human presence attestation: logout = full logout)
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "rev-d2@example.com").await;
    let auth_a = create_test_authenticator(&state.store, &user.id).await;
    let auth_b = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (token_a, _) = issue_oauth_access_token(&app, &state, &user, &auth_a, &client).await;
    let token_b = create_test_session(&state, &user.id, &user.email, &auth_b).await;

    // Revoke token_a — should kill ALL sessions for the user
    let auth_header = client.basic_auth_header();
    let (status, _) = http_post_form(
        &app,
        "/oauth/revoke",
        &format!("token={token_a}"),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // token_a should be dead
    let (status, _) = http_get(
        &app,
        "/v1/keys",
        &[("Authorization", &format!("Bearer {token_a}"))],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "Revoked token_a should fail"
    );

    // token_b should also be dead (all user sessions revoked)
    let (status, _) = http_get(
        &app,
        "/v1/keys",
        &[("Authorization", &format!("Bearer {token_b}"))],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "token_b should also be revoked (full user logout)"
    );
}

// ========================================================================
// Group E: Cross-Flow Scenarios
// ========================================================================

#[tokio::test]
async fn test_register_then_delete_original_key() {
    // Enroll Key A → register Key B → delete Key A → session invalidated
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "cross-e1@example.com").await;
    let auth_a = create_test_authenticator(&state.store, &user.id).await;

    let token_a = create_test_session(&state, &user.id, &user.email, &auth_a).await;

    // "Register" Key B
    let _auth_b = create_test_authenticator(&state.store, &user.id).await;

    // Delete original Key A (the session key)
    let (status, _) = http_delete(
        &app,
        &format!("/v1/keys/{auth_a}"),
        &[("Authorization", &format!("Bearer {token_a}"))],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "Delete Key A should succeed");

    // Session A should be invalidated
    let (status, _) = http_get(
        &app,
        "/v1/keys",
        &[("Authorization", &format!("Bearer {token_a}"))],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "Session should be invalidated after deleting its key"
    );
}

#[tokio::test]
async fn test_delete_registered_key_preserves_original_session() {
    // Enroll Key A → register Key B → delete Key B → session A still valid
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "cross-e2@example.com").await;
    let auth_a = create_test_authenticator(&state.store, &user.id).await;

    let token_a = create_test_session(&state, &user.id, &user.email, &auth_a).await;

    // "Register" Key B
    let auth_b = create_test_authenticator(&state.store, &user.id).await;

    // Delete Key B (the non-session key)
    let (status, _) = http_delete(
        &app,
        &format!("/v1/keys/{auth_b}"),
        &[("Authorization", &format!("Bearer {token_a}"))],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "Delete Key B should succeed");

    // Session A should still work
    let (status, _) = http_get(
        &app,
        "/v1/keys",
        &[("Authorization", &format!("Bearer {token_a}"))],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "Session A should survive deletion of non-session key"
    );
}

#[tokio::test]
async fn test_delete_self_then_login_with_other_key() {
    // Has A+B, login Key A → delete Key A → session invalid → login Key B → works
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "cross-e4@example.com").await;
    let auth_a = create_test_authenticator(&state.store, &user.id).await;
    let auth_b = create_test_authenticator(&state.store, &user.id).await;

    let token_a = create_test_session(&state, &user.id, &user.email, &auth_a).await;

    // Delete Key A (self-delete)
    let (status, _) = http_delete(
        &app,
        &format!("/v1/keys/{auth_a}"),
        &[("Authorization", &format!("Bearer {token_a}"))],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "Self-delete should succeed");

    // Token A should be dead
    let (status, _) = http_get(
        &app,
        "/v1/keys",
        &[("Authorization", &format!("Bearer {token_a}"))],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "Token A should be revoked"
    );

    // Login with Key B
    let token_b = create_test_session(&state, &user.id, &user.email, &auth_b).await;
    let (status, body) = http_get(
        &app,
        "/v1/keys",
        &[("Authorization", &format!("Bearer {token_b}"))],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "Session B should work: {body}");

    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let keys = response["keys"].as_array().expect("keys array");
    assert_eq!(keys.len(), 1, "Only Key B should remain");
}

#[tokio::test]
async fn test_full_lifecycle() {
    // Full credential lifecycle:
    // 1. Create user + Key A + session A
    // 2. GET /v1/keys → 1 key
    // 3. Add Key B
    // 4. GET /v1/keys → 2 keys
    // 5. Delete Key A → session A revoked
    // 6. GET /v1/keys with session A → 401
    // 7. Create session B
    // 8. GET /v1/keys with session B → 1 key (B only)
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "cross-e5@example.com").await;
    let auth_a = create_test_authenticator(&state.store, &user.id).await;
    let token_a = create_test_session(&state, &user.id, &user.email, &auth_a).await;

    // Step 2: 1 key
    let (status, body) = http_get(
        &app,
        "/v1/keys",
        &[("Authorization", &format!("Bearer {token_a}"))],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let resp: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(resp["keys"].as_array().expect("keys").len(), 1);

    // Step 3: Add Key B
    let auth_b = create_test_authenticator(&state.store, &user.id).await;

    // Step 4: 2 keys
    let (status, body) = http_get(
        &app,
        "/v1/keys",
        &[("Authorization", &format!("Bearer {token_a}"))],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let resp: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(resp["keys"].as_array().expect("keys").len(), 2);

    // Step 5: Delete Key A
    let (status, _) = http_delete(
        &app,
        &format!("/v1/keys/{auth_a}"),
        &[("Authorization", &format!("Bearer {token_a}"))],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Step 6: Session A is dead
    let (status, _) = http_get(
        &app,
        "/v1/keys",
        &[("Authorization", &format!("Bearer {token_a}"))],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Step 7: New session with Key B
    let token_b = create_test_session(&state, &user.id, &user.email, &auth_b).await;

    // Step 8: Only Key B remains
    let (status, body) = http_get(
        &app,
        "/v1/keys",
        &[("Authorization", &format!("Bearer {token_b}"))],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let resp: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let keys = resp["keys"].as_array().expect("keys");
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["id"].as_str(), Some(auth_b.as_str()));
    assert!(
        keys[0]["is_current_session"].as_bool().unwrap_or(false),
        "Key B should be marked as current session"
    );
}

#[tokio::test]
async fn test_token_revocation_vs_key_deletion() {
    // Token revocation kills ALL sessions for the user.
    // Key deletion cascades to sessions for that specific key.
    // Both mechanisms result in session cleanup but trigger differently.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "cross-e6@example.com").await;
    let auth_a = create_test_authenticator(&state.store, &user.id).await;
    let auth_b = create_test_authenticator(&state.store, &user.id).await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (token_a1, _) = issue_oauth_access_token(&app, &state, &user, &auth_a, &client).await;
    let token_a2 = create_test_session(&state, &user.id, &user.email, &auth_a).await;

    // Revoke token_a1 — kills ALL sessions for the user
    let auth_header = client.basic_auth_header();
    let (status, _) = http_post_form(
        &app,
        "/oauth/revoke",
        &format!("token={token_a1}"),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Both token_a1 and token_a2 should be dead (full user logout)
    let (status, _) = http_get(
        &app,
        "/v1/keys",
        &[("Authorization", &format!("Bearer {token_a1}"))],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "Revoked token should fail"
    );

    let (status, _) = http_get(
        &app,
        "/v1/keys",
        &[("Authorization", &format!("Bearer {token_a2}"))],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "All user sessions should be revoked"
    );

    // Key deletion is a separate mechanism — create fresh sessions and
    // verify key deletion cascades to sessions for that key
    let token_b = create_test_session(&state, &user.id, &user.email, &auth_b).await;
    let token_a3 = create_test_session(&state, &user.id, &user.email, &auth_a).await;

    // Delete Key A via session bound to Key B
    let (status, _) = http_delete(
        &app,
        &format!("/v1/keys/{auth_a}"),
        &[("Authorization", &format!("Bearer {token_b}"))],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // token_a3 should be dead (key deletion cascade)
    let (status, _) = http_get(
        &app,
        "/v1/keys",
        &[("Authorization", &format!("Bearer {token_a3}"))],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "Key deletion should cascade to key's sessions"
    );

    // token_b should still work (different key)
    let (status, _) = http_get(
        &app,
        "/v1/keys",
        &[("Authorization", &format!("Bearer {token_b}"))],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "Key B session should survive");
}

#[tokio::test]
async fn test_step_up_recovery() {
    // Login (>60s old) → delete fails → re-login → delete succeeds
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "cross-e8@example.com").await;
    let auth_a = create_test_authenticator(&state.store, &user.id).await;
    let auth_b = create_test_authenticator(&state.store, &user.id).await;

    // Stale session
    let stale_iat = jiff::Timestamp::now().as_second() - 600;
    let stale_token =
        create_test_session_with_iat(&state, &user.id, &user.email, &auth_a, stale_iat).await;

    // Delete fails due to step-up
    let response = http_delete_full(
        &app,
        &format!("/v1/keys/{auth_b}"),
        &[("Authorization", &format!("Bearer {stale_token}"))],
    )
    .await;
    assert_eq!(
        response.status,
        StatusCode::UNAUTHORIZED,
        "Stale session should be rejected"
    );

    // Fresh re-login
    let fresh_token = create_test_session(&state, &user.id, &user.email, &auth_a).await;

    // Delete now succeeds
    let (status, body) = http_delete(
        &app,
        &format!("/v1/keys/{auth_b}"),
        &[("Authorization", &format!("Bearer {fresh_token}"))],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "Fresh session should allow deletion: {body}"
    );
}
