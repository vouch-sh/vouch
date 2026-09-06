// SPDX-License-Identifier: Apache-2.0 OR MIT
#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable"
)]

use axum::http::StatusCode;

use crate::test_utils::*;

// ========================================================================
// Helper: create a test app owned by a user, returning (app_id, token)
// ========================================================================

async fn setup_user_with_app(state: &crate::AppState, email: &str) -> (String, String) {
    let user = create_test_user(&state.store, email).await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session_with(
        state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    let client = create_test_oauth_client(&state.store, &user.id).await;
    (client.app_id, token)
}

fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

// ========================================================================
// POST /api/v1/applications/:id/secrets — Add Secret
// ========================================================================

#[tokio::test]
async fn test_add_secret_success() {
    let (app, state) = test_app().await;
    let (app_id, token) = setup_user_with_app(&state, "add-secret@example.com").await;
    let auth = bearer(&token);

    let (status, body) = http_post_json(
        &app,
        &format!("/api/v1/applications/{app_id}/secrets"),
        r#"{}"#,
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(status, StatusCode::CREATED, "body: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid json");
    assert!(json.get("secret_id").is_some());
    assert!(json.get("client_secret").is_some());
    assert!(json.get("created_at").is_some());

    let secret_value = json["client_secret"].as_str().unwrap();
    assert!(secret_value.starts_with("vouch_"));
}

#[tokio::test]
async fn test_add_secret_with_description() {
    let (app, state) = test_app().await;
    let (app_id, token) = setup_user_with_app(&state, "add-desc@example.com").await;
    let auth = bearer(&token);

    let (status, _body) = http_post_json(
        &app,
        &format!("/api/v1/applications/{app_id}/secrets"),
        r#"{"description": "CI/CD pipeline"}"#,
        &[("Authorization", &auth)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // Verify description appears in list
    let (status, body) = http_get(
        &app,
        &format!("/api/v1/applications/{app_id}/secrets"),
        &[("Authorization", &auth)],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let json: serde_json::Value = serde_json::from_str(&body).expect("valid json");
    let secrets = json["secrets"].as_array().unwrap();
    let has_desc = secrets
        .iter()
        .any(|s| s["description"].as_str() == Some("CI/CD pipeline"));
    assert!(has_desc, "Description should be visible in list");
}

#[tokio::test]
async fn test_add_secret_max_reached() {
    let (app, state) = test_app().await;
    let (app_id, token) = setup_user_with_app(&state, "max-secrets@example.com").await;
    let auth = bearer(&token);

    // App already has 1 secret from creation. Add a second.
    let (status, _) = http_post_json(
        &app,
        &format!("/api/v1/applications/{app_id}/secrets"),
        r#"{}"#,
        &[("Authorization", &auth)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // Third should fail (max is 2 active)
    let (status, body) = http_post_json(
        &app,
        &format!("/api/v1/applications/{app_id}/secrets"),
        r#"{}"#,
        &[("Authorization", &auth)],
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid json");
    assert_eq!(json["code"], "max_secrets_reached");
}

#[tokio::test]
async fn test_add_secret_after_revoking_one() {
    let (app, state) = test_app().await;
    let (app_id, token) = setup_user_with_app(&state, "revoke-add@example.com").await;
    let auth = bearer(&token);

    // Add second secret (now at max)
    let (status, body) = http_post_json(
        &app,
        &format!("/api/v1/applications/{app_id}/secrets"),
        r#"{}"#,
        &[("Authorization", &auth)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let second: serde_json::Value = serde_json::from_str(&body).unwrap();
    let second_id = second["secret_id"].as_str().unwrap();

    // Revoke the second secret
    let (status, _) = http_delete(
        &app,
        &format!("/api/v1/applications/{app_id}/secrets/{second_id}"),
        &[("Authorization", &auth)],
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Now we should be able to add another
    let (status, _) = http_post_json(
        &app,
        &format!("/api/v1/applications/{app_id}/secrets"),
        r#"{}"#,
        &[("Authorization", &auth)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
}

#[tokio::test]
async fn test_add_secret_unauthenticated() {
    let (app, state) = test_app().await;
    let (app_id, _token) = setup_user_with_app(&state, "unauth@example.com").await;

    let (status, _body) = http_post_json(
        &app,
        &format!("/api/v1/applications/{app_id}/secrets"),
        r#"{}"#,
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_add_secret_wrong_owner() {
    let (app, state) = test_app().await;

    // Create app owned by user1
    let user1 = create_test_user(&state.store, "owner@example.com").await;
    let client = create_test_oauth_client(&state.store, &user1.id).await;

    // Authenticate as user2
    let user2 = create_test_user(&state.store, "other@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user2.id).await;
    let token2 = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user2.id,
            email: &user2.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    let auth = bearer(&token2);

    let (status, _) = http_post_json(
        &app,
        &format!("/api/v1/applications/{}/secrets", client.app_id),
        r#"{}"#,
        &[("Authorization", &auth)],
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_add_secret_nonexistent_app() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "noapp@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    let auth = bearer(&token);

    let bogus_id = uuid::Uuid::now_v7();
    let (status, _) = http_post_json(
        &app,
        &format!("/api/v1/applications/{bogus_id}/secrets"),
        r#"{}"#,
        &[("Authorization", &auth)],
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_add_secret_invalid_app_id() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "badid@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    let auth = bearer(&token);

    let (status, _) = http_post_json(
        &app,
        "/api/v1/applications/not-a-uuid/secrets",
        r#"{}"#,
        &[("Authorization", &auth)],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ========================================================================
// ValidPath<ValidUuid> rejection — other endpoints
// Each handler that uses ValidPath<ValidUuid> must return 400 for
// a malformed UUID path segment, before any auth or DB check.
// ========================================================================

async fn authed_user(state: &crate::AppState, email: &str) -> String {
    let user = create_test_user(&state.store, email).await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session_with(
        state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    bearer(&token)
}

#[tokio::test]
async fn test_get_application_invalid_uuid_returns_400() {
    let (app, state) = test_app().await;
    let auth = authed_user(&state, "get-badid@example.com").await;

    let (status, body) = http_get(
        &app,
        "/api/v1/applications/not-a-uuid",
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
}

#[tokio::test]
async fn test_delete_application_invalid_uuid_returns_400() {
    let (app, state) = test_app().await;
    let auth = authed_user(&state, "del-badid@example.com").await;

    let (status, body) = http_delete(
        &app,
        "/api/v1/applications/not-a-uuid",
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
}

#[tokio::test]
async fn test_list_secrets_invalid_uuid_returns_400() {
    let (app, state) = test_app().await;
    let auth = authed_user(&state, "list-badid@example.com").await;

    let (status, body) = http_get(
        &app,
        "/api/v1/applications/not-a-uuid/secrets",
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
}

#[tokio::test]
async fn test_revoke_tokens_invalid_uuid_returns_400() {
    let (app, state) = test_app().await;
    let auth = authed_user(&state, "revoke-badid@example.com").await;

    let (status, body) = http_post_json(
        &app,
        "/api/v1/applications/not-a-uuid/revoke",
        r#"{}"#,
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
}

#[tokio::test]
async fn test_delete_secret_invalid_app_id_returns_400() {
    let (app, state) = test_app().await;
    let auth = authed_user(&state, "del-sec-badappid@example.com").await;
    let valid_uuid = uuid::Uuid::now_v7();

    let (status, body) = http_delete(
        &app,
        &format!("/api/v1/applications/not-a-uuid/secrets/{valid_uuid}"),
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
}

#[tokio::test]
async fn test_delete_secret_invalid_secret_id_returns_400() {
    let (app, state) = test_app().await;
    let auth = authed_user(&state, "del-sec-badsecid@example.com").await;
    let valid_uuid = uuid::Uuid::now_v7();

    let (status, body) = http_delete(
        &app,
        &format!("/api/v1/applications/{valid_uuid}/secrets/not-a-uuid"),
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
}

#[tokio::test]
async fn test_invalid_uuid_error_response_is_json() {
    // ValidPath must return a JSON error body (not a plain string or HTML)
    // when the path param fails UUID validation.
    let (app, state) = test_app().await;
    let auth = authed_user(&state, "json-err@example.com").await;

    let (status, body) = http_post_json(
        &app,
        "/api/v1/applications/not-a-uuid/secrets",
        r#"{}"#,
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    // ServiceError::api produces {"code": "...", "message": "..."}
    let json: serde_json::Value =
        serde_json::from_str(&body).expect("error response must be valid JSON");
    assert!(
        json.get("code").is_some(),
        "JSON error response must contain 'code' field; got: {json}"
    );
}

// ========================================================================
// GET /api/v1/applications/:id/secrets — List Secrets
// ========================================================================

#[tokio::test]
async fn test_list_secrets_single() {
    let (app, state) = test_app().await;
    let (app_id, token) = setup_user_with_app(&state, "list-one@example.com").await;
    let auth = bearer(&token);

    let (status, body) = http_get(
        &app,
        &format!("/api/v1/applications/{app_id}/secrets"),
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid json");
    let secrets = json["secrets"].as_array().unwrap();
    assert_eq!(secrets.len(), 1);

    let s = &secrets[0];
    assert!(s.get("id").is_some());
    assert!(s.get("created_at").is_some());
    assert_eq!(s["active"], true);
    // secret_hash must NOT be exposed
    assert!(s.get("secret_hash").is_none());
}

#[tokio::test]
async fn test_list_secrets_shows_revoked() {
    let (app, state) = test_app().await;
    let (app_id, token) = setup_user_with_app(&state, "list-revoked@example.com").await;
    let auth = bearer(&token);

    // Add second secret
    let (_, body) = http_post_json(
        &app,
        &format!("/api/v1/applications/{app_id}/secrets"),
        r#"{}"#,
        &[("Authorization", &auth)],
    )
    .await;
    let second: serde_json::Value = serde_json::from_str(&body).unwrap();
    let second_id = second["secret_id"].as_str().unwrap();

    // Revoke it
    let (status, _) = http_delete(
        &app,
        &format!("/api/v1/applications/{app_id}/secrets/{second_id}"),
        &[("Authorization", &auth)],
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // List should show both (1 active, 1 revoked)
    let (status, body) = http_get(
        &app,
        &format!("/api/v1/applications/{app_id}/secrets"),
        &[("Authorization", &auth)],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let json: serde_json::Value = serde_json::from_str(&body).expect("valid json");
    let secrets = json["secrets"].as_array().unwrap();
    assert_eq!(secrets.len(), 2);

    let active_count = secrets.iter().filter(|s| s["active"] == true).count();
    let revoked_count = secrets.iter().filter(|s| s["active"] == false).count();
    assert_eq!(active_count, 1);
    assert_eq!(revoked_count, 1);
}

#[tokio::test]
async fn test_list_secrets_wrong_owner() {
    let (app, state) = test_app().await;

    let user1 = create_test_user(&state.store, "owner2@example.com").await;
    let client = create_test_oauth_client(&state.store, &user1.id).await;

    let user2 = create_test_user(&state.store, "other2@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user2.id).await;
    let token2 = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user2.id,
            email: &user2.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    let auth = bearer(&token2);

    let (status, _) = http_get(
        &app,
        &format!("/api/v1/applications/{}/secrets", client.app_id),
        &[("Authorization", &auth)],
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ========================================================================
// DELETE /api/v1/applications/:id/secrets/:secret_id — Delete Secret
// ========================================================================

#[tokio::test]
async fn test_delete_secret_success() {
    let (app, state) = test_app().await;
    let (app_id, token) = setup_user_with_app(&state, "del-ok@example.com").await;
    let auth = bearer(&token);

    // Add second secret
    let (_, body) = http_post_json(
        &app,
        &format!("/api/v1/applications/{app_id}/secrets"),
        r#"{}"#,
        &[("Authorization", &auth)],
    )
    .await;
    let second: serde_json::Value = serde_json::from_str(&body).unwrap();
    let second_id = second["secret_id"].as_str().unwrap();

    // Delete the second secret
    let (status, _) = http_delete(
        &app,
        &format!("/api/v1/applications/{app_id}/secrets/{second_id}"),
        &[("Authorization", &auth)],
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Verify it shows as inactive in list
    let (_, body) = http_get(
        &app,
        &format!("/api/v1/applications/{app_id}/secrets"),
        &[("Authorization", &auth)],
    )
    .await;
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    let secrets = json["secrets"].as_array().unwrap();
    let deleted = secrets.iter().find(|s| s["id"] == second_id).unwrap();
    assert_eq!(deleted["active"], false);
}

#[tokio::test]
async fn test_delete_last_secret_rejected() {
    let (app, state) = test_app().await;
    let (app_id, token) = setup_user_with_app(&state, "del-last@example.com").await;
    let auth = bearer(&token);

    // Get the only secret's ID
    let (_, body) = http_get(
        &app,
        &format!("/api/v1/applications/{app_id}/secrets"),
        &[("Authorization", &auth)],
    )
    .await;
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    let secret_id = json["secrets"][0]["id"].as_str().unwrap();

    // Try to delete it
    let (status, body) = http_delete(
        &app,
        &format!("/api/v1/applications/{app_id}/secrets/{secret_id}"),
        &[("Authorization", &auth)],
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid json");
    assert_eq!(json["code"], "last_secret");
}

#[tokio::test]
async fn test_delete_already_revoked() {
    let (app, state) = test_app().await;
    let (app_id, token) = setup_user_with_app(&state, "del-revoked@example.com").await;
    let auth = bearer(&token);

    // Add and then revoke a secret
    let (_, body) = http_post_json(
        &app,
        &format!("/api/v1/applications/{app_id}/secrets"),
        r#"{}"#,
        &[("Authorization", &auth)],
    )
    .await;
    let second: serde_json::Value = serde_json::from_str(&body).unwrap();
    let second_id = second["secret_id"].as_str().unwrap();

    let (status, _) = http_delete(
        &app,
        &format!("/api/v1/applications/{app_id}/secrets/{second_id}"),
        &[("Authorization", &auth)],
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Try to delete again
    let (status, _) = http_delete(
        &app,
        &format!("/api/v1/applications/{app_id}/secrets/{second_id}"),
        &[("Authorization", &auth)],
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_delete_secret_wrong_app() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "wrong-app@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    let auth = bearer(&token);

    // Create two apps
    let client1 = create_test_oauth_client(&state.store, &user.id).await;
    let client2 = create_test_oauth_client(&state.store, &user.id).await;

    // Get secret from app2
    let (_, body) = http_get(
        &app,
        &format!("/api/v1/applications/{}/secrets", client2.app_id),
        &[("Authorization", &auth)],
    )
    .await;
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    let secret2_id = json["secrets"][0]["id"].as_str().unwrap();

    // Try to delete app2's secret via app1's route
    let (status, _) = http_delete(
        &app,
        &format!(
            "/api/v1/applications/{}/secrets/{secret2_id}",
            client1.app_id
        ),
        &[("Authorization", &auth)],
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_delete_secret_wrong_owner() {
    let (app, state) = test_app().await;

    let user1 = create_test_user(&state.store, "del-owner1@example.com").await;
    let client = create_test_oauth_client(&state.store, &user1.id).await;

    let user2 = create_test_user(&state.store, "del-owner2@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user2.id).await;
    let token2 = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user2.id,
            email: &user2.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    let auth = bearer(&token2);

    // Get secret ID from app (via db directly, since API would 404)
    let secrets = crate::db::get_oauth_client_secrets(&state.store, &client.app_id)
        .await
        .unwrap();
    let secret_id = &secrets[0].id;

    let (status, _) = http_delete(
        &app,
        &format!("/api/v1/applications/{}/secrets/{secret_id}", client.app_id),
        &[("Authorization", &auth)],
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ========================================================================
// Edge Case: last-secret protection with revoked secrets
// ========================================================================

#[tokio::test]
async fn test_cannot_delete_sole_active_when_other_revoked() {
    let (app, state) = test_app().await;
    let (app_id, token) = setup_user_with_app(&state, "sole-active@example.com").await;
    let auth = bearer(&token);

    // Add second secret (now 2 active)
    let (_, body) = http_post_json(
        &app,
        &format!("/api/v1/applications/{app_id}/secrets"),
        r#"{}"#,
        &[("Authorization", &auth)],
    )
    .await;
    let second: serde_json::Value = serde_json::from_str(&body).unwrap();
    let second_id = second["secret_id"].as_str().unwrap();

    // Revoke the second (now 1 active + 1 revoked)
    let (status, _) = http_delete(
        &app,
        &format!("/api/v1/applications/{app_id}/secrets/{second_id}"),
        &[("Authorization", &auth)],
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Get the remaining active secret's ID
    let (_, body) = http_get(
        &app,
        &format!("/api/v1/applications/{app_id}/secrets"),
        &[("Authorization", &auth)],
    )
    .await;
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    let secrets = json["secrets"].as_array().unwrap();
    let active_secret = secrets
        .iter()
        .find(|s| s["active"] == true)
        .expect("should have 1 active secret");
    let active_id = active_secret["id"].as_str().unwrap();

    // Trying to delete the sole active secret should fail,
    // even though there's a revoked secret present
    let (status, body) = http_delete(
        &app,
        &format!("/api/v1/applications/{app_id}/secrets/{active_id}"),
        &[("Authorization", &auth)],
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid json");
    assert_eq!(json["code"], "last_secret");
}

// ========================================================================
// Validation-before-auth tests (Phase 1C defense-in-depth)
// ========================================================================

#[tokio::test]
async fn test_create_app_empty_name_returns_400_without_auth() {
    let (app, _state) = test_app().await;

    let (status, body) = http_post_json(
        &app,
        "/api/v1/applications",
        r#"{"name": "  ", "application_type": "web", "redirect_uris": ["https://example.com/cb"]}"#,
        &[], // No auth header
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Empty name must return 400 (not 401) even without auth: {body}"
    );
}

#[tokio::test]
async fn test_create_app_invalid_type_returns_400_without_auth() {
    let (app, _state) = test_app().await;

    let (status, body) = http_post_json(
        &app,
        "/api/v1/applications",
        r#"{"name": "Test", "application_type": "invalid", "redirect_uris": ["https://example.com/cb"]}"#,
        &[], // No auth header
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Invalid app type must return 400 (not 401) even without auth: {body}"
    );
}

#[tokio::test]
async fn test_create_app_malformed_redirect_uri_returns_400_without_auth() {
    let (app, _state) = test_app().await;

    let (status, body) = http_post_json(
        &app,
        "/api/v1/applications",
        r#"{"name": "Test", "application_type": "web", "redirect_uris": ["not-a-url"]}"#,
        &[], // No auth header
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Malformed redirect URI must return 400 (not 401) even without auth: {body}"
    );
}

#[tokio::test]
async fn test_create_app_invalid_jwks_returns_400_without_auth() {
    let (app, _state) = test_app().await;

    let (status, body) = http_post_json(
        &app,
        "/api/v1/applications",
        r#"{"name": "Test", "application_type": "web", "redirect_uris": ["https://example.com/cb"], "jwks": "not-json"}"#,
        &[], // No auth header
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Invalid JWKS must return 400 (not 401) even without auth: {body}"
    );
}

// ========================================================================
// GET /api/v1/applications — List Applications
// ========================================================================

#[tokio::test]
async fn test_list_applications_empty() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "list-empty@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    let auth = bearer(&token);

    let (status, body) = http_get(&app, "/api/v1/applications", &[("Authorization", &auth)]).await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid json");
    assert_eq!(json["applications"], serde_json::json!([]));
}

#[tokio::test]
async fn test_list_applications_returns_created() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "list-created@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    let auth = bearer(&token);

    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (status, body) = http_get(&app, "/api/v1/applications", &[("Authorization", &auth)]).await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid json");
    let apps = json["applications"].as_array().unwrap();
    assert_eq!(apps.len(), 1);
    assert_eq!(apps[0]["id"].as_str().unwrap(), client.app_id);
}

#[tokio::test]
async fn test_list_applications_requires_auth() {
    let (app, _state) = test_app().await;

    let (status, _body) = http_get(&app, "/api/v1/applications", &[]).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ========================================================================
// POST /api/v1/applications — Create Application
// ========================================================================

#[tokio::test]
async fn test_create_application_succeeds() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "create-ok@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    let auth = bearer(&token);

    let (status, body) = http_post_json(
        &app,
        "/api/v1/applications",
        r#"{"name": "My App", "application_type": "web", "redirect_uris": ["https://example.com/callback"]}"#,
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid json");
    assert!(json.get("id").is_some());
    assert_eq!(json["name"].as_str().unwrap(), "My App");
    assert_eq!(json["application_type"].as_str().unwrap(), "web");
}

#[tokio::test]
async fn test_create_application_returns_client_credentials() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "create-creds@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    let auth = bearer(&token);

    let (status, body) = http_post_json(
        &app,
        "/api/v1/applications",
        r#"{"name": "Creds App", "application_type": "web", "redirect_uris": ["https://example.com/callback"]}"#,
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid json");

    let client_id = json["client_id"].as_str().unwrap();
    let client_secret = json["client_secret"].as_str().unwrap();
    assert!(!client_id.is_empty(), "client_id must not be empty");
    assert!(!client_secret.is_empty(), "client_secret must not be empty");
    assert!(
        client_secret.starts_with("vouch_"),
        "client_secret must have expected prefix"
    );
}

/// RFC 7591 §2 (https://www.rfc-editor.org/rfc/rfc7591#section-2),
/// `token_endpoint_auth_method`:
///
/// > "none": The client is a public client as defined in OAuth 2.0,
/// > Section 2.1, and does not have a client secret.
///
/// SPA clients are issued no secret, so they must be stored as public
/// clients — otherwise the token endpoint's public-client chokepoint
/// (`NoClientAuth::for_public_client`) rejects them with `invalid_client`
/// and no authorization-code flow can complete.
#[tokio::test]
async fn test_create_spa_application_is_public_client() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "spa-public@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    let auth = bearer(&token);

    let (status, body) = http_post_json(
        &app,
        "/api/v1/applications",
        r#"{"name": "SPA App", "application_type": "spa", "redirect_uris": ["https://app.example.com/callback"]}"#,
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid json");
    assert!(
        json["client_secret"].is_null(),
        "public clients must not be issued a secret"
    );

    let client_id = json["client_id"].as_str().unwrap();
    let client = crate::db::get_oauth_client_by_client_id(&state.store, client_id)
        .await
        .expect("lookup")
        .expect("client exists");
    assert_eq!(
        client.token_endpoint_auth_method,
        crate::db::TokenEndpointAuthMethod::None,
        "secretless client types must be stored as public clients"
    );
    assert!(
        crate::services::auth::NoClientAuth::for_public_client(&client).is_ok(),
        "token endpoint must accept the SPA client as public"
    );
}

/// Same invariant as the SPA case: `native` clients are issued no secret
/// and must be stored as public clients (RFC 7591 §2 `"none"`).
#[tokio::test]
async fn test_create_native_application_is_public_client() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "native-public@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    let auth = bearer(&token);

    let (status, body) = http_post_json(
        &app,
        "/api/v1/applications",
        r#"{"name": "Native App", "application_type": "native", "redirect_uris": ["http://127.0.0.1:8400/callback"]}"#,
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid json");
    assert!(json["client_secret"].is_null());

    let client_id = json["client_id"].as_str().unwrap();
    let client = crate::db::get_oauth_client_by_client_id(&state.store, client_id)
        .await
        .expect("lookup")
        .expect("client exists");
    assert_eq!(
        client.token_endpoint_auth_method,
        crate::db::TokenEndpointAuthMethod::None,
    );
    assert!(crate::services::auth::NoClientAuth::for_public_client(&client).is_ok());
}

/// Confidential (`web`) clients keep the RFC 7591 §2 default:
///
/// > If unspecified or omitted, the default is "client_secret_basic",
/// > denoting the HTTP Basic authentication scheme as specified in
/// > Section 2.3.1 of OAuth 2.0.
#[tokio::test]
async fn test_create_web_application_is_confidential_client() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "web-confidential@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    let auth = bearer(&token);

    let (status, body) = http_post_json(
        &app,
        "/api/v1/applications",
        r#"{"name": "Web App", "application_type": "web", "redirect_uris": ["https://example.com/callback"]}"#,
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid json");
    assert!(json["client_secret"].as_str().is_some());

    let client_id = json["client_id"].as_str().unwrap();
    let client = crate::db::get_oauth_client_by_client_id(&state.store, client_id)
        .await
        .expect("lookup")
        .expect("client exists");
    assert_eq!(
        client.token_endpoint_auth_method,
        crate::db::TokenEndpointAuthMethod::ClientSecretBasic,
    );
}

#[tokio::test]
async fn test_create_application_requires_auth() {
    let (app, _state) = test_app().await;

    let (status, _body) = http_post_json(
        &app,
        "/api/v1/applications",
        r#"{"name": "App", "application_type": "web", "redirect_uris": ["https://example.com/cb"]}"#,
        &[],
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_create_application_rejects_deactivated_user() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "deactivated-create@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    let auth = bearer(&token);

    crate::db::update_user_active_status(&state.store, &user.id, false)
        .await
        .expect("deactivate user");

    let (status, body) = http_post_json(
        &app,
        "/api/v1/applications",
        r#"{"name":"Test App","application_type":"web","redirect_uris":["https://example.com/cb"]}"#,
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["code"], "unauthorized");
    assert_eq!(error["message"], "User account is deactivated");
}

#[tokio::test]
async fn test_create_application_rejects_empty_name() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "create-emptyname@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    let auth = bearer(&token);

    let (status, body) = http_post_json(
        &app,
        "/api/v1/applications",
        r#"{"name": "", "application_type": "web", "redirect_uris": ["https://example.com/cb"]}"#,
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid json");
    assert_eq!(json["code"].as_str().unwrap(), "invalid_name");
}

#[tokio::test]
async fn test_create_application_rejects_http_redirect_uri() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "create-http-uri@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    let auth = bearer(&token);

    // http:// redirect URIs are not valid for web apps — only https:// or custom schemes
    let (status, body) = http_post_json(
        &app,
        "/api/v1/applications",
        r#"{"name": "App", "application_type": "web", "redirect_uris": ["not-a-url"]}"#,
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid json");
    assert_eq!(json["code"].as_str().unwrap(), "invalid_redirect_uris");
}

// ========================================================================
// GET /api/v1/applications/:id — Get Application
// ========================================================================

#[tokio::test]
async fn test_get_application_by_id() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "get-app@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    let auth = bearer(&token);
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (status, body) = http_get(
        &app,
        &format!("/api/v1/applications/{}", client.app_id),
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid json");
    assert_eq!(json["id"].as_str().unwrap(), client.app_id);
}

#[tokio::test]
async fn test_get_application_not_found() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "get-notfound@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    let auth = bearer(&token);
    let bogus_id = uuid::Uuid::now_v7();

    let (status, _body) = http_get(
        &app,
        &format!("/api/v1/applications/{bogus_id}"),
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_get_application_requires_auth() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "get-noauth@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (status, _body) = http_get(
        &app,
        &format!("/api/v1/applications/{}", client.app_id),
        &[],
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ========================================================================
// PATCH /api/v1/applications/:id — Update Application
// ========================================================================

#[tokio::test]
async fn test_update_application_name() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "update-name@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    let auth = bearer(&token);
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let body = r#"{"name": "Renamed App"}"#.to_string();
    let (status, resp_body) = http_request(
        &app,
        "PATCH",
        &format!("/api/v1/applications/{}", client.app_id),
        Some(body),
        &[
            ("Content-Type", "application/json"),
            ("Authorization", &auth),
        ],
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {resp_body}");
    let json: serde_json::Value = serde_json::from_str(&resp_body).expect("valid json");
    assert_eq!(json["name"].as_str().unwrap(), "Renamed App");
}

#[tokio::test]
async fn test_update_application_rejects_deactivated_user() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "deactivated-update@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    let auth = bearer(&token);
    let client = create_test_oauth_client(&state.store, &user.id).await;

    crate::db::update_user_active_status(&state.store, &user.id, false)
        .await
        .expect("deactivate user");

    let (status, body) = http_request(
        &app,
        "PATCH",
        &format!("/api/v1/applications/{}", client.app_id),
        Some(r#"{"name": "Renamed App"}"#.to_string()),
        &[
            ("Content-Type", "application/json"),
            ("Authorization", &auth),
        ],
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["code"], "unauthorized");
    assert_eq!(error["message"], "User account is deactivated");
}

// ========================================================================
// DELETE /api/v1/applications/:id — Delete Application
// ========================================================================

#[tokio::test]
async fn test_delete_application_succeeds() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "delete-ok@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    let auth = bearer(&token);
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (status, _body) = http_delete(
        &app,
        &format!("/api/v1/applications/{}", client.app_id),
        &[("Authorization", &auth)],
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Subsequent GET returns 404
    let (status, _body) = http_get(
        &app,
        &format!("/api/v1/applications/{}", client.app_id),
        &[("Authorization", &auth)],
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_delete_application_not_found() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "delete-notfound@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    let auth = bearer(&token);
    let bogus_id = uuid::Uuid::now_v7();

    let (status, _body) = http_delete(
        &app,
        &format!("/api/v1/applications/{bogus_id}"),
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_delete_application_requires_auth() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "delete-noauth@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (status, _body) = http_delete(
        &app,
        &format!("/api/v1/applications/{}", client.app_id),
        &[],
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ========================================================================
// POST /api/v1/applications/:id/revoke — Revoke Tokens
// ========================================================================

#[tokio::test]
async fn test_revoke_tokens_requires_auth() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "revoke-noauth@example.com").await;
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (status, _body) = http_post_json(
        &app,
        &format!("/api/v1/applications/{}/revoke", client.app_id),
        "{}",
        &[],
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_revoke_tokens_not_found() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "revoke-notfound@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    let auth = bearer(&token);
    let bogus_id = uuid::Uuid::now_v7();

    let (status, _body) = http_post_json(
        &app,
        &format!("/api/v1/applications/{bogus_id}/revoke"),
        "{}",
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ========================================================================
// #539 — revoke_tokens also invalidates M2M (client_credentials) sessions
// ========================================================================

// Count SessionDoc rows indexed under a given user_id.
// For client_credentials grants the session's user_id is the client_id.
async fn count_sessions_for_user(store: &crate::db::store::DocumentStore, user_id: &str) -> i64 {
    store
        .count::<crate::db::documents::session::SessionDoc>("user_id", user_id)
        .await
        .expect("count must not error")
}

#[tokio::test]
async fn test_revoke_tokens_clears_m2m_sessions() {
    let (app, state) = test_app().await;

    // Owner user + their application
    let user = create_test_user(&state.store, "revoke-m2m@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let owner_token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    let auth = bearer(&owner_token);
    let client = create_test_oauth_client(&state.store, &user.id).await;

    // Mint a client_credentials session for the OAuth client.
    // Per RFC 9068 §2.2 the session's user_id is the client's client_id.
    create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &client.client_id,
            email: &format!("{}@clients", client.client_id),
            auth_id: Some(&auth_id),
            client_id: Some(&client.client_id),
            ..Default::default()
        },
    )
    .await;

    // Confirm the M2M session exists before revocation.
    let before = count_sessions_for_user(&state.store, &client.client_id).await;
    assert!(
        before >= 1,
        "should have at least one M2M session before revoke"
    );

    // Issue revoke
    let (status, _) = http_post_json(
        &app,
        &format!("/api/v1/applications/{}/revoke", client.app_id),
        "{}",
        &[("Authorization", &auth)],
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // M2M sessions must be gone after revocation.
    let after = count_sessions_for_user(&state.store, &client.client_id).await;
    assert_eq!(after, 0, "M2M sessions must be deleted by revoke");
}

// ========================================================================
// #539 (follow-up) — revoke_tokens also revokes user-issued access tokens
// (authorization_code, device_code, RFC 8693 token_exchange, FIDO2).
// These grants persist sessions under the *real resource owner's* user_id,
// not the client's, so the M2M-only delete (user_id == client_id) misses
// them. The client_id index on SessionDoc lets revoke_tokens_api reach
// every token an application minted.
// ========================================================================

// Count SessionDoc rows indexed under a given client_id.
async fn count_sessions_for_client(
    store: &crate::db::store::DocumentStore,
    client_id: &str,
) -> i64 {
    store
        .count::<crate::db::documents::session::SessionDoc>("client_id", client_id)
        .await
        .expect("count must not error")
}

// Probe whether an access token still validates at the userinfo resource
// endpoint. 200 means the session is live; 401 means it has been revoked.
async fn userinfo_status(app: &axum::Router, token: &str) -> StatusCode {
    let (status, _) = http_get(app, "/oauth/userinfo", &[("Authorization", &bearer(token))]).await;
    status
}

/// A user-issued access token minted for the revoked client must stop
/// validating after `revoke_tokens_api`, and its session row must be gone.
///
/// Regression for the bug where `revoke_tokens_api` only deleted
/// `client_credentials` (M2M) sessions — keyed by `user_id == client_id` —
/// and left every user-issued grant (`authorization_code`, `device_code`,
/// RFC 8693 `token_exchange`, FIDO2) alive until `exp`. The fixture mints a
/// real `OAuthAccessToken` session through `create_test_session_with` (which
/// drives the production `create_oauth_access_token` path) with
/// `user_id == real_user` and `client_id == the_oauth_client`, exactly the
/// shape of a user-issued grant, then confirms the userinfo endpoint flips
/// from 200 to 401 across the revoke call.
#[tokio::test]
async fn test_revoke_tokens_revokes_user_issued_access_tokens() {
    let (app, state) = test_app().await;

    // Owner user + their OAuth application.
    let user = create_test_user(&state.store, "revoke-user@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let owner_token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    let auth = bearer(&owner_token);
    let client = create_test_oauth_client(&state.store, &user.id).await;

    // A real user-issued access token for this client. The session row is
    // keyed by the real user's user_id (per RFC 9068 for authorization_code,
    // device_code, token_exchange, FIDO2) but tagged with the issuing client.
    let user_access_token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            client_id: Some(&client.client_id),
            ..Default::default()
        },
    )
    .await;

    // The user-issued token validates before revoke.
    assert_eq!(
        userinfo_status(&app, &user_access_token).await,
        StatusCode::OK,
        "user access token should validate before revoke"
    );
    assert!(
        count_sessions_for_client(&state.store, &client.client_id).await >= 1,
        "client should have at least one user-issued session before revoke"
    );

    // Mint a second client owned by the same user, with its own user-issued
    // token, to prove revoke is scoped to a single application and does not
    // over-revoke sibling clients' tokens.
    let other_client = create_test_oauth_client(&state.store, &user.id).await;
    let other_token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            client_id: Some(&other_client.client_id),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(
        userinfo_status(&app, &other_token).await,
        StatusCode::OK,
        "other client's token should validate before revoke"
    );

    // Owner revokes all tokens for `client`. 204 + "All tokens revoked".
    let (status, _) = http_post_json(
        &app,
        &format!("/api/v1/applications/{}/revoke", client.app_id),
        "{}",
        &[("Authorization", &auth)],
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // The user-issued access token for the revoked client must now be dead.
    assert_eq!(
        userinfo_status(&app, &user_access_token).await,
        StatusCode::UNAUTHORIZED,
        "user-issued access token must NOT validate after revoke_tokens_api"
    );

    // Its session row is gone, indexed by the issuing client.
    assert_eq!(
        count_sessions_for_client(&state.store, &client.client_id).await,
        0,
        "user-issued sessions for the revoked client must be deleted"
    );

    // M2M sessions for the revoked client are also gone (the M2M half still
    // works alongside the new user-issued delete).
    create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &client.client_id,
            email: &format!("{}@clients", client.client_id),
            auth_id: Some(&auth_id),
            client_id: Some(&client.client_id),
            ..Default::default()
        },
    )
    .await;
    // Re-revoke to clear the M2M session just minted, confirming both halves
    // of the delete coexist.
    let (status, _) = http_post_json(
        &app,
        &format!("/api/v1/applications/{}/revoke", client.app_id),
        "{}",
        &[("Authorization", &auth)],
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        count_sessions_for_user(&state.store, &client.client_id).await,
        0,
        "M2M sessions must also be deleted by revoke"
    );

    // No over-revocation: the sibling client's token is still valid.
    assert_eq!(
        userinfo_status(&app, &other_token).await,
        StatusCode::OK,
        "revoking one client must not revoke another client's tokens"
    );
    assert!(
        count_sessions_for_client(&state.store, &other_client.client_id).await >= 1,
        "sibling client's sessions must survive revoking the other client"
    );
}

// ========================================================================
// #546 — update validates empty redirect_uris and empty name
// ========================================================================

#[tokio::test]
async fn test_update_application_should_reject_empty_redirect_uris() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "update-no-uris@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    let auth = bearer(&token);
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (status, body) = http_request(
        &app,
        "PATCH",
        &format!("/api/v1/applications/{}", client.app_id),
        Some(r#"{"redirect_uris": []}"#.to_string()),
        &[
            ("Content-Type", "application/json"),
            ("Authorization", &auth),
        ],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid json");
    assert_eq!(json["code"], "invalid_redirect_uris", "body: {body}");
}

// Regression for #743: a FAPI client authenticates with private_key_jwt and
// holds no client secret. Switching it to a standard profile set
// client_secret_basic without minting one, so every later token request
// failed with invalid_client. The update must be refused outright.
#[tokio::test]
async fn test_update_application_rejects_fapi_downgrade() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "fapi-downgrade@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    let auth = bearer(&token);

    let client = create_test_client(
        &state.store,
        &user.id,
        TestClientSpec {
            fapi_profile: Some(crate::db::FapiProfile::Fapi2Security),
            token_endpoint_auth_method: Some(crate::db::TokenEndpointAuthMethod::PrivateKeyJwt),
            jwks: TestJwks::Shared,
            dpop_bound_access_tokens: true,
            with_secret: false,
            ..Default::default()
        },
    )
    .await;

    let (status, body) = http_request(
        &app,
        "PATCH",
        &format!("/api/v1/applications/{}", client.app_id),
        Some(r#"{"fapi_profile": "none"}"#.to_string()),
        &[
            ("Content-Type", "application/json"),
            ("Authorization", &auth),
        ],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid json");
    assert_eq!(json["code"], "fapi_downgrade_unsupported", "body: {body}");

    // The rejection must leave the client untouched — in particular it must
    // not be left on client_secret_basic with no secret.
    let persisted = crate::db::get_oauth_client_by_id(&state.store, &client.app_id)
        .await
        .expect("db lookup")
        .expect("client still exists");
    assert!(persisted.is_fapi(), "client must remain FAPI");
    assert_eq!(
        persisted.token_endpoint_auth_method,
        crate::db::TokenEndpointAuthMethod::PrivateKeyJwt,
        "auth method must be unchanged"
    );
}

// Regression: a non-FAPI `private_key_jwt` client (e.g. one created via
// authenticated dynamic registration) carries JWKS for `private_key_jwt`
// auth. A PATCH that omits both `fapi_profile` and `jwks` must preserve the
// existing JWKS so the client can still authenticate. Previously the JWKS was
// silently cleared, breaking all subsequent token requests.
#[tokio::test]
async fn test_update_application_preserves_jwks_when_fapi_profile_absent() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "pkjwt-preserve@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    let auth = bearer(&token);

    let client = create_test_client(
        &state.store,
        &user.id,
        TestClientSpec {
            token_endpoint_auth_method: Some(crate::db::TokenEndpointAuthMethod::PrivateKeyJwt),
            jwks: TestJwks::Shared,
            fapi_profile: None,
            with_secret: false,
            ..Default::default()
        },
    )
    .await;

    let (status, body) = http_request(
        &app,
        "PATCH",
        &format!("/api/v1/applications/{}", client.app_id),
        Some(r#"{"name": "Updated Name"}"#.to_string()),
        &[
            ("Content-Type", "application/json"),
            ("Authorization", &auth),
        ],
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");

    let persisted = crate::db::get_oauth_client_by_id(&state.store, &client.app_id)
        .await
        .expect("db lookup")
        .expect("client still exists");
    assert!(
        persisted
            .keys
            .as_ref()
            .is_some_and(|k| k.inline().is_some()),
        "JWKS must be preserved after update that omits fapi_profile"
    );
    assert_eq!(
        persisted.token_endpoint_auth_method,
        crate::db::TokenEndpointAuthMethod::PrivateKeyJwt,
        "auth method must be unchanged"
    );
}

// Complement: explicitly setting `fapi_profile: "none"` on a non-FAPI
// Clearing JWKS on a `private_key_jwt` client would leave it unable to
// authenticate, with no way back through this endpoint. Refuse it end to end.
#[tokio::test]
async fn test_update_application_rejects_clearing_jwks_for_pkjwt_client() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "pkjwt-clear@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    let auth = bearer(&token);

    let client = create_test_client(
        &state.store,
        &user.id,
        TestClientSpec {
            token_endpoint_auth_method: Some(crate::db::TokenEndpointAuthMethod::PrivateKeyJwt),
            jwks: TestJwks::Shared,
            fapi_profile: None,
            with_secret: false,
            ..Default::default()
        },
    )
    .await;

    let (status, body) = http_request(
        &app,
        "PATCH",
        &format!("/api/v1/applications/{}", client.app_id),
        Some(r#"{"fapi_profile": "none"}"#.to_string()),
        &[
            ("Content-Type", "application/json"),
            ("Authorization", &auth),
        ],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert!(
        body.contains("missing_jwks"),
        "error code should identify the missing keys: {body}"
    );

    let persisted = crate::db::get_oauth_client_by_id(&state.store, &client.app_id)
        .await
        .expect("db lookup")
        .expect("client still exists");
    assert!(
        persisted
            .keys
            .as_ref()
            .is_some_and(|k| k.inline().is_some()),
        "a rejected update must leave the client's keys intact"
    );
}

#[tokio::test]
async fn test_update_application_should_reject_empty_name() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "update-empty-name@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    let auth = bearer(&token);
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (status, body) = http_request(
        &app,
        "PATCH",
        &format!("/api/v1/applications/{}", client.app_id),
        Some(r#"{"name": ""}"#.to_string()),
        &[
            ("Content-Type", "application/json"),
            ("Authorization", &auth),
        ],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid json");
    assert_eq!(json["code"], "invalid_name", "body: {body}");
}

#[tokio::test]
async fn test_update_application_absent_name_keeps_existing() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "update-no-name@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    let auth = bearer(&token);
    let client = create_test_oauth_client(&state.store, &user.id).await;

    // PATCH without a `name` field must preserve the existing name.
    let (status, body) = http_request(
        &app,
        "PATCH",
        &format!("/api/v1/applications/{}", client.app_id),
        Some(r#"{"redirect_uris": ["https://example.com/cb"]}"#.to_string()),
        &[
            ("Content-Type", "application/json"),
            ("Authorization", &auth),
        ],
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid json");
    assert_eq!(json["name"].as_str().unwrap(), "Test App");
}

// ================================================================
// post_logout_redirect_uris — applications JSON API
// ================================================================

#[tokio::test]
async fn test_create_application_with_post_logout_redirect_uris() {
    // POST /api/v1/applications with post_logout_redirect_uris should store them
    // and echo them back in the create response, mirroring resource_uris.
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "post-logout-create@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    let auth = bearer(&token);

    let payload = serde_json::json!({
        "name": "Logout Test App",
        "application_type": "web",
        "redirect_uris": ["https://example.com/callback"],
        "post_logout_redirect_uris": ["https://example.com/logged-out"]
    });

    let (status, body) = http_request(
        &app,
        "POST",
        "/api/v1/applications",
        Some(payload.to_string()),
        &[
            ("Content-Type", "application/json"),
            ("Authorization", &auth),
        ],
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    let create_json: serde_json::Value = serde_json::from_str(&body).expect("valid json");
    let app_id = create_json["id"].as_str().expect("id in create response");

    // The create response itself must echo post_logout_redirect_uris (#574).
    let created_post_logout = create_json["post_logout_redirect_uris"]
        .as_array()
        .expect("post_logout_redirect_uris must be present in create response");
    assert_eq!(
        created_post_logout.len(),
        1,
        "Expected 1 post_logout_redirect_uri in create response, got {created_post_logout:?}"
    );
    assert_eq!(
        created_post_logout[0].as_str().unwrap(),
        "https://example.com/logged-out"
    );

    // Verify the stored post_logout_redirect_uris via GET.
    let (get_status, get_body) = http_request(
        &app,
        "GET",
        &format!("/api/v1/applications/{app_id}"),
        None,
        &[("Authorization", &auth)],
    )
    .await;
    assert_eq!(get_status, StatusCode::OK, "GET body: {get_body}");
    let get_json: serde_json::Value = serde_json::from_str(&get_body).expect("valid json");
    let post_logout = get_json["post_logout_redirect_uris"]
        .as_array()
        .expect("post_logout_redirect_uris must be present in GET response");
    assert_eq!(
        post_logout.len(),
        1,
        "Expected 1 post_logout_redirect_uri, got {post_logout:?}"
    );
    assert_eq!(
        post_logout[0].as_str().unwrap(),
        "https://example.com/logged-out"
    );
}

#[tokio::test]
async fn test_create_application_rejects_invalid_post_logout_redirect_uri() {
    // A post_logout_redirect_uri with ftp:// scheme must be rejected.
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "post-logout-invalid-create@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    let auth = bearer(&token);

    let payload = serde_json::json!({
        "name": "Bad Logout App",
        "application_type": "web",
        "redirect_uris": ["https://example.com/callback"],
        "post_logout_redirect_uris": ["ftp://example.com/logged-out"]
    });

    let (status, body) = http_request(
        &app,
        "POST",
        "/api/v1/applications",
        Some(payload.to_string()),
        &[
            ("Content-Type", "application/json"),
            ("Authorization", &auth),
        ],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid json");
    assert_eq!(
        json["code"], "invalid_post_logout_redirect_uris",
        "body: {body}"
    );
}

#[tokio::test]
async fn test_update_application_post_logout_redirect_uris_roundtrip() {
    // PATCH /api/v1/applications/:id with post_logout_redirect_uris should store and return them.
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "post-logout-update@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    let auth = bearer(&token);
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let payload = serde_json::json!({
        "post_logout_redirect_uris": ["https://example.com/logged-out"]
    });

    let (status, body) = http_request(
        &app,
        "PATCH",
        &format!("/api/v1/applications/{}", client.app_id),
        Some(payload.to_string()),
        &[
            ("Content-Type", "application/json"),
            ("Authorization", &auth),
        ],
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid json");
    let post_logout = json["post_logout_redirect_uris"]
        .as_array()
        .expect("post_logout_redirect_uris must be present after PATCH");
    assert_eq!(
        post_logout.len(),
        1,
        "Expected 1 post_logout_redirect_uri, got {post_logout:?}"
    );
    assert_eq!(
        post_logout[0].as_str().unwrap(),
        "https://example.com/logged-out"
    );
}

// ========================================================================
// Invalid enum values for access_scope / fapi_profile must be rejected
// with 400, not silently coerced to defaults.
// ========================================================================

#[tokio::test]
async fn test_create_application_rejects_invalid_access_scope() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "bad-scope@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    let auth = bearer(&token);

    let (status, body) = http_post_json(
        &app,
        "/api/v1/applications",
        r#"{"name": "App", "application_type": "web", "redirect_uris": ["https://example.com/cb"], "access_scope": "organizaton"}"#,
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid json");
    assert_eq!(json["code"], "invalid_access_scope", "body: {body}");
}

#[tokio::test]
async fn test_create_application_rejects_invalid_access_scope_without_auth() {
    // Format validation runs before auth, so an invalid access_scope must
    // produce 400 (not 401) even without an Authorization header.
    let (app, _state) = test_app().await;

    let (status, body) = http_post_json(
        &app,
        "/api/v1/applications",
        r#"{"name": "App", "application_type": "web", "redirect_uris": ["https://example.com/cb"], "access_scope": "organizaton"}"#,
        &[],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "invalid access_scope must return 400 without auth: {body}"
    );
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid json");
    assert_eq!(json["code"], "invalid_access_scope");
}

#[tokio::test]
async fn test_create_application_rejects_invalid_fapi_profile() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "bad-fapi@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    let auth = bearer(&token);

    let (status, body) = http_post_json(
        &app,
        "/api/v1/applications",
        r#"{"name": "App", "application_type": "web", "redirect_uris": ["https://example.com/cb"], "fapi_profile": "fapi_security"}"#,
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid json");
    assert_eq!(json["code"], "invalid_fapi_profile", "body: {body}");
}

#[tokio::test]
async fn test_create_application_rejects_invalid_fapi_profile_without_auth() {
    let (app, _state) = test_app().await;

    let (status, body) = http_post_json(
        &app,
        "/api/v1/applications",
        r#"{"name": "App", "application_type": "web", "redirect_uris": ["https://example.com/cb"], "fapi_profile": "fapi_security"}"#,
        &[],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "invalid fapi_profile must return 400 without auth: {body}"
    );
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid json");
    assert_eq!(json["code"], "invalid_fapi_profile");
}

#[tokio::test]
async fn test_create_application_accepts_valid_access_scope() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "good-scope@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    let auth = bearer(&token);

    let (status, body) = http_post_json(
        &app,
        "/api/v1/applications",
        r#"{"name": "App", "application_type": "web", "redirect_uris": ["https://example.com/cb"], "access_scope": "public"}"#,
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid json");
    assert_eq!(json["access_scope"].as_str().unwrap(), "public");
}

#[tokio::test]
async fn test_create_application_defaults_access_scope_to_personal() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "default-scope@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    let auth = bearer(&token);

    let (status, body) = http_post_json(
        &app,
        "/api/v1/applications",
        r#"{"name": "App", "application_type": "web", "redirect_uris": ["https://example.com/cb"]}"#,
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid json");
    assert_eq!(json["access_scope"].as_str().unwrap(), "personal");
}

#[tokio::test]
async fn test_update_application_rejects_invalid_access_scope() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "upd-bad-scope@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    let auth = bearer(&token);
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (status, body) = http_request(
        &app,
        "PATCH",
        &format!("/api/v1/applications/{}", client.app_id),
        Some(r#"{"access_scope": "organizaton"}"#.to_string()),
        &[
            ("Content-Type", "application/json"),
            ("Authorization", &auth),
        ],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid json");
    assert_eq!(json["code"], "invalid_access_scope", "body: {body}");
}

#[tokio::test]
async fn test_update_application_rejects_invalid_fapi_profile() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "upd-bad-fapi@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    let auth = bearer(&token);
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (status, body) = http_request(
        &app,
        "PATCH",
        &format!("/api/v1/applications/{}", client.app_id),
        Some(r#"{"fapi_profile": "fapi1_adv"}"#.to_string()),
        &[
            ("Content-Type", "application/json"),
            ("Authorization", &auth),
        ],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid json");
    assert_eq!(json["code"], "invalid_fapi_profile", "body: {body}");
}

#[tokio::test]
async fn test_update_application_rejects_invalid_access_scope_without_auth() {
    let (app, state) = test_app().await;
    let client = create_test_oauth_client(
        &state.store,
        &create_test_user(&state.store, "upd-noauth-scope@example.com")
            .await
            .id,
    )
    .await;

    let (status, body) = http_request(
        &app,
        "PATCH",
        &format!("/api/v1/applications/{}", client.app_id),
        Some(r#"{"access_scope": "organizaton"}"#.to_string()),
        &[("Content-Type", "application/json")],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "invalid access_scope must return 400 without auth: {body}"
    );
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid json");
    assert_eq!(json["code"], "invalid_access_scope");
}

#[tokio::test]
async fn test_update_application_rejects_invalid_fapi_profile_without_auth() {
    let (app, state) = test_app().await;
    let client = create_test_oauth_client(
        &state.store,
        &create_test_user(&state.store, "upd-noauth-fapi@example.com")
            .await
            .id,
    )
    .await;

    let (status, body) = http_request(
        &app,
        "PATCH",
        &format!("/api/v1/applications/{}", client.app_id),
        Some(r#"{"fapi_profile": "fapi1_adv"}"#.to_string()),
        &[("Content-Type", "application/json")],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "invalid fapi_profile must return 400 without auth: {body}"
    );
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid json");
    assert_eq!(json["code"], "invalid_fapi_profile");
}

#[tokio::test]
async fn test_update_application_accepts_valid_access_scope() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "upd-good-scope@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    let auth = bearer(&token);
    let client = create_test_oauth_client(&state.store, &user.id).await;

    let (status, body) = http_request(
        &app,
        "PATCH",
        &format!("/api/v1/applications/{}", client.app_id),
        Some(r#"{"access_scope": "public"}"#.to_string()),
        &[
            ("Content-Type", "application/json"),
            ("Authorization", &auth),
        ],
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid json");
    assert_eq!(json["access_scope"].as_str().unwrap(), "public");
}

#[tokio::test]
async fn test_update_application_absent_access_scope_preserves_existing() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "upd-keep-scope@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    let auth = bearer(&token);

    // Create with public scope, then PATCH without access_scope.
    let created = create_test_client(
        &state.store,
        &user.id,
        TestClientSpec {
            access_scope: crate::db::AccessScope::Public,
            ..Default::default()
        },
    )
    .await;

    let (status, body) = http_request(
        &app,
        "PATCH",
        &format!("/api/v1/applications/{}", created.app_id),
        Some(r#"{"name": "Renamed"}"#.to_string()),
        &[
            ("Content-Type", "application/json"),
            ("Authorization", &auth),
        ],
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid json");
    assert_eq!(
        json["access_scope"].as_str().unwrap(),
        "public",
        "absent access_scope must preserve existing value"
    );
}
