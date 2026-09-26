// SPDX-License-Identifier: Apache-2.0 OR MIT
#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable"
)]

use axum::http::StatusCode;

use crate::arrival::ArrivalTime;
use crate::db::documents::session::SessionDoc;
use crate::db::store::DocumentStore;
use crate::db::{
    self, AccessScope, AuditEventFilter, ClientType, FapiProfile, OAuthClientType,
    TokenEndpointAuthMethod,
};
use crate::services::auth::NoClientAuth;
use crate::test_utils::{TestJwks, *};

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
    let secrets = db::get_oauth_client_secrets(&state.store, &client.app_id)
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

/// Revoking the *sole* expired-but-unrevoked secret of a credential client must
/// succeed at the API layer: the target is already dead, so the revoke does not
/// reduce the active count (it stays at zero) and the floor guard must not fire.
/// Before the fix, `DELETE /api/v1/applications/:id/secrets/:secret_id` returned
/// `409 "last_secret" / "Cannot delete the last active secret"` for this case.
/// Regression for the missing `target_active` condition in the `delete_secret_api`
/// pre-flight check.
#[tokio::test]
async fn test_delete_sole_expired_secret_allowed() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "sole-expired@example.com").await;
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
    let client = create_test_client(
        &state.store,
        &user.id,
        TestClientSpec {
            with_secret: false, // start with no secrets; we seed a sole expired one below
            ..Default::default()
        },
    )
    .await;
    let app_id = client.app_id;
    let auth = bearer(&token);

    // The client's only secret, already expired (but not revoked).
    let past: jiff::Timestamp = "2020-01-01T00:00:00Z".parse().unwrap();
    let expired = db::create_oauth_client_secret(
        &state.store,
        &app_id,
        "hash_sole_expired_api",
        None,
        Some(past),
    )
    .await
    .expect("create sole expired secret");
    let secret_id = expired.id.to_string();

    // Before the fix this returned 409 `last_secret`; it must now succeed because
    // revoking a dead row leaves the active count unchanged at zero.
    let (status, body) = http_delete(
        &app,
        &format!("/api/v1/applications/{app_id}/secrets/{secret_id}"),
        &[("Authorization", &auth)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "revoking the sole expired secret must succeed; got body: {body}"
    );

    // The row is soft-deleted and the client remains at zero active secrets.
    let now = jiff::Timestamp::now();
    let secrets = db::get_oauth_client_secrets(&state.store, &app_id)
        .await
        .expect("db query ok");
    let revoked = secrets
        .iter()
        .find(|s| s.id == secret_id)
        .expect("the revoked row must still be present (soft-delete retains it)");
    assert!(
        revoked.revoked_at.is_some(),
        "the target secret must be marked revoked; got {revoked:?}"
    );
    assert!(
        secrets.iter().all(|s| !s.is_valid(&now)),
        "the client must remain at zero active secrets; got {secrets:?}"
    );
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
    let client = db::get_oauth_client_by_client_id(&state.store, client_id)
        .await
        .expect("lookup")
        .expect("client exists");
    assert_eq!(
        client.token_endpoint_auth_method,
        TokenEndpointAuthMethod::None,
        "secretless client types must be stored as public clients"
    );
    assert!(
        NoClientAuth::for_public_client(&client).is_ok(),
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
    let client = db::get_oauth_client_by_client_id(&state.store, client_id)
        .await
        .expect("lookup")
        .expect("client exists");
    assert_eq!(
        client.token_endpoint_auth_method,
        TokenEndpointAuthMethod::None,
    );
    assert!(NoClientAuth::for_public_client(&client).is_ok());
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
    let client = db::get_oauth_client_by_client_id(&state.store, client_id)
        .await
        .expect("lookup")
        .expect("client exists");
    assert_eq!(
        client.token_endpoint_auth_method,
        TokenEndpointAuthMethod::ClientSecretBasic,
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

    db::update_user_active_status(&state.store, &user.id, false)
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

    db::update_user_active_status(&state.store, &user.id, false)
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

/// Regression for the gate-ordering outlier: a deactivated user holding a
/// live session who PATCHes an app they do **not** own must get
/// `401 "User account is deactivated"`, matching `delete_application_api` and
/// the other state-changing handlers that gate first via
/// `load_active_owned_client`. Before the fix the ownership check ran before
/// the active-user gate and returned `404 "Application not found"`, making
/// `update_application_api` the sole gate-after-ownership outlier among the
/// write handlers — observable divergence: `PATCH` non-owned → 404 while
/// `DELETE` on the same app → 401.
#[tokio::test]
async fn test_update_non_owned_application_rejects_deactivated_user() {
    let (app, state) = test_app().await;

    // A second, active user owns the target application.
    let owner = create_test_user(&state.store, "non-owner-active@example.com").await;
    let owners_client = create_test_oauth_client(&state.store, &owner.id).await;
    let original = db::get_oauth_client_by_id(&state.store, &owners_client.app_id)
        .await
        .expect("db read")
        .expect("owner's application exists");

    // A separate user holds a live session, then is deactivated while the
    // session row stays intact — the deactivated-with-live-session state
    // from the bug report (the cross-replica `SessionCache` window).
    let (_deactivated_users_own_app, token) =
        setup_deactivated_owner_with_app(&state, "deactivated-non-owner@example.com").await;

    let (status, body) = http_request(
        &app,
        "PATCH",
        &format!("/api/v1/applications/{}", owners_client.app_id),
        Some(r#"{"name": "Hostile Takeover"}"#.to_string()),
        &[
            ("Content-Type", "application/json"),
            ("Authorization", &bearer(&token)),
        ],
    )
    .await;

    // The active-user gate must reject the deactivated account (401) BEFORE
    // the ownership check discloses that the app exists or belongs to someone
    // else (404).
    assert_deactivated_rejection(status, &body);

    // The target application must survive the rejected update unchanged.
    let survivor = db::get_oauth_client_by_id(&state.store, &owners_client.app_id)
        .await
        .expect("db read")
        .expect("application must still exist");
    assert_eq!(survivor.name, original.name, "name must not change");
    assert_eq!(
        survivor.user_id, original.user_id,
        "ownership must not change"
    );
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

/// Deleting an application must revoke every access token it minted — both
/// user-issued grants (session keyed by the resource owner's `user_id`,
/// tagged with the issuing `client_id`) and M2M `client_credentials`
/// sessions (keyed by `user_id == client_id`, RFC 9068 §2.2).
///
/// Regression for the sibling of the `revoke_tokens_api` bug: deletion is a
/// stronger revocation intent than the "revoke all tokens" button, yet
/// `delete_application_api` used to call the bare `delete_oauth_client`,
/// leaving already-minted tokens validating at resource endpoints until
/// `exp`. Without the fix the userinfo probe below stays 200 after the
/// delete and this test fails.
#[tokio::test]
async fn test_delete_application_revokes_minted_sessions() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "delete-revokes@example.com").await;
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

    // A user-issued access token for this client (authorization_code shape:
    // session keyed by the real user, tagged with the issuing client).
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

    // An M2M (client_credentials) session: user_id == client_id.
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

    // A sibling client owned by the same user, to prove deletion does not
    // over-revoke another application's tokens.
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
        userinfo_status(&app, &user_access_token).await,
        StatusCode::OK,
        "user-issued token should validate before the app is deleted"
    );

    // Delete the application.
    let (status, _body) = http_delete(
        &app,
        &format!("/api/v1/applications/{}", client.app_id),
        &[("Authorization", &auth)],
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // The user-issued token must be dead.
    assert_eq!(
        userinfo_status(&app, &user_access_token).await,
        StatusCode::UNAUTHORIZED,
        "user-issued access token must NOT validate after the app is deleted"
    );
    assert_eq!(
        count_sessions_for_client(&state.store, &client.client_id).await,
        0,
        "user-issued sessions for the deleted client must be gone"
    );
    // The M2M session must be dead too.
    assert_eq!(
        count_sessions_for_user(&state.store, &client.client_id).await,
        0,
        "M2M sessions for the deleted client must be gone"
    );

    // No over-revocation: the sibling client's token still validates.
    assert_eq!(
        userinfo_status(&app, &other_token).await,
        StatusCode::OK,
        "deleting one application must not revoke another client's tokens"
    );
    // And the owner's own first-party session survives.
    assert_eq!(
        userinfo_status(&app, &owner_token).await,
        StatusCode::OK,
        "the owner's first-party session must survive the app delete"
    );
}

// ========================================================================
// End-to-end: chokepoint partial failure must revoke the cached M2M token
// (regression for the (A)-OK / (B)-Err arm through the real axum router)
// ========================================================================

/// Probe whether an access token still validates at `GET /v1/keys`. 200 means
/// the session is live (the cache served a `Hit` or missed through to a live
/// DB row); 401 means the session has been revoked (cache evicted and DB row
/// gone). M2M (`client_credentials`) tokens with the default audience
/// (`aud == client_id`) reach this handler: `enforce_audience_coverage`
/// fast-paths that case, and `list_keys` does not call `load_active_user`, so
/// an M2M token with `sub == client_id` and no user row returns 200 (empty key
/// list) rather than 401.
async fn v1_keys_status(app: &axum::Router, token: &str) -> StatusCode {
    let (status, _) = http_get(app, "/v1/keys", &[("Authorization", &bearer(token))]).await;
    status
}

/// End-to-end regression for the cache/DB desync on the chokepoint's
/// (A)-OK / (B)-Err arm, driven through the real axum router — the exploit
/// scenario from the bug report.
///
/// 1. The attacker's M2M (`client_credentials`) token warms `SessionCache` by
///    hitting `GET /v1/keys` (200).
/// 2. The admin deletes the OAuth application; the chokepoint's second
///    `delete_by_index` (the `client_id`-indexed delete) faults, so the
///    request returns 500.
/// 3. The attacker's next `GET /v1/keys` within the cache TTL must NOT
///    authenticate from a stale cache `Hit`: with the fix,
///    `invalidate_for_user` ran between the two deletes and evicted the M2M
///    entry, so the cache misses through to the DB (row gone) and returns 401.
///    Under the bug both invalidations are skipped and this probe returns 200
///    from the stale `Hit` until the TTL elapses.
///
/// `set_delete_by_index_remaining_successes(1)` faults exactly the chokepoint's
/// second `delete_by_index` while letting the first commit. A sibling client's
/// M2M token is also warmed and must keep validating — the chokepoint
/// invalidates only the deleted client's entries, not another application's.
#[tokio::test]
async fn test_delete_application_partial_failure_revokes_m2m_token_from_cache() {
    let (app, state) = test_app_with_modify_hook(|store| {
        // Let exactly one top-level `delete_by_index` succeed (the M2M
        // `user_id`-scoped delete, step A), then fault the client-scoped
        // delete (step B). The setup helpers never call `delete_by_index`, so
        // the budget is consumed only by the chokepoint's two
        // `delete_sessions_for_*` calls during the DELETE below.
        store.set_delete_by_index_remaining_successes(1);
    })
    .await;

    // Owner + first-party session (the bearer the admin uses to call DELETE).
    let user = create_test_user(&state.store, "partial-e2e@example.com").await;
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
    let owner_auth = bearer(&owner_token);

    let client = create_test_client(
        &state.store,
        &user.id,
        TestClientSpec {
            name: "Partial E2E App".to_string(),
            // Register the shared test httpsig JWKS so the auto-signed
            // `/v1/keys` probe's signature verifies against this client's
            // keys (the httpsig resolver looks up the verification key by
            // the Bearer token's `client_id` claim). Without this the
            // M2M token's `/v1/keys` probe is rejected by the httpsig
            // middleware before reaching the handler.
            jwks: TestJwks::Shared,
            with_secret: false,
            ..Default::default()
        },
    )
    .await;

    // Attacker's M2M (client_credentials) token: `user_id == client_id`
    // (RFC 9068 §2.2), default audience `aud == client_id`. This is the token
    // that warms the cache and must be revoked by the partial-failure arm.
    let m2m_token = create_test_session_with(
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

    // A sibling client's M2M token, to prove the faulted delete does not
    // over-revoke another application's tokens.
    let other_client = create_test_client(
        &state.store,
        &user.id,
        TestClientSpec {
            name: "Partial E2E Sibling".to_string(),
            jwks: TestJwks::Shared,
            with_secret: false,
            ..Default::default()
        },
    )
    .await;
    let other_m2m_token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &other_client.client_id,
            email: &format!("{}@clients", other_client.client_id),
            auth_id: Some(&auth_id),
            client_id: Some(&other_client.client_id),
            ..Default::default()
        },
    )
    .await;

    // Step 1: warm the session cache for both M2M tokens by hitting the
    // resource endpoint, exactly as an attacker would before the admin's
    // delete. 200 confirms the token authenticates and the cache now holds a
    // `Hit` for its hash.
    let (warm_status, warm_body) =
        http_get(&app, "/v1/keys", &[("Authorization", &bearer(&m2m_token))]).await;
    assert_eq!(
        warm_status,
        StatusCode::OK,
        "attacker's M2M token must authenticate (and warm the cache) before the delete: {warm_body}"
    );
    assert_eq!(
        v1_keys_status(&app, &other_m2m_token).await,
        StatusCode::OK,
        "sibling M2M token must authenticate (and warm the cache) before the delete"
    );

    // Step 2: admin deletes the application. The chokepoint's second
    // `delete_by_index` faults, so the delete surfaces as 500 — the admin is
    // told to retry, matching the error-propagation contract.
    let (status, _body) = http_delete(
        &app,
        &format!("/api/v1/applications/{}", client.app_id),
        &[("Authorization", &owner_auth)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "the (B)-delete failure must surface as 500, not 204"
    );

    // Step 3: the attacker's next probe within the cache TTL must NOT
    // authenticate. With the fix, `invalidate_for_user` evicted the M2M entry
    // between the two deletes, so the cache misses through to the DB (row
    // gone) and returns 401. Under the bug both invalidations are skipped and
    // this probe returns 200 from the stale `Hit` — the exploit.
    assert_eq!(
        v1_keys_status(&app, &m2m_token).await,
        StatusCode::UNAUTHORIZED,
        "the attacker's DB-revoked M2M token must not authenticate from a stale \
         cache Hit within the TTL after the delete returned 500"
    );

    // No over-revocation: the sibling client's M2M token is untouched (its
    // `user_id`/`client_id` are a different client), so it stays cached and
    // keeps authenticating.
    assert_eq!(
        v1_keys_status(&app, &other_m2m_token).await,
        StatusCode::OK,
        "a sibling client's M2M token must keep validating after the faulted delete"
    );
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
async fn count_sessions_for_user(store: &DocumentStore, user_id: &str) -> i64 {
    store
        .count::<SessionDoc>("user_id", user_id)
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
async fn count_sessions_for_client(store: &DocumentStore, client_id: &str) -> i64 {
    store
        .count::<SessionDoc>("client_id", client_id)
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
            fapi_profile: Some(FapiProfile::Fapi2Security),
            token_endpoint_auth_method: Some(TokenEndpointAuthMethod::PrivateKeyJwt),
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
    let persisted = db::get_oauth_client_by_id(&state.store, &client.app_id)
        .await
        .expect("db lookup")
        .expect("client still exists");
    assert!(persisted.is_fapi(), "client must remain FAPI");
    assert_eq!(
        persisted.token_endpoint_auth_method,
        TokenEndpointAuthMethod::PrivateKeyJwt,
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
            token_endpoint_auth_method: Some(TokenEndpointAuthMethod::PrivateKeyJwt),
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

    let persisted = db::get_oauth_client_by_id(&state.store, &client.app_id)
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
        TokenEndpointAuthMethod::PrivateKeyJwt,
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
            token_endpoint_auth_method: Some(TokenEndpointAuthMethod::PrivateKeyJwt),
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

    let persisted = db::get_oauth_client_by_id(&state.store, &client.app_id)
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
            access_scope: AccessScope::Public,
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

// ========================================================================
// #214 / FAPI-over-mTLS: the JSON API secret-minting guard must block every
// FAPI client, not just `private_key_jwt`. mTLS-FAPI clients previously
// slipped past the narrow `== PrivateKeyJwt` guard and persisted a dead
// secret row. Mirrors the web-handler regression coverage above.
// ========================================================================

#[tokio::test]
async fn test_add_secret_rejects_mtls_fapi_client() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "api-mtls-fapi-secret@example.com").await;
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
    let client = create_test_client(
        &state.store,
        &user.id,
        TestClientSpec {
            token_endpoint_auth_method: Some(TokenEndpointAuthMethod::TlsClientAuth),
            tls_client_auth_subject_dn: Some("CN=test.example.com".to_string()),
            jwks: TestJwks::Shared,
            dpop_bound_access_tokens: true,
            fapi_profile: Some(FapiProfile::Fapi2Security),
            with_secret: false,
            ..Default::default()
        },
    )
    .await;
    let app_id = client.app_id;
    let auth = bearer(&token);

    let (status, body) = http_post_json(
        &app,
        &format!("/api/v1/applications/{app_id}/secrets"),
        r#"{}"#,
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid json");
    assert_eq!(json["code"], "no_secret", "body: {body}");

    let secrets = db::get_oauth_client_secrets(&state.store, &app_id)
        .await
        .expect("db query ok");
    assert!(
        secrets.is_empty(),
        "no secret rows should exist for an mTLS FAPI client, got {secrets:?}"
    );
}

#[tokio::test]
async fn test_add_secret_rejects_self_signed_mtls_fapi_client() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "api-self-signed-mtls-fapi-secret@example.com").await;
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
    let client = create_test_client(
        &state.store,
        &user.id,
        TestClientSpec {
            token_endpoint_auth_method: Some(TokenEndpointAuthMethod::SelfSignedTlsClientAuth),
            tls_client_auth_subject_dn: Some("CN=test.example.com".to_string()),
            jwks: TestJwks::Shared,
            dpop_bound_access_tokens: true,
            fapi_profile: Some(FapiProfile::Fapi2Security),
            with_secret: false,
            ..Default::default()
        },
    )
    .await;
    let app_id = client.app_id;
    let auth = bearer(&token);

    let (status, body) = http_post_json(
        &app,
        &format!("/api/v1/applications/{app_id}/secrets"),
        r#"{}"#,
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid json");
    assert_eq!(json["code"], "no_secret", "body: {body}");

    let secrets = db::get_oauth_client_secrets(&state.store, &app_id)
        .await
        .expect("db query ok");
    assert!(
        secrets.is_empty(),
        "no secret rows should exist for a self-signed mTLS FAPI client, got {secrets:?}"
    );
}

#[tokio::test]
async fn test_add_secret_rejects_private_key_jwt_fapi_client() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "api-privkeyjwt-fapi-secret@example.com").await;
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
            token_endpoint_auth_method: Some(TokenEndpointAuthMethod::PrivateKeyJwt),
            jwks: TestJwks::Shared,
            dpop_bound_access_tokens: true,
            fapi_profile: Some(FapiProfile::Fapi2Security),
            with_secret: false,
            ..Default::default()
        },
    )
    .await;

    let (status, body) = http_post_json(
        &app,
        &format!("/api/v1/applications/{}/secrets", client.app_id),
        r#"{}"#,
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid json");
    assert_eq!(json["code"], "no_secret", "body: {body}");

    let secrets = db::get_oauth_client_secrets(&state.store, &client.app_id)
        .await
        .expect("db query ok");
    assert!(
        secrets.is_empty(),
        "no secret rows should exist for a private_key_jwt FAPI client, got {secrets:?}"
    );
}

// OIDC Core 1.0 §3.1.3.1: a confidential client "MUST authenticate to the
// Token Endpoint using the authentication method registered for its
// "client_id"". A non-FAPI `private_key_jwt` client has no secret method,
// so the rotation endpoint refuses to mint one.
#[tokio::test]
async fn test_add_secret_rejects_non_fapi_private_key_jwt_service_client() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "pkjwt-service-secret@example.com").await;
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
    let client = create_test_client(
        &state.store,
        &user.id,
        TestClientSpec {
            application_type: OAuthClientType::Service,
            grant_types: Some(vec!["client_credentials".to_string()]),
            token_endpoint_auth_method: Some(TokenEndpointAuthMethod::PrivateKeyJwt),
            jwks: TestJwks::Shared,
            fapi_profile: None,
            with_secret: false,
            ..Default::default()
        },
    )
    .await;
    let app_id = client.app_id;
    let auth = bearer(&token);

    let (status, body) = http_post_json(
        &app,
        &format!("/api/v1/applications/{app_id}/secrets"),
        r#"{}"#,
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid json");
    assert_eq!(json["code"], "no_secret", "body: {body}");

    let secrets = db::get_oauth_client_secrets(&state.store, &app_id)
        .await
        .expect("db query ok");
    assert!(
        secrets.is_empty(),
        "no secret rows should be minted for a non-FAPI private_key_jwt client, got {secrets:?}"
    );
}

// The refusal keys on the registered method, not `application_type`: a
// native app registered for `private_key_jwt` is refused the same way.
#[tokio::test]
async fn test_add_secret_rejects_non_fapi_private_key_jwt_native_client() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "pkjwt-native-secret@example.com").await;
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
    let client = create_test_client(
        &state.store,
        &user.id,
        TestClientSpec {
            application_type: OAuthClientType::Native,
            redirect_uris: vec!["http://127.0.0.1:8400/cb".to_string()],
            grant_types: Some(vec!["authorization_code".to_string()]),
            token_endpoint_auth_method: Some(TokenEndpointAuthMethod::PrivateKeyJwt),
            jwks: TestJwks::Shared,
            fapi_profile: None,
            with_secret: false,
            ..Default::default()
        },
    )
    .await;
    let app_id = client.app_id;
    let auth = bearer(&token);

    let (status, body) = http_post_json(
        &app,
        &format!("/api/v1/applications/{app_id}/secrets"),
        r#"{}"#,
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid json");
    assert_eq!(json["code"], "no_secret", "body: {body}");

    let secrets = db::get_oauth_client_secrets(&state.store, &app_id)
        .await
        .expect("db query ok");
    assert!(
        secrets.is_empty(),
        "no secret rows should be minted for a non-FAPI native private_key_jwt client, got {secrets:?}"
    );
}

// RFC 8705 §2: mTLS clients authenticate with a certificate, and
// `authenticate_client` never compares a secret for them, so the rotation
// endpoint refuses to mint one.
#[tokio::test]
async fn test_add_secret_rejects_non_fapi_mtls_client() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "mtls-nonfapi-secret@example.com").await;
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
    let client = create_test_client(
        &state.store,
        &user.id,
        TestClientSpec {
            grant_types: Some(vec!["client_credentials".to_string()]),
            token_endpoint_auth_method: Some(TokenEndpointAuthMethod::TlsClientAuth),
            tls_client_auth_subject_dn: Some("CN=test.example.com".to_string()),
            fapi_profile: None,
            with_secret: false,
            ..Default::default()
        },
    )
    .await;
    let app_id = client.app_id;
    let auth = bearer(&token);

    let (status, body) = http_post_json(
        &app,
        &format!("/api/v1/applications/{app_id}/secrets"),
        r#"{}"#,
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid json");
    assert_eq!(json["code"], "no_secret", "body: {body}");

    let secrets = db::get_oauth_client_secrets(&state.store, &app_id)
        .await
        .expect("db query ok");
    assert!(
        secrets.is_empty(),
        "no secret rows should be minted for a non-FAPI mTLS client, got {secrets:?}"
    );
}

// OIDC Core 1.0 §3.1.3.1, end to end: rotation refuses a non-FAPI
// `private_key_jwt` client, and a secret row such a client already holds
// does not authenticate it at `/oauth/token`.
#[tokio::test]
async fn test_pkjwt_secret_downgrade_blocked_e2e() {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "pkjwt-e2e@example.com").await;
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

    // (a) Rotation is refused for a non-FAPI `private_key_jwt` Service client.
    let client = create_test_client(
        &state.store,
        &user.id,
        TestClientSpec {
            application_type: OAuthClientType::Service,
            grant_types: Some(vec!["client_credentials".to_string()]),
            token_endpoint_auth_method: Some(TokenEndpointAuthMethod::PrivateKeyJwt),
            jwks: TestJwks::Shared,
            fapi_profile: None,
            with_secret: false,
            ..Default::default()
        },
    )
    .await;
    let (status, body) = http_post_json(
        &app,
        &format!("/api/v1/applications/{}/secrets", client.app_id),
        r#"{}"#,
        &[("Authorization", &auth)],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "rotation body: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid json");
    assert_eq!(json["code"], "no_secret", "rotation body: {body}");

    // (b) A secret row the client already holds does not authenticate it.
    let stray = create_test_client(
        &state.store,
        &user.id,
        TestClientSpec {
            application_type: OAuthClientType::Service,
            grant_types: Some(vec!["client_credentials".to_string()]),
            token_endpoint_auth_method: Some(TokenEndpointAuthMethod::PrivateKeyJwt),
            jwks: TestJwks::Shared,
            fapi_profile: None,
            with_secret: true, // a secret row the registered method never uses
            ..Default::default()
        },
    )
    .await;
    let basic = format!(
        "Basic {}",
        STANDARD.encode(format!("{}:{}", stray.client_id, stray.client_secret))
    );
    let (status, body) = http_post_form(
        &app,
        "/oauth/token",
        "grant_type=client_credentials",
        &[("Authorization", &basic)],
    )
    .await;
    assert_ne!(
        status,
        StatusCode::OK,
        "a stray secret must not authenticate a private_key_jwt client at /oauth/token: {body}"
    );
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid json");
    assert!(
        json.get("access_token").is_none(),
        "no access_token may be issued for a private_key_jwt client using a shared secret: {body}"
    );
    assert_eq!(
        json["error"], "invalid_client",
        "the rejection must surface as RFC 6749 §5.2 invalid_client: {body}"
    );
}

// RFC 8252 §8.4: "Except when using a mechanism like Dynamic Client
// Registration [RFC7591] to provision per-instance secrets, native apps are
// classified as public clients". A native client holding a registered
// `client_secret_post` secret can add a secret, and the new secret
// authenticates it at the token endpoint.
#[tokio::test]
async fn test_add_secret_succeeds_for_native_client_with_registered_secret() {
    use crate::services::oidc::token::{ClientCredentials, authenticate_client};
    use secrecy::SecretString;

    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "native-secret-rotate@example.com").await;
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
    let client = create_test_client(
        &state.store,
        &user.id,
        TestClientSpec {
            application_type: OAuthClientType::Native,
            redirect_uris: vec!["http://127.0.0.1:8400/cb".to_string()],
            token_endpoint_auth_method: Some(TokenEndpointAuthMethod::ClientSecretPost),
            with_secret: true,
            ..Default::default()
        },
    )
    .await;
    let app_id = client.app_id;
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
    assert!(json.get("secret_id").is_some(), "secret_id missing: {body}");
    let new_secret = json["client_secret"]
        .as_str()
        .expect("client_secret missing");
    assert!(
        new_secret.starts_with("vouch_"),
        "rotated secret must be a vouch_ value: {new_secret}"
    );

    // The rotated secret row must be persisted alongside the seeded one.
    let secrets = db::get_oauth_client_secrets(&state.store, &app_id)
        .await
        .expect("db query ok");
    assert_eq!(
        secrets.len(),
        2,
        "the rotated secret row must be persisted alongside the seeded one: {secrets:?}"
    );

    // The new secret must authenticate the client.
    let arrival = ArrivalTime::for_test(jiff::Timestamp::now());
    let creds = ClientCredentials {
        client_id: client.client_id.clone(),
        client_secret: Some(SecretString::from(new_secret.to_string())),
    };
    let (authed, verification) = authenticate_client(&state, &creds, arrival)
        .await
        .expect("the rotated secret must authenticate the native+secret client");
    assert_eq!(
        authed.client_type(),
        ClientType::Confidential,
        "a native client registered with a secret is confidential"
    );
    assert!(
        verification.is_some(),
        "the rotated secret must be validated against its stored hash"
    );
}

// RFC 7591 §2: "\"none\": The client is a public client as defined in OAuth
// 2.0, Section 2.1, and does not have a client secret." A public native client
// is refused and no secret row is written.
#[tokio::test]
async fn test_add_secret_rejects_public_native_client_with_no_secret() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "native-public-rotate@example.com").await;
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
    let client = create_test_client(
        &state.store,
        &user.id,
        TestClientSpec {
            application_type: OAuthClientType::Native,
            redirect_uris: vec!["http://127.0.0.1:8400/cb".to_string()],
            token_endpoint_auth_method: Some(TokenEndpointAuthMethod::None),
            with_secret: false,
            ..Default::default()
        },
    )
    .await;
    let app_id = client.app_id;
    let auth = bearer(&token);

    let (status, body) = http_post_json(
        &app,
        &format!("/api/v1/applications/{app_id}/secrets"),
        r#"{}"#,
        &[("Authorization", &auth)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid json");
    assert_eq!(json["code"], "no_secret", "body: {body}");

    let secrets = db::get_oauth_client_secrets(&state.store, &app_id)
        .await
        .expect("db query ok");
    assert!(
        secrets.is_empty(),
        "no secret rows should be minted for a public native client, got {secrets:?}"
    );
}

// ========================================================================
// FAPI delete-floor exemption: FAPI clients cannot authenticate with a
// secret (minting is blocked for every FAPI profile), so a dead secret row
// minted before the guard must remain deletable. The unconditional
// "last active secret" floor previously pinned it forever.
// ========================================================================

// FAPI 2.0 Security Profile §5.3.2.1 item 6: mTLS-FAPI clients authenticate
// only via mutual TLS, so a FAPI client's last (unusable) secret must be
// deletable.
#[tokio::test]
async fn test_delete_last_secret_allowed_for_fapi_client() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "api-fapi-del-last@example.com").await;
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
    let client = create_test_client(
        &state.store,
        &user.id,
        TestClientSpec {
            token_endpoint_auth_method: Some(TokenEndpointAuthMethod::TlsClientAuth),
            tls_client_auth_subject_dn: Some("CN=test.example.com".to_string()),
            jwks: TestJwks::Shared,
            dpop_bound_access_tokens: true,
            fapi_profile: Some(FapiProfile::Fapi2Security),
            with_secret: true, // a pre-guard mTLS-FAPI client with a dead secret row
            ..Default::default()
        },
    )
    .await;
    let app_id = client.app_id;
    let auth = bearer(&token);

    let (_, body) = http_get(
        &app,
        &format!("/api/v1/applications/{app_id}/secrets"),
        &[("Authorization", &auth)],
    )
    .await;
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid json");
    let secret_id = json["secrets"][0]["id"].as_str().expect("secret id");

    let (status, body) = http_delete(
        &app,
        &format!("/api/v1/applications/{app_id}/secrets/{secret_id}"),
        &[("Authorization", &auth)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "a FAPI client's last dead secret must be deletable, body: {body}"
    );

    let now = jiff::Timestamp::now();
    let secrets = db::get_oauth_client_secrets(&state.store, &app_id)
        .await
        .expect("db query ok");
    assert!(
        secrets.iter().all(|s| !s.is_valid(&now)),
        "the dead secret must be revoked, got {secrets:?}"
    );
}

// FAPI 2.0 Security Profile §5.3.2.1 item 6: the exemption is scoped to
// FAPI clients; the non-FAPI floor stays intact (see
// test_delete_last_secret_rejected above for the sibling negative case at
// the handler level).
#[tokio::test]
async fn test_delete_last_secret_still_rejected_for_non_fapi_client() {
    let (app, state) = test_app().await;
    let (app_id, token) = setup_user_with_app(&state, "api-nonfapi-del-last@example.com").await;
    let auth = bearer(&token);

    let (_, body) = http_get(
        &app,
        &format!("/api/v1/applications/{app_id}/secrets"),
        &[("Authorization", &auth)],
    )
    .await;
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid json");
    let secret_id = json["secrets"][0]["id"].as_str().expect("secret id");

    let (status, body) = http_delete(
        &app,
        &format!("/api/v1/applications/{app_id}/secrets/{secret_id}"),
        &[("Authorization", &auth)],
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "body: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid json");
    assert_eq!(json["code"], "last_secret");
}

// FAPI 2.0 Security Profile §5.3.2.1 item 6 requires mTLS or private_key_jwt,
// and `authenticate_client` now refuses a secret from any FAPI client, so a
// private_key_jwt FAPI client's pre-guard secret row is just as dead as an
// mTLS client's: the delete-floor exemption covers it too.
#[tokio::test]
async fn test_delete_last_secret_allowed_for_private_key_jwt_fapi_client() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "api-pkjwt-fapi-del-last@example.com").await;
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
            token_endpoint_auth_method: Some(TokenEndpointAuthMethod::PrivateKeyJwt),
            jwks: TestJwks::Shared,
            dpop_bound_access_tokens: true,
            fapi_profile: Some(FapiProfile::Fapi2Security),
            with_secret: true, // pre-guard row; refused by authenticate_client
            ..Default::default()
        },
    )
    .await;
    let app_id = client.app_id;

    let (_, body) = http_get(
        &app,
        &format!("/api/v1/applications/{app_id}/secrets"),
        &[("Authorization", &auth)],
    )
    .await;
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid json");
    let secret_id = json["secrets"][0]["id"].as_str().expect("secret id");

    let (status, body) = http_delete(
        &app,
        &format!("/api/v1/applications/{app_id}/secrets/{secret_id}"),
        &[("Authorization", &auth)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "a private_key_jwt FAPI client's last dead secret must be deletable, body: {body}"
    );
    let now = jiff::Timestamp::now();
    let secrets = db::get_oauth_client_secrets(&state.store, &app_id)
        .await
        .expect("db query ok");
    assert!(
        secrets.iter().all(|s| !s.is_valid(&now)),
        "the dead secret must be revoked, got {secrets:?}"
    );
}

// A non-FAPI mTLS client's secret row is never compared (`authenticate_client`
// returns through the certificate branch), so the last-secret floor does not
// pin it.
#[tokio::test]
async fn test_delete_last_secret_allowed_for_non_fapi_mtls_client() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "api-mtls-nonfapi-del-last@example.com").await;
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
    let client = create_test_client(
        &state.store,
        &user.id,
        TestClientSpec {
            grant_types: Some(vec!["client_credentials".to_string()]),
            token_endpoint_auth_method: Some(TokenEndpointAuthMethod::TlsClientAuth),
            tls_client_auth_subject_dn: Some("CN=test.example.com".to_string()),
            fapi_profile: None,
            with_secret: true,
            ..Default::default()
        },
    )
    .await;
    let app_id = client.app_id;
    let auth = bearer(&token);

    let (_, body) = http_get(
        &app,
        &format!("/api/v1/applications/{app_id}/secrets"),
        &[("Authorization", &auth)],
    )
    .await;
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid json");
    let secret_id = json["secrets"][0]["id"].as_str().expect("secret id");

    let (status, body) = http_delete(
        &app,
        &format!("/api/v1/applications/{app_id}/secrets/{secret_id}"),
        &[("Authorization", &auth)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "a non-FAPI mTLS client's last secret must be deletable, body: {body}"
    );
}

// ========================================================================
// Deactivated-user gate — delete/secret/revoke handlers
// ========================================================================
//
// `AuthenticatedToken` validates the token only, so each state-changing
// handler must reject a deactivated account itself (via
// `load_active_owned_client`). Fixture: deactivate WITHOUT deleting the
// session — the exact deactivated-with-live-session state the
// `test_create_application_rejects_deactivated_user` sibling above uses.

/// Create an app-owning user with a live session, then deactivate the user
/// while leaving the session row intact. Returns `(app_id, bearer_token)`.
async fn setup_deactivated_owner_with_app(
    state: &crate::AppState,
    email: &str,
) -> (String, String) {
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
    db::update_user_active_status(&state.store, &user.id, false)
        .await
        .expect("deactivate user");
    (client.app_id, token)
}

fn assert_deactivated_rejection(status: StatusCode, body: &str) {
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "deactivated user must be rejected; got body: {body}"
    );
    let error: serde_json::Value = serde_json::from_str(body).expect("valid JSON");
    assert_eq!(error["code"], "unauthorized");
    assert_eq!(error["message"], "User account is deactivated");
}

#[tokio::test]
async fn test_delete_application_rejects_deactivated_user() {
    let (app, state) = test_app().await;
    let (app_id, token) =
        setup_deactivated_owner_with_app(&state, "deactivated-del-app@example.com").await;

    let (status, body) = http_delete(
        &app,
        &format!("/api/v1/applications/{app_id}"),
        &[("Authorization", &bearer(&token))],
    )
    .await;

    assert_deactivated_rejection(status, &body);
    // The application must survive the rejected deletion.
    let survivor = db::get_oauth_client_by_id(&state.store, &app_id)
        .await
        .expect("db read")
        .expect("application must still exist");
    assert!(survivor.user_id.is_some());
}

#[tokio::test]
async fn test_add_secret_rejects_deactivated_user() {
    let (app, state) = test_app().await;
    let (app_id, token) =
        setup_deactivated_owner_with_app(&state, "deactivated-add-secret@example.com").await;

    let before = db::get_oauth_client_secrets(&state.store, &app_id)
        .await
        .expect("db read")
        .len();

    let (status, body) = http_post_json(
        &app,
        &format!("/api/v1/applications/{app_id}/secrets"),
        r#"{}"#,
        &[("Authorization", &bearer(&token))],
    )
    .await;

    assert_deactivated_rejection(status, &body);
    let after = db::get_oauth_client_secrets(&state.store, &app_id)
        .await
        .expect("db read")
        .len();
    assert_eq!(after, before, "deactivated user must not mint a secret");
}

#[tokio::test]
async fn test_delete_secret_rejects_deactivated_user() {
    let (app, state) = test_app().await;
    let (app_id, token) =
        setup_deactivated_owner_with_app(&state, "deactivated-del-secret@example.com").await;

    let secrets = db::get_oauth_client_secrets(&state.store, &app_id)
        .await
        .expect("db read");
    let secret_id = &secrets.first().expect("fixture secret").id;

    let (status, body) = http_delete(
        &app,
        &format!("/api/v1/applications/{app_id}/secrets/{secret_id}"),
        &[("Authorization", &bearer(&token))],
    )
    .await;

    assert_deactivated_rejection(status, &body);
    let now = jiff::Timestamp::now();
    let survivors = db::get_oauth_client_secrets(&state.store, &app_id)
        .await
        .expect("db read");
    assert!(
        survivors
            .iter()
            .any(|s| s.id == *secret_id && s.is_valid(&now)),
        "the secret must survive the rejected revocation"
    );
}

#[tokio::test]
async fn test_revoke_tokens_rejects_deactivated_user() {
    let (app, state) = test_app().await;
    let (app_id, token) =
        setup_deactivated_owner_with_app(&state, "deactivated-revoke@example.com").await;

    let (status, body) = http_post_json(
        &app,
        &format!("/api/v1/applications/{app_id}/revoke"),
        r#"{}"#,
        &[("Authorization", &bearer(&token))],
    )
    .await;

    assert_deactivated_rejection(status, &body);
    let now = jiff::Timestamp::now();
    let survivors = db::get_oauth_client_secrets(&state.store, &app_id)
        .await
        .expect("db read");
    assert!(
        survivors.iter().any(|s| s.is_valid(&now)),
        "secrets must survive the rejected revoke-all"
    );
}

// ========================================================================
// DELETE /api/v1/applications/:id — ClientDeleted audit event
// ========================================================================

/// `delete_application_api` must record a `ClientDeleted` (`oauth_client_deleted`)
/// audit event after the delete commits, mirroring the RFC 7592 delete path.
/// Regression for the audit-parity gap: the most destructive application
/// operation left no durable record in the audit/OCSF pipeline.
#[tokio::test]
async fn delete_application_api_records_client_deleted_audit_event() {
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "audit-delete@example.com").await;
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

    let events = state
        .audit
        .query_events(&AuditEventFilter {
            event_types: Some(vec!["oauth_client_deleted".to_string()]),
            user_id: Some(user.id.clone()),
            ..Default::default()
        })
        .await
        .expect("query audit events");

    assert_eq!(
        events.len(),
        1,
        "API delete must write exactly one audit event; got {}",
        events.len()
    );
}

/// The `ClientDeleted` event's org-domain attribution must fall through to the
/// client's own org when the owning user has no org. Regression for the
/// pre-resolution step: the client doc is already deleted when the event is
/// recorded, so a naive client-org lookup would miss. Mirrors the RFC 7592
/// regression test at `rfc7592.rs:1821`.
#[tokio::test]
async fn delete_application_api_attributes_org_domain_for_org_owned_client() {
    let (app, state) = test_app().await;

    let org = create_test_org(&state.store, "api-org-owned-deleted.example").await;
    // The owner has no org of their own, so the user-org branch of the
    // resolution guard does not fire; attribution must come from the captured
    // `client.org_id`.
    let owner = create_test_user(&state.store, "solo-owner-api@personal.example").await;
    let auth_id = create_test_authenticator(&state.store, &owner.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &owner.id,
            email: &owner.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    let auth = bearer(&token);
    let client = create_test_client(
        &state.store,
        &owner.id,
        TestClientSpec {
            org_id: Some(org.id.clone()),
            ..Default::default()
        },
    )
    .await;

    let (status, _body) = http_delete(
        &app,
        &format!("/api/v1/applications/{}", client.app_id),
        &[("Authorization", &auth)],
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let events = state
        .audit
        .query_events(&AuditEventFilter {
            event_types: Some(vec!["oauth_client_deleted".to_string()]),
            user_id: Some(owner.id.clone()),
            ..Default::default()
        })
        .await
        .expect("query audit events");
    assert_eq!(events.len(), 1, "delete must write exactly one audit event");
    assert_eq!(
        events[0].email_domain.as_deref(),
        Some("api-org-owned-deleted.example"),
        "the client's own org must be attributed even though the owning user \
         has no org and the client doc is already deleted by the time the \
         event is recorded"
    );
}

// ========================================================================
// DELETE /api/v1/applications/:id — ClientDeleted org-domain/edge cases
// (guards B/G7, G9, G14, G15 not pinned by the two parity tests above)
// ========================================================================

/// **G7** — when the owning user belongs to an org and the deleted app is
/// personal (`org_id == None`), the `ClientDeleted` event's `email_domain`
/// must be the acting user's own org domain (resolved via the
/// `user.org_id` → `get_organization_domain` branch of the pre-resolution
/// guard, since `upsert_user_with_org` leaves `org_domain` unstamped).
#[tokio::test]
async fn delete_application_api_attributes_user_org_domain_for_personal_app() {
    let (app, state) = test_app().await;

    let org = create_test_org(&state.store, "user-org-personal.example").await;
    let owner = create_test_user_in_org(
        &state.store,
        "org-member@user-org-personal.example",
        &org.id,
        false,
    )
    .await;
    let auth_id = create_test_authenticator(&state.store, &owner.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &owner.id,
            email: &owner.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    let auth = bearer(&token);
    // Personal app: client.org_id == None even though the owner has an org.
    let client = create_test_oauth_client(&state.store, &owner.id).await;

    let (status, _body) = http_delete(
        &app,
        &format!("/api/v1/applications/{}", client.app_id),
        &[("Authorization", &auth)],
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let events = state
        .audit
        .query_events(&AuditEventFilter {
            event_types: Some(vec!["oauth_client_deleted".to_string()]),
            user_id: Some(owner.id.clone()),
            ..Default::default()
        })
        .await
        .expect("query audit events");
    assert_eq!(events.len(), 1, "delete must write exactly one audit event");
    assert_eq!(
        events[0].email_domain.as_deref(),
        Some("user-org-personal.example"),
        "a personal app deleted by an org member must be attributed to the \
         acting user's own org domain"
    );
}

/// **G9** — when neither the owning user nor the deleted app has an org, the
/// `ClientDeleted` event's `email_domain` must be `None` (no spurious
/// attribution, no panic, no failed lookup surfacing as an error).
#[tokio::test]
async fn delete_application_api_no_org_when_personal_app_and_solo_owner() {
    let (app, state) = test_app().await;

    let owner = create_test_user(&state.store, "solo-no-org@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &owner.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &owner.id,
            email: &owner.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    let auth = bearer(&token);
    let client = create_test_oauth_client(&state.store, &owner.id).await;

    let (status, _body) = http_delete(
        &app,
        &format!("/api/v1/applications/{}", client.app_id),
        &[("Authorization", &auth)],
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let events = state
        .audit
        .query_events(&AuditEventFilter {
            event_types: Some(vec!["oauth_client_deleted".to_string()]),
            user_id: Some(owner.id.clone()),
            ..Default::default()
        })
        .await
        .expect("query audit events");
    assert_eq!(events.len(), 1, "delete must write exactly one audit event");
    assert!(
        events[0].email_domain.is_none(),
        "an app with no org deleted by a user with no org must have no \
         email_domain attribution; got {:?}",
        events[0].email_domain
    );
}

/// **G14** — a non-owner caller is rejected with 404 and must write **no**
/// `oauth_client_deleted` event (the audit row reflects only a successful
/// delete commit). Pins the "no event on rejection" half that the existing
/// `test_delete_application_not_found` (response half) does not assert.
#[tokio::test]
async fn delete_application_api_non_owner_writes_no_audit_event() {
    let (app, state) = test_app().await;

    let owner = create_test_user(&state.store, "owner@non-owner-audit.example").await;
    let caller = create_test_user(&state.store, "caller@non-owner-audit.example").await;
    let caller_auth_id = create_test_authenticator(&state.store, &caller.id).await;
    let caller_token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &caller.id,
            email: &caller.email,
            auth_id: Some(&caller_auth_id),
            ..Default::default()
        },
    )
    .await;
    let client = create_test_oauth_client(&state.store, &owner.id).await;

    let (status, _body) = http_delete(
        &app,
        &format!("/api/v1/applications/{}", client.app_id),
        &[("Authorization", &bearer(&caller_token))],
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "non-owner must get 404");

    let events = state
        .audit
        .query_events(&AuditEventFilter {
            event_types: Some(vec!["oauth_client_deleted".to_string()]),
            ..Default::default()
        })
        .await
        .expect("query audit events");
    assert!(
        events.is_empty(),
        "a rejected (non-owner) delete must write no oauth_client_deleted event; \
         got {events_len}",
        events_len = events.len()
    );
    // The client must survive a rejected delete.
    assert!(
        db::get_oauth_client_by_id(&state.store, &client.app_id)
            .await
            .expect("db read")
            .is_some(),
        "the application must still exist after a rejected delete"
    );
}

/// **G14 (deactivated)** — a deactivated owner is rejected (401
/// `unauthorized`) and must write **no** `oauth_client_deleted` event.
#[tokio::test]
async fn delete_application_api_deactivated_owner_writes_no_audit_event() {
    let (app, state) = test_app().await;
    let (app_id, token) =
        setup_deactivated_owner_with_app(&state, "deactivated-del-audit@example.com").await;

    let (status, _body) = http_delete(
        &app,
        &format!("/api/v1/applications/{app_id}"),
        &[("Authorization", &bearer(&token))],
    )
    .await;
    // The handler's `load_active_owned_client` gates on an active user first.
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let events = state
        .audit
        .query_events(&AuditEventFilter {
            event_types: Some(vec!["oauth_client_deleted".to_string()]),
            ..Default::default()
        })
        .await
        .expect("query audit events");
    assert!(
        events.is_empty(),
        "a rejected (deactivated owner) delete must write no oauth_client_deleted \
         event; got {events_len}",
        events_len = events.len()
    );
}

/// **G15** — when `delete_oauth_client_and_revoke_sessions` errors, the handler
/// returns 500 `db_error` and must write **no** `oauth_client_deleted` event;
/// the audit row reflects only what actually committed. Uses the same
/// fault-injection seam as `test_delete_application_partial_failure_*`:
/// `set_delete_by_index_remaining_successes(0)` faults the cascade's first
/// `delete_by_index` (the M2M session sweep), so `delete_oauth_client` is never
/// reached and the client document survives.
#[tokio::test]
async fn delete_application_api_failed_delete_writes_no_audit_event() {
    let (app, state) = test_app_with_modify_hook(|store| {
        store.set_delete_by_index_remaining_successes(0);
    })
    .await;

    let user = create_test_user(&state.store, "failed-delete-audit@example.com").await;
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
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "a faulted delete must surface as 500 db_error, not 204"
    );

    let events = state
        .audit
        .query_events(&AuditEventFilter {
            event_types: Some(vec!["oauth_client_deleted".to_string()]),
            ..Default::default()
        })
        .await
        .expect("query audit events");
    assert!(
        events.is_empty(),
        "a failed delete must write no oauth_client_deleted event; got {events_len}",
        events_len = events.len()
    );
    // The client document must survive the failed delete (the cascade faults
    // before `delete_oauth_client`).
    assert!(
        db::get_oauth_client_by_id(&state.store, &client.app_id)
            .await
            .expect("db read")
            .is_some(),
        "the application must still exist after a failed delete cascade"
    );
}

// ========================================================================
// Transport metadata on the application API audit rows
// ========================================================================

/// Adding and revoking a secret, revoking all tokens, and deleting the
/// application through the API each record the requester's IP and
/// User-Agent on their audit row. Before the fix all four wrote
/// `ip_address: None, user_agent: None` although the handler had the request
/// in hand.
#[tokio::test]
async fn application_api_audit_rows_record_transport() {
    let (app, state) = test_app().await;
    let (app_id, token) = setup_user_with_app(&state, "api-audit-transport@example.com").await;
    let auth = bearer(&token);
    let ua = "vouch-applications-audit/1.0";
    let headers = [("Authorization", auth.as_str()), ("User-Agent", ua)];

    let (status, body) = http_post_json(
        &app,
        &format!("/api/v1/applications/{app_id}/secrets"),
        "{}",
        &headers,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "add secret: {body}");
    let added: serde_json::Value = serde_json::from_str(&body).unwrap();
    let secret_id = added["secret_id"].as_str().unwrap();

    let (status, body) = http_delete(
        &app,
        &format!("/api/v1/applications/{app_id}/secrets/{secret_id}"),
        &headers,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "delete secret: {body}");

    let (status, body) = http_post_json(
        &app,
        &format!("/api/v1/applications/{app_id}/revoke"),
        "{}",
        &headers,
    )
    .await;
    assert!(status.is_success(), "revoke tokens: {status} {body}");

    let (status, body) =
        http_delete(&app, &format!("/api/v1/applications/{app_id}"), &headers).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "delete application: {body}");

    for event_type in [
        "oauth_secret_added",
        "oauth_secret_revoked",
        "oauth_token_revoked",
        "oauth_client_deleted",
    ] {
        assert_audit_rows_record_transport(&state, event_type, ua).await;
    }
}

// ========================================================================
// mTLS port: peer IP without ConnectInfo<SocketAddr>
// ========================================================================

/// On the mTLS port axum's `into_make_service_with_connect_info::<PeerClientCert>()`
/// injects only `ConnectInfo<PeerClientCert>` — there is no
/// `ConnectInfo<SocketAddr>`. The `TrustedProxyKeyExtractor` (rate limiter) and
/// the `ClientInfo` audit extractor must therefore resolve the peer IP from
/// `PeerClientCert.peer_addr` via `peer_ip_from_extensions`. Before the fix the
/// rate limiter found no key and returned HTTP 500 on every rate-limited mTLS
/// request (`/oauth/token`, `/oauth/register`, `/oauth/revoke`,
/// `/oauth/introspect`, `/api/v1/*`); this test pins the fix by asserting the
/// handler runs (non-500) on the simulated mTLS port, and that the HTTPS-port
/// control (which has `ConnectInfo<SocketAddr>`) is unchanged.
#[tokio::test]
async fn mtls_port_without_socketaddr_extension_does_not_500() {
    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use axum::http::Request;
    use std::net::SocketAddr;
    use tower::ServiceExt;

    use crate::infra::mtls_listener::PeerClientCert;

    // --- mTLS-port simulation: only ConnectInfo<PeerClientCert> present ---
    // `test_config()` has `certification_test_token: None`, so the real
    // auth rate limiter is installed on `/oauth/token`.
    let (app, _state) = test_app().await;
    let request = Request::builder()
        .method("POST")
        .uri("/oauth/token")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from("grant_type=client_credentials"))
        .unwrap();
    let (mut parts, body) = request.into_parts();
    parts.extensions.insert(ConnectInfo(PeerClientCert {
        peer_chain_der: Vec::new(),
        peer_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
    }));
    let request = Request::from_parts(parts, body);
    let mtls_status = app.oneshot(request).await.unwrap().status();
    assert_ne!(
        mtls_status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "mTLS port (only ConnectInfo<PeerClientCert>): the rate limiter must \
         resolve a key from PeerClientCert.peer_addr and hand off to the \
         handler (non-500); got {mtls_status}"
    );

    // --- Control: HTTPS-port simulation — ConnectInfo<SocketAddr> present ---
    let (app2, _state2) = test_app().await;
    let request = Request::builder()
        .method("POST")
        .uri("/oauth/token")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from("grant_type=client_credentials"))
        .unwrap();
    let (mut parts, body) = request.into_parts();
    parts
        .extensions
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))));
    let request = Request::from_parts(parts, body);
    let https_status = app2.oneshot(request).await.unwrap().status();
    assert_ne!(
        https_status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "HTTPS port (ConnectInfo<SocketAddr> present): expected handler to \
         run (non-500), got {https_status}"
    );
}

/// An audit row written on the simulated mTLS port — only
/// `ConnectInfo<PeerClientCert>` injected, no `ConnectInfo<SocketAddr>` —
/// records the peer IP carried by `PeerClientCert.peer_addr`. Before the fix
/// commit 9c4231fc's `ClientInfo` extractor read only `ConnectInfo<SocketAddr>`
/// (absent on the mTLS port), so every mTLS audit row carried
/// `client_ip: null` despite the commit's "every audit row" scope.
#[tokio::test]
async fn mtls_port_audit_row_records_peer_cert_addr() {
    let (app, state) = test_app().await;
    let (app_id, token) = setup_user_with_app(&state, "mtls-audit-transport@example.com").await;
    let auth = bearer(&token);
    let ua = "vouch-mtls-audit/1.0";
    let headers = [("Authorization", auth.as_str()), ("User-Agent", ua)];

    // Simulated mTLS port: `http_post_json_with_cert` injects only
    // `ConnectInfo<PeerClientCert{peer_addr: 127.0.0.1}>` — no
    // `ConnectInfo<SocketAddr>`. No client cert is needed: the applications
    // API authenticates via the bearer token.
    let (status, body) = http_post_json_with_cert(
        &app,
        &format!("/api/v1/applications/{app_id}/secrets"),
        "{}",
        &headers,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "add secret on mTLS port: {body}"
    );

    // `assert_audit_rows_record_transport` asserts `client_ip == "127.0.0.1"`
    // and `user_agent == ua`; with the fallback broken, `client_ip` would be
    // null and this would fail.
    assert_audit_rows_record_transport(&state, "oauth_secret_added", ua).await;
}
