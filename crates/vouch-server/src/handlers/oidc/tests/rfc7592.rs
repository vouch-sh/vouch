// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 7592 — OAuth 2.0 Dynamic Client Registration Management tests.
//!
//! Tests for `PUT /oauth/register/:client_id` and `DELETE /oauth/register/:client_id`.
//!
//! Reference: <https://www.rfc-editor.org/rfc/rfc7592>

use super::helpers::*;

/// Register a client via POST /oauth/register, return (client_id, registration_access_token).
async fn register_dynamic_client(app: &axum::Router) -> (String, String) {
    let body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "client_name": "RFC7592 Test Client"
    });

    let (status, body) = http_post_json(app, "/oauth/register", &body.to_string(), &[]).await;
    assert_eq!(status, StatusCode::CREATED, "Registration failed: {body}");

    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let client_id = json["client_id"].as_str().expect("client_id").to_string();
    let token = json["registration_access_token"]
        .as_str()
        .expect("registration_access_token")
        .to_string();

    (client_id, token)
}

// =========================================================================
// PUT /oauth/register/:client_id — Update Client Configuration
// =========================================================================

#[tokio::test]
async fn test_rfc7592_put_updates_redirect_uris() {
    let (app, _state) = test_app().await;
    let (client_id, token) = register_dynamic_client(&app).await;

    let update_body = serde_json::json!({
        "redirect_uris": ["https://new-callback.example.com/callback"],
        "client_name": "Updated Client"
    });

    let (status, body) = http_request(
        &app,
        "PUT",
        &format!("/oauth/register/{client_id}"),
        Some(update_body.to_string()),
        &[
            ("Authorization", &format!("Bearer {token}")),
            ("Content-Type", "application/json"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "PUT failed: {body}");

    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(json["client_id"].as_str().unwrap(), client_id);
    let uris = json["redirect_uris"]
        .as_array()
        .expect("redirect_uris array");
    assert_eq!(uris.len(), 1, "Old URI should be gone");
    assert_eq!(
        uris[0].as_str().unwrap(),
        "https://new-callback.example.com/callback"
    );
    // PUT must return a new registration_access_token (token rotation)
    let new_token = json["registration_access_token"]
        .as_str()
        .expect("PUT response must include a new registration_access_token");

    // Verify stored state via GET with the new token
    let (status, body) = http_request(
        &app,
        "GET",
        &format!("/oauth/register/{client_id}"),
        None,
        &[("Authorization", &format!("Bearer {new_token}"))],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "GET after PUT failed: {body}");
    let get_json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        get_json["redirect_uris"][0].as_str().unwrap(),
        "https://new-callback.example.com/callback",
        "Stored redirect_uri should match the PUT update"
    );
}

#[tokio::test]
async fn test_rfc7592_put_rotates_token() {
    let (app, _state) = test_app().await;
    let (client_id, token) = register_dynamic_client(&app).await;

    let update_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback2"]
    });

    let (status, body) = http_request(
        &app,
        "PUT",
        &format!("/oauth/register/{client_id}"),
        Some(update_body.to_string()),
        &[
            ("Authorization", &format!("Bearer {token}")),
            ("Content-Type", "application/json"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let new_token = json["registration_access_token"]
        .as_str()
        .expect("new token")
        .to_string();

    // Old token must no longer work
    let (status, _body) = http_request(
        &app,
        "GET",
        &format!("/oauth/register/{client_id}"),
        None,
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "Old token should be rejected after rotation"
    );

    // New token must work
    let (status, _body) = http_request(
        &app,
        "GET",
        &format!("/oauth/register/{client_id}"),
        None,
        &[("Authorization", &format!("Bearer {new_token}"))],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "New token should work");
}

#[tokio::test]
async fn test_rfc7592_put_missing_bearer_token() {
    let (app, _state) = test_app().await;
    let (client_id, _token) = register_dynamic_client(&app).await;

    let update_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"]
    });

    let response = http_request_full(
        &app,
        "PUT",
        &format!("/oauth/register/{client_id}"),
        Some(update_body.to_string()),
        &[("Content-Type", "application/json")],
    )
    .await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_rfc7592_put_invalid_bearer_token() {
    let (app, _state) = test_app().await;
    let (client_id, _token) = register_dynamic_client(&app).await;

    let update_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"]
    });

    let (status, _body) = http_request(
        &app,
        "PUT",
        &format!("/oauth/register/{client_id}"),
        Some(update_body.to_string()),
        &[
            ("Authorization", "Bearer invalid_token_value"),
            ("Content-Type", "application/json"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_rfc7592_put_nonexistent_client() {
    let (app, _state) = test_app().await;

    let update_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"]
    });

    let (status, _body) = http_request(
        &app,
        "PUT",
        "/oauth/register/nonexistent-client-id",
        Some(update_body.to_string()),
        &[
            ("Authorization", "Bearer some_token"),
            ("Content-Type", "application/json"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// =========================================================================
// DELETE /oauth/register/:client_id — Delete Client Configuration
// =========================================================================

#[tokio::test]
async fn test_rfc7592_delete_client_succeeds() {
    let (app, _state) = test_app().await;
    let (client_id, token) = register_dynamic_client(&app).await;

    // DELETE with valid token — expect 204
    let (status, _body) = http_delete(
        &app,
        &format!("/oauth/register/{client_id}"),
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // GET after delete — expect 404
    let (status, _body) = http_request(
        &app,
        "GET",
        &format!("/oauth/register/{client_id}"),
        None,
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "Deleted client should return 404"
    );
}

#[tokio::test]
async fn test_rfc7592_delete_client_missing_bearer_token() {
    let (app, _state) = test_app().await;
    let (client_id, _token) = register_dynamic_client(&app).await;

    // DELETE without Authorization header — expect 401
    let response = http_delete_full(&app, &format!("/oauth/register/{client_id}"), &[]).await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    assert!(
        response
            .headers
            .get("www-authenticate")
            .is_some_and(|v| v.to_str().is_ok_and(|s| s.contains("Bearer"))),
        "Must include WWW-Authenticate: Bearer header"
    );
}

#[tokio::test]
async fn test_rfc7592_delete_client_invalid_bearer_token() {
    let (app, _state) = test_app().await;
    let (client_id, _token) = register_dynamic_client(&app).await;

    // DELETE with wrong token — expect 401
    let (status, _body) = http_delete(
        &app,
        &format!("/oauth/register/{client_id}"),
        &[("Authorization", "Bearer invalid_token_value")],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_rfc7592_delete_client_nonexistent() {
    let (app, _state) = test_app().await;

    // DELETE for a client_id that doesn't exist — expect 404
    let (status, _body) = http_delete(
        &app,
        "/oauth/register/nonexistent-client-id",
        &[("Authorization", "Bearer some_token")],
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_rfc7592_delete_client_already_deleted() {
    let (app, _state) = test_app().await;
    let (client_id, token) = register_dynamic_client(&app).await;

    // First delete — 204
    let (status, _body) = http_delete(
        &app,
        &format!("/oauth/register/{client_id}"),
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Second delete — 404 (idempotent)
    let (status, _body) = http_delete(
        &app,
        &format!("/oauth/register/{client_id}"),
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "Second delete should return 404"
    );
}
