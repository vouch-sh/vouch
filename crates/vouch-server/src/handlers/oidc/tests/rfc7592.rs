// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 7592 — OAuth 2.0 Dynamic Client Registration Management tests.
//!
//! Tests for the `DELETE /oauth/register/:client_id` endpoint.
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
