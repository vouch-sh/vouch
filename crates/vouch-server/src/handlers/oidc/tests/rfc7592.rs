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

// =========================================================================
// PUT /oauth/register/:client_id — userinfo_signed_response_alg + request_uris
// =========================================================================

#[tokio::test]
async fn test_rfc7592_put_sets_userinfo_signed_response_alg() {
    // RFC 7592 Section 2.2: PUT must allow setting userinfo_signed_response_alg.
    // The field must be stored and returned in the response.
    let (app, _state) = test_app().await;
    let (client_id, token) = register_dynamic_client(&app).await;

    let update_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "userinfo_signed_response_alg": "ES256"
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
    assert_eq!(
        json["userinfo_signed_response_alg"].as_str(),
        Some("ES256"),
        "PUT response must echo userinfo_signed_response_alg: {json}"
    );
}

#[tokio::test]
async fn test_rfc7592_put_clears_userinfo_signed_response_alg() {
    // RFC 7592 Section 2.2: PUT is a full replacement. Omitting
    // userinfo_signed_response_alg must clear any previously set value.
    let (app, _state) = test_app().await;

    // Register with ES256 userinfo signing
    let body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "client_name": "Userinfo Alg Clear Test",
        "userinfo_signed_response_alg": "ES256"
    });
    let (status, body_str) = http_post_json(&app, "/oauth/register", &body.to_string(), &[]).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "Registration failed: {body_str}"
    );
    let reg_json: serde_json::Value = serde_json::from_str(&body_str).expect("Valid JSON");
    let client_id = reg_json["client_id"]
        .as_str()
        .expect("client_id")
        .to_string();
    let token = reg_json["registration_access_token"]
        .as_str()
        .expect("registration_access_token")
        .to_string();

    // PUT without userinfo_signed_response_alg — must clear the field
    let update_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"]
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
    // Field must be absent or null — plain JSON response means unsigned userinfo
    assert!(
        json.get("userinfo_signed_response_alg").is_none()
            || json["userinfo_signed_response_alg"].is_null(),
        "PUT without userinfo_signed_response_alg must clear the field, got: {json}"
    );
}

#[tokio::test]
async fn test_rfc7592_put_sets_request_uris() {
    // RFC 7592 Section 2.2: PUT must store request_uris (OIDC Core Section 6.2 allowlist).
    // The field must be present in the response when set.
    let (app, _state) = test_app().await;
    let (client_id, token) = register_dynamic_client(&app).await;

    let update_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "request_uris": ["https://example.com/requests/req1.jwt"]
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
    let uris = json["request_uris"]
        .as_array()
        .expect("request_uris must be a JSON array in PUT response");
    assert_eq!(uris.len(), 1, "Must store exactly one request_uri");
    assert_eq!(
        uris[0].as_str(),
        Some("https://example.com/requests/req1.jwt"),
        "Stored request_uri must match the PUT value"
    );
}

#[tokio::test]
async fn test_rfc7592_put_clears_request_uris() {
    // RFC 7592 Section 2.2: PUT is a full replacement. Omitting request_uris
    // in a subsequent PUT must clear the allowlist (revert to "accept any").
    let (app, _state) = test_app().await;

    // Register with a request_uri allowlist
    let body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "client_name": "Request URIs Clear Test",
        "request_uris": ["https://example.com/requests/req1.jwt"]
    });
    let (status, body_str) = http_post_json(&app, "/oauth/register", &body.to_string(), &[]).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "Registration failed: {body_str}"
    );
    let reg_json: serde_json::Value = serde_json::from_str(&body_str).expect("Valid JSON");
    let client_id = reg_json["client_id"]
        .as_str()
        .expect("client_id")
        .to_string();
    let token = reg_json["registration_access_token"]
        .as_str()
        .expect("registration_access_token")
        .to_string();

    // PUT without request_uris — must clear the allowlist
    let update_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"]
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
    // Field must be absent or null — no allowlist means any HTTPS request_uri accepted
    assert!(
        json.get("request_uris").is_none() || json["request_uris"].is_null(),
        "PUT without request_uris must clear the allowlist, got: {json}"
    );
}

#[tokio::test]
async fn test_rfc7592_put_rejects_non_https_request_uri() {
    // RFC 7592 Section 2.2 + OIDC Core Section 6.2: request_uris must be HTTPS.
    // An HTTP URI in request_uris must be rejected with 400.
    let (app, _state) = test_app().await;
    let (client_id, token) = register_dynamic_client(&app).await;

    let update_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "request_uris": ["http://evil.example.com/request.jwt"]
    });

    let (status, _body) = http_request(
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
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Non-HTTPS request_uri in PUT must be rejected with 400"
    );
}

#[tokio::test]
async fn test_rfc7592_put_rejects_invalid_userinfo_signing_alg() {
    // RFC 7592 Section 2.2: Invalid userinfo_signed_response_alg must return 400.
    // Only RS256 and ES256 are accepted.
    let (app, _state) = test_app().await;
    let (client_id, token) = register_dynamic_client(&app).await;

    let update_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "userinfo_signed_response_alg": "HS256"
    });

    let (status, _body) = http_request(
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
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Invalid userinfo_signed_response_alg (HS256) in PUT must return 400"
    );
}

// =========================================================================
// PUT /oauth/register/:client_id — contacts and URI validation
//
// The create path (POST /oauth/register) runs validate_contacts_and_uris.
// The update path (PUT /oauth/register/:client_id) must apply the same
// rules: non-HTTPS logo_uri and non-@ contacts are rejected at update time,
// not silently stored.
// =========================================================================

/// RFC 7592 PUT with an invalid `logo_uri` (HTTP, not HTTPS) must be rejected
/// with 400 `invalid_client_metadata`, matching the create-path behaviour.
#[tokio::test]
async fn test_rfc7592_put_rejects_invalid_logo_uri() {
    let (app, _state) = test_app().await;
    let (client_id, token) = register_dynamic_client(&app).await;

    let update_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "logo_uri": "http://insecure.example.com/logo.png"
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
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Non-HTTPS logo_uri in PUT must return 400, got: {body}"
    );
    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        json["error"], "invalid_client_metadata",
        "logo_uri rejection must use invalid_client_metadata: {body}"
    );
}

/// RFC 7592 PUT with a contact that lacks an `@` sign must be rejected with
/// 400 `invalid_client_metadata`, matching the create-path behaviour.
#[tokio::test]
async fn test_rfc7592_put_rejects_invalid_contact() {
    let (app, _state) = test_app().await;
    let (client_id, token) = register_dynamic_client(&app).await;

    let update_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "contacts": ["not-an-email-address"]
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
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Contact without @ in PUT must return 400, got: {body}"
    );
    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        json["error"], "invalid_client_metadata",
        "contact rejection must use invalid_client_metadata: {body}"
    );
}

/// RFC 7592 PUT with a valid `logo_uri` (HTTPS) must succeed.
/// Confirms the validation is not over-restrictive.
#[tokio::test]
async fn test_rfc7592_put_accepts_valid_logo_uri() {
    let (app, _state) = test_app().await;
    let (client_id, token) = register_dynamic_client(&app).await;

    let update_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "logo_uri": "https://example.com/logo.png"
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
    assert_eq!(
        status,
        StatusCode::OK,
        "Valid HTTPS logo_uri in PUT must succeed: {body}"
    );
    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        json["logo_uri"].as_str(),
        Some("https://example.com/logo.png"),
        "logo_uri must be echoed back in PUT response"
    );
}

/// RFC 7592 PUT with valid contacts must succeed.
#[tokio::test]
async fn test_rfc7592_put_accepts_valid_contacts() {
    let (app, _state) = test_app().await;
    let (client_id, token) = register_dynamic_client(&app).await;

    let update_body = serde_json::json!({
        "redirect_uris": ["https://example.com/callback"],
        "contacts": ["admin@example.com"]
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
    assert_eq!(
        status,
        StatusCode::OK,
        "Valid contact in PUT must succeed: {body}"
    );
    let json: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let contacts = json["contacts"].as_array().expect("contacts must be array");
    assert_eq!(contacts.len(), 1, "PUT response must echo the contact list");
    assert_eq!(contacts[0].as_str(), Some("admin@example.com"));
}
