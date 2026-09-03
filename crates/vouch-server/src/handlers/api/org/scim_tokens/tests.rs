// SPDX-License-Identifier: Apache-2.0 OR MIT
#![expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable"
)]

use crate::handlers::admin::MAX_SCIM_TOKEN_DESCRIPTION_CHARS;
use axum::http::StatusCode;

use crate::test_utils::*;

// ValidPath<ValidUuid> is extracted before the handler body runs auth checks,
// so a malformed UUID must produce 400 regardless of authentication state.

#[tokio::test]
async fn test_delete_scim_token_invalid_uuid_returns_400() {
    let (app, _state) = test_app().await;

    let (status, body) = http_delete(&app, "/api/v1/org/scim-tokens/not-a-uuid", &[]).await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
}

#[tokio::test]
async fn test_delete_scim_token_invalid_uuid_error_is_json() {
    let (app, _state) = test_app().await;

    let (status, body) = http_delete(&app, "/api/v1/org/scim-tokens/not-a-uuid", &[]).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    // ServiceError::api produces {"code": "...", "message": "..."}
    let json: serde_json::Value =
        serde_json::from_str(&body).expect("error response must be valid JSON");
    assert!(
        json.get("code").is_some(),
        "JSON error must contain 'code' field; got: {json}"
    );
}

#[tokio::test]
async fn test_delete_scim_token_valid_uuid_proceeds_to_auth_check() {
    // A valid UUID with no auth should fail with 401, not 400,
    // confirming UUID validation passed and auth ran.
    let (app, _state) = test_app().await;
    let valid_uuid = uuid::Uuid::now_v7();

    let (status, _body) =
        http_delete(&app, &format!("/api/v1/org/scim-tokens/{valid_uuid}"), &[]).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ================================================================
// Input validation runs before auth (fail fast on bad input)
// ================================================================

#[tokio::test]
async fn test_create_scim_token_invalid_expiry_returns_400_without_auth() {
    let (app, _state) = test_app().await;

    // Invalid expires_in_days returns 400 (input validation before auth)
    let (status, _body) = http_post_json(
        &app,
        "/api/v1/org/scim-tokens",
        r#"{"description": "test", "expires_in_days": 0}"#,
        &[], // No auth header
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Invalid input must return 400 before auth check"
    );
}

#[tokio::test]
async fn test_create_scim_token_long_description_returns_400_without_auth() {
    let (app, _state) = test_app().await;

    let long_desc = "x".repeat(257);
    let body_json = format!(
        r#"{{"description": "{}", "expires_in_days": 30}}"#,
        long_desc
    );

    let (status, _body) = http_post_json(
        &app,
        "/api/v1/org/scim-tokens",
        &body_json,
        &[], // No auth header
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Invalid input must return 400 before auth check"
    );
}

// The description guard counts Unicode characters, not UTF-8 bytes, so a
// multibyte description under the limit the form advertises clears
// validation and fails only on auth.
#[tokio::test]
async fn test_create_scim_token_multibyte_description_within_char_limit() {
    let (app, _state) = test_app().await;

    // 200 CJK characters = 600 UTF-8 bytes.
    let desc = "説".repeat(200);
    assert_eq!(desc.chars().count(), 200);
    assert!(desc.len() > MAX_SCIM_TOKEN_DESCRIPTION_CHARS);
    let body_json = serde_json::json!({ "description": desc, "expires_in_days": 30 }).to_string();

    let (status, body) = http_post_json(&app, "/api/v1/org/scim-tokens", &body_json, &[]).await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "multibyte description within the character limit must pass validation: {body}"
    );
}

#[tokio::test]
async fn test_create_scim_token_multibyte_description_over_char_limit() {
    let (app, _state) = test_app().await;

    let desc = "説".repeat(257);
    let body_json = serde_json::json!({ "description": desc, "expires_in_days": 30 }).to_string();

    let (status, _body) = http_post_json(&app, "/api/v1/org/scim-tokens", &body_json, &[]).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_create_scim_token_valid_input_returns_401_without_auth() {
    let (app, _state) = test_app().await;

    // Valid input but no auth → 401 (input validation passes, auth fails)
    let (status, _body) = http_post_json(
        &app,
        "/api/v1/org/scim-tokens",
        r#"{"description": "test", "expires_in_days": 30}"#,
        &[], // No auth header
    )
    .await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "Valid input without auth must return 401"
    );
}

// ================================================================
// Authenticated CRUD — Create (positive)
// ================================================================

#[tokio::test]
async fn test_create_scim_token_succeeds() {
    let (app, state) = test_app().await;
    let org = create_test_org(&state.store, "example.com").await;
    let admin = create_test_user_in_org(&state.store, "admin@example.com", &org.id, true).await;
    let auth_id = create_test_authenticator(&state.store, &admin.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &admin.id,
            email: &admin.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    let auth_header = format!("Bearer {token}");

    let (status, body) = http_post_json(
        &app,
        "/api/v1/org/scim-tokens",
        r#"{"description": "CI provisioning", "expires_in_days": 30}"#,
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    let resp: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert!(resp["id"].as_str().is_some(), "response must contain id");
    let scim_token = resp["token"].as_str().expect("response must contain token");
    assert!(
        scim_token.starts_with("vouch_scim_"),
        "token must start with vouch_scim_, got: {scim_token}"
    );
    assert_eq!(
        resp["description"].as_str(),
        Some("CI provisioning"),
        "description must match"
    );
    assert!(
        resp["expires_at"].as_str().is_some(),
        "expires_at must be present"
    );
}

// RFC 8705 Section 3: "The protected resource MUST obtain, from its TLS
// implementation layer, the client certificate used for mutual TLS and MUST
// verify that the certificate matches the certificate associated with the
// access token."
#[tokio::test]
async fn test_create_scim_token_cert_bound_token_with_matching_cert_succeeds() {
    let (app, state) = test_app().await;
    let org = create_test_org(&state.store, "example.com").await;
    let admin = create_test_user_in_org(&state.store, "admin@example.com", &org.id, true).await;
    let auth_id = create_test_authenticator(&state.store, &admin.id).await;

    let cert_der = make_test_cert_der("scim-admin");
    let thumbprint = crate::services::oidc::mtls::compute_cert_thumbprint(&cert_der);
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &admin.id,
            email: &admin.email,
            auth_id: Some(&auth_id),
            binding: TestBinding::Mtls(&thumbprint),
            ..Default::default()
        },
    )
    .await;
    let auth_header = format!("Bearer {token}");

    let (status, body) = http_post_json_with_cert(
        &app,
        "/api/v1/org/scim-tokens",
        r#"{"description": "CI provisioning", "expires_in_days": 30}"#,
        &[("Authorization", &auth_header)],
        Some(cert_der),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    let resp: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert!(resp["id"].as_str().is_some(), "response must contain id");
}

// RFC 8705 Section 3: "If they do not match, the resource access attempt MUST
// be rejected with an error, per [RFC6750], using an HTTP 401 status code and
// the "invalid_token" error code."
#[tokio::test]
async fn test_create_scim_token_cert_bound_token_without_cert_returns_401() {
    let (app, state) = test_app().await;
    let org = create_test_org(&state.store, "example.com").await;
    let admin = create_test_user_in_org(&state.store, "admin@example.com", &org.id, true).await;
    let auth_id = create_test_authenticator(&state.store, &admin.id).await;

    let cert_der = make_test_cert_der("scim-admin");
    let thumbprint = crate::services::oidc::mtls::compute_cert_thumbprint(&cert_der);
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &admin.id,
            email: &admin.email,
            auth_id: Some(&auth_id),
            binding: TestBinding::Mtls(&thumbprint),
            ..Default::default()
        },
    )
    .await;
    let auth_header = format!("Bearer {token}");

    let (status, body) = http_post_json_with_cert(
        &app,
        "/api/v1/org/scim-tokens",
        r#"{"description": "CI provisioning", "expires_in_days": 30}"#,
        &[("Authorization", &auth_header)],
        None,
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body}");
    assert!(
        body.contains("invalid_token"),
        "RFC 8705 Section 3 requires the invalid_token error code; body: {body}"
    );
}

#[tokio::test]
async fn test_create_scim_token_cert_bound_token_with_wrong_cert_returns_401() {
    let (app, state) = test_app().await;
    let org = create_test_org(&state.store, "example.com").await;
    let admin = create_test_user_in_org(&state.store, "admin@example.com", &org.id, true).await;
    let auth_id = create_test_authenticator(&state.store, &admin.id).await;

    let bound_cert_der = make_test_cert_der("scim-admin");
    let thumbprint = crate::services::oidc::mtls::compute_cert_thumbprint(&bound_cert_der);
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &admin.id,
            email: &admin.email,
            auth_id: Some(&auth_id),
            binding: TestBinding::Mtls(&thumbprint),
            ..Default::default()
        },
    )
    .await;
    let auth_header = format!("Bearer {token}");

    let other_cert_der = make_test_cert_der("imposter");
    let (status, body) = http_post_json_with_cert(
        &app,
        "/api/v1/org/scim-tokens",
        r#"{"description": "CI provisioning", "expires_in_days": 30}"#,
        &[("Authorization", &auth_header)],
        Some(other_cert_der),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body}");
    assert!(
        body.contains("invalid_token"),
        "RFC 8705 Section 3 requires the invalid_token error code; body: {body}"
    );
}

#[tokio::test]
async fn test_bootstrap_admin_session_cannot_mint_scim_token() {
    // An org admin session minted by upstream IdP sign-in alone (no FIDO2
    // ceremony) must not mint a SCIM token — a long-lived credential that
    // would outlive any later step-up. Same bar as credential issuance.
    let (app, state) = test_app().await;
    let org = create_test_org(&state.store, "example.com").await;
    let admin = create_test_user_in_org(&state.store, "admin@example.com", &org.id, true).await;
    let auth_id = create_test_authenticator(&state.store, &admin.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &admin.id,
            email: &admin.email,
            auth_id: Some(&auth_id),
            verification: TestVerification::NotVerified,
            ..Default::default()
        },
    )
    .await;
    let auth_header = format!("Bearer {token}");

    let (status, body) = http_post_json(
        &app,
        "/api/v1/org/scim-tokens",
        r#"{"description": "CI provisioning", "expires_in_days": 30}"#,
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "an unverified session must not mint SCIM tokens: {body}"
    );
    assert!(
        body.contains("hardware_required"),
        "the refusal must name the missing proof: {body}"
    );
}

#[tokio::test]
async fn test_create_scim_token_custom_expiry() {
    let (app, state) = test_app().await;
    let org = create_test_org(&state.store, "example.com").await;
    let admin = create_test_user_in_org(&state.store, "admin@example.com", &org.id, true).await;
    let auth_id = create_test_authenticator(&state.store, &admin.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &admin.id,
            email: &admin.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    let auth_header = format!("Bearer {token}");

    let (status, body) = http_post_json(
        &app,
        "/api/v1/org/scim-tokens",
        r#"{"description": "long-lived", "expires_in_days": 365}"#,
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    let resp: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    let expires_at_str = resp["expires_at"]
        .as_str()
        .expect("expires_at must be present");
    let expires_at: jiff::Timestamp = expires_at_str
        .parse()
        .expect("expires_at must be valid timestamp");
    let now = jiff::Timestamp::now();
    let diff_secs = expires_at.duration_since(now).as_secs();
    let expected_secs: i64 = 365 * 24 * 3600;
    assert!(
        diff_secs >= expected_secs - 60 && diff_secs <= expected_secs + 60,
        "expires_at should be ~365 days from now, diff was {diff_secs}s"
    );
}

// ================================================================
// Authenticated CRUD — Create (negative)
// ================================================================

#[tokio::test]
async fn test_create_scim_token_requires_auth() {
    let (app, _state) = test_app().await;

    let (status, _body) = http_post_json(
        &app,
        "/api/v1/org/scim-tokens",
        r#"{"description": "test", "expires_in_days": 30}"#,
        &[],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "missing auth must return 401"
    );
}

#[tokio::test]
async fn test_create_scim_token_requires_admin() {
    let (app, state) = test_app().await;
    let org = create_test_org(&state.store, "example.com").await;
    let member = create_test_user_in_org(&state.store, "member@example.com", &org.id, false).await;
    let auth_id = create_test_authenticator(&state.store, &member.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &member.id,
            email: &member.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    let auth_header = format!("Bearer {token}");

    let (status, _body) = http_post_json(
        &app,
        "/api/v1/org/scim-tokens",
        r#"{"description": "test", "expires_in_days": 30}"#,
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN, "non-admin must receive 403");
}

#[tokio::test]
async fn test_create_scim_token_max_limit() {
    let (app, state) = test_app().await;
    let org = create_test_org(&state.store, "example.com").await;
    let admin = create_test_user_in_org(&state.store, "admin@example.com", &org.id, true).await;
    let auth_id = create_test_authenticator(&state.store, &admin.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &admin.id,
            email: &admin.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    let auth_header = format!("Bearer {token}");

    // Create first token
    let (status, _) = http_post_json(
        &app,
        "/api/v1/org/scim-tokens",
        r#"{"description": "first", "expires_in_days": 30}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "first token must succeed");

    // Create second token
    let (status, _) = http_post_json(
        &app,
        "/api/v1/org/scim-tokens",
        r#"{"description": "second", "expires_in_days": 30}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "second token must succeed");

    // Third token must be rejected with 409
    let (status, body) = http_post_json(
        &app,
        "/api/v1/org/scim-tokens",
        r#"{"description": "third", "expires_in_days": 30}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "third token must return 409; body: {body}"
    );
}

// ================================================================
// Authenticated CRUD — List (positive)
// ================================================================

#[tokio::test]
async fn test_list_scim_tokens_empty() {
    let (app, state) = test_app().await;
    let org = create_test_org(&state.store, "example.com").await;
    let admin = create_test_user_in_org(&state.store, "admin@example.com", &org.id, true).await;
    let auth_id = create_test_authenticator(&state.store, &admin.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &admin.id,
            email: &admin.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    let auth_header = format!("Bearer {token}");

    let (status, body) = http_get(
        &app,
        "/api/v1/org/scim-tokens",
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    let resp: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    let tokens = resp["tokens"].as_array().expect("tokens must be an array");
    assert!(tokens.is_empty(), "no tokens created, list must be empty");
}

#[tokio::test]
async fn test_list_scim_tokens_returns_created() {
    let (app, state) = test_app().await;
    let org = create_test_org(&state.store, "example.com").await;
    let admin = create_test_user_in_org(&state.store, "admin@example.com", &org.id, true).await;
    let auth_id = create_test_authenticator(&state.store, &admin.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &admin.id,
            email: &admin.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    let auth_header = format!("Bearer {token}");

    // Create a token
    let (status, create_body) = http_post_json(
        &app,
        "/api/v1/org/scim-tokens",
        r#"{"description": "listed token", "expires_in_days": 30}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "create must succeed; body: {create_body}"
    );
    let created: serde_json::Value = serde_json::from_str(&create_body).expect("valid JSON");
    let created_id = created["id"].as_str().expect("id present");

    // List tokens — should contain the created one
    let (status, list_body) = http_get(
        &app,
        "/api/v1/org/scim-tokens",
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "list must succeed; body: {list_body}"
    );
    let resp: serde_json::Value = serde_json::from_str(&list_body).expect("valid JSON");
    let tokens = resp["tokens"].as_array().expect("tokens must be an array");
    assert_eq!(tokens.len(), 1, "list must contain exactly one token");
    assert_eq!(
        tokens[0]["id"].as_str(),
        Some(created_id),
        "listed token id must match created id"
    );
    assert_eq!(
        tokens[0]["description"].as_str(),
        Some("listed token"),
        "listed token description must match"
    );
}

// ================================================================
// Authenticated CRUD — List (negative)
// ================================================================

#[tokio::test]
async fn test_list_scim_tokens_requires_auth() {
    let (app, _state) = test_app().await;

    let (status, _body) = http_get(&app, "/api/v1/org/scim-tokens", &[]).await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "missing auth must return 401"
    );
}

// ================================================================
// Authenticated CRUD — Delete (positive)
// ================================================================

#[tokio::test]
async fn test_delete_scim_token_succeeds() {
    let (app, state) = test_app().await;
    let org = create_test_org(&state.store, "example.com").await;
    let admin = create_test_user_in_org(&state.store, "admin@example.com", &org.id, true).await;
    let auth_id = create_test_authenticator(&state.store, &admin.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &admin.id,
            email: &admin.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    let auth_header = format!("Bearer {token}");

    // Create a token to delete
    let (status, create_body) = http_post_json(
        &app,
        "/api/v1/org/scim-tokens",
        r#"{"description": "to delete", "expires_in_days": 30}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "create must succeed; body: {create_body}"
    );
    let resp: serde_json::Value = serde_json::from_str(&create_body).expect("valid JSON");
    let token_id = resp["id"].as_str().expect("id present");

    // Delete the token
    let (status, _body) = http_delete(
        &app,
        &format!("/api/v1/org/scim-tokens/{token_id}"),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::NO_CONTENT, "delete must return 204");
}

// ================================================================
// Authenticated CRUD — Delete (negative)
// ================================================================

#[tokio::test]
async fn test_delete_scim_token_not_found() {
    let (app, state) = test_app().await;
    let org = create_test_org(&state.store, "example.com").await;
    let admin = create_test_user_in_org(&state.store, "admin@example.com", &org.id, true).await;
    let auth_id = create_test_authenticator(&state.store, &admin.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &admin.id,
            email: &admin.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;
    let auth_header = format!("Bearer {token}");

    let nonexistent_id = uuid::Uuid::now_v7();
    let (status, _body) = http_delete(
        &app,
        &format!("/api/v1/org/scim-tokens/{nonexistent_id}"),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "unknown token id must return 404"
    );
}

#[tokio::test]
async fn test_delete_scim_token_requires_auth() {
    let (app, _state) = test_app().await;
    let token_id = uuid::Uuid::now_v7();

    let (status, _body) =
        http_delete(&app, &format!("/api/v1/org/scim-tokens/{token_id}"), &[]).await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "missing auth must return 401"
    );
}
