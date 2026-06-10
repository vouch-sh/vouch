// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Tests for the cookie-authenticated key management API used during enrollment
//! (`handlers/enroll_keys.rs`): list, rename, and delete with freshness check.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]

use axum::http::StatusCode;
use serde_json::Value;
use vouch_server::test_utils::{
    self, HttpResponse, http_delete_full, http_get_full, http_request_full,
};
use vouch_tests::TestHarness;

fn cookie_header(token: &str) -> String {
    format!("{}={}", vouch_common::SESSION_COOKIE_NAME, token)
}

async fn list_keys(harness: &TestHarness, token: &str) -> HttpResponse {
    let cookie = cookie_header(token);
    http_get_full(&harness.router, "/enroll/keys/api", &[("Cookie", &cookie)]).await
}

async fn rename_key(harness: &TestHarness, token: &str, key_id: &str, body: &str) -> HttpResponse {
    let cookie = cookie_header(token);
    http_request_full(
        &harness.router,
        "POST",
        &format!("/enroll/keys/{key_id}/rename"),
        Some(body.to_string()),
        &[
            ("Cookie", &cookie),
            ("Content-Type", "application/x-www-form-urlencoded"),
        ],
    )
    .await
}

async fn delete_key(harness: &TestHarness, token: &str, key_id: &str) -> HttpResponse {
    let cookie = cookie_header(token);
    http_delete_full(
        &harness.router,
        &format!("/enroll/keys/{key_id}"),
        &[("Cookie", &cookie)],
    )
    .await
}

#[tokio::test]
async fn list_returns_user_keys() {
    let harness = TestHarness::new().await;
    let (_user, auth_id, token) = harness
        .create_authenticated_user("keys-list@example.com")
        .await
        .expect("create authed user");

    let resp = list_keys(&harness, &token).await;
    assert_eq!(resp.status, StatusCode::OK);

    let body: Value = serde_json::from_str(&resp.body).expect("json body");
    let keys = body.get("keys").and_then(Value::as_array).expect("keys[]");
    assert!(
        keys.iter().any(|k| k
            .get("id")
            .and_then(Value::as_str)
            .is_some_and(|id| id == auth_id)),
        "expected created auth_id {auth_id} in list, got {body}"
    );
}

#[tokio::test]
async fn list_rejects_missing_cookie() {
    let harness = TestHarness::new().await;
    let resp = http_get_full(&harness.router, "/enroll/keys/api", &[]).await;
    assert_eq!(resp.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn rename_updates_name() {
    let harness = TestHarness::new().await;
    let (_user, auth_id, token) = harness
        .create_authenticated_user("keys-rename@example.com")
        .await
        .expect("create authed user");

    // Form POST redirects back to /enroll/keys on success (303 See Other).
    let resp = rename_key(&harness, &token, &auth_id, "name=renamed-yubikey").await;
    assert_eq!(
        resp.status,
        StatusCode::SEE_OTHER,
        "rename failed: {}",
        resp.body
    );

    let list = list_keys(&harness, &token).await;
    let body: Value = serde_json::from_str(&list.body).expect("json body");
    let keys = body.get("keys").and_then(Value::as_array).expect("keys[]");
    let renamed = keys
        .iter()
        .find(|k| k.get("id").and_then(Value::as_str) == Some(&auth_id))
        .expect("renamed key present");
    assert_eq!(
        renamed.get("name").and_then(Value::as_str),
        Some("renamed-yubikey")
    );
}

#[tokio::test]
async fn delete_rejects_stale_session() {
    let harness = TestHarness::new().await;
    let user = harness
        .create_user("stale-delete@example.com")
        .await
        .expect("create user");
    let auth_id = harness
        .create_authenticator(&user.id)
        .await
        .expect("create authenticator");

    // KEY_DELETE_MAX_AGE_SECS is 60. A session with auth_time an hour in the
    // past must fail the freshness gate.
    let stale_iat = jiff::Timestamp::now().as_second() - 3600;
    let token = test_utils::create_test_session_with_iat(
        &harness.state,
        &user.id,
        &user.email,
        &auth_id,
        stale_iat,
    )
    .await;

    let resp = delete_key(&harness, &token, &auth_id).await;
    // RFC 9470: stale auth_time produces `insufficient_user_authentication`
    // with a 401 status, prompting the caller to step up.
    assert_eq!(
        resp.status,
        StatusCode::UNAUTHORIZED,
        "stale session should be rejected, body: {}",
        resp.body
    );
    assert!(
        resp.body.contains("insufficient_user_authentication"),
        "expected step-up error code, body: {}",
        resp.body
    );
}

#[tokio::test]
async fn delete_with_fresh_session_succeeds() {
    let harness = TestHarness::new().await;
    let user = harness
        .create_user("fresh-delete@example.com")
        .await
        .expect("create user");
    // The service refuses to remove a user's last key, so we need two.
    let kept = harness
        .create_authenticator(&user.id)
        .await
        .expect("create kept authenticator");
    let doomed = harness
        .create_authenticator(&user.id)
        .await
        .expect("create doomed authenticator");
    let token = harness
        .create_session(&user.id, &user.email, &kept)
        .await
        .expect("create fresh session");

    let resp = delete_key(&harness, &token, &doomed).await;
    assert_eq!(
        resp.status,
        StatusCode::OK,
        "fresh delete should succeed, body: {}",
        resp.body
    );

    let body: Value = serde_json::from_str(&resp.body).expect("json body");
    assert!(
        body.get("message")
            .and_then(Value::as_str)
            .is_some_and(|m| m.contains("deleted"))
    );
}
