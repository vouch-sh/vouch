// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Tests for the cookie-authenticated key management API used during enrollment
//! (`handlers/enroll_keys.rs`): list, rename, and delete with freshness check.

#![expect(
    clippy::expect_used,
    reason = "test code: panicking on an assertion failure is the point"
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
            ("Origin", harness.base_url()),
        ],
    )
    .await
}

async fn delete_key(harness: &TestHarness, token: &str, key_id: &str) -> HttpResponse {
    let cookie = cookie_header(token);
    http_delete_full(
        &harness.router,
        &format!("/enroll/keys/{key_id}"),
        &[("Cookie", &cookie), ("Origin", harness.base_url())],
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
async fn rename_rejects_invalid_name_with_redirect() {
    // A failed rename (here, a name longer than the 100-char limit) must
    // redirect back to /enroll/keys (PRG + flash), not return a raw JSON error
    // body, and must leave the key name unchanged.
    let harness = TestHarness::new().await;
    let (_user, auth_id, token) = harness
        .create_authenticated_user("keys-rename-bad@example.com")
        .await
        .expect("create authed user");

    let too_long = "a".repeat(101);
    let resp = rename_key(&harness, &token, &auth_id, &format!("name={too_long}")).await;
    assert_eq!(
        resp.status,
        StatusCode::SEE_OTHER,
        "invalid rename should redirect, got body: {}",
        resp.body
    );

    let list = list_keys(&harness, &token).await;
    let body: Value = serde_json::from_str(&list.body).expect("json body");
    let keys = body.get("keys").and_then(Value::as_array).expect("keys[]");
    let key = keys
        .iter()
        .find(|k| k.get("id").and_then(Value::as_str) == Some(&auth_id))
        .expect("key present");
    assert_ne!(
        key.get("name").and_then(Value::as_str),
        Some(too_long.as_str()),
        "invalid name must not be applied"
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
    let token = test_utils::create_test_session_with(
        &harness.state,
        test_utils::TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            verification: test_utils::TestVerification::Verified {
                auth_time: Some(stale_iat),
            },
            ..Default::default()
        },
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
async fn delete_rejects_future_dated_session() {
    // Mirror of `delete_rejects_stale_session` for the other
    // impossible-timestamp direction. The cookie route `/enroll/keys/{id}`
    // has no HTTP-signature timestamp layer in front of the freshness gate,
    // so a future-dated `auth_time` reaches `require_fresh_timestamp`
    // directly. If the server wall clock regresses past the token's
    // `auth_time` (NTP step-back, VM migration, stale-RTC container restart),
    // a hardware-verified session whose real age already exceeds the 60 s
    // step-up window must still be refused — an impossible future ceremony
    // is not proof of a recent one.
    let harness = TestHarness::new().await;
    let user = harness
        .create_user("future-delete@example.com")
        .await
        .expect("create user");
    let auth_id = harness
        .create_authenticator(&user.id)
        .await
        .expect("create authenticator");

    // auth_time one hour *ahead* of the server clock: an impossible ceremony
    // the gate must not treat as age-0 fresh.
    let future_iat = jiff::Timestamp::now().as_second().saturating_add(3600);
    let token = test_utils::create_test_session_with(
        &harness.state,
        test_utils::TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            verification: test_utils::TestVerification::Verified {
                auth_time: Some(future_iat),
            },
            ..Default::default()
        },
    )
    .await;

    let resp = delete_key(&harness, &token, &auth_id).await;
    assert_eq!(
        resp.status,
        StatusCode::UNAUTHORIZED,
        "future-dated session should be rejected, body: {}",
        resp.body
    );
    assert!(
        resp.body.contains("insufficient_user_authentication"),
        "expected step-up error code, body: {}",
        resp.body
    );

    // The key must survive the refused deletion.
    let list = list_keys(&harness, &token).await;
    let body: Value = serde_json::from_str(&list.body).expect("json body");
    let ids: Vec<&str> = body
        .get("keys")
        .and_then(Value::as_array)
        .expect("keys[]")
        .iter()
        .map(|k| k.get("id").and_then(Value::as_str).unwrap_or(""))
        .collect();
    assert!(
        ids.contains(&auth_id.as_str()),
        "key must survive the rejected deletion, got ids: {ids:?}"
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
    // The session is bound to `kept`, not the deleted `doomed` key, so the
    // current session must NOT be reported as revoked.
    assert_eq!(
        body.get("current_session_revoked").and_then(Value::as_bool),
        Some(false),
        "deleting a non-session key must not flag the current session revoked"
    );
}

#[tokio::test]
async fn delete_of_current_session_key_reports_revoked() {
    let harness = TestHarness::new().await;
    let user = harness
        .create_user("self-delete@example.com")
        .await
        .expect("create user");
    // Keep one key so we're allowed to delete the session's own key.
    let _kept = harness
        .create_authenticator(&user.id)
        .await
        .expect("create kept authenticator");
    let session_key = harness
        .create_authenticator(&user.id)
        .await
        .expect("create session authenticator");
    let token = harness
        .create_session(&user.id, &user.email, &session_key)
        .await
        .expect("create fresh session");

    let resp = delete_key(&harness, &token, &session_key).await;
    assert_eq!(resp.status, StatusCode::OK, "delete failed: {}", resp.body);

    let body: Value = serde_json::from_str(&resp.body).expect("json body");
    // Deleting the authenticator the session is bound to revokes that session.
    assert_eq!(
        body.get("current_session_revoked").and_then(Value::as_bool),
        Some(true),
        "deleting the session's own key must flag the current session revoked"
    );
}

#[tokio::test]
async fn delete_rejects_bootstrap_session_without_fido2_auth_time() {
    // Regression for the enrollment bootstrap `auth_time` bug: a bootstrap
    // session minted after upstream IdP sign-in (no FIDO2 assertion) has
    // `hardware_verified: false` and `auth_time: None`. The destructive-key
    // freshness gate in `delete_key` anchors on `auth_time.unwrap_or(0)`,
    // so it must fail closed (epoch → stale → step-up), rather than accept
    // the IdP login time as proof of recent FIDO2 — otherwise an attacker
    // who hijacked the victim's IdP session could delete the victim's keys
    // (n-1) within the 60-second window without ever touching a key.
    let harness = TestHarness::new().await;
    let user = harness
        .create_user("bootstrap-delete@example.com")
        .await
        .expect("create user");
    // Two keys so the "last key" guard would otherwise permit deletion.
    let kept = harness
        .create_authenticator(&user.id)
        .await
        .expect("create kept authenticator");
    let doomed = harness
        .create_authenticator(&user.id)
        .await
        .expect("create doomed authenticator");

    // The helper mirrors the (fixed) production bootstrap session: a
    // returning user with an existing key gets `authenticator_id = Some(kept)`,
    // `hardware_verified = false`, and `auth_time = None`.
    let token = test_utils::create_test_session_with(
        &harness.state,
        test_utils::TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&kept),
            verification: test_utils::TestVerification::NotVerified,
            ..Default::default()
        },
    )
    .await;

    let resp = delete_key(&harness, &token, &doomed).await;
    assert_eq!(
        resp.status,
        StatusCode::UNAUTHORIZED,
        "bootstrap session must not delete keys, body: {}",
        resp.body
    );
    assert!(
        resp.body.contains("insufficient_user_authentication"),
        "expected step-up error code, body: {}",
        resp.body
    );

    // Both keys must survive the rejected deletion.
    let list = list_keys(&harness, &token).await;
    let body: Value = serde_json::from_str(&list.body).expect("json body");
    let ids: Vec<&str> = body
        .get("keys")
        .and_then(Value::as_array)
        .expect("keys[]")
        .iter()
        .map(|k| k.get("id").and_then(Value::as_str).unwrap_or(""))
        .collect();
    assert!(
        ids.contains(&kept.as_str()) && ids.contains(&doomed.as_str()),
        "both keys must survive the rejected deletion, got ids: {ids:?}"
    );
}

#[tokio::test]
async fn delete_rejects_deactivated_user() {
    // Defense-in-depth: a deactivated user holding a live stepped-up session
    // must not delete their own security key over the cookie route.
    // Production deactivation writers route through
    // `services::auth::revoke_then_persist` (#1151), which deletes the session
    // rows before persisting `active=false`, so a subsequent cookie-authed
    // request would fail at the cookie extractor; but a writer that bypasses
    // `revoke_then_persist` (or any future such writer) leaves the dangerous
    // state this fixture manufactures — `update_user_active_status(false)`
    // with the session row left intact. Mirrors the bearer-route regression
    // `handlers::keys::tests::test_delete_key_rejects_deactivated_user`, the
    // `test_register_start_rejects_deactivated_user` sibling, and the
    // RFC 7662 fixture in `oidc/tests/rfc7662.rs`.
    let harness = TestHarness::new().await;
    let user = harness
        .create_user("deactivated-delete-cookie@example.com")
        .await
        .expect("create user");
    // Two keys so the "last key" guard would otherwise permit deletion.
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
        .expect("create fresh stepped-up session");

    // Deactivate WITHOUT deleting the session — the exact fixture the
    // deactivated-with-live-session siblings use.
    vouch_server::db::update_user_active_status(&harness.state.store, &user.id, false)
        .await
        .expect("deactivate user");

    let resp = delete_key(&harness, &token, &doomed).await;
    assert_eq!(
        resp.status,
        StatusCode::UNAUTHORIZED,
        "deactivated user must not delete a key, body: {}",
        resp.body
    );
    assert!(
        resp.body.contains("User account is deactivated"),
        "expected a deactivation refusal, body: {}",
        resp.body
    );

    // Both keys must survive the rejected deletion.
    let list = list_keys(&harness, &token).await;
    let body: Value = serde_json::from_str(&list.body).expect("json body");
    let ids: Vec<&str> = body
        .get("keys")
        .and_then(Value::as_array)
        .expect("keys[]")
        .iter()
        .map(|k| k.get("id").and_then(Value::as_str).unwrap_or(""))
        .collect();
    assert!(
        ids.contains(&kept.as_str()) && ids.contains(&doomed.as_str()),
        "both keys must survive the rejected deletion, got ids: {ids:?}"
    );
}
