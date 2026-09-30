// SPDX-License-Identifier: Apache-2.0 OR MIT
//! A deactivated account's still-live session is refused on every route that
//! reads a token or session cookie, including the read-only ones.
//!
//! Deactivation and session deletion commit in separate transactions, so a
//! deactivated user can hold a live session. The token and cookie extractors
//! load the account and refuse it before any handler runs. Each route below
//! answers an active user normally (the control) and refuses the same session
//! once the account is deactivated.

#![expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code: panicking on an assertion failure is the point"
)]

use axum::Router;
use axum::http::StatusCode;
use vouch_server::AppState;
use vouch_server::db;
use vouch_server::test_utils::*;

struct Fixture {
    app: Router,
    state: std::sync::Arc<AppState>,
    user_id: String,
    bearer: String,
    cookie: String,
    app_id: String,
}

async fn fixture(email: &str) -> Fixture {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, email).await;
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
    let client = create_test_client(&state.store, &user.id, TestClientSpec::default()).await;
    Fixture {
        app,
        state,
        user_id: user.id,
        bearer: format!("Bearer {token}"),
        cookie: format!("{}={token}", vouch_common::SESSION_COOKIE_NAME),
        app_id: client.app_id,
    }
}

async fn deactivate(f: &Fixture) {
    db::update_user_active_status(&f.state.store, &f.user_id, false)
        .await
        .expect("deactivate user");
}

fn bearer_routes(f: &Fixture) -> Vec<String> {
    vec![
        "/v1/keys".to_string(),
        "/api/v1/applications".to_string(),
        format!("/api/v1/applications/{}", f.app_id),
        format!("/api/v1/applications/{}/secrets", f.app_id),
    ]
}

#[tokio::test]
async fn bearer_routes_refuse_a_deactivated_account() {
    let f = fixture("deactivated-bearer@example.com").await;
    for path in bearer_routes(&f) {
        let (status, body) = http_get(&f.app, &path, &[("Authorization", &f.bearer)]).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "control, active user: {path}: {body}"
        );
    }

    deactivate(&f).await;
    for path in bearer_routes(&f) {
        let (status, body) = http_get(&f.app, &path, &[("Authorization", &f.bearer)]).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "deactivated account must be refused: {path}: {body}"
        );
        assert!(
            body.contains("User account is deactivated"),
            "{path}: {body}"
        );
    }
}

#[tokio::test]
async fn auth_status_reports_a_deactivated_account_as_unauthenticated() {
    let f = fixture("deactivated-status@example.com").await;
    let (status, body) = http_get(&f.app, "/v1/auth/status", &[("Authorization", &f.bearer)]).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let json: serde_json::Value = serde_json::from_str(&body).expect("JSON");
    assert_eq!(json["authenticated"], true, "control, active user: {body}");

    deactivate(&f).await;
    let (status, body) = http_get(&f.app, "/v1/auth/status", &[("Authorization", &f.bearer)]).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let json: serde_json::Value = serde_json::from_str(&body).expect("JSON");
    assert_eq!(json["authenticated"], false, "{body}");
    assert!(
        json["email"].is_null(),
        "no email for a deactivated account: {body}"
    );
    assert!(json["device_name"].is_null(), "{body}");
}

#[tokio::test]
async fn cookie_key_list_refuses_a_deactivated_account() {
    let f = fixture("deactivated-cookie-api@example.com").await;
    let (status, body) = http_get(&f.app, "/enroll/keys/api", &[("Cookie", &f.cookie)]).await;
    assert_eq!(status, StatusCode::OK, "control, active user: {body}");

    deactivate(&f).await;
    let (status, body) = http_get(&f.app, "/enroll/keys/api", &[("Cookie", &f.cookie)]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
}

#[tokio::test]
async fn cookie_key_page_refuses_a_deactivated_account() {
    let f = fixture("deactivated-cookie-page@example.com").await;
    let (status, body) = http_get(&f.app, "/enroll/keys", &[("Cookie", &f.cookie)]).await;
    assert_eq!(status, StatusCode::OK, "control, active user: {body}");

    deactivate(&f).await;
    let (status, body) = http_get(&f.app, "/enroll/keys", &[("Cookie", &f.cookie)]).await;
    assert_ne!(
        status,
        StatusCode::OK,
        "the key page must not render for a deactivated account: {body}"
    );
    assert!(
        !body.contains("Test Key"),
        "no key list for a deactivated account: {body}"
    );
}
