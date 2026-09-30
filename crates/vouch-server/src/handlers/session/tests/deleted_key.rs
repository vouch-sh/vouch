//! Deleting a security key revokes the sessions it established. A session row
//! that still names a deleted key (one created after the delete's cascade, by
//! a login racing the deletion) must be refused by every validator that turns
//! an access token into a session: `/v1/*`, userinfo, introspection, and
//! token exchange.

use axum::Router;
use axum::http::StatusCode;

use crate::AppState;
use crate::services::keys;
use crate::test_utils::{
    TestClientSpec, TestJwks, TestOAuthClient, TestSessionSpec, create_test_authenticator,
    create_test_client, create_test_session_with, create_test_user, http_get, http_post_form,
    test_app,
};

struct Fixture {
    app: Router,
    state: std::sync::Arc<AppState>,
    client: TestOAuthClient,
    user_id: String,
    email: String,
}

async fn fixture(email: &str) -> Fixture {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, email).await;
    let client = create_test_client(
        &state.store,
        &user.id,
        TestClientSpec {
            jwks: TestJwks::Shared,
            with_secret: true,
            ..Default::default()
        },
    )
    .await;
    Fixture {
        app,
        state,
        client,
        user_id: user.id,
        email: user.email,
    }
}

async fn session_for(f: &Fixture, auth_id: &str) -> String {
    create_test_session_with(
        &f.state,
        TestSessionSpec {
            user_id: &f.user_id,
            email: &f.email,
            auth_id: Some(auth_id),
            client_id: Some(&f.client.client_id),
            ..Default::default()
        },
    )
    .await
}

/// The status each validator gives `token`, as
/// `(/v1/keys, userinfo, introspection active, token exchange)`.
async fn validators(f: &Fixture, token: &str) -> (StatusCode, StatusCode, bool, StatusCode) {
    let bearer = format!("Bearer {token}");
    let (keys, _) = http_get(&f.app, "/v1/keys", &[("Authorization", &bearer)]).await;
    let (userinfo, _) = http_get(&f.app, "/oauth/userinfo", &[("Authorization", &bearer)]).await;
    let basic = f.client.basic_auth_header();
    let (_, body) = http_post_form(
        &f.app,
        "/oauth/introspect",
        &format!("token={token}"),
        &[("Authorization", &basic)],
    )
    .await;
    let introspection: serde_json::Value = serde_json::from_str(&body).expect("introspection JSON");
    let (exchange, _) = http_post_form(
        &f.app,
        "/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token={token}\
             &subject_token_type=urn:ietf:params:oauth:token-type:access_token"
        ),
        &[("Authorization", &basic)],
    )
    .await;
    let active = introspection.get("active") == Some(&serde_json::Value::Bool(true));
    (keys, userinfo, active, exchange)
}

#[tokio::test]
async fn every_validator_refuses_a_session_of_a_deleted_key() {
    let f = fixture("deleted-key@example.com").await;
    let kept = create_test_authenticator(&f.state.store, &f.user_id).await;
    let deleted = create_test_authenticator(&f.state.store, &f.user_id).await;

    let live = session_for(&f, &kept).await;
    assert_eq!(
        validators(&f, &live).await,
        (StatusCode::OK, StatusCode::OK, true, StatusCode::OK),
        "control: a session of an existing key is accepted everywhere"
    );

    keys::delete_key(&f.state.store, &f.user_id, &deleted)
        .await
        .expect("delete key");
    // The row a login racing the deletion leaves behind: written after the
    // delete's cascade removed the key's sessions.
    let orphan = session_for(&f, &deleted).await;

    let (keys, userinfo, active, exchange) = validators(&f, &orphan).await;
    assert_eq!(keys, StatusCode::UNAUTHORIZED, "/v1/keys");
    assert_eq!(userinfo, StatusCode::UNAUTHORIZED, "userinfo");
    assert!(!active, "introspection reports the session inactive");
    assert_eq!(exchange, StatusCode::BAD_REQUEST, "token exchange");
}
