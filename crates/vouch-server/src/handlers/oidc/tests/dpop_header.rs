// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 9449 §4.3 check 1 (at most one `DPoP` header) at every DPoP consumer:
//! `/v1/*` resources, each `/oauth/token` grant, `/oauth/par`, and
//! `/oauth/userinfo`.
//!
//! RFC 9449 §4.3 (specs/rfc/rfc9449.txt, lines 487-490):
//!
//! ```text
//!    To validate a DPoP proof, the receiving server MUST ensure the
//!    following:
//!
//!    1.   There is not more than one DPoP HTTP request header field.
//! ```
#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code: panicking on an assertion failure is the point"
)]

use crate::AppState;
use crate::test_utils::*;
use axum::Router;
use axum::http::StatusCode;

const GARBAGE: &str = "not-a-jwt";

fn json(body: &str) -> serde_json::Value {
    serde_json::from_str(body).unwrap_or(serde_json::Value::Null)
}

/// Fetch a fresh token-endpoint DPoP nonce (RFC 9449 §8).
async fn token_nonce(
    app: &Router,
    key: &aws_lc_rs::signature::EcdsaKeyPair,
    jwk: &serde_json::Value,
    htu: &str,
) -> String {
    let proof = create_dpop_proof(key, jwk, "POST", htu, None, None);
    let r = http_post_form_full(
        app,
        "/oauth/token",
        "grant_type=authorization_code&code=dummy",
        &[("DPoP", &proof)],
    )
    .await;
    r.headers
        .get("DPoP-Nonce")
        .expect("DPoP-Nonce")
        .to_str()
        .unwrap()
        .to_string()
}

/// Fetch a fresh PAR DPoP nonce.
async fn par_nonce(
    app: &Router,
    key: &aws_lc_rs::signature::EcdsaKeyPair,
    jwk: &serde_json::Value,
    htu: &str,
) -> String {
    let proof = create_dpop_proof(key, jwk, "POST", htu, None, None);
    let r = http_post_form_full(app, "/oauth/par", "response_type=code", &[("DPoP", &proof)]).await;
    r.headers
        .get("DPoP-Nonce")
        .unwrap_or_else(|| panic!("PAR must hand out DPoP-Nonce: {} {}", r.status, r.body))
        .to_str()
        .unwrap()
        .to_string()
}

async fn dpop_bound_token(
    state: &AppState,
    email: &str,
) -> (
    aws_lc_rs::signature::EcdsaKeyPair,
    serde_json::Value,
    String,
) {
    let user = create_test_user(&state.store, email).await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let (key, jwk) = generate_dpop_key_pair();
    let jkt = dpop_jkt(&jwk);
    let token = create_test_session_with(
        state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            binding: TestBinding::Dpop(&jkt),
            ..Default::default()
        },
    )
    .await;
    (key, jwk, token)
}

// ---------------------------------------------------------------------------
// Site: handlers/session.rs extract_resource_token (every /v1/* resource)
// ---------------------------------------------------------------------------

async fn v1_keys(app: &Router, token: &str, proofs: &[&str]) -> (StatusCode, String) {
    let auth = format!("DPoP {token}");
    let mut headers: Vec<(&str, &str)> = vec![("Authorization", &auth)];
    for p in proofs {
        headers.push(("DPoP", p));
    }
    http_get(app, "/v1/keys", &headers).await
}

// Positive control: one valid proof is accepted; one garbage proof is refused.
#[tokio::test]
async fn control_v1_resource_single_header() {
    let (app, state) = test_app().await;
    let (key, jwk, token) = dpop_bound_token(&state, "mh-v1-ctl@example.com").await;
    let uri = format!("{}/v1/keys", state.config().base_url);
    let proof = create_dpop_proof(&key, &jwk, "GET", &uri, None, Some(&token));

    let (status, body) = v1_keys(&app, &token, &[&proof]).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "single valid proof must succeed: {body}"
    );

    let (status, body) = v1_keys(&app, &token, &[GARBAGE]).await;
    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::BAD_REQUEST,
        "single garbage proof must be refused: {status} {body}"
    );
}

// RFC 9449 §4.3: "the receiving server MUST ensure ... 1. There is not more
// than one DPoP HTTP request header field."
#[tokio::test]
async fn v1_resource_two_dpop_headers_rejected() {
    let (app, state) = test_app().await;
    let (key, jwk, token) = dpop_bound_token(&state, "mh-v1@example.com").await;
    let uri = format!("{}/v1/keys", state.config().base_url);
    let proof = create_dpop_proof(&key, &jwk, "GET", &uri, None, Some(&token));

    let (status, body) = v1_keys(&app, &token, &[&proof, GARBAGE]).await;
    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::BAD_REQUEST,
        "RFC 9449 §4.3 check 1: GET /v1/keys with two DPoP headers (valid, garbage) must be \
         refused: {status} {body}"
    );
}

// ---------------------------------------------------------------------------
// Site: token.rs handle_client_credentials_grant — full end-to-end success
// ---------------------------------------------------------------------------

async fn cc_request(state: &AppState, app: &Router, second: Option<&str>) -> (StatusCode, String) {
    let user = create_test_user(
        &state.store,
        &format!("mh-cc-{}@example.com", uuid::Uuid::now_v7()),
    )
    .await;
    let client = create_test_client(
        &state.store,
        &user.id,
        TestClientSpec {
            dpop_bound_access_tokens: true,
            grant_types: Some(vec!["client_credentials".to_string()]),
            ..Default::default()
        },
    )
    .await;
    let (key, jwk) = generate_dpop_key_pair();
    let htu = format!("{}/oauth/token", state.config().base_url);
    let nonce = token_nonce(app, &key, &jwk, &htu).await;
    let proof = create_dpop_proof(&key, &jwk, "POST", &htu, Some(&nonce), None);
    let basic = client.basic_auth_header();
    let mut headers: Vec<(&str, &str)> = vec![("Authorization", &basic), ("DPoP", &proof)];
    if let Some(s) = second {
        headers.push(("DPoP", s));
    }
    http_post_form(
        app,
        "/oauth/token",
        "grant_type=client_credentials",
        &headers,
    )
    .await
}

#[tokio::test]
async fn control_client_credentials_single_header_succeeds() {
    let (app, state) = test_app().await;
    let (status, body) = cc_request(&state, &app, None).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "single-proof client_credentials: {body}"
    );
    assert_eq!(json(&body)["token_type"], "DPoP", "{body}");
}

// RFC 9449 §4.3: "the receiving server MUST ensure ... 1. There is not more
// than one DPoP HTTP request header field."
#[tokio::test]
async fn client_credentials_two_dpop_headers_rejected() {
    let (app, state) = test_app().await;
    let (status, body) = cc_request(&state, &app, Some(GARBAGE)).await;
    assert_eq!(
        (status, json(&body)["error"].clone()),
        (
            StatusCode::BAD_REQUEST,
            serde_json::json!("invalid_dpop_proof")
        ),
        "RFC 9449 §4.3 check 1: client_credentials with two DPoP headers (valid, garbage) \
         must be 400 invalid_dpop_proof: {body}"
    );
}

// ---------------------------------------------------------------------------
// Per-site probes at /oauth/token and /oauth/par. Each handler validates the
// DPoP header *before* client authentication. So with no client credentials:
//   - one garbage header   -> invalid_dpop_proof  (control: DPoP checked first)
//   - [valid, garbage]     -> MUST be invalid_dpop_proof per §4.3, not the
//                             invalid_client of a request whose first proof
//                             passed and fell through to client authentication.
// ---------------------------------------------------------------------------

const GRANTS: &[(&str, &str)] = &[
    (
        "authorization_code",
        "grant_type=authorization_code&code=dummy&redirect_uri=https%3A%2F%2Fexample.com%2Fcallback",
    ),
    (
        "device_code",
        "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=dummy",
    ),
    (
        "token_exchange",
        "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token=dummy\
         &subject_token_type=urn:ietf:params:oauth:token-type:access_token",
    ),
    (
        "fido2_assertion",
        "grant_type=urn:ietf:params:oauth:grant-type:fido2-assertion&assertion=dummy",
    ),
    ("client_credentials", "grant_type=client_credentials"),
];

fn grant_body(name: &str) -> &'static str {
    GRANTS.iter().find(|(n, _)| *n == name).unwrap().1
}

async fn token_probe(name: &str, dual: bool) -> (StatusCode, String) {
    let (app, state) = test_app().await;
    let (key, jwk) = generate_dpop_key_pair();
    let htu = format!("{}/oauth/token", state.config().base_url);
    let nonce = token_nonce(&app, &key, &jwk, &htu).await;
    let proof = create_dpop_proof(&key, &jwk, "POST", &htu, Some(&nonce), None);
    let headers: Vec<(&str, &str)> = if dual {
        vec![("DPoP", &proof), ("DPoP", GARBAGE)]
    } else {
        vec![("DPoP", GARBAGE)]
    };
    http_post_form(&app, "/oauth/token", grant_body(name), &headers).await
}

async fn assert_control(name: &str) {
    let (status, body) = token_probe(name, false).await;
    assert_eq!(
        json(&body)["error"],
        "invalid_dpop_proof",
        "control ({name}): a single garbage DPoP header must be invalid_dpop_proof, proving DPoP \
         is checked before client auth: {status} {body}"
    );
}

async fn assert_dual_rejected(name: &str) {
    let (status, body) = token_probe(name, true).await;
    assert_eq!(
        (status, json(&body)["error"].clone()),
        (
            StatusCode::BAD_REQUEST,
            serde_json::json!("invalid_dpop_proof")
        ),
        "RFC 9449 §4.3 check 1 ({name} grant): two DPoP headers (valid, garbage) must be 400 \
         invalid_dpop_proof: {body}"
    );
}

#[tokio::test]
async fn control_token_authorization_code() {
    assert_control("authorization_code").await;
}
// RFC 9449 §4.3: "the receiving server MUST ensure ... 1. There is not more
// than one DPoP HTTP request header field."
#[tokio::test]
async fn token_authorization_code_two_dpop_headers_rejected() {
    assert_dual_rejected("authorization_code").await;
}

#[tokio::test]
async fn control_token_client_credentials() {
    assert_control("client_credentials").await;
}
// RFC 9449 §4.3 check 1 (see module doc).
#[tokio::test]
async fn token_client_credentials_probe_two_dpop_headers_rejected() {
    assert_dual_rejected("client_credentials").await;
}

#[tokio::test]
async fn control_token_device_code() {
    assert_control("device_code").await;
}
// RFC 9449 §4.3 check 1 (see module doc).
#[tokio::test]
async fn token_device_code_two_dpop_headers_rejected() {
    assert_dual_rejected("device_code").await;
}

#[tokio::test]
async fn control_token_token_exchange() {
    assert_control("token_exchange").await;
}
// RFC 9449 §4.3 check 1 (see module doc).
#[tokio::test]
async fn token_token_exchange_two_dpop_headers_rejected() {
    assert_dual_rejected("token_exchange").await;
}

#[tokio::test]
async fn control_token_fido2_assertion() {
    assert_control("fido2_assertion").await;
}
// RFC 9449 §4.3 check 1 (see module doc).
#[tokio::test]
async fn token_fido2_assertion_two_dpop_headers_rejected() {
    assert_dual_rejected("fido2_assertion").await;
}

// ---------------------------------------------------------------------------
// Site: handlers/oidc/par.rs
// ---------------------------------------------------------------------------

async fn par_probe(dual: bool) -> (StatusCode, String) {
    let (app, state) = test_app().await;
    let (key, jwk) = generate_dpop_key_pair();
    let htu = format!("{}/oauth/par", state.config().base_url);
    let nonce = par_nonce(&app, &key, &jwk, &htu).await;
    let proof = create_dpop_proof(&key, &jwk, "POST", &htu, Some(&nonce), None);
    let headers: Vec<(&str, &str)> = if dual {
        vec![("DPoP", &proof), ("DPoP", GARBAGE)]
    } else {
        vec![("DPoP", GARBAGE)]
    };
    http_post_form(&app, "/oauth/par", "response_type=code", &headers).await
}

#[tokio::test]
async fn control_par_single_garbage_header() {
    let (status, body) = par_probe(false).await;
    assert_eq!(
        json(&body)["error"],
        "invalid_dpop_proof",
        "{status} {body}"
    );
}

// RFC 9449 §4.3 check 1 (see module doc).
#[tokio::test]
async fn par_two_dpop_headers_rejected() {
    let (status, body) = par_probe(true).await;
    assert_eq!(
        (status, json(&body)["error"].clone()),
        (
            StatusCode::BAD_REQUEST,
            serde_json::json!("invalid_dpop_proof")
        ),
        "RFC 9449 §4.3 check 1 (PAR): two DPoP headers (valid, garbage) must be 400 \
         invalid_dpop_proof: {body}"
    );
}

// ---------------------------------------------------------------------------
// Positive control: userinfo already enforces check 1.
// ---------------------------------------------------------------------------

// RFC 9449 §4.3 check 1 (see module doc).
#[tokio::test]
async fn control_userinfo_two_dpop_headers_rejected() {
    let (app, state) = test_app().await;
    let (key, jwk, token) = dpop_bound_token(&state, "mh-ui@example.com").await;
    let uri = format!("{}/oauth/userinfo", state.config().base_url);
    let proof = create_dpop_proof(&key, &jwk, "GET", &uri, None, Some(&token));
    let auth = format!("DPoP {token}");
    let (status, body) = http_get(
        &app,
        "/oauth/userinfo",
        &[
            ("Authorization", &auth),
            ("DPoP", &proof),
            ("DPoP", GARBAGE),
        ],
    )
    .await;
    // RFC 9449 §7.1: a protected resource answers with a 401 challenge.
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(json(&body)["error"], "invalid_dpop_proof", "{body}");

    let proof = create_dpop_proof(&key, &jwk, "GET", &uri, None, Some(&token));
    let (status, body) = http_get(
        &app,
        "/oauth/userinfo",
        &[("Authorization", &auth), ("DPoP", &proof)],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "single-header userinfo: {body}");
}
