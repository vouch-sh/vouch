// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Session resource-auth handler tests: bearer/cookie precedence,
//! DPoP and mTLS sender-constraint enforcement, and the RFC 9449
//! nonce-replay retry flow.
#![expect(
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]

use axum::http::StatusCode;

use crate::db;
use crate::error::ServiceError;
use crate::handlers::session;
use crate::services::oidc::claims::PossessionError;
use crate::services::oidc::mtls;
use crate::test_utils::*;

/// Normal (non-DPoP) token via cookie should succeed.
#[tokio::test]
async fn test_cookie_session_normal_token_succeeds() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "cookie-ok@example.com").await;
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

    let cookie = format!("{}={token}", vouch_common::SESSION_COOKIE_NAME);
    let (status, _body) = http_get(&app, "/api/v1/applications", &[("Cookie", &cookie)]).await;

    assert_eq!(status, StatusCode::OK);
}

/// DPoP-bound token (with cnf.jkt) via cookie must be rejected.
#[tokio::test]
async fn test_cookie_session_dpop_bound_token_rejected() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "cookie-dpop@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            binding: TestBinding::Dpop("fake-jkt-thumbprint"),
            ..Default::default()
        },
    )
    .await;

    let cookie = format!("{}={token}", vouch_common::SESSION_COOKIE_NAME);
    let (status, body) = http_get(&app, "/api/v1/applications", &[("Cookie", &cookie)]).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body}");
    assert!(
        body.contains("does not hold a browser session"),
        "a bound token is not a browser session, got: {body}"
    );
}

/// DPoP-bound token via Bearer header (without DPoP proof) should also
/// be rejected, but with a different message than the cookie case.
#[tokio::test]
async fn test_bearer_dpop_bound_token_rejected() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "bearer-dpop@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            binding: TestBinding::Dpop("fake-jkt-thumbprint"),
            ..Default::default()
        },
    )
    .await;

    let auth = format!("Bearer {token}");
    let (status, body) = http_get(&app, "/api/v1/applications", &[("Authorization", &auth)]).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body}");
    assert!(
        body.contains("DPoP authorization scheme"),
        "Error should mention DPoP scheme requirement, got: {body}"
    );
}

/// mTLS-bound token (with cnf.x5t#S256) presented via Bearer without a
/// client certificate must be rejected. The server cannot verify the
/// certificate binding since no cert was presented.
#[tokio::test]
async fn test_mtls_bound_token_without_cert_rejected() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "bearer-mtls@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            binding: TestBinding::Mtls(&mtls::compute_cert_thumbprint(b"fake-cert-der")),
            ..Default::default()
        },
    )
    .await;

    // Present the mTLS-bound token as a plain Bearer token (no client cert)
    let auth = format!("Bearer {token}");
    let (status, body) = http_get(&app, "/api/v1/applications", &[("Authorization", &auth)]).await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "mTLS-bound token without cert must be rejected: {body}"
    );
}

/// mTLS-bound token presented with the matching client certificate must succeed.
#[tokio::test]
async fn test_mtls_bound_token_with_matching_cert_succeeds() {
    let (_app, state) = test_app().await;
    let user = create_test_user(&state.store, "mtls-match@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;

    // Generate a self-signed client certificate for binding
    let cert_der = make_test_cert_der("test-mtls");
    let cert = mtls::parse_client_certificate(&cert_der).expect("parse cert");

    // Issue a token bound to this cert's thumbprint
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            binding: TestBinding::Mtls(&cert.thumbprint),
            ..Default::default()
        },
    )
    .await;

    // Call extract_resource_token directly with the matching cert
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::AUTHORIZATION,
        format!("Bearer {token}").parse().expect("header value"),
    );
    let jar = axum_extra::extract::cookie::CookieJar::new();
    let result = session::extract_resource_token(
        &state,
        &headers,
        &jar,
        "GET",
        "/api/v1/applications",
        Some(&cert),
        test_arrival(),
    )
    .await;

    assert!(
        result.is_ok(),
        "mTLS-bound token with matching cert must succeed, got: {:?}",
        result.err()
    );
    assert_eq!(result.expect("ok").sub, user.id);
}

/// mTLS-bound token presented with the wrong client certificate must be rejected.
#[tokio::test]
async fn test_mtls_bound_token_with_wrong_cert_rejected() {
    let (_app, state) = test_app().await;
    let user = create_test_user(&state.store, "mtls-wrong@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;

    // Generate two separate self-signed certs — the token is bound to cert_a's
    // thumbprint but we present cert_b.
    let cert_a_der = make_test_cert_der("client-a");
    let cert_b_der = make_test_cert_der("client-b");
    let cert_a = mtls::parse_client_certificate(&cert_a_der).expect("parse cert A");
    let cert_b = mtls::parse_client_certificate(&cert_b_der).expect("parse cert B");

    // Token is bound to cert_a's thumbprint
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            binding: TestBinding::Mtls(&cert_a.thumbprint),
            ..Default::default()
        },
    )
    .await;

    // Present cert_b (wrong cert)
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::AUTHORIZATION,
        format!("Bearer {token}").parse().expect("header value"),
    );
    let jar = axum_extra::extract::cookie::CookieJar::new();
    let result = session::extract_resource_token(
        &state,
        &headers,
        &jar,
        "GET",
        "/api/v1/applications",
        Some(&cert_b),
        test_arrival(),
    )
    .await;

    let err = result.expect_err("wrong cert should be rejected");
    assert!(
        matches!(
            &err,
            ServiceError::Api { status, .. }
            if *status == StatusCode::UNAUTHORIZED
        ),
        "Expected 401, got: {err:?}"
    );
}

/// A token with both cnf.jkt (DPoP) and cnf.x5t#S256 (mTLS) — DPoP takes precedence.
///
/// The current implementation checks `jkt.is_some()` first, so a DPoP-bound token
/// sent as Bearer should be rejected for the DPoP reason, not the mTLS reason.
#[tokio::test]
async fn test_dpop_takes_precedence_over_mtls() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "dpop-precedence@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;

    // Create a DPoP-bound token (jkt is set; mTLS thumbprint is not set via
    // create_oauth_access_token because dpop_jkt takes precedence)
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            binding: TestBinding::Dpop("fake-dpop-jkt-thumbprint"),
            ..Default::default()
        },
    )
    .await;

    // Present as plain Bearer without DPoP proof
    let auth = format!("Bearer {token}");
    let (status, body) = http_get(&app, "/api/v1/applications", &[("Authorization", &auth)]).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body}");
    // The error must mention DPoP, not mTLS — DPoP check runs first
    assert!(
        body.contains("DPoP") || body.contains("sender-constrained"),
        "Error must mention DPoP (not mTLS), got: {body}"
    );
}

// ========================================================================
// RFC 9449 DPoP nonce replay at resource endpoints
//
// Nonces are optional at resource endpoints (`require_nonce = false` in
// `validate_dpop_at_resource`), so `DpopError::UseNonce` only fires when a
// client supplies a nonce that was already consumed (replay). The handler
// surfaces a fresh `DPoP-Nonce` header + `use_dpop_nonce` error so the
// client can retry per RFC 9449 §7.2.
// ========================================================================

/// Common setup for DPoP resource-endpoint tests: user, authenticator, a
/// real DPoP key pair, and a DPoP-bound access token whose `cnf.jkt`
/// matches the proof key.
async fn setup_dpop_resource_token(
    state: &crate::AppState,
    email: &str,
) -> (
    aws_lc_rs::signature::EcdsaKeyPair,
    serde_json::Value,
    String,
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
    let resource_uri = format!("{}/api/v1/applications", state.config().base_url);
    (key, jwk, token, resource_uri)
}

/// RFC 9449 §7.2: When a client replays an already-consumed nonce at a
/// resource endpoint, the server MUST respond with `401 use_dpop_nonce`
/// and a fresh `DPoP-Nonce` header so the client can retry.
#[tokio::test]
async fn test_dpop_use_nonce_at_resource_returns_nonce_header() {
    let (app, state) = test_app().await;
    let (key, jwk, token, resource_uri) =
        setup_dpop_resource_token(&state, "dpop-usenonce@example.com").await;

    // Delete the nonce so the request presents one the server does not hold.
    let nonce = db::generate_dpop_nonce(&state.store, 300)
        .await
        .expect("generate nonce");
    db::delete_dpop_nonce(&state.store, &nonce)
        .await
        .expect("delete nonce");

    // DPoP proof reuses the consumed nonce.
    let proof = create_dpop_proof(&key, &jwk, "GET", &resource_uri, Some(&nonce), Some(&token));
    let auth = format!("DPoP {token}");
    let response = http_get_full(
        &app,
        "/api/v1/applications",
        &[("Authorization", &auth), ("DPoP", &proof)],
    )
    .await;

    assert_eq!(
        response.status,
        StatusCode::UNAUTHORIZED,
        "body: {}",
        response.body
    );

    // Fresh DPoP-Nonce header MUST be present and differ from the replay.
    let new_nonce = response
        .headers
        .get("dpop-nonce")
        .and_then(|v| v.to_str().ok())
        .expect("DPoP-Nonce header must be present on use_dpop_nonce");
    assert!(!new_nonce.is_empty(), "fresh nonce must not be empty");
    assert_ne!(
        new_nonce, nonce,
        "fresh nonce must differ from the replayed nonce"
    );

    // Body carries the use_dpop_nonce error code.
    let body: serde_json::Value =
        serde_json::from_str(&response.body).expect("valid JSON error body");
    assert_eq!(
        body.get("code").and_then(|v| v.as_str()),
        Some("use_dpop_nonce"),
        "error code must be use_dpop_nonce, got: {body}"
    );
}

/// RFC 9449 §8: "The intent is that clients need to keep only one nonce value
/// and servers need to keep a window of recent nonces." One nonce serves a
/// sequence of requests, each with its own `jti`, until it expires.
#[tokio::test]
async fn test_dpop_nonce_serves_repeated_requests_until_it_expires() {
    let (app, state) = test_app().await;
    let (key, jwk, token, resource_uri) =
        setup_dpop_resource_token(&state, "dpop-nonce-window@example.com").await;
    let nonce = db::generate_dpop_nonce(&state.store, 300)
        .await
        .expect("generate nonce");
    let auth = format!("DPoP {token}");

    for request in 0..3 {
        let proof = create_dpop_proof(&key, &jwk, "GET", &resource_uri, Some(&nonce), Some(&token));
        let response = http_get_full(
            &app,
            "/api/v1/applications",
            &[("Authorization", &auth), ("DPoP", &proof)],
        )
        .await;
        assert_eq!(
            response.status,
            StatusCode::OK,
            "request {request} with the held nonce: {}",
            response.body
        );
    }
}

/// RFC 9449 retry flow at a resource endpoint: a request with a nonce the
/// server does not know yields `use_dpop_nonce` and a fresh nonce, and
/// retrying with that nonce succeeds.
#[tokio::test]
async fn test_dpop_unknown_nonce_retry_flow_succeeds() {
    let (app, state) = test_app().await;
    let (key, jwk, token, resource_uri) =
        setup_dpop_resource_token(&state, "dpop-retry@example.com").await;

    // 1. Valid request with a fresh nonce → 200 (consumes the nonce).
    let nonce = db::generate_dpop_nonce(&state.store, 300)
        .await
        .expect("generate nonce");
    let proof1 = create_dpop_proof(&key, &jwk, "GET", &resource_uri, Some(&nonce), Some(&token));
    let auth = format!("DPoP {token}");
    let resp1 = http_get_full(
        &app,
        "/api/v1/applications",
        &[("Authorization", &auth), ("DPoP", &proof1)],
    )
    .await;
    assert_eq!(
        resp1.status,
        StatusCode::OK,
        "first request should succeed and consume the nonce: {}",
        resp1.body
    );

    // 2. An unknown nonce → use_dpop_nonce + a fresh nonce.
    let proof2 = create_dpop_proof(
        &key,
        &jwk,
        "GET",
        &resource_uri,
        Some("unknown-nonce"),
        Some(&token),
    );
    let resp2 = http_get_full(
        &app,
        "/api/v1/applications",
        &[("Authorization", &auth), ("DPoP", &proof2)],
    )
    .await;
    assert_eq!(
        resp2.status,
        StatusCode::UNAUTHORIZED,
        "an unknown nonce must be rejected: {}",
        resp2.body
    );
    let fresh_nonce = resp2
        .headers
        .get("dpop-nonce")
        .and_then(|v| v.to_str().ok())
        .expect("DPoP-Nonce header on use_dpop_nonce");
    assert_ne!(
        fresh_nonce, nonce,
        "fresh nonce must differ from the one held"
    );
    let body2: serde_json::Value =
        serde_json::from_str(&resp2.body).expect("valid JSON error body");
    assert_eq!(
        body2.get("code").and_then(|v| v.as_str()),
        Some("use_dpop_nonce")
    );

    // 3. Retry with the fresh nonce (fresh jti) → 200 (RFC 9449 retry succeeds).
    let proof3 = create_dpop_proof(
        &key,
        &jwk,
        "GET",
        &resource_uri,
        Some(fresh_nonce),
        Some(&token),
    );
    let resp3 = http_get_full(
        &app,
        "/api/v1/applications",
        &[("Authorization", &auth), ("DPoP", &proof3)],
    )
    .await;
    assert_eq!(
        resp3.status,
        StatusCode::OK,
        "retry with fresh nonce should succeed: {}",
        resp3.body
    );
}

/// Regression: non-`UseNonce` DPoP errors (here `UriMismatch`) must still
/// map to `401 invalid_token` WITHOUT a `DPoP-Nonce` header. Guards the
/// catch-all arm against accidentally swallowing or surfacing a nonce.
#[tokio::test]
async fn test_dpop_non_use_nonce_error_omits_nonce_header() {
    let (app, state) = test_app().await;
    let (key, jwk, token, _resource_uri) =
        setup_dpop_resource_token(&state, "dpop-nonce-regression@example.com").await;

    // Proof targets the wrong htu → UriMismatch → catch-all → 401 invalid_token.
    let wrong_uri = format!("{}/api/v1/other-resource", state.config().base_url);
    let proof = create_dpop_proof(&key, &jwk, "GET", &wrong_uri, None, Some(&token));
    let auth = format!("DPoP {token}");
    let response = http_get_full(
        &app,
        "/api/v1/applications",
        &[("Authorization", &auth), ("DPoP", &proof)],
    )
    .await;

    assert_eq!(
        response.status,
        StatusCode::UNAUTHORIZED,
        "body: {}",
        response.body
    );
    assert!(
        response.headers.get("dpop-nonce").is_none(),
        "non-use_dpop_nonce errors must not carry a DPoP-Nonce header"
    );
    let body: serde_json::Value =
        serde_json::from_str(&response.body).expect("valid JSON error body");
    // RFC 9449 §7.1: a proof that fails the §4.3 checks is
    // `invalid_dpop_proof`, in the body and in the DPoP challenge.
    assert_eq!(
        body.get("code").and_then(|v| v.as_str()),
        Some("invalid_dpop_proof"),
        "{body}"
    );
    let challenge = response
        .headers
        .get("www-authenticate")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        challenge.starts_with(r#"DPoP error="invalid_dpop_proof""#),
        "{challenge}"
    );
}

// ========================================================================
// RFC 9449 §7.1 + RFC 8705 §3 — proof-first ordering on `/v1/*`
//
// `extract_resource_token` is the shared OAuth access-token extraction path
// every `/v1/*` handler takes. For a token whose `cnf.jkt` is `None`
// (mTLS-bound via `cnf.x5t#S256`, or fully unbound) presented under the
// `DPoP` scheme, the proof (RFC 9449 §4.3) MUST be validated before the
// `cnf.jkt` binding gate, mirroring `/oauth/userinfo`, so the two surfaces
// render one `DpopChallenge` for every DPoP refusal: `invalid_dpop_proof`
// for a missing/bad proof, `use_dpop_nonce` + a fresh `DPoP-Nonce` for a
// stale nonce, and `invalid_token` (NotDpopBound) only once the proof has
// passed and the binding is then found missing. Before the fix the
// `(AuthScheme::DPoP, None)` arm returned `invalid_token` without ever
// calling `validate_dpop_at_resource`, so `/v1/*` returned `invalid_token`
// where `/oauth/userinfo` returned `invalid_dpop_proof` for the same request.
// ========================================================================

/// The `WWW-Authenticate` header value, or empty when absent, for cross-arm
/// comparison of the `DpopChallenge` both surfaces render.
fn www_authenticate(response: &HttpResponse) -> &str {
    response
        .headers
        .get("www-authenticate")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
}

/// The `/api/v1/applications` resource URI the request must target for the
/// DPoP `htu` comparison and the audience-coverage check to pass.
fn applications_uri(state: &crate::AppState) -> String {
    format!("{}/api/v1/applications", state.config().base_url)
}

/// RFC 8705 §3 + RFC 9449 §7.1: an mTLS-bound token (`cnf.x5t#S256`,
/// `cnf.jkt == None`) presented under the `DPoP` scheme with NO proof must
/// yield `401 invalid_dpop_proof` on `/v1/*` — the proof check runs before
/// the binding check, mirroring
/// `test_rfc8705_userinfo_mtls_bound_token_with_dpop_scheme_rejected` on
/// `/oauth/userinfo`. Before the fix `/v1/*` returned `invalid_token`
/// without validating the proof.
#[tokio::test]
async fn test_v1_mtls_bound_token_under_dpop_without_proof_returns_invalid_dpop_proof() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "v1-mtls-dpop-noproof@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let thumbprint = mtls::compute_cert_thumbprint(b"v1-mtls-dpop-noproof");
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            binding: TestBinding::Mtls(&thumbprint),
            ..Default::default()
        },
    )
    .await;

    // No client certificate is presented: the mTLS binding check (which runs
    // AFTER the DPoP proof check) is never reached, so its absence cannot
    // mask the proof-check failure.
    let response = http_get_full(
        &app,
        "/api/v1/applications",
        &[("Authorization", &format!("DPoP {token}"))],
    )
    .await;

    assert_eq!(
        response.status,
        StatusCode::UNAUTHORIZED,
        "{}",
        response.body
    );
    let body: serde_json::Value =
        serde_json::from_str(&response.body).expect("valid JSON error body");
    assert_eq!(
        body.get("code").and_then(|v| v.as_str()),
        Some("invalid_dpop_proof"),
        "{body}"
    );
    assert_eq!(
        body.get("message").and_then(|v| v.as_str()),
        Some(PossessionError::MissingDpopProof.as_str()),
        "{body}"
    );
    let challenge = www_authenticate(&response);
    assert!(
        challenge.starts_with(r#"DPoP error="invalid_dpop_proof""#),
        "{challenge}"
    );
    // A missing proof never yields a nonce demand, so no `DPoP-Nonce`.
    assert!(
        response.headers.get("dpop-nonce").is_none(),
        "missing-proof rejection must not carry a DPoP-Nonce header"
    );
}

/// RFC 9449 §9: an mTLS-bound token presented under the `DPoP` scheme with a
/// proof whose nonce the server does not hold must yield `401 use_dpop_nonce`
/// and a fresh `DPoP-Nonce` header on `/v1/*` — the proof check (which issues
/// the nonce) runs before the binding check. Before the fix `/v1/*` returned
/// `invalid_token` with no `DPoP-Nonce`, diverging from `/oauth/userinfo`.
#[tokio::test]
async fn test_v1_mtls_bound_token_under_dpop_with_stale_nonce_returns_use_dpop_nonce() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "v1-mtls-dpop-stale@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let thumbprint = mtls::compute_cert_thumbprint(b"v1-mtls-dpop-stale");
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            binding: TestBinding::Mtls(&thumbprint),
            ..Default::default()
        },
    )
    .await;

    // Generate a nonce, then delete it so the proof presents one the server
    // does not hold — `validate_dpop_at_resource` answers with `use_dpop_nonce`.
    // NB: the nonce must actually be issued so `delete_dpop_nonce` has a row.
    let stale_nonce = db::generate_dpop_nonce(&state.store, 300)
        .await
        .expect("generate nonce");
    db::delete_dpop_nonce(&state.store, &stale_nonce)
        .await
        .expect("delete nonce");

    let (key, jwk) = generate_dpop_key_pair();
    let proof = create_dpop_proof(
        &key,
        &jwk,
        "GET",
        &applications_uri(&state),
        Some(&stale_nonce),
        Some(&token),
    );
    let response = http_get_full(
        &app,
        "/api/v1/applications",
        &[
            ("Authorization", &format!("DPoP {token}")),
            ("DPoP", &proof),
        ],
    )
    .await;

    assert_eq!(
        response.status,
        StatusCode::UNAUTHORIZED,
        "{}",
        response.body
    );
    let fresh_nonce = response
        .headers
        .get("dpop-nonce")
        .and_then(|v| v.to_str().ok())
        .expect("use_dpop_nonce must carry a fresh DPoP-Nonce header");
    assert!(!fresh_nonce.is_empty(), "fresh nonce must not be empty");
    assert_ne!(
        fresh_nonce, &stale_nonce,
        "fresh nonce must differ from the stale one"
    );
    let body: serde_json::Value =
        serde_json::from_str(&response.body).expect("valid JSON error body");
    assert_eq!(
        body.get("code").and_then(|v| v.as_str()),
        Some("use_dpop_nonce"),
        "{body}"
    );
    assert!(
        www_authenticate(&response).starts_with(r#"DPoP error="use_dpop_nonce""#),
        "{}",
        www_authenticate(&response)
    );
}

/// RFC 8705 §3 + RFC 9449 §7.1: an mTLS-bound token whose DPoP proof
/// validates is still not DPoP-bound, so it yields `401 invalid_token`
/// (NotDpopBound) — the mTLS binding check is never reached because the
/// DPoP binding gate returns first. Mirrors the `Some(_) | None =>
/// NotDpopBound` arm in `userinfo.rs`, and pins the second half of the
/// proof-first ordering: an unbound token whose proof passes still
/// terminates at `invalid_token`, and the mTLS certificate check
/// (`extract_resource_token` step 4b) stays gated below the DPoP binding
/// gate (step 4).
#[tokio::test]
async fn test_v1_mtls_bound_token_under_dpop_with_valid_proof_returns_invalid_token() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "v1-mtls-dpop-valid@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let thumbprint = mtls::compute_cert_thumbprint(b"v1-mtls-dpop-valid");
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            binding: TestBinding::Mtls(&thumbprint),
            ..Default::default()
        },
    )
    .await;

    let (key, jwk) = generate_dpop_key_pair();
    let proof = create_dpop_proof(
        &key,
        &jwk,
        "GET",
        &applications_uri(&state),
        None,
        Some(&token),
    );
    // No client certificate is presented: were the mTLS binding check
    // (`extract_resource_token` step 4b) reached, a missing cert would yield
    // `MissingClientCertificate`; reaching `NotDpopBound` here proves the
    // DPoP binding gate (step 4) returned first.
    let response = http_get_full(
        &app,
        "/api/v1/applications",
        &[
            ("Authorization", &format!("DPoP {token}")),
            ("DPoP", &proof),
        ],
    )
    .await;

    assert_eq!(
        response.status,
        StatusCode::UNAUTHORIZED,
        "{}",
        response.body
    );
    let body: serde_json::Value =
        serde_json::from_str(&response.body).expect("valid JSON error body");
    assert_eq!(
        body.get("code").and_then(|v| v.as_str()),
        Some("invalid_token"),
        "{body}"
    );
    assert_eq!(
        body.get("message").and_then(|v| v.as_str()),
        Some(PossessionError::NotDpopBound.as_str()),
        "{body}"
    );
}

/// Cross-surface parity (the unification commit f6485dd0 set out to make):
/// the SAME `Authorization: DPoP <mTLS-bound token>` request (no proof)
/// must render one `DpopChallenge` on both `/api/v1/applications` and
/// `/oauth/userinfo` — same status, same `WWW-Authenticate` challenge, and
/// each surface's own body shape carrying the same error code and
/// description. Before the fix `/v1/*` returned `invalid_token` while
/// `/oauth/userinfo` returned `invalid_dpop_proof`.
#[tokio::test]
async fn test_v1_and_userinfo_render_one_dpop_challenge_for_mtls_bound_token_under_dpop() {
    let (app, state) = test_app().await;
    let user = create_test_user(&state.store, "v1-parity@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let thumbprint = mtls::compute_cert_thumbprint(b"v1-parity");
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            binding: TestBinding::Mtls(&thumbprint),
            ..Default::default()
        },
    )
    .await;
    let auth = format!("DPoP {token}");

    let v1 = http_get_full(&app, "/api/v1/applications", &[("Authorization", &auth)]).await;
    let userinfo = http_get_full(&app, "/oauth/userinfo", &[("Authorization", &auth)]).await;

    // Both surfaces refuse with 401.
    assert_eq!(v1.status, StatusCode::UNAUTHORIZED, "v1: {}", v1.body);
    assert_eq!(
        userinfo.status,
        StatusCode::UNAUTHORIZED,
        "userinfo: {}",
        userinfo.body
    );

    // Same `DpopChallenge` on the wire: identical `WWW-Authenticate`.
    assert_eq!(
        www_authenticate(&v1),
        www_authenticate(&userinfo),
        "both surfaces must render the same DPoP challenge"
    );
    assert!(
        www_authenticate(&v1).starts_with(r#"DPoP error="invalid_dpop_proof""#),
        "{}",
        www_authenticate(&v1)
    );

    // Each surface's body uses its own shape but carries the same code and
    // description: `/v1/*` -> `{"code", "message"}`, userinfo ->
    // `{"error", "error_description"}`.
    let v1_body: serde_json::Value = serde_json::from_str(&v1.body).expect("v1 body is JSON");
    let ui_body: serde_json::Value =
        serde_json::from_str(&userinfo.body).expect("userinfo body is JSON");
    assert_eq!(
        v1_body.get("code").and_then(|v| v.as_str()),
        Some("invalid_dpop_proof"),
        "v1 code: {v1_body}"
    );
    assert_eq!(
        ui_body.get("error").and_then(|v| v.as_str()),
        Some("invalid_dpop_proof"),
        "userinfo error: {ui_body}"
    );
    assert_eq!(
        v1_body.get("message").and_then(|v| v.as_str()),
        ui_body.get("error_description").and_then(|v| v.as_str()),
        "both surfaces must carry the same error_description"
    );
    assert_eq!(
        v1_body.get("message").and_then(|v| v.as_str()),
        Some(PossessionError::MissingDpopProof.as_str()),
        "v1 message: {v1_body}"
    );
}

/// Contract: the strict API path (`extract_session_from_cookie`) and the
/// admin-UI path (`get_resource_auth_context`) must agree on a DPoP-bound
/// cookie token — both must reject it. Before the fix the strict path
/// returned `Err` ("Sender-constrained") while the UI path returned an
/// authenticated `AuthContext`; this test pins the symmetry.
#[tokio::test]
async fn test_get_resource_auth_context_rejects_dpop_bound_cookie() {
    use axum_extra::extract::cookie::CookieJar;

    let (_app, state) = test_app().await;
    let user = create_test_user(&state.store, "ctx-dpop@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            binding: TestBinding::Dpop("fake-dpop-jkt-thumbprint"),
            ..Default::default()
        },
    )
    .await;

    let jar = CookieJar::from_headers(&axum::http::HeaderMap::new());
    let jar = jar.add(axum_extra::extract::cookie::Cookie::new(
        vouch_common::SESSION_COOKIE_NAME,
        token.to_string(),
    ));

    // Strict path: rejection.
    let strict = super::extract_session_from_cookie(&state, &jar, test_arrival()).await;
    assert!(strict.is_err(), "strict path must reject DPoP-bound cookie");

    // UI path: unauthenticated context.
    let auth = super::get_resource_auth_context(&state, &jar, test_arrival()).await;
    assert!(
        !auth.authenticated,
        "UI path must treat DPoP-bound cookie as unauthenticated"
    );
    assert!(auth.user_id.is_none(), "no user_id on rejected cookie");
    assert!(!auth.is_org_admin, "no admin flag on rejected cookie");
}

/// The session cookie's `Max-Age` is derived from the minted token's own
/// `expires_in`, so a lifetime ceiling applied at issuance (the RFC 8693
/// exchange path caps by the subject token's remaining TTL) reaches the
/// cookie too, instead of being re-derived from `session_hours` at the
/// call site and drifting from the token it carries.
#[test]
fn test_session_cookie_max_age_tracks_minted_lifetime() {
    use super::{create_session_cookie, session_cookie_max_age};

    let cookie = create_session_cookie("tok", session_cookie_max_age(60));
    assert_eq!(cookie.max_age().map(|d| d.whole_seconds()), Some(60));
    assert_eq!(
        session_cookie_max_age(u64::MAX),
        i64::MAX,
        "saturates, never wraps"
    );
}

mod deactivated_account;
mod deleted_key;

mod negative_auth;
