// SPDX-License-Identifier: Apache-2.0 OR MIT
//! End-to-end (router-level) regression for the RFC 7523 `private_key_jwt`
//! double-JWKS-fetch 408 surface (bug report 94991ed6).
//!
//! The unit/inline tests in
//! `crates/vouch-server/src/services/oidc/jwt_bearer/client_auth.rs` prove the
//! mechanism: a counting loopback TLS server asserts exactly one JWKS fetch
//! where two were performed before the `JwksOrigin::Fetched` gate. This file
//! proves the **observable contract** at the production-router level: against
//! the real `build_app` (with the live innermost
//! `TimeoutLayer::with_status_code(REQUEST_TIMEOUT 10s)`), a `jwks_uri` client
//! whose served JWKS lacks the assertion's `kid` receives a structured
//! `401 invalid_client` JSON response — never the bare transport `408` a
//! dropped handler future would produce.
//!
//! The dribble-timing race the bug report describes is not reproduced here on
//! purpose: it requires sub-100ms pacing to win against the 10s `TimeoutLayer`
//! and is non-deterministic. The mechanism the race rides on (two sequential
//! fetches in one request) is exactly what the `JwksOrigin::Fetched` gate
//! removes, and that removal is what these tests assert at the router level.
//! See `services::oidc::jwt_bearer::client_auth::tests::
//! resolve_client_decoding_key_bounded_to_one_jwks_fetch` for the
//! mutation-killing fetch-count assertion.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code: panicking on an assertion failure is the point"
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::db::{ClientKeys, OAuthClientType, TokenEndpointAuthMethod};
use crate::infra::router;
use crate::test_utils::{
    TestClientSpec, TestJwks, build_test_app_state_with_http_client, create_test_client,
    create_test_user, test_tls_acceptor,
};
use crate::{AppState, db};
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http::{Request, StatusCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tower::ServiceExt;

/// A reqwest client that performs a real TLS handshake but does not verify
/// the server certificate, so the loopback mock's self-signed cert is
/// accepted. Kept off the shared `AppState::http_client` to avoid weakening
/// any other test's trust store.
fn https_client_trusting_any_cert() -> reqwest::Client {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("build test https client")
}

/// Spawn a loopback HTTPS server that serves `body` on every connection and
/// counts how many TCP connections it accepts, returning the URL. Each
/// accepted connection is one JWKS fetch initiated by the handler, so the
/// counter is the mutation-killing signal at the router level too: it must
/// read `1` where, before the fix, two sequential fetches read `2`.
async fn spawn_counting_jwks_server(body: String, accepted: Arc<AtomicU64>) -> String {
    let acceptor = test_tls_acceptor();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback listener");
    let port = listener.local_addr().expect("local_addr").port();
    let response = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        body.len()
    );
    tokio::spawn(async move {
        loop {
            let (stream, _peer) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => return,
            };
            accepted.fetch_add(1, Ordering::SeqCst);
            let acceptor = acceptor.clone();
            let response = response.clone();
            tokio::spawn(async move {
                let mut tls = match acceptor.accept(stream).await {
                    Ok(t) => t,
                    Err(_) => return,
                };
                // Drain the (small, body-less) GET so the kernel does not
                // RST before reqwest reads the response. Bounded so a
                // misbehaving peer cannot wedge the server task. Named
                // bindings (not `let _ =`) keep `#[must_use]` results
                // acknowledged.
                let mut buf = [0u8; 1024];
                let _read =
                    tokio::time::timeout(std::time::Duration::from_secs(1), tls.read(&mut buf))
                        .await;
                let _write = tls.write_all(response.as_bytes()).await;
                let _shutdown = tls.shutdown().await;
            });
        }
    });
    format!("https://127.0.0.1:{port}/jwks")
}

/// Generate an ES256 key pair (PKCS#8 + public JWK with `kid`).
fn generate_es256_key() -> (Vec<u8>, serde_json::Value) {
    use aws_lc_rs::signature::KeyPair;
    let rng = aws_lc_rs::rand::SystemRandom::new();
    let pkcs8 =
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).expect("gen key");
    let key_pair =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref()).expect("parse");
    let pub_bytes = key_pair.public_key().as_ref();
    let x = URL_SAFE_NO_PAD.encode(&pub_bytes[1..33]);
    let y = URL_SAFE_NO_PAD.encode(&pub_bytes[33..65]);
    let jwk = serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": x,
        "y": y,
        "use": "sig",
        "alg": "ES256",
        "kid": "assertion-key",
    });
    (pkcs8.as_ref().to_vec(), jwk)
}

/// Sign a JWT assertion with an ES256 key.
fn sign_jwt_assertion(
    pkcs8: &[u8],
    header: &serde_json::Value,
    claims: &serde_json::Value,
) -> String {
    let key_pair =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8).expect("parse");
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(header).unwrap());
    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
    let signing_input = format!("{header_b64}.{claims_b64}");
    let rng = aws_lc_rs::rand::SystemRandom::new();
    let sig = key_pair.sign(&rng, signing_input.as_bytes()).expect("sign");
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.as_ref());
    format!("{header_b64}.{claims_b64}.{sig_b64}")
}

/// Build a `private_key_jwt` client whose `jwks_uri` points at
/// `jwks_url` and whose `kid` differs from the assertion's key, so the
/// server's served JWKS will lack the assertion `kid`.
async fn make_private_key_jwt_client(
    state: &Arc<AppState>,
    jwks_url: String,
    email: &str,
) -> (db::OAuthClient, String) {
    let user = create_test_user(&state.store, email).await;
    let created = create_test_client(
        &state.store,
        &user.id,
        TestClientSpec {
            name: "RFC7523 two-fetch regression".to_string(),
            application_type: OAuthClientType::Web,
            redirect_uris: vec!["https://client.example/cb".to_string()],
            token_endpoint_auth_method: Some(TokenEndpointAuthMethod::PrivateKeyJwt),
            jwks: TestJwks::None,
            jwks_uri: Some(jwks_url),
            with_secret: false,
            ..Default::default()
        },
    )
    .await;
    let client = db::get_oauth_client_by_id(&state.store, &created.app_id)
        .await
        .expect("db lookup")
        .expect("client exists");
    // The Uri variant is what makes the JWKS cache path run.
    assert!(
        client.keys.as_ref().and_then(ClientKeys::uri).is_some(),
        "client must be registered with a jwks_uri"
    );
    (client, created.client_id)
}

/// Build the production router (`build_app`) over a state whose outbound HTTP
/// client trusts the loopback self-signed mock.
fn build_production_router(state: Arc<AppState>) -> axum::Router {
    let config = state.config();
    router::build_app(state, &config).expect("build production router")
}

/// Send `POST /oauth/token` with a `private_key_jwt` client assertion.
async fn post_token(
    router: axum::Router,
    client_id: &str,
    assertion: &str,
) -> (StatusCode, String) {
    let form = format!(
        "grant_type=authorization_code&code=x&redirect_uri=https://client.example/cb\
         &client_id={client_id}\
         &client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer\
         &client_assertion={assertion}"
    );
    let req = Request::builder()
        .method("POST")
        .uri("https://test.example.com/oauth/token")
        .header("content-type", "application/x-www-form-urlencoded")
        .header("content-length", form.len().to_string())
        .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            0,
        ))))
        .body(axum::body::Body::from(form))
        .expect("build request");
    let resp = router.oneshot(req).await.expect("router oneshot");
    let status = resp.status();
    let body_bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .expect("read body");
    (status, String::from_utf8_lossy(&body_bytes).into_owned())
}

/// Router-level regression: a `private_key_jwt` request whose JWKS lacks the
/// assertion `kid` returns the structured `401 invalid_client` — never a bare
/// transport `408` — and performs exactly one JWKS fetch against the loopback
/// TLS mock.
///
/// Before the fix the kid-miss force-refresh issued a second `fetch_and_cache`
/// in the same request. Two sequential 5s fetches could consume the whole 10s
/// `REQUEST_TIMEOUT` (set at `infra::router.rs::REQUEST_TIMEOUT`), and the
/// router's innermost `TimeoutLayer` would drop the handler mid-second-fetch,
/// surfacing a transport `408` in place of the structured `401 invalid_client`.
/// The `JwksOrigin::Fetched` gate bounds the path to one fetch; this asserts
/// the observable consequence at the router level.
#[tokio::test]
async fn rfc7523_kid_miss_returns_structured_401_not_408_at_router() {
    let accepted = Arc::new(AtomicU64::new(0));
    // The served JWKS is valid JSON but empty — the assertion's `kid` is not
    // present, so `find_matching_key` misses and the kid-miss force-refresh
    // path fires (or, post-fix, is gated off when resolution already fetched).
    let server_url =
        spawn_counting_jwks_server(serde_json::json!({"keys":[]}).to_string(), accepted.clone())
            .await;

    let http_client = https_client_trusting_any_cert();
    let state = build_test_app_state_with_http_client(Vec::new(), |_| {}, http_client).await;
    let router = build_production_router(state.clone());
    let (_client, client_id) =
        make_private_key_jwt_client(&state, server_url, "rfc7523-408@example.com").await;

    // No seeded cache — first request: `resolve_client_jwks` fetches the kid-less
    // JWKS (fetch #1, `JwksOrigin::Fetched`), then `find_matching_key` misses and
    // the kid-miss force-refresh is gated OFF. Exactly one fetch, the handler
    // completes inside the 10s budget, and the client sees `401 invalid_client`.
    let (pkcs8, _jwk) = generate_es256_key();
    let now = jiff::Timestamp::now().as_second();
    let header = serde_json::json!({"alg":"ES256","typ":"JWT","kid":"assertion-key"});
    let claims = serde_json::json!({
        "iss": client_id,
        "sub": client_id,
        "aud": "https://test.example.com",
        "exp": now + 300,
        "iat": now,
        "jti": "router-408-regression-jti",
    });
    let assertion = sign_jwt_assertion(&pkcs8, &header, &claims);

    let (status, body) = post_token(router, &client_id, &assertion).await;

    // The observable contract: status is 401 (NOT 408), and the body is the
    // structured OAuth error JSON the handler emits, not the empty body a
    // `TimeoutLayer` preemption leaves.
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "status must be 401 invalid_client, not the 408 a dropped handler future produces; \
         body: {body}"
    );
    assert!(
        body.contains("\"invalid_client\""),
        "body must be the structured OAuth error: {body}"
    );

    // The mechanism: exactly one network fetch where two ran before the fix.
    let fetches = accepted.load(Ordering::SeqCst);
    assert_eq!(
        fetches, 1,
        "the RFC 7523 router path must perform exactly one JWKS fetch per request \
         (got {fetches}); a second fetch can race the 10s REQUEST_TIMEOUT and surface \
         a 408 instead of the structured 401 invalid_client"
    );
}

/// RFC 3986 §3.1: "Although schemes are case-insensitive, the canonical form
/// is lowercase". Registration admits an `HTTPS://` `jwks_uri`, so client
/// authentication must fetch it: one TLS fetch, the assertion verifies, and the
/// request fails later at grant validation (`code=x`).
#[tokio::test]
async fn uppercase_scheme_jwks_uri_authenticates() {
    let (pkcs8, jwk) = generate_es256_key();
    let jwks_body = serde_json::json!({"keys": [jwk]}).to_string();
    let accepted = Arc::new(AtomicU64::new(0));
    let server_url = spawn_counting_jwks_server(jwks_body, accepted.clone()).await;

    let http_client = https_client_trusting_any_cert();
    let state = build_test_app_state_with_http_client(Vec::new(), |_| {}, http_client).await;
    let router = build_production_router(state.clone());

    let uppercase_url = server_url.replacen("https://", "HTTPS://", 1);
    let (_client, client_id) =
        make_private_key_jwt_client(&state, uppercase_url, "uppercase-scheme@example.com").await;

    let now = jiff::Timestamp::now().as_second();
    let header = serde_json::json!({"alg":"ES256","typ":"JWT","kid":"assertion-key"});
    let claims = serde_json::json!({
        "iss": client_id,
        "sub": client_id,
        "aud": "https://test.example.com",
        "exp": now + 300,
        "iat": now,
        "jti": "uppercase-scheme-jti",
    });
    let assertion = sign_jwt_assertion(&pkcs8, &header, &claims);

    let (status, body) = post_token(router, &client_id, &assertion).await;

    assert_ne!(
        status,
        StatusCode::UNAUTHORIZED,
        "upper-case HTTPS:// jwks_uri must pass client auth; got 401: {body}"
    );
    assert!(
        !body.contains("\"invalid_client\""),
        "must not be invalid_client; body: {body}"
    );

    let fetches = accepted.load(Ordering::SeqCst);
    assert_eq!(
        fetches, 1,
        "upper-case-scheme jwks_uri must trigger exactly one TLS fetch (got {fetches})"
    );
}
