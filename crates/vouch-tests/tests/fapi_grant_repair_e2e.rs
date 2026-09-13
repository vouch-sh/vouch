// SPDX-License-Identifier: Apache-2.0 OR MIT
//! End-to-end coverage for the RFC 7592 PUT repair of stale FAPI client
//! `grant_types` (the `d3ad2063` follow-up bug).
//!
//! The CLI registers a single FAPI 2.0 client at enrollment and reuses its
//! `client_id` thereafter. The server persists the registered `grant_types`
//! and re-reads them at every token request (RFC 6749 §5.2
//! `unauthorized_client` gate). Commit `d3ad2063` added `token-exchange` to
//! `REGISTERED_GRANT_TYPES`, but that value only reached the POST
//! create-new-client path; `ensure_client_registered` / `register_fapi_client_open`
//! short-circuit on a cached `client_id`, so already-enrolled clients never
//! re-POSTed and their server-stored `grant_types` never gained
//! `token-exchange`. After the upgrade, `vouch credential openai|anthropic`
//! kept failing with HTTP 401 `unauthorized_client`.
//!
//! These tests reproduce the upgrade scenario end-to-end against the real
//! `vouch-server` router served on a loopback TCP port (the CLI's
//! `register_fapi_client` / `update_fapi_client` / `is_client_registered` take
//! a raw `reqwest::Client`, so they require a real HTTP endpoint), then drive
//! the CLI's actual repair path (`vouch_cli::fapi::registration::update_fapi_client`)
//! to confirm:
//! 1. A pre-fix client (server-stored `grant_types` = `[device_code,
//!    fido2_assertion]`) is rejected at the token-exchange gate (bug repro).
//! 2. `update_fapi_client` PUTs the full replacement body, the server persists
//!    `token-exchange`, rotates the `registration_access_token`, and the same
//!    `client_id` / JWKS continue to authenticate.
//! 3. After the repair, the same token-exchange request succeeds.
//! 4. The old `registration_access_token` is rejected (rotation enforced).

#![expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code: panicking on an assertion failure is the point"
)]

use std::sync::Arc;

use secrecy::ExposeSecret;
use vouch_cli::fapi::registration::{
    grant_types_stale, registered_grant_types_version, update_fapi_client,
};
use vouch_cli::fapi::{ClientAssertionBuilder, ClientKey};
use vouch_common::protocol;
use vouch_server::config::BaseUrl;
use vouch_server::test_utils::{
    TestSessionSpec, create_test_authenticator, create_test_session_with, create_test_user,
    test_app_state,
};
use vouch_server::{AppState, infra::router::build_app};

// ── Helpers ──────────────────────────────────────────────────────────────

/// Materialize an in-process `vouch-server` on an ephemeral loopback TCP port
/// and return `(base_url, reqwest_client, app_state)`. The server's
/// `config.base_url` is rewritten to the bound URL so that the
/// `registration_client_uri` the server returns in registration responses
/// points at the live listener (the CLI PUTs/GETs to it verbatim).
async fn spawn_server() -> (String, reqwest::Client, Arc<AppState>) {
    let state = test_app_state().await;

    // Bind the listener first so we know the port, then rewrite base_url
    // before the router is built (the router bakes `base_url` into the
    // registration responses).
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback listener");
    let port = listener.local_addr().expect("local_addr").port();
    let base_url = format!("http://127.0.0.1:{port}");

    // Replace the server config with one whose base_url is the live URL.
    // `state.config()` returns an arc_swap Guard (already loaded); clone the
    // inner Arc and deref it to mutate.
    let current_cfg = state.config();
    let mut cfg = (**current_cfg).clone();
    cfg.base_url = BaseUrl::new(&base_url);
    drop(current_cfg);
    state.config.store(Arc::new(cfg));

    let cfg_for_router = state.config();
    let router = build_app(state.clone(), &cfg_for_router).expect("build test app router");
    drop(cfg_for_router);

    // Serve the router on the loopback listener. The task is tied to the test
    // process's runtime and is dropped (and the listener with it) when the
    // test returns.
    //
    // `into_make_service_with_connect_info` injects `ConnectInfo<SocketAddr>`
    // into each request's extensions, which the rate limiter's key extractor
    // (`TrustedProxyKeyExtractor`) reads to identify the client IP. Without it
    // every request fails with "Unable to extract key!" (HTTP 500).
    tokio::spawn(async move {
        if axum::serve(
            listener,
            router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .is_err()
        {
            // The server task ends when the test releases the listener or on
            // error; a serve failure surfaces as a test failure (the requests
            // below won't get responses).
        }
    });

    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("build reqwest client");

    (base_url, http, state)
}

/// POST a client registration with the given `grant_types` (open registration,
/// no Bearer token) and return `(client_id, registration_access_token,
/// registration_client_uri)`.
async fn register_client(
    http: &reqwest::Client,
    base_url: &str,
    key: &ClientKey,
    grant_types: &[&str],
) -> (String, String, String) {
    let public_jwk = key.public_jwk().expect("export public jwk");
    let jwks = serde_json::json!({ "keys": [public_jwk] });
    let body = serde_json::json!({
        "token_endpoint_auth_method": "private_key_jwt",
        "grant_types": grant_types,
        "response_types": [],
        "dpop_bound_access_tokens": true,
        "jwks": jwks,
        "client_name": "vouch-cli-test",
        "software_id": "vouch-cli",
        "software_version": "test",
    });

    let resp = http
        .post(format!("{base_url}/oauth/register"))
        .json(&body)
        .send()
        .await
        .expect("POST /oauth/register");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::CREATED,
        "registration failed: {}",
        resp.text().await.unwrap_or_default()
    );
    let json: serde_json::Value = resp.json().await.expect("registration response JSON");
    let client_id = json["client_id"].as_str().expect("client_id").to_string();
    let rat = json["registration_access_token"]
        .as_str()
        .expect("registration_access_token")
        .to_string();
    let uri = json["registration_client_uri"]
        .as_str()
        .expect("registration_client_uri")
        .to_string();
    (client_id, rat, uri)
}

/// GET the registration at `uri` with the given bearer token and return the
/// parsed body (or `None` if the request fails). Used to inspect the stored
/// `grant_types`.
async fn get_registration(
    http: &reqwest::Client,
    uri: &str,
    token: &str,
) -> Option<serde_json::Value> {
    let resp = http.get(uri).bearer_auth(token).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    resp.json().await.ok()
}

/// POST a `grant_type=token-exchange` request to `/oauth/token` using
/// `private_key_jwt` client authentication signed by `key`, with a DPoP proof
/// (required by FAPI 2.0 sender-constrained tokens). Mirrors the shape
/// `vouch credential openai` sends, including the RFC 9449 `use_dpop_nonce`
/// retry: the first request is sent without a nonce; if the server demands
/// one, the request is retried with the server-provided nonce. Returns
/// `(status, body_text)` for the final attempt.
async fn token_exchange(
    http: &reqwest::Client,
    base_url: &str,
    client_id: &str,
    key: &ClientKey,
    subject_token: &str,
) -> (reqwest::StatusCode, String) {
    let endpoint = format!("{base_url}/oauth/token");
    let outcome = send_token_exchange(
        http,
        &endpoint,
        base_url,
        client_id,
        key,
        subject_token,
        None,
    )
    .await;
    let nonce = match outcome {
        ExchangeOutcome::Success { status, body } => return (status, body),
        ExchangeOutcome::NeedNonce(nonce) => nonce,
        ExchangeOutcome::Other { status, body } => return (status, body),
    };

    // Retry once with the server-provided nonce (RFC 9449).
    let outcome = send_token_exchange(
        http,
        &endpoint,
        base_url,
        client_id,
        key,
        subject_token,
        Some(&nonce),
    )
    .await;
    match outcome {
        ExchangeOutcome::Success { status, body } => (status, body),
        ExchangeOutcome::NeedNonce(_) => (
            reqwest::StatusCode::BAD_REQUEST,
            "repeated nonce demand".to_string(),
        ),
        ExchangeOutcome::Other { status, body } => (status, body),
    }
}

enum ExchangeOutcome {
    Success {
        status: reqwest::StatusCode,
        body: String,
    },
    NeedNonce(String),
    Other {
        status: reqwest::StatusCode,
        body: String,
    },
}

async fn send_token_exchange(
    http: &reqwest::Client,
    endpoint: &str,
    base_url: &str,
    client_id: &str,
    key: &ClientKey,
    subject_token: &str,
    nonce: Option<&str>,
) -> ExchangeOutcome {
    use vouch_cli::fapi::DpopProofBuilder;

    let assertion = ClientAssertionBuilder::new(client_id, base_url)
        .build(key)
        .expect("build client assertion");
    let assertion_val = assertion.assertion.expose_secret();

    let form = [
        ("grant_type", protocol::GRANT_TYPE_TOKEN_EXCHANGE),
        ("subject_token", subject_token),
        (
            "subject_token_type",
            "urn:ietf:params:oauth:token-type:access_token",
        ),
        (
            "requested_token_type",
            "urn:ietf:params:oauth:token-type:id_token",
        ),
        ("client_id", client_id),
        (
            "client_assertion_type",
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        ),
        ("client_assertion", assertion_val),
    ];

    let mut dpop_builder = DpopProofBuilder::new("POST", endpoint);
    if let Some(n) = nonce {
        dpop_builder = dpop_builder.nonce(n);
    }
    let dpop_proof = dpop_builder.build(key).expect("build DPoP proof");

    let resp = http
        .post(endpoint)
        .header("dpop", dpop_proof)
        .form(&form)
        .send()
        .await
        .expect("POST /oauth/token");
    let status = resp.status();
    let resp_nonce = resp
        .headers()
        .get("dpop-nonce")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let body = resp.text().await.unwrap_or_default();

    if status.is_success() {
        return ExchangeOutcome::Success { status, body };
    }
    // RFC 9449: `use_dpop_nonce` carries a fresh nonce to retry with.
    if let Ok(err) = serde_json::from_str::<serde_json::Value>(&body)
        && err.get("error").and_then(|v| v.as_str()) == Some("use_dpop_nonce")
        && let Some(n) = resp_nonce
    {
        return ExchangeOutcome::NeedNonce(n);
    }
    ExchangeOutcome::Other { status, body }
}

// ── Tests ───────────────────────────────────────────────────────────────

/// The upgrade-path bug and its in-band repair via `update_fapi_client`:
///
/// 1. Register with the *pre-fix* grant list (no `token-exchange`).
/// 2. Confirm the stored `grant_types` lack `token-exchange`.
/// 3. Attempt a token-exchange: HTTP 401 `unauthorized_client` (bug repro).
/// 4. Run the CLI's repair path (`update_fapi_client`) — the fix.
/// 5. `GET` confirms the stored `grant_types` now include `token-exchange`.
/// 6. `GET` with the *old* token is rejected (rotation enforced).
/// 7. The same token-exchange now succeeds.
/// 8. `grant_types_stale` flips from `true` (pre-fix stamp) to `false`
///    (current stamp) — the decision that drives step 4 in the live CLI.
#[tokio::test]
async fn update_fapi_client_repairs_stale_grant_types_for_already_enrolled_client() {
    let (base_url, http, state) = spawn_server().await;

    // Mint a real first-party access token to use as the RFC 8693 subject_token.
    // `vouch credential openai` exchanges the user's session token for a Vouch
    // ID token; here we mint a session the way the rfc8693 server tests do.
    let user = create_test_user(&state.store, "repair@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    let subject_token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &user.id,
            email: &user.email,
            auth_id: Some(&auth_id),
            ..Default::default()
        },
    )
    .await;

    // 1. Register with the pre-fix grant list, as the server stored it before
    //    commit d3ad2063 added token-exchange to REGISTERED_GRANT_TYPES.
    let key = ClientKey::generate().expect("generate ES256 key");
    let pre_fix_grants = [
        protocol::GRANT_TYPE_DEVICE_CODE,
        protocol::GRANT_TYPE_FIDO2_ASSERTION,
    ];
    let (client_id, rat, uri) = register_client(&http, &base_url, &key, &pre_fix_grants).await;

    // 2. Confirm the stored grant_types lack token-exchange.
    let stored = get_registration(&http, &uri, &rat)
        .await
        .expect("GET stored registration");
    let stored_grants = stored["grant_types"].as_array().expect("grant_types array");
    let stored_grants: Vec<String> = stored_grants
        .iter()
        .map(|v| v.as_str().expect("grant string").to_string())
        .collect();
    assert!(
        !stored_grants.contains(&protocol::GRANT_TYPE_TOKEN_EXCHANGE.to_string()),
        "precondition: stored grant_types must lack token-exchange (bug repro), got {stored_grants:?}"
    );

    // 3. Attempt a token-exchange: the server's unauthorized_client gate rejects
    //    it. This is the user-visible bug.
    let (status, body) = token_exchange(&http, &base_url, &client_id, &key, &subject_token).await;
    assert_eq!(
        status,
        reqwest::StatusCode::UNAUTHORIZED,
        "pre-fix token-exchange must be rejected by the unauthorized_client gate: status={status}, body={body}"
    );
    assert!(
        body.contains("unauthorized_client"),
        "pre-fix token-exchange must return error=unauthorized_client, got: {body}"
    );

    // 4. Run the CLI's repair path (the fix): PUT the full registration body.
    let repair = update_fapi_client(&http, &uri, &rat, &key)
        .await
        .expect("update_fapi_client must succeed on an active client");
    assert_eq!(
        repair.client_id, client_id,
        "PUT repair reuses the same client_id (no fresh POST)"
    );
    let new_rat = repair
        .registration_access_token
        .expect("PUT must return a new registration_access_token")
        .expose_secret()
        .to_string();
    assert_ne!(
        new_rat, rat,
        "the server must rotate the registration_access_token on PUT"
    );
    let new_uri = repair
        .registration_client_uri
        .expect("PUT must echo the registration_client_uri");
    assert_eq!(
        new_uri, uri,
        "PUT must preserve the registration_client_uri"
    );

    // 5. GET confirms the stored grant_types now include token-exchange (with
    //    the rotated token).
    let repaired = get_registration(&http, &new_uri, &new_rat)
        .await
        .expect("GET stored registration after repair");
    let repaired_grants = repaired["grant_types"]
        .as_array()
        .expect("grant_types array after repair");
    let repaired_grants: Vec<String> = repaired_grants
        .iter()
        .map(|v| v.as_str().expect("grant string").to_string())
        .collect();
    assert!(
        repaired_grants.contains(&protocol::GRANT_TYPE_TOKEN_EXCHANGE.to_string()),
        "after repair, stored grant_types must include token-exchange, got {repaired_grants:?}"
    );
    // The original grants are preserved (full replacement carries them all).
    assert!(
        repaired_grants.contains(&protocol::GRANT_TYPE_DEVICE_CODE.to_string())
            && repaired_grants.contains(&protocol::GRANT_TYPE_FIDO2_ASSERTION.to_string()),
        "full-replacement PUT must preserve the original grants, got {repaired_grants:?}"
    );

    // 6. The OLD registration_access_token is now rejected (rotation enforced).
    let old_token_lookup = get_registration(&http, &new_uri, &rat).await;
    assert!(
        old_token_lookup.is_none(),
        "the old registration_access_token must be rejected after PUT rotation"
    );

    // 7. The same token-exchange request now succeeds (the user-visible fix).
    let (status, body) = token_exchange(&http, &base_url, &client_id, &key, &subject_token).await;
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "post-repair token-exchange must succeed: status={status}, body={body}"
    );
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid JSON response");
    assert!(
        json.get("access_token").is_some(),
        "token-exchange must return an access_token, got: {body}"
    );

    // 8. Pin the staleness decision that drives the repair in the live CLI.
    let pre_fix_version = pre_fix_grants.join(",");
    assert_ne!(
        pre_fix_version,
        registered_grant_types_version(),
        "pre-fix stamp must differ from the current version"
    );
    assert!(
        grant_types_stale(Some(&pre_fix_version)),
        "pre-fix stamp must be detected stale so the repair fires"
    );
    assert!(
        !grant_types_stale(Some(&registered_grant_types_version())),
        "current stamp must not be stale (steady-state fast path preserved)"
    );
    assert!(
        grant_types_stale(None),
        "a config with no stamp (pre-stamp / cleared) must be stale so \
         already-enrolled clients are repaired on the next login"
    );
}

/// `update_fapi_client` against a non-existent / revoked client returns an
/// error rather than silently succeeding — this is the branch where the live
/// CLI's `ensure_client_registered` falls through to a fresh POST.
#[tokio::test]
async fn update_fapi_client_errors_when_client_is_gone() {
    let (base_url, http, _state) = spawn_server().await;

    let key = ClientKey::generate().expect("generate ES256 key");
    let (client_id, rat, uri) = register_client(
        &http,
        &base_url,
        &key,
        &[
            protocol::GRANT_TYPE_DEVICE_CODE,
            protocol::GRANT_TYPE_FIDO2_ASSERTION,
        ],
    )
    .await;

    // Delete the client via RFC 7592 DELETE.
    let resp = http
        .delete(&uri)
        .bearer_auth(&rat)
        .send()
        .await
        .expect("DELETE /oauth/register/{id}");
    assert_eq!(resp.status(), reqwest::StatusCode::NO_CONTENT);
    let _ = client_id;

    // PUT against the now-gone client must error.
    let err = update_fapi_client(&http, &uri, &rat, &key)
        .await
        .expect_err("PUT against a deleted client must error");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("client update failed") || msg.contains("40"),
        "expected an HTTP-failure error, got: {msg}"
    );
}
