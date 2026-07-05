// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Integration tests for per-org issuer subdomains (AWS workload identity
//! federation).
//!
//! Covers: host-aware discovery on org subdomains, the WIF-only route gate,
//! the `/admin/subdomain` claim/release admin UI, and per-org `iss`/`aud`
//! on AWS tokens. The harness base URL is `https://test.example.com`, so an
//! org host looks like `acme-com.test.example.com` and is exercised by setting
//! the `Host` header on router-level requests.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]

use axum::http::StatusCode;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use vouch_server::db;
use vouch_server::test_utils::{
    HttpResponse, http_get_full, http_post_form_full, test_app_state_encrypted,
    test_app_state_with_rsa_key,
};
use vouch_tests::TestHarness;

const DISCOVERY_PATH: &str = "/.well-known/openid-configuration";
const BASE_URL: &str = "https://test.example.com";

fn cookie_header(token: &str) -> String {
    format!("{}={}", vouch_common::SESSION_COOKIE_NAME, token)
}

fn redirect_location(resp: &HttpResponse) -> String {
    resp.headers
        .get("location")
        .expect("location header")
        .to_str()
        .expect("location utf8")
        .to_string()
}

/// Find a `Set-Cookie` header whose name matches `cookie_name`.
fn find_set_cookie<'a>(resp: &'a HttpResponse, cookie_name: &str) -> Option<&'a str> {
    let prefix = format!("{cookie_name}=");
    resp.headers
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|v| v.starts_with(&prefix))
}

/// Decode a JWT payload (middle part) without signature verification.
fn decode_jwt_payload(token: &str) -> serde_json::Value {
    let payload = token.split('.').nth(1).expect("JWT must have 3 parts");
    let bytes = URL_SAFE_NO_PAD.decode(payload).expect("valid base64url");
    serde_json::from_slice(&bytes).expect("valid JSON payload")
}

// ============================================================================
// Host-aware discovery
// ============================================================================

#[tokio::test]
async fn discovery_404s_for_unclaimed_label() {
    let harness = TestHarness::new().await;

    let resp = http_get_full(
        &harness.router,
        DISCOVERY_PATH,
        &[("Host", "acme-com.test.example.com")],
    )
    .await;

    assert_eq!(resp.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn discovery_serves_wif_doc_for_claimed_label() {
    let harness = TestHarness::new().await;
    let org = harness.create_org("acme.com").await.unwrap();
    db::claim_subdomain(&harness.state.store, &org.id, "acme-com")
        .await
        .unwrap();

    let resp = http_get_full(
        &harness.router,
        DISCOVERY_PATH,
        &[("Host", "acme-com.test.example.com")],
    )
    .await;

    assert_eq!(resp.status, StatusCode::OK, "body: {}", resp.body);
    let doc: serde_json::Value = serde_json::from_str(&resp.body).unwrap();
    assert_eq!(doc["issuer"], "https://acme-com.test.example.com");
    assert_eq!(
        doc["jwks_uri"], "https://acme-com.test.example.com/oauth/jwks",
        "jwks_uri must live on the org host"
    );
    // The WIF doc is deliberately minimal — no primary-host endpoints.
    assert!(
        doc.get("authorization_endpoint").is_none(),
        "WIF discovery must not advertise an authorization endpoint"
    );
    assert!(
        doc.get("token_endpoint").is_none(),
        "WIF discovery must not advertise a token endpoint"
    );
}

#[tokio::test]
async fn discovery_on_primary_host_is_unchanged() {
    let harness = TestHarness::new().await;
    // Even with an org subdomain claimed, the primary host serves the full
    // FAPI document with the shared issuer.
    let org = harness.create_org("acme.com").await.unwrap();
    db::claim_subdomain(&harness.state.store, &org.id, "acme-com")
        .await
        .unwrap();

    let resp = http_get_full(
        &harness.router,
        DISCOVERY_PATH,
        &[("Host", "test.example.com")],
    )
    .await;

    assert_eq!(resp.status, StatusCode::OK);
    let doc: serde_json::Value = serde_json::from_str(&resp.body).unwrap();
    assert_eq!(doc["issuer"], "https://test.example.com");
    assert!(
        doc.get("authorization_endpoint").is_some(),
        "primary-host discovery must remain the full document"
    );
}

#[tokio::test]
async fn discovery_404_becomes_200_after_claim() {
    let harness = TestHarness::new().await;
    let org = harness.create_org("acme.com").await.unwrap();

    let before = http_get_full(
        &harness.router,
        DISCOVERY_PATH,
        &[("Host", "acme-com.test.example.com")],
    )
    .await;
    assert_eq!(before.status, StatusCode::NOT_FOUND);

    db::claim_subdomain(&harness.state.store, &org.id, "acme-com")
        .await
        .unwrap();

    let after = http_get_full(
        &harness.router,
        DISCOVERY_PATH,
        &[("Host", "acme-com.test.example.com")],
    )
    .await;
    assert_eq!(after.status, StatusCode::OK);
}

// ============================================================================
// WIF-only route gate on org hosts
// ============================================================================

#[tokio::test]
async fn org_host_gate_blocks_non_wif_routes() {
    let harness = TestHarness::new().await;
    let org = harness.create_org("acme.com").await.unwrap();
    db::claim_subdomain(&harness.state.store, &org.id, "acme-com")
        .await
        .unwrap();

    for path in [
        "/login",
        "/",
        "/enroll/start",
        "/v1/auth/status",
        "/oauth/authorize",
        "/.well-known/oauth-authorization-server",
        "/api/v1/org/subdomain",
    ] {
        let resp = http_get_full(
            &harness.router,
            path,
            &[("Host", "acme-com.test.example.com")],
        )
        .await;
        assert_eq!(
            resp.status,
            StatusCode::NOT_FOUND,
            "{path} must 404 on an org host"
        );
    }
}

#[tokio::test]
async fn org_host_gate_applies_even_for_unclaimed_labels() {
    // The gate is shape-based (DB-free): unclaimed org-shaped hosts also
    // only expose the WIF surface.
    let harness = TestHarness::new().await;

    let resp = http_get_full(
        &harness.router,
        "/login",
        &[("Host", "nobody.test.example.com")],
    )
    .await;
    assert_eq!(resp.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn health_and_jwks_allowed_on_org_host() {
    let harness = TestHarness::new().await;
    let org = harness.create_org("acme.com").await.unwrap();
    db::claim_subdomain(&harness.state.store, &org.id, "acme-com")
        .await
        .unwrap();

    let health = http_get_full(
        &harness.router,
        "/health",
        &[("Host", "acme-com.test.example.com")],
    )
    .await;
    assert_eq!(health.status, StatusCode::OK, "/health must pass the gate");

    let jwks = http_get_full(
        &harness.router,
        "/oauth/jwks",
        &[("Host", "acme-com.test.example.com")],
    )
    .await;
    assert_eq!(jwks.status, StatusCode::OK, "body: {}", jwks.body);
    let keys: serde_json::Value = serde_json::from_str(&jwks.body).unwrap();
    assert!(
        !keys["keys"].as_array().unwrap().is_empty(),
        "JWKS on the org host must contain the shared signing keys"
    );
}

#[tokio::test]
async fn primary_host_routes_unaffected_by_gate() {
    let harness = TestHarness::new().await;

    for (path, host) in [
        ("/login", "test.example.com"),
        ("/health", "test.example.com"),
        // NLB health checks send an IP or the NLB DNS name as Host.
        ("/health", "10.1.2.3"),
    ] {
        let resp = http_get_full(&harness.router, path, &[("Host", host)]).await;
        assert_ne!(
            resp.status,
            StatusCode::NOT_FOUND,
            "{path} with Host {host} must not be gated"
        );
    }
}

// ============================================================================
// Claim / release admin UI (/admin/subdomain)
// ============================================================================

#[tokio::test]
async fn subdomain_page_gates_by_auth_and_role() {
    let harness = TestHarness::new().await;

    // Anonymous → enroll.
    let resp = http_get_full(&harness.router, "/admin/subdomain", &[]).await;
    assert!(resp.status.is_redirection(), "got {}", resp.status);
    assert_eq!(redirect_location(&resp), "/enroll/start");

    // Non-admin member → integrations.
    let org = harness.create_org("acme.com").await.unwrap();
    let (_user, _auth_id, member_token) = harness
        .create_authenticated_org_member("member@acme.com", &org.id)
        .await
        .unwrap();
    let cookie = cookie_header(&member_token);
    let resp = http_get_full(&harness.router, "/admin/subdomain", &[("Cookie", &cookie)]).await;
    assert!(resp.status.is_redirection(), "got {}", resp.status);
    assert_eq!(redirect_location(&resp), "/integrations");

    // Non-admin POST is forbidden outright.
    let resp = http_post_form_full(
        &harness.router,
        "/admin/subdomain",
        "label=acme-com",
        &[("Cookie", &cookie), ("Origin", BASE_URL)],
    )
    .await;
    assert_eq!(resp.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn subdomain_page_explains_unusable_candidates() {
    let harness = TestHarness::from_state(test_app_state_encrypted().await);
    // The primary domain's apex-derived label exceeds the 63-character DNS
    // label limit, so the page must explain the unusable candidate rather
    // than claim the org has no verified domains.
    let long_name = "a".repeat(60);
    let long_domain = format!("{long_name}.com");
    let (_user, _org, _auth_id, token) = harness
        .create_authenticated_org_admin(&format!("admin@{long_domain}"), &long_domain)
        .await
        .unwrap();
    let cookie = cookie_header(&token);

    let resp = http_get_full(&harness.router, "/admin/subdomain", &[("Cookie", &cookie)]).await;
    assert_eq!(resp.status, StatusCode::OK);
    assert!(
        resp.body.contains("cannot be used as an issuer subdomain"),
        "page should explain the unusable candidate; body len={}",
        resp.body.len()
    );
    assert!(
        resp.body.contains(&format!("{long_name}-com")),
        "page should name the unusable candidate"
    );
}

#[tokio::test]
async fn claim_rejected_when_store_not_encrypted() {
    // Per-org signing keys are never persisted in plaintext: the claim
    // handler refuses on the dev plaintext store (and startup refuses to
    // boot an unencrypted server that already has claims).
    let harness = TestHarness::new().await; // default = PlaintextDocumentCrypto
    let (_user, _org, _auth_id, token) = harness
        .create_authenticated_org_admin("admin@acme.com", "acme.com")
        .await
        .unwrap();
    let cookie = cookie_header(&token);

    let resp = http_post_form_full(
        &harness.router,
        "/admin/subdomain",
        "label=acme-com",
        &[("Cookie", &cookie), ("Origin", BASE_URL)],
    )
    .await;
    assert!(resp.status.is_redirection(), "got {}", resp.status);
    let flash = find_set_cookie(&resp, "vouch_flash_err").expect("error flash cookie set");
    assert!(
        flash.contains("encrypted"),
        "flash should explain the encryption requirement: {flash}"
    );

    // The page offers the explanation instead of a claim form.
    let resp = http_get_full(&harness.router, "/admin/subdomain", &[("Cookie", &cookie)]).await;
    assert_eq!(resp.status, StatusCode::OK);
    assert!(
        !resp.body.contains("<option value="),
        "no claim select on a plaintext store"
    );
    assert!(
        resp.body.contains("not encrypted"),
        "page should explain why claiming is unavailable"
    );
}

#[tokio::test]
async fn subdomain_ui_claim_release_flow() {
    let harness = TestHarness::from_state(test_app_state_encrypted().await);
    let (_user, _org, _auth_id, token) = harness
        .create_authenticated_org_admin("admin@acme.com", "acme.com")
        .await
        .unwrap();
    let cookie = cookie_header(&token);

    // Page renders the eligible label from the primary domain's apex.
    let resp = http_get_full(&harness.router, "/admin/subdomain", &[("Cookie", &cookie)]).await;
    assert_eq!(resp.status, StatusCode::OK);
    assert!(
        resp.body.contains(r#"<option value="acme-com">"#),
        "eligible label should be offered in the claim select; body len={}",
        resp.body.len()
    );

    // Claim without an Origin header is rejected (CSRF check).
    let resp = http_post_form_full(
        &harness.router,
        "/admin/subdomain",
        "label=acme-com",
        &[("Cookie", &cookie)],
    )
    .await;
    assert_eq!(resp.status, StatusCode::FORBIDDEN);

    // Claim → PRG with success flash carrying the issuer URL.
    let resp = http_post_form_full(
        &harness.router,
        "/admin/subdomain",
        "label=acme-com",
        &[("Cookie", &cookie), ("Origin", BASE_URL)],
    )
    .await;
    assert!(resp.status.is_redirection(), "got {}", resp.status);
    assert_eq!(redirect_location(&resp), "/admin/subdomain");
    let flash = find_set_cookie(&resp, "vouch_flash_ok").expect("success flash cookie set");
    assert!(
        flash.contains("acme-com.test.example.com"),
        "flash should carry the issuer URL: {flash}"
    );

    // Page now shows the claimed state with issuer + discovery URLs.
    let resp = http_get_full(&harness.router, "/admin/subdomain", &[("Cookie", &cookie)]).await;
    assert_eq!(resp.status, StatusCode::OK);
    assert!(resp.body.contains("https://acme-com.test.example.com"));
    assert!(
        resp.body
            .contains("https://acme-com.test.example.com/.well-known/openid-configuration"),
        "claimed page should show the discovery URL"
    );

    // Discovery on the org host resolves while claimed.
    let resp = http_get_full(
        &harness.router,
        DISCOVERY_PATH,
        &[("Host", "acme-com.test.example.com")],
    )
    .await;
    assert_eq!(resp.status, StatusCode::OK);

    // Release → PRG with the IAM cleanup warning in the success flash.
    let resp = http_post_form_full(
        &harness.router,
        "/admin/subdomain/release",
        "",
        &[("Cookie", &cookie), ("Origin", BASE_URL)],
    )
    .await;
    assert!(resp.status.is_redirection(), "got {}", resp.status);
    assert_eq!(redirect_location(&resp), "/admin/subdomain");
    let flash = find_set_cookie(&resp, "vouch_flash_ok").expect("success flash cookie set");
    assert!(
        flash.contains("IAM%20OIDC") || flash.contains("IAM OIDC"),
        "release flash must warn about IAM provider cleanup: {flash}"
    );

    // Released host stops resolving on discovery.
    let resp = http_get_full(
        &harness.router,
        DISCOVERY_PATH,
        &[("Host", "acme-com.test.example.com")],
    )
    .await;
    assert_eq!(resp.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn subdomain_ui_rejects_conflicts_and_ineligible_labels() {
    let harness = TestHarness::from_state(test_app_state_encrypted().await);
    let (_u1, _o1, _a1, first_admin) = harness
        .create_authenticated_org_admin("admin@acme.com", "acme.com")
        .await
        .unwrap();
    // The second org derives the same "acme-com" label from a verified
    // subdomain of the same apex, so its claim attempt reaches the slot.
    let (_u2, second_org, _a2, second_admin) = harness
        .create_authenticated_org_admin("admin@widgets.io", "widgets.io")
        .await
        .unwrap();
    db::add_additional_domain(
        &harness.state.store,
        &second_org.id,
        "mail.acme.com",
        "u1",
        "u1@widgets.io",
    )
    .await
    .unwrap();
    db::mark_additional_domain_verified(&harness.state.store, &second_org.id, "mail.acme.com")
        .await
        .unwrap();
    let first_cookie = cookie_header(&first_admin);
    let second_cookie = cookie_header(&second_admin);

    // Ineligible label (does not match a verified domain) → error flash.
    let resp = http_post_form_full(
        &harness.router,
        "/admin/subdomain",
        "label=widgets",
        &[("Cookie", &first_cookie), ("Origin", BASE_URL)],
    )
    .await;
    assert!(resp.status.is_redirection(), "got {}", resp.status);
    assert!(
        find_set_cookie(&resp, "vouch_flash_err").is_some(),
        "ineligible label should set an error flash"
    );

    // Reserved label → error flash, not a 500.
    let resp = http_post_form_full(
        &harness.router,
        "/admin/subdomain",
        "label=www",
        &[("Cookie", &first_cookie), ("Origin", BASE_URL)],
    )
    .await;
    assert!(resp.status.is_redirection(), "got {}", resp.status);
    assert!(
        find_set_cookie(&resp, "vouch_flash_err").is_some(),
        "reserved label should set an error flash"
    );

    // First org claims "acme-com"; the second org (same apex) conflicts.
    let resp = http_post_form_full(
        &harness.router,
        "/admin/subdomain",
        "label=acme-com",
        &[("Cookie", &first_cookie), ("Origin", BASE_URL)],
    )
    .await;
    assert!(
        find_set_cookie(&resp, "vouch_flash_ok").is_some(),
        "first claim should succeed"
    );

    let resp = http_post_form_full(
        &harness.router,
        "/admin/subdomain",
        "label=acme-com",
        &[("Cookie", &second_cookie), ("Origin", BASE_URL)],
    )
    .await;
    assert!(resp.status.is_redirection(), "got {}", resp.status);
    let flash = find_set_cookie(&resp, "vouch_flash_err").expect("conflict sets error flash");
    assert!(
        flash.contains("another%20organization") || flash.contains("another organization"),
        "conflict flash should name the cause: {flash}"
    );

    // Releasing when nothing is claimed → error flash.
    let resp = http_post_form_full(
        &harness.router,
        "/admin/subdomain/release",
        "",
        &[("Cookie", &second_cookie), ("Origin", BASE_URL)],
    )
    .await;
    assert!(resp.status.is_redirection(), "got {}", resp.status);
    assert!(
        find_set_cookie(&resp, "vouch_flash_err").is_some(),
        "release without a claim should set an error flash"
    );
}

// ============================================================================
// Per-org iss/aud on AWS tokens
// ============================================================================

#[tokio::test]
async fn aws_token_uses_org_issuer_when_claimed() {
    let harness = TestHarness::new().await;
    let org = harness.create_org("acme.com").await.unwrap();
    db::claim_subdomain(&harness.state.store, &org.id, "acme-com")
        .await
        .unwrap();
    let (_user, _auth_id, token) = harness
        .create_authenticated_org_member("user@acme.com", &org.id)
        .await
        .unwrap();

    let resp = harness
        .get_authenticated("/v1/credentials/aws/token", &token)
        .await
        .unwrap();
    assert_eq!(
        resp.status,
        200,
        "body: {}",
        resp.text().unwrap_or_default()
    );
    let body: serde_json::Value = resp.json().unwrap();
    let claims = decode_jwt_payload(body["id_token"].as_str().unwrap());

    assert_eq!(claims["iss"], "https://acme-com.test.example.com");
    assert_eq!(claims["aud"], "https://acme-com.test.example.com");
}

#[tokio::test]
async fn aws_token_uses_base_url_without_claim() {
    let harness = TestHarness::new().await;
    let org = harness.create_org("acme.com").await.unwrap();
    let (_user, _auth_id, token) = harness
        .create_authenticated_org_member("user@acme.com", &org.id)
        .await
        .unwrap();

    let resp = harness
        .get_authenticated("/v1/credentials/aws/token", &token)
        .await
        .unwrap();
    assert_eq!(
        resp.status,
        200,
        "body: {}",
        resp.text().unwrap_or_default()
    );
    let body: serde_json::Value = resp.json().unwrap();
    let claims = decode_jwt_payload(body["id_token"].as_str().unwrap());

    assert_eq!(claims["iss"], "https://test.example.com");
    assert_eq!(claims["aud"], "https://test.example.com");
}

#[tokio::test]
async fn aws_sso_token_uses_org_issuer_when_claimed() {
    let harness = TestHarness::from_state(test_app_state_with_rsa_key().await);
    let org = harness.create_org("acme.com").await.unwrap();
    db::claim_subdomain(&harness.state.store, &org.id, "acme-com")
        .await
        .unwrap();
    let (_user, _auth_id, token) = harness
        .create_authenticated_org_member("user@acme.com", &org.id)
        .await
        .unwrap();

    let resp = harness
        .get_authenticated("/v1/credentials/aws/sso/token", &token)
        .await
        .unwrap();
    assert_eq!(
        resp.status,
        200,
        "body: {}",
        resp.text().unwrap_or_default()
    );
    let body: serde_json::Value = resp.json().unwrap();
    let claims = decode_jwt_payload(body["id_token"].as_str().unwrap());

    assert_eq!(claims["iss"], "https://acme-com.test.example.com");
    assert_eq!(claims["aud"], "https://acme-com.test.example.com");
}

// ============================================================================
// Per-org signing keys (require a store that encrypts at rest)
// ============================================================================

/// `kid` from a JWT's header.
fn jwt_kid(token: &str) -> String {
    let header = token.split('.').next().expect("JWT header segment");
    let bytes = URL_SAFE_NO_PAD.decode(header).expect("base64url header");
    let v: serde_json::Value = serde_json::from_slice(&bytes).expect("header JSON");
    v["kid"].as_str().expect("kid claim").to_string()
}

/// All `kid`s in a JWKS response body.
fn jwks_kids(body: &serde_json::Value) -> Vec<String> {
    body["keys"]
        .as_array()
        .expect("keys array")
        .iter()
        .filter_map(|k| k["kid"].as_str().map(String::from))
        .collect()
}

async fn org_jwks_kids(harness: &TestHarness, host: &str) -> Vec<String> {
    let resp = http_get_full(&harness.router, "/oauth/jwks", &[("Host", host)]).await;
    assert_eq!(resp.status, StatusCode::OK, "jwks body: {}", resp.body);
    jwks_kids(&serde_json::from_str(&resp.body).expect("jwks JSON"))
}

/// The signing key is per-org: a token minted for one org is verifiable at that
/// org's JWKS host and **absent** from another org's — the property that makes
/// the issuer host a real tenant boundary.
#[tokio::test]
async fn aws_token_signed_with_isolated_per_org_key() {
    let harness = TestHarness::from_state(test_app_state_encrypted().await);
    let org_a = harness.create_org("acme.com").await.unwrap();
    db::claim_subdomain(&harness.state.store, &org_a.id, "acme-com")
        .await
        .unwrap();
    let org_b = harness.create_org("beta.com").await.unwrap();
    db::claim_subdomain(&harness.state.store, &org_b.id, "beta-com")
        .await
        .unwrap();

    let (_user, _auth_id, token) = harness
        .create_authenticated_org_member("user@acme.com", &org_a.id)
        .await
        .unwrap();
    let resp = harness
        .get_authenticated("/v1/credentials/aws/token", &token)
        .await
        .unwrap();
    assert_eq!(
        resp.status,
        200,
        "body: {}",
        resp.text().unwrap_or_default()
    );
    let body: serde_json::Value = resp.json().unwrap();
    let kid = jwt_kid(body["id_token"].as_str().unwrap());

    let kids_a = org_jwks_kids(&harness, "acme-com.test.example.com").await;
    let kids_b = org_jwks_kids(&harness, "beta-com.test.example.com").await;

    assert!(
        kids_a.contains(&kid),
        "acme's JWKS must contain the token's signing key: {kids_a:?}"
    );
    assert!(
        !kids_b.contains(&kid),
        "beta's JWKS must NOT contain acme's key (tenant isolation): {kids_b:?}"
    );
}

/// Two orgs get cryptographically distinct key sets — the basis for cross-org
/// reclaim safety (a new claimant of a released label serves different keys).
#[tokio::test]
async fn org_jwks_keys_differ_between_orgs() {
    let harness = TestHarness::from_state(test_app_state_encrypted().await);
    let org_a = harness.create_org("acme.com").await.unwrap();
    db::claim_subdomain(&harness.state.store, &org_a.id, "acme-com")
        .await
        .unwrap();
    let org_b = harness.create_org("beta.com").await.unwrap();
    db::claim_subdomain(&harness.state.store, &org_b.id, "beta-com")
        .await
        .unwrap();

    let kids_a = org_jwks_kids(&harness, "acme-com.test.example.com").await;
    let kids_b = org_jwks_kids(&harness, "beta-com.test.example.com").await;

    assert!(!kids_a.is_empty() && !kids_b.is_empty());
    assert!(
        kids_a.iter().all(|k| !kids_b.contains(k)),
        "org key sets must be disjoint: a={kids_a:?} b={kids_b:?}"
    );
}

/// Without at-rest encryption no per-org key is created: the org host serves
/// the *shared* key. On a running server this state is unreachable (startup
/// refuses to boot with claims, the claim handler rejects) — this pins the
/// fail-safe serving behavior should it ever be reached anyway.
#[tokio::test]
async fn dev_store_falls_back_to_shared_key() {
    let harness = TestHarness::new().await; // default = PlaintextDocumentCrypto
    let org = harness.create_org("acme.com").await.unwrap();
    db::claim_subdomain(&harness.state.store, &org.id, "acme-com")
        .await
        .unwrap();

    let org_kids = org_jwks_kids(&harness, "acme-com.test.example.com").await;
    let primary_kids = org_jwks_kids(&harness, "test.example.com").await;

    assert_eq!(
        org_kids, primary_kids,
        "dev fallback: org host must serve the shared platform keys"
    );
}

// ============================================================================
// RFC 8693 token exchange under a per-org issuer
// ============================================================================

/// Token exchange mints the requested id_token under the org's issuer and
/// signs it with the org's own key — the same tenant isolation as the AWS
/// paths, for every OIDC federation consumer.
#[tokio::test]
async fn token_exchange_id_token_uses_org_issuer_and_key() {
    let harness = TestHarness::from_state(test_app_state_encrypted().await);
    let org = harness.create_org("acme.com").await.unwrap();
    db::claim_subdomain(&harness.state.store, &org.id, "acme-com")
        .await
        .unwrap();
    let (user, _auth_id, token) = harness
        .create_authenticated_org_member("user@acme.com", &org.id)
        .await
        .unwrap();

    // Token exchange requires client authentication (RFC 8693).
    let client = harness.create_oauth_client(&user.id).await.unwrap();
    let auth_header = client.basic_auth_header();

    let body = format!(
        "grant_type=urn:ietf:params:oauth:grant-type:token-exchange\
         &subject_token={token}\
         &subject_token_type=urn:ietf:params:oauth:token-type:access_token\
         &requested_token_type=urn:ietf:params:oauth:token-type:id_token"
    );
    let response = harness
        .post_form_with_auth("/oauth/token", &body, &auth_header)
        .await
        .unwrap();
    assert_eq!(
        response.status,
        200,
        "body: {}",
        response.text().unwrap_or_default()
    );
    let resp: serde_json::Value = response.json().unwrap();
    assert_eq!(
        resp["issued_token_type"], "urn:ietf:params:oauth:token-type:id_token",
        "exchange must issue an id_token"
    );

    let id_token = resp["access_token"].as_str().expect("issued token");
    let claims = decode_jwt_payload(id_token);
    assert_eq!(claims["iss"], "https://acme-com.test.example.com");
    assert_eq!(
        claims["aud"], "https://acme-com.test.example.com",
        "default audience must follow the org issuer"
    );

    let kid = jwt_kid(id_token);
    let org_kids = org_jwks_kids(&harness, "acme-com.test.example.com").await;
    assert!(
        org_kids.contains(&kid),
        "exchanged token's kid must be in the org JWKS: {org_kids:?}"
    );
}
