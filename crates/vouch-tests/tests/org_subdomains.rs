// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Integration tests for per-org issuer subdomains (AWS workload identity
//! federation).
//!
//! Covers: host-aware discovery on org subdomains, the WIF-only route gate,
//! the `/admin/subdomain` claim/release admin UI, and per-org `iss`/`aud`
//! on AWS tokens. The harness base URL is `https://test.example.com`, so an
//! org host looks like `acme.test.example.com` and is exercised by setting
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
    HttpResponse, http_get_full, http_post_form_full, test_app_state_with_rsa_key,
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
        &[("Host", "acme.test.example.com")],
    )
    .await;

    assert_eq!(resp.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn discovery_serves_wif_doc_for_claimed_label() {
    let harness = TestHarness::new().await;
    let org = harness.create_org("acme.com").await.unwrap();
    db::claim_subdomain(&harness.state.store, &org.id, "acme")
        .await
        .unwrap();

    let resp = http_get_full(
        &harness.router,
        DISCOVERY_PATH,
        &[("Host", "acme.test.example.com")],
    )
    .await;

    assert_eq!(resp.status, StatusCode::OK, "body: {}", resp.body);
    let doc: serde_json::Value = serde_json::from_str(&resp.body).unwrap();
    assert_eq!(doc["issuer"], "https://acme.test.example.com");
    assert_eq!(
        doc["jwks_uri"], "https://acme.test.example.com/oauth/jwks",
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
    db::claim_subdomain(&harness.state.store, &org.id, "acme")
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
        &[("Host", "acme.test.example.com")],
    )
    .await;
    assert_eq!(before.status, StatusCode::NOT_FOUND);

    db::claim_subdomain(&harness.state.store, &org.id, "acme")
        .await
        .unwrap();

    let after = http_get_full(
        &harness.router,
        DISCOVERY_PATH,
        &[("Host", "acme.test.example.com")],
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
    db::claim_subdomain(&harness.state.store, &org.id, "acme")
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
        let resp = http_get_full(&harness.router, path, &[("Host", "acme.test.example.com")]).await;
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
    db::claim_subdomain(&harness.state.store, &org.id, "acme")
        .await
        .unwrap();

    let health = http_get_full(
        &harness.router,
        "/health",
        &[("Host", "acme.test.example.com")],
    )
    .await;
    assert_eq!(health.status, StatusCode::OK, "/health must pass the gate");

    let jwks = http_get_full(
        &harness.router,
        "/oauth/jwks",
        &[("Host", "acme.test.example.com")],
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
        "label=acme",
        &[("Cookie", &cookie), ("Origin", BASE_URL)],
    )
    .await;
    assert_eq!(resp.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn subdomain_page_explains_reserved_only_candidates() {
    let harness = TestHarness::new().await;
    // Primary domain vouch.sh yields only the reserved candidate 'vouch',
    // so the page must explain the reservation rather than claim the org
    // has no verified domains.
    let (_user, _org, _auth_id, token) = harness
        .create_authenticated_org_admin("admin@vouch.sh", "vouch.sh")
        .await
        .unwrap();
    let cookie = cookie_header(&token);

    let resp = http_get_full(&harness.router, "/admin/subdomain", &[("Cookie", &cookie)]).await;
    assert_eq!(resp.status, StatusCode::OK);
    assert!(
        resp.body.contains("reserved for platform use"),
        "page should explain that the candidate subdomain is reserved; body len={}",
        resp.body.len()
    );
    assert!(
        resp.body.contains("vouch"),
        "page should name the reserved candidate"
    );
}

#[tokio::test]
async fn subdomain_ui_claim_release_flow() {
    let harness = TestHarness::new().await;
    let (_user, _org, _auth_id, token) = harness
        .create_authenticated_org_admin("admin@acme.com", "acme.com")
        .await
        .unwrap();
    let cookie = cookie_header(&token);

    // Page renders the eligible label from the primary domain.
    let resp = http_get_full(&harness.router, "/admin/subdomain", &[("Cookie", &cookie)]).await;
    assert_eq!(resp.status, StatusCode::OK);
    assert!(
        resp.body.contains(r#"<option value="acme">"#),
        "eligible label should be offered in the claim select; body len={}",
        resp.body.len()
    );

    // Claim without an Origin header is rejected (CSRF check).
    let resp = http_post_form_full(
        &harness.router,
        "/admin/subdomain",
        "label=acme",
        &[("Cookie", &cookie)],
    )
    .await;
    assert_eq!(resp.status, StatusCode::FORBIDDEN);

    // Claim → PRG with success flash carrying the issuer URL.
    let resp = http_post_form_full(
        &harness.router,
        "/admin/subdomain",
        "label=acme",
        &[("Cookie", &cookie), ("Origin", BASE_URL)],
    )
    .await;
    assert!(resp.status.is_redirection(), "got {}", resp.status);
    assert_eq!(redirect_location(&resp), "/admin/subdomain");
    let flash = find_set_cookie(&resp, "vouch_flash_ok").expect("success flash cookie set");
    assert!(
        flash.contains("acme.test.example.com"),
        "flash should carry the issuer URL: {flash}"
    );

    // Page now shows the claimed state with issuer + discovery URLs.
    let resp = http_get_full(&harness.router, "/admin/subdomain", &[("Cookie", &cookie)]).await;
    assert_eq!(resp.status, StatusCode::OK);
    assert!(resp.body.contains("https://acme.test.example.com"));
    assert!(
        resp.body
            .contains("https://acme.test.example.com/.well-known/openid-configuration"),
        "claimed page should show the discovery URL"
    );

    // Discovery on the org host resolves while claimed.
    let resp = http_get_full(
        &harness.router,
        DISCOVERY_PATH,
        &[("Host", "acme.test.example.com")],
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
        &[("Host", "acme.test.example.com")],
    )
    .await;
    assert_eq!(resp.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn subdomain_ui_rejects_conflicts_and_ineligible_labels() {
    let harness = TestHarness::new().await;
    let (_u1, _o1, _a1, first_admin) = harness
        .create_authenticated_org_admin("admin@acme.com", "acme.com")
        .await
        .unwrap();
    let (_u2, _o2, _a2, second_admin) = harness
        .create_authenticated_org_admin("admin@acme.io", "acme.io")
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

    // First org claims "acme"; the second org (same first label) conflicts.
    let resp = http_post_form_full(
        &harness.router,
        "/admin/subdomain",
        "label=acme",
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
        "label=acme",
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
    db::claim_subdomain(&harness.state.store, &org.id, "acme")
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

    assert_eq!(claims["iss"], "https://acme.test.example.com");
    assert_eq!(claims["aud"], "https://acme.test.example.com");
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
    db::claim_subdomain(&harness.state.store, &org.id, "acme")
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

    assert_eq!(claims["iss"], "https://acme.test.example.com");
    assert_eq!(claims["aud"], "https://acme.test.example.com");
}
