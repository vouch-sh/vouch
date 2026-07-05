// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Integration tests for per-org issuer subdomains (AWS workload identity
//! federation).
//!
//! Covers: host-aware discovery on org subdomains, the WIF-only route gate,
//! the `/api/v1/org/subdomain` claim/release API, and per-org `iss`/`aud`
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
use vouch_server::test_utils::http_get_full;
use vouch_tests::TestHarness;

const DISCOVERY_PATH: &str = "/.well-known/openid-configuration";

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
// Claim / release admin API
// ============================================================================

#[tokio::test]
async fn subdomain_api_claim_release_flow() {
    let harness = TestHarness::new().await;
    let (_user, _org, _auth_id, token) = harness
        .create_authenticated_org_admin("admin@acme.com", "acme.com")
        .await
        .unwrap();

    // GET: no claim yet, "acme" is eligible from the primary domain.
    let resp = harness
        .get_authenticated("/api/v1/org/subdomain", &token)
        .await
        .unwrap();
    assert_eq!(
        resp.status,
        200,
        "body: {}",
        resp.text().unwrap_or_default()
    );
    let body: serde_json::Value = resp.json().unwrap();
    assert!(body["subdomain"].is_null());
    assert!(body["issuer"].is_null());
    assert_eq!(body["eligible_labels"], serde_json::json!(["acme"]));

    // PUT: claim it.
    let resp = harness
        .put_json_authenticated(
            "/api/v1/org/subdomain",
            &serde_json::json!({"label": "acme"}),
            &token,
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status,
        200,
        "body: {}",
        resp.text().unwrap_or_default()
    );
    let body: serde_json::Value = resp.json().unwrap();
    assert_eq!(body["subdomain"], "acme");
    assert_eq!(body["issuer"], "https://acme.test.example.com");

    // DELETE: release it; the response carries the IAM cleanup warning.
    let resp = harness
        .delete_authenticated("/api/v1/org/subdomain", &token)
        .await
        .unwrap();
    assert_eq!(
        resp.status,
        200,
        "body: {}",
        resp.text().unwrap_or_default()
    );
    let body: serde_json::Value = resp.json().unwrap();
    assert_eq!(body["released"], "acme");
    assert!(
        body["warning"].as_str().unwrap().contains("IAM OIDC"),
        "release response must warn about IAM provider cleanup"
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
async fn subdomain_api_rejects_conflicts_and_ineligible_labels() {
    let harness = TestHarness::new().await;
    let (_u1, _o1, _a1, first_admin) = harness
        .create_authenticated_org_admin("admin@acme.com", "acme.com")
        .await
        .unwrap();
    let (_u2, _o2, _a2, second_admin) = harness
        .create_authenticated_org_admin("admin@acme.io", "acme.io")
        .await
        .unwrap();

    // Ineligible label (does not match a verified domain).
    let resp = harness
        .put_json_authenticated(
            "/api/v1/org/subdomain",
            &serde_json::json!({"label": "widgets"}),
            &first_admin,
        )
        .await
        .unwrap();
    assert_eq!(resp.status, 400);

    // Reserved label fails validation before auth.
    let resp = harness
        .put_json_authenticated(
            "/api/v1/org/subdomain",
            &serde_json::json!({"label": "www"}),
            &first_admin,
        )
        .await
        .unwrap();
    assert_eq!(resp.status, 400);

    // First org claims "acme"; the second org (same first label) conflicts.
    let resp = harness
        .put_json_authenticated(
            "/api/v1/org/subdomain",
            &serde_json::json!({"label": "acme"}),
            &first_admin,
        )
        .await
        .unwrap();
    assert_eq!(resp.status, 200);

    let resp = harness
        .put_json_authenticated(
            "/api/v1/org/subdomain",
            &serde_json::json!({"label": "acme"}),
            &second_admin,
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status,
        409,
        "body: {}",
        resp.text().unwrap_or_default()
    );
}

#[tokio::test]
async fn subdomain_api_requires_org_admin() {
    let harness = TestHarness::new().await;
    let org = harness.create_org("acme.com").await.unwrap();
    let (_user, _auth_id, member_token) = harness
        .create_authenticated_org_member("member@acme.com", &org.id)
        .await
        .unwrap();

    let resp = harness
        .put_json_authenticated(
            "/api/v1/org/subdomain",
            &serde_json::json!({"label": "acme"}),
            &member_token,
        )
        .await
        .unwrap();
    assert_eq!(resp.status, 403);

    let resp = harness.get("/api/v1/org/subdomain").await.unwrap();
    assert_eq!(resp.status, 401, "anonymous must get 401");
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
