// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Tests for the admin "additional domains" UI handlers
//! (`handlers/admin/domains.rs`).
//!
//! Covers GET listing, POST add, POST verify, POST remove. The DNS
//! verification step itself hits the system resolver and is not exercised
//! here — only the auth gate, Origin-CSRF check, and the "not pending"
//! / "not found" branches reachable without network calls.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]

use axum::http::StatusCode;
use vouch_server::db;
use vouch_server::test_utils::{HttpResponse, http_get_full, http_post_form_full};
use vouch_tests::TestHarness;

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

// ============================================================================
// GET /admin/domains — auth + role gating
// ============================================================================

#[tokio::test]
async fn list_redirects_anonymous_to_enroll() {
    let harness = TestHarness::new().await;
    let resp = http_get_full(&harness.router, "/admin/domains", &[]).await;

    assert!(resp.status.is_redirection(), "got {}", resp.status);
    assert_eq!(redirect_location(&resp), "/enroll/start");
}

#[tokio::test]
async fn list_redirects_non_admin_to_integrations() {
    let harness = TestHarness::new().await;
    let org = harness
        .create_org("members-only.example")
        .await
        .expect("create org");
    let (_user, _auth_id, token) = harness
        .create_authenticated_org_member("member@members-only.example", &org.id)
        .await
        .expect("create org member");

    let cookie = cookie_header(&token);
    let resp = http_get_full(&harness.router, "/admin/domains", &[("Cookie", &cookie)]).await;

    assert!(resp.status.is_redirection(), "got {}", resp.status);
    assert_eq!(redirect_location(&resp), "/integrations");
}

#[tokio::test]
async fn list_renders_for_org_admin() {
    let harness = TestHarness::new().await;
    let (_user, _org, _auth_id, token) = harness
        .create_authenticated_org_admin("admin@example.com", "example.com")
        .await
        .expect("create org admin");

    let cookie = cookie_header(&token);
    let resp = http_get_full(&harness.router, "/admin/domains", &[("Cookie", &cookie)]).await;

    assert_eq!(resp.status, StatusCode::OK);
    // Primary domain should appear somewhere in the rendered page.
    assert!(
        resp.body.contains("example.com"),
        "primary domain should be listed in body; body len={}",
        resp.body.len()
    );
}

// ============================================================================
// POST /admin/domains — add pending
// ============================================================================

#[tokio::test]
async fn add_requires_origin_header() {
    let harness = TestHarness::new().await;
    let (_user, _org, _auth_id, token) = harness
        .create_authenticated_org_admin("admin@example.com", "example.com")
        .await
        .expect("create org admin");

    let cookie = cookie_header(&token);
    let resp = http_post_form_full(
        &harness.router,
        "/admin/domains",
        "domain=new.example.com",
        &[("Cookie", &cookie)],
    )
    .await;

    assert_eq!(resp.status, StatusCode::FORBIDDEN);
    assert!(
        resp.body.contains("missing_origin") || resp.body.contains("Origin"),
        "body should call out Origin: {}",
        resp.body
    );
}

#[tokio::test]
async fn add_pending_domain_redirects_with_success_flash() {
    let harness = TestHarness::new().await;
    let (_user, org, _auth_id, token) = harness
        .create_authenticated_org_admin("admin@example.com", "example.com")
        .await
        .expect("create org admin");

    let cookie = cookie_header(&token);
    let resp = http_post_form_full(
        &harness.router,
        "/admin/domains",
        "domain=secondary.example.com",
        &[("Cookie", &cookie), ("Origin", BASE_URL)],
    )
    .await;

    assert!(resp.status.is_redirection(), "got {}", resp.status);
    assert_eq!(redirect_location(&resp), "/admin/domains");

    let flash = find_set_cookie(&resp, "vouch_flash_ok").expect("success flash cookie set");
    // Cookie values are percent-encoded; check for the domain we added.
    assert!(
        flash.contains("secondary.example.com"),
        "flash should reference added domain: {flash}"
    );

    // The domain should now be persisted as pending on the org.
    let refreshed = db::get_organization(&harness.state.store, &org.id)
        .await
        .expect("get org")
        .expect("org exists");
    assert!(
        refreshed
            .additional_domains
            .iter()
            .any(|ad| ad.domain == "secondary.example.com"),
        "domain should be added to org"
    );
}

#[tokio::test]
async fn add_existing_domain_redirects_with_error_flash() {
    let harness = TestHarness::new().await;
    let (user, org, _auth_id, token) = harness
        .create_authenticated_org_admin("admin@example.com", "example.com")
        .await
        .expect("create org admin");

    // Pre-seed an additional domain so the second add hits the
    // "already attached" branch.
    db::add_additional_domain(
        &harness.state.store,
        &org.id,
        "duplicate.example.com",
        &user.id,
        &user.email,
    )
    .await
    .expect("seed pending domain");

    let cookie = cookie_header(&token);
    let resp = http_post_form_full(
        &harness.router,
        "/admin/domains",
        "domain=duplicate.example.com",
        &[("Cookie", &cookie), ("Origin", BASE_URL)],
    )
    .await;

    assert!(resp.status.is_redirection(), "got {}", resp.status);
    assert_eq!(redirect_location(&resp), "/admin/domains");

    let flash = find_set_cookie(&resp, "vouch_flash_err").expect("error flash cookie set");
    assert!(
        flash.contains("already") || flash.contains("attached"),
        "flash should explain the duplicate: {flash}"
    );
}

// ============================================================================
// POST /admin/domains/{domain}/verify
// ============================================================================

#[tokio::test]
async fn verify_unknown_domain_flashes_not_pending() {
    let harness = TestHarness::new().await;
    let (_user, _org, _auth_id, token) = harness
        .create_authenticated_org_admin("admin@example.com", "example.com")
        .await
        .expect("create org admin");

    let cookie = cookie_header(&token);
    let resp = http_post_form_full(
        &harness.router,
        "/admin/domains/never-added.example.com/verify",
        "",
        &[("Cookie", &cookie), ("Origin", BASE_URL)],
    )
    .await;

    assert!(resp.status.is_redirection(), "got {}", resp.status);
    let flash = find_set_cookie(&resp, "vouch_flash_err").expect("error flash cookie set");
    // The "not pending" branch is the only one that fires without DNS.
    assert!(
        flash.contains("not%20pending") || flash.contains("not pending"),
        "flash should explain not-pending state: {flash}"
    );
}

// ============================================================================
// POST /admin/domains/{domain}/remove
// ============================================================================

#[tokio::test]
async fn remove_unknown_domain_flashes_not_found() {
    let harness = TestHarness::new().await;
    let (_user, _org, _auth_id, token) = harness
        .create_authenticated_org_admin("admin@example.com", "example.com")
        .await
        .expect("create org admin");

    let cookie = cookie_header(&token);
    let resp = http_post_form_full(
        &harness.router,
        "/admin/domains/missing-domain.example.com/remove",
        "",
        &[("Cookie", &cookie), ("Origin", BASE_URL)],
    )
    .await;

    assert!(resp.status.is_redirection(), "got {}", resp.status);
    let flash = find_set_cookie(&resp, "vouch_flash_err").expect("error flash cookie set");
    assert!(
        flash.contains("not%20found") || flash.contains("not found"),
        "flash should explain missing domain: {flash}"
    );
}

#[tokio::test]
async fn remove_existing_pending_domain_succeeds() {
    let harness = TestHarness::new().await;
    let (user, org, _auth_id, token) = harness
        .create_authenticated_org_admin("admin@example.com", "example.com")
        .await
        .expect("create org admin");

    db::add_additional_domain(
        &harness.state.store,
        &org.id,
        "removeme.example.com",
        &user.id,
        &user.email,
    )
    .await
    .expect("seed pending domain");

    let cookie = cookie_header(&token);
    let resp = http_post_form_full(
        &harness.router,
        "/admin/domains/removeme.example.com/remove",
        "",
        &[("Cookie", &cookie), ("Origin", BASE_URL)],
    )
    .await;

    assert!(resp.status.is_redirection(), "got {}", resp.status);
    assert_eq!(redirect_location(&resp), "/admin/domains");
    let flash = find_set_cookie(&resp, "vouch_flash_ok").expect("success flash cookie set");
    assert!(
        flash.contains("removeme.example.com") || flash.contains("Removed"),
        "flash should mention removal: {flash}"
    );

    let refreshed = db::get_organization(&harness.state.store, &org.id)
        .await
        .expect("get org")
        .expect("org exists");
    assert!(
        refreshed
            .additional_domains
            .iter()
            .all(|ad| ad.domain != "removeme.example.com"),
        "domain should have been removed"
    );
}
