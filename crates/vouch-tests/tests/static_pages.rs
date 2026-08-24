// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Tests for the lightweight static pages served by the auth server:
//! - `/privacy`, `/terms`, `/.well-known/security.txt` (`handlers/legal.rs`)
//! - `/install` (`handlers/install.rs`)
//! - `/integrations` (`handlers/integrations.rs`)

#![expect(
    clippy::expect_used,
    reason = "test code: panicking on an assertion failure is the point"
)]

use std::sync::Arc;

use axum::http::StatusCode;
use vouch_server::test_utils::http_get_full;
use vouch_tests::TestHarness;

fn cookie_header(token: &str) -> String {
    format!("{}={}", vouch_common::SESSION_COOKIE_NAME, token)
}

// ============================================================================
// handlers/legal.rs
// ============================================================================

mod legal {
    use super::*;

    #[tokio::test]
    async fn privacy_redirects_to_vouch_sh() {
        let harness = TestHarness::new().await;
        let resp = http_get_full(&harness.router, "/privacy", &[]).await;

        assert_eq!(resp.status, StatusCode::PERMANENT_REDIRECT);
        let location = resp
            .headers
            .get("location")
            .expect("location header")
            .to_str()
            .expect("location utf8");
        assert_eq!(location, "https://vouch.sh/privacy/");
    }

    #[tokio::test]
    async fn terms_redirects_to_vouch_sh() {
        let harness = TestHarness::new().await;
        let resp = http_get_full(&harness.router, "/terms", &[]).await;

        assert_eq!(resp.status, StatusCode::PERMANENT_REDIRECT);
        let location = resp
            .headers
            .get("location")
            .expect("location header")
            .to_str()
            .expect("location utf8");
        assert_eq!(location, "https://vouch.sh/terms/");
    }
}

mod security_txt {
    use super::*;

    #[tokio::test]
    async fn serves_rfc9116_document_unsigned() {
        let harness = TestHarness::new().await;
        // http_get_full sends no RFC 9421 signature; a 200 proves the route
        // stays reachable without one.
        let resp = http_get_full(&harness.router, "/.well-known/security.txt", &[]).await;

        assert_eq!(resp.status, StatusCode::OK);
        let content_type = resp
            .headers
            .get("content-type")
            .expect("content-type header")
            .to_str()
            .expect("content-type utf8");
        assert!(content_type.starts_with("text/plain"));
        assert!(resp.body.contains("Contact: mailto:security@vouch.sh\r\n"));
        assert!(
            resp.body
                .contains("Canonical: https://test.example.com/.well-known/security.txt\r\n")
        );
    }

    #[tokio::test]
    async fn expires_is_rfc3339_and_in_the_future() {
        let harness = TestHarness::new().await;
        let resp = http_get_full(&harness.router, "/.well-known/security.txt", &[]).await;

        let expires_field = resp
            .body
            .lines()
            .find_map(|line| line.strip_prefix("Expires: "))
            .expect("Expires field present");
        let expires: jiff::Timestamp = expires_field.trim().parse().expect("RFC 3339 timestamp");
        assert!(expires > jiff::Timestamp::now());
    }
}

// ============================================================================
// handlers/install.rs
// ============================================================================

mod install {
    use super::*;

    #[tokio::test]
    async fn install_page_renders_anonymous() {
        let harness = TestHarness::new().await;
        let resp = http_get_full(&harness.router, "/install", &[]).await;

        assert_eq!(resp.status, StatusCode::OK);
        assert!(
            resp.headers
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.contains("text/html")),
            "expected HTML response, got headers: {:?}",
            resp.headers
        );
    }

    #[tokio::test]
    async fn install_page_renders_for_authenticated_user() {
        let harness = TestHarness::new().await;
        let (_user, _auth_id, token) = harness
            .create_authenticated_user("install-auth@example.com")
            .await
            .expect("create authed user");

        let cookie = cookie_header(&token);
        let resp = http_get_full(&harness.router, "/install", &[("Cookie", &cookie)]).await;

        assert_eq!(resp.status, StatusCode::OK);
    }

    #[tokio::test]
    async fn install_page_embeds_configured_download_urls() {
        let harness = TestHarness::new().await;
        // Mutate the live config so the `has_downloads` branch is exercised.
        let mut cfg = (**harness.state.config()).clone();
        cfg.cli_download_macos = Some("https://example.com/vouch-macos.tar.gz".to_string());
        cfg.cli_download_linux = Some("https://example.com/vouch-linux.tar.gz".to_string());
        harness.state.config.store(Arc::new(cfg));

        let resp = http_get_full(&harness.router, "/install", &[]).await;
        assert_eq!(resp.status, StatusCode::OK);
        assert!(
            resp.body.contains("vouch-macos.tar.gz") || resp.body.contains("vouch-linux.tar.gz"),
            "rendered install page should mention configured download URL; body len={}",
            resp.body.len()
        );
    }
}

// ============================================================================
// handlers/integrations.rs
// ============================================================================

mod integrations {
    use super::*;

    #[tokio::test]
    async fn integrations_redirects_anonymous_to_enroll() {
        let harness = TestHarness::new().await;
        let resp = http_get_full(&harness.router, "/integrations", &[]).await;

        assert!(
            resp.status.is_redirection(),
            "expected redirection, got {}",
            resp.status
        );
        let location = resp
            .headers
            .get("location")
            .expect("location header")
            .to_str()
            .expect("location utf8");
        assert_eq!(location, "/enroll/start");
    }

    #[tokio::test]
    async fn integrations_renders_for_authed_user_without_org() {
        let harness = TestHarness::new().await;
        let (_user, _auth_id, token) = harness
            .create_authenticated_user("no-org@example.com")
            .await
            .expect("create authed user");

        let cookie = cookie_header(&token);
        let resp = http_get_full(&harness.router, "/integrations", &[("Cookie", &cookie)]).await;
        assert_eq!(resp.status, StatusCode::OK);
    }

    #[tokio::test]
    async fn integrations_renders_for_org_admin_with_no_github_installs() {
        let harness = TestHarness::new().await;
        let (_user, _org, _auth_id, token) = harness
            .create_authenticated_org_admin("admin@example.com", "example.com")
            .await
            .expect("create org admin");

        let cookie = cookie_header(&token);
        let resp = http_get_full(&harness.router, "/integrations", &[("Cookie", &cookie)]).await;
        assert_eq!(resp.status, StatusCode::OK);
        assert!(harness.state.github_app.is_none());
    }
}
