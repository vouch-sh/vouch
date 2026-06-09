// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Negative-auth coverage for API routes (security evaluation P2.5).
//!
//! Individual handlers verify authentication correctly, but that is a
//! per-handler property. This test turns "every handler looks right" into a
//! mechanical, regression-proof invariant: it builds the full router and
//! asserts that protected API routes reject unauthenticated requests with
//! 401/403, while public routes never answer with an auth error.
//!
//! NOTE: axum's `Router` does not expose its route table for introspection, so
//! the route lists below are *maintained by hand*. When you add a new
//! authenticated API route, add it to `PROTECTED_ROUTES`. When you add a new
//! public (no-auth) route, add it to `PUBLIC_ROUTES`. Keeping these lists
//! current is what makes this a meaningful invariant for future routes.
//!
//! Scope: JSON/API routes with Bearer / HTTP-signature / JWT auth, which
//! return 401/403. Cookie-session UI routes (e.g. `/admin/*`) redirect to
//! `/login` instead of returning an auth status code, so they are out of
//! scope here.

use vouch_tests::TestHarness;

/// Protected API routes: each must reject an unauthenticated request with
/// 401 Unauthorized or 403 Forbidden.
///
/// These are probed with GET on purpose. POST routes (credential issuance,
/// SCIM/application creation) deserialize a typed JSON body *before* the
/// handler's token check, so an empty body returns 422 — which would mask the
/// auth check rather than exercise it. The GET endpoints below cover every
/// authenticated route group (`/v1/*`, `/api/v1/*`, `/scim/v2/*`), so missing
/// auth surfaces cleanly as 401/403.
const PROTECTED_ROUTES: &[&str] = &[
    "/v1/keys",
    "/v1/credentials/aws/token",
    "/api/v1/applications",
    "/api/v1/org/scim-tokens",
    "/scim/v2/Users",
    "/scim/v2/Groups",
];

/// Public routes: these must NOT answer with an auth error (401/403) when
/// called without credentials. They may legitimately return 200/3xx/etc.
///
/// `/v1/auth/status` is deliberately public: with no/invalid token it returns
/// `200 {"authenticated": false}` rather than 401, since it is a status probe.
const PUBLIC_ROUTES: &[&str] = &[
    "/health",
    "/health/ready",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/oauth/jwks",
    "/v1/credentials/ssh/ca",
    "/v1/auth/status",
];

#[tokio::test]
async fn protected_routes_reject_unauthenticated_requests() {
    let harness = TestHarness::new().await;

    for path in PROTECTED_ROUTES {
        let response = harness
            .get(path)
            .await
            .unwrap_or_else(|e| panic!("request to {path} failed to execute: {e}"));

        assert!(
            response.status == 401 || response.status == 403,
            "{path} must reject unauthenticated requests with 401/403, got {}",
            response.status
        );
    }
}

#[tokio::test]
async fn public_routes_do_not_require_auth() {
    let harness = TestHarness::new().await;

    for path in PUBLIC_ROUTES {
        let response = harness
            .get(path)
            .await
            .unwrap_or_else(|e| panic!("request to {path} failed to execute: {e}"));

        assert!(
            response.status != 401 && response.status != 403,
            "{path} is public and must not return an auth error, got {}",
            response.status
        );
    }
}
