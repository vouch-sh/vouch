// SPDX-License-Identifier: Apache-2.0 OR MIT
//! CORS and security response header middleware.
//!
//! Provides CORS policies for API and UI route groups, plus global security
//! headers (X-Frame-Options, CSP, HSTS, etc.).

use std::sync::Arc;

use axum::{
    Router,
    http::{HeaderName, HeaderValue, Method, header},
};
use tower_http::cors::CorsLayer;
use tower_http::set_header::SetResponseHeaderLayer;

use crate::{AppState, config};

/// Build permissive CORS layer for API endpoints (OIDC, SCIM, v1, api).
///
/// These endpoints authenticate via tokens in request bodies or Authorization headers,
/// never cookies -- so `Access-Control-Allow-Origin: *` without credentials is safe and
/// allows any OIDC relying party to integrate without configuration.
pub fn build_api_cors_layer() -> CorsLayer {
    CorsLayer::new()
        .allow_origin(tower_http::cors::Any)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::ACCEPT,
            HeaderName::from_static("dpop"),
        ])
        .expose_headers([HeaderName::from_static("dpop-nonce")])
        .max_age(std::time::Duration::from_secs(3600))
}

/// Build restrictive CORS layer for UI routes (login, enroll, applications, etc.).
///
/// These routes use cookie-based sessions and should not be accessible cross-origin
/// by default. `VOUCH_CORS_ORIGINS` can override this for advanced use cases.
pub fn build_ui_cors_layer(config: &config::ServerConfig) -> CorsLayer {
    match &config.cors_origins {
        Some(origins) if !origins.is_empty() => {
            tracing::info!("UI CORS configured for origins: {:?}", origins);
            let parsed_origins: Vec<_> = origins.iter().filter_map(|o| o.parse().ok()).collect();

            CorsLayer::new()
                .allow_origin(parsed_origins)
                .allow_methods([
                    Method::GET,
                    Method::POST,
                    Method::PUT,
                    Method::PATCH,
                    Method::DELETE,
                    Method::OPTIONS,
                ])
                .allow_headers([
                    header::AUTHORIZATION,
                    header::CONTENT_TYPE,
                    header::ACCEPT,
                    header::ORIGIN,
                ])
                .allow_credentials(true)
                .max_age(std::time::Duration::from_secs(3600))
        }
        _ => {
            // No CORS configured -- restrictive same-origin defaults
            CorsLayer::new()
        }
    }
}

/// Apply security response headers globally to the router.
///
/// Sets X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy,
/// Cross-Origin-Opener-Policy, Content-Security-Policy, and HSTS (when TLS is configured).
pub fn apply_security_layers(
    router: Router<Arc<AppState>>,
    config: &config::ServerConfig,
) -> Router<Arc<AppState>> {
    let router = router
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-cache"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("referrer-policy"),
            HeaderValue::from_static("strict-origin-when-cross-origin"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("permissions-policy"),
            HeaderValue::from_static(
                "camera=(), microphone=(), geolocation=(), payment=()",
            ),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("cross-origin-opener-policy"),
            HeaderValue::from_static("same-origin"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("content-security-policy"),
            HeaderValue::from_static(
                "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
            ),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-dns-prefetch-control"),
            HeaderValue::from_static("off"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("cross-origin-resource-policy"),
            HeaderValue::from_static("same-origin"),
        ));

    // HSTS only when TLS is configured.
    // `preload` enables submission to browser HSTS preload lists per RFC 6797 / FAPI 2.0.
    if config.tls_configured() {
        router.layer(SetResponseHeaderLayer::overriding(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=63072000; includeSubDomains; preload"),
        ))
    } else {
        router
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use crate::test_utils::*;

    #[tokio::test]
    async fn test_x_frame_options_header() {
        let state = test_app_state().await;
        let config = state.config();
        let router = apply_security_layers_to_test_router(state.clone(), &config);

        let resp = http_get_full(&router, "/health", &[]).await;
        assert_eq!(resp.headers.get("x-frame-options").unwrap(), "DENY");
    }

    #[tokio::test]
    async fn test_x_content_type_options_header() {
        let state = test_app_state().await;
        let config = state.config();
        let router = apply_security_layers_to_test_router(state.clone(), &config);

        let resp = http_get_full(&router, "/health", &[]).await;
        assert_eq!(
            resp.headers.get("x-content-type-options").unwrap(),
            "nosniff"
        );
    }

    #[tokio::test]
    async fn test_content_security_policy_header() {
        let state = test_app_state().await;
        let config = state.config();
        let router = apply_security_layers_to_test_router(state.clone(), &config);

        let resp = http_get_full(&router, "/health", &[]).await;
        let csp = resp
            .headers
            .get("content-security-policy")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(csp.contains("default-src 'self'"));
        assert!(csp.contains("frame-ancestors 'none'"));
    }

    #[tokio::test]
    async fn test_referrer_policy_header() {
        let state = test_app_state().await;
        let config = state.config();
        let router = apply_security_layers_to_test_router(state.clone(), &config);

        let resp = http_get_full(&router, "/health", &[]).await;
        assert_eq!(
            resp.headers.get("referrer-policy").unwrap(),
            "strict-origin-when-cross-origin"
        );
    }

    #[tokio::test]
    async fn test_permissions_policy_header() {
        let state = test_app_state().await;
        let config = state.config();
        let router = apply_security_layers_to_test_router(state.clone(), &config);

        let resp = http_get_full(&router, "/health", &[]).await;
        let pp = resp
            .headers
            .get("permissions-policy")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(pp.contains("camera=()"));
        assert!(pp.contains("microphone=()"));
    }

    #[tokio::test]
    async fn test_cross_origin_opener_policy_header() {
        let state = test_app_state().await;
        let config = state.config();
        let router = apply_security_layers_to_test_router(state.clone(), &config);

        let resp = http_get_full(&router, "/health", &[]).await;
        assert_eq!(
            resp.headers.get("cross-origin-opener-policy").unwrap(),
            "same-origin"
        );
    }

    /// Build a minimal router with security headers for testing.
    fn apply_security_layers_to_test_router(
        state: std::sync::Arc<crate::AppState>,
        config: &crate::config::ServerConfig,
    ) -> axum::Router {
        use axum::routing::get;

        let router: axum::Router<std::sync::Arc<crate::AppState>> =
            axum::Router::new().route("/health", get(|| async { "ok" }));

        super::apply_security_layers(router, config).with_state(state)
    }
}
