// SPDX-License-Identifier: BUSL-1.1
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
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE, header::ACCEPT])
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
        ));

    // HSTS only when TLS is configured
    if config.tls_configured() {
        router.layer(SetResponseHeaderLayer::overriding(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=63072000; includeSubDomains"),
        ))
    } else {
        router
    }
}
