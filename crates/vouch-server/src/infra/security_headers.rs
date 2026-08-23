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
use vouch_common::protocol;

use crate::{AppState, config, services::idp};

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
            HeaderName::from_static(protocol::HEADER_DPOP),
        ])
        .expose_headers([
            HeaderName::from_static(protocol::HEADER_DPOP_NONCE),
            header::LINK,
        ])
        .max_age(std::time::Duration::from_hours(1))
}

/// Build restrictive CORS layer for UI routes (login, enroll, applications, etc.).
///
/// These routes use cookie-based sessions and should not be accessible cross-origin
/// by default. `VOUCH_CORS_ORIGINS` can override this for advanced use cases.
///
/// `VOUCH_CORS_ORIGINS` must **not** contain `"*"` — `allow_credentials(true)` and
/// a wildcard origin are forbidden by CORS spec and cause tower-http to panic at
/// router build time. `ServerConfig::validate()` enforces this at startup.
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
                .max_age(std::time::Duration::from_hours(1))
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
///
/// `idp` extends the CSP `form-action` source list with the configured upstream
/// IdP's origin(s). Chromium-based browsers enforce `form-action` through
/// redirects (CSP3 §6.4.1.1), so without this widening the `POST /device`
/// flow's 303 redirect to the IdP would be blocked.
///
/// # Errors
///
/// Returns an error if the constructed CSP `HeaderValue` cannot be built. This
/// is unreachable in practice -- origins from `CspOrigin` are ASCII-only -- but
/// `Result` propagation ensures any future bug fails server startup loudly
/// rather than silently producing a CSP without IdP origins.
pub fn apply_security_layers(
    router: Router<Arc<AppState>>,
    config: &config::ServerConfig,
    idps: &[idp::ConfiguredIdp],
) -> anyhow::Result<Router<Arc<AppState>>> {
    let csp = build_csp_header(idps)?;
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
            HeaderValue::from_static("camera=(), microphone=(), geolocation=(), payment=()"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("cross-origin-opener-policy"),
            HeaderValue::from_static("same-origin"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("content-security-policy"),
            csp,
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
    let router = if config.tls_configured() {
        router.layer(SetResponseHeaderLayer::overriding(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=63072000; includeSubDomains; preload"),
        ))
    } else {
        router
    };

    Ok(router)
}

/// Build the `Content-Security-Policy` header value.
///
/// Extends `form-action 'self'` with origins from every configured IdP
/// (OIDC + SAML). The remaining directives are static.
fn build_csp_header(idps: &[idp::ConfiguredIdp]) -> anyhow::Result<HeaderValue> {
    let mut origins: Vec<crate::infra::csp::CspOrigin> = Vec::new();
    for idp in idps {
        for origin in idp.form_action_origins() {
            if !origins.contains(&origin) {
                origins.push(origin);
            }
        }
    }
    let mut form_action = String::from("form-action 'self'");
    for origin in &origins {
        form_action.push(' ');
        form_action.push_str(origin.as_str());
    }
    let csp = format!(
        "default-src 'self'; script-src 'self'; style-src 'self'; \
         img-src 'self'; font-src 'self'; connect-src 'self'; \
         frame-ancestors 'none'; base-uri 'self'; {form_action}"
    );
    HeaderValue::from_str(&csp).map_err(|e| {
        anyhow::anyhow!("failed to build Content-Security-Policy header from {csp:?}: {e}")
    })
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::string_slice,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use crate::test_utils::*;

    #[tokio::test]
    async fn test_x_frame_options_header() {
        let state = test_app_state().await;
        let config = state.config();
        let router = apply_security_layers_to_test_router(state.clone(), &config, &[]);

        let resp = http_get_full(&router, "/health", &[]).await;
        assert_eq!(resp.headers.get("x-frame-options").unwrap(), "DENY");
    }

    #[tokio::test]
    async fn test_x_content_type_options_header() {
        let state = test_app_state().await;
        let config = state.config();
        let router = apply_security_layers_to_test_router(state.clone(), &config, &[]);

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
        let router = apply_security_layers_to_test_router(state.clone(), &config, &[]);

        let resp = http_get_full(&router, "/health", &[]).await;
        let csp = resp
            .headers
            .get("content-security-policy")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(csp.contains("default-src 'self'"));
        assert!(csp.contains("frame-ancestors 'none'"));
        // form-action must be present and -- because no IdP is configured --
        // contain only 'self'. The character following 'self' must be `;` or
        // end-of-string; any other character would indicate a stray source.
        let needle = "form-action 'self'";
        let idx = csp.find(needle).expect("form-action 'self' present");
        let next = csp[idx + needle.len()..].chars().next();
        assert!(
            matches!(next, None | Some(';')),
            "form-action 'self' must end the directive when no IdP is configured; \
             next char was {next:?}; full CSP: {csp}"
        );
    }

    /// Regression guard: with no IdP configured, the CSP header is byte-
    /// identical to the previous static value. Catches accidental trailing
    /// whitespace or empty source tokens introduced by future refactors.
    #[tokio::test]
    async fn test_csp_form_action_no_idp_byte_identical() {
        let state = test_app_state().await;
        let config = state.config();
        let router = apply_security_layers_to_test_router(state.clone(), &config, &[]);

        let resp = http_get_full(&router, "/health", &[]).await;
        let csp = resp
            .headers
            .get("content-security-policy")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(
            csp,
            "default-src 'self'; script-src 'self'; style-src 'self'; \
             img-src 'self'; font-src 'self'; connect-src 'self'; \
             frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        );
    }

    fn make_oidc_idps(auth_endpoint: &str) -> Vec<crate::services::idp::ConfiguredIdp> {
        vec![crate::services::idp::ConfiguredIdp::Oidc(
            crate::services::idp::ConfiguredOidcProvider {
                id: "google".to_string(),
                client_id: "test-client-id".to_string(),
                client_secret: secrecy::SecretString::from("test-secret"),
                provider: crate::services::idp::oidc::OidcProvider {
                    issuer: "https://accounts.google.com".to_string(),
                    authorization_endpoint: url::Url::parse(auth_endpoint).unwrap(),
                    token_endpoint: url::Url::parse("https://oauth2.googleapis.com/token").unwrap(),
                    jwks_uri: url::Url::parse("https://www.googleapis.com/oauth2/v3/certs")
                        .unwrap(),
                },
            },
        )]
    }

    fn make_saml_idps(
        sso_post: Option<&str>,
        sso_redirect: Option<&str>,
    ) -> Vec<crate::services::idp::ConfiguredIdp> {
        vec![crate::services::idp::ConfiguredIdp::Saml(
            crate::services::idp::saml::SamlProvider {
                id: "corp-saml".to_string(),
                idp_metadata: crate::services::idp::saml::IdpMetadata {
                    entity_id: "https://idp.example.com/saml".to_string(),
                    sso_post_url: sso_post.map(str::to_string),
                    sso_redirect_url: sso_redirect.map(str::to_string),
                    signing_certificates: vec![],
                },
                sp_entity_id: "https://vouch.example.com".to_string(),
                acs_url: "https://vouch.example.com/saml/acs".to_string(),
                email_attribute: None,
                domain_attribute: None,
            },
        )]
    }

    /// Extract the `form-action` directive's full value from a CSP string.
    ///
    /// The CSP is `directive value; directive value; ...`. This pulls out
    /// the substring between `form-action ` and the next `;` (or end of
    /// string), enabling an exact-equality assertion that catches mutations
    /// the loose `.contains()` would miss (e.g. tab vs space, missing
    /// origin, extra whitespace).
    fn extract_form_action(csp: &str) -> &str {
        csp.split(';')
            .map(str::trim)
            .find(|d| d.starts_with("form-action"))
            .expect("form-action directive present in CSP")
    }

    #[tokio::test]
    async fn test_csp_form_action_includes_oidc_origin() {
        let state = test_app_state().await;
        let config = state.config();
        let idps = make_oidc_idps("https://accounts.google.com/o/oauth2/v2/auth");
        let router = apply_security_layers_to_test_router(state.clone(), &config, &idps);

        let resp = http_get_full(&router, "/health", &[]).await;
        let csp = resp
            .headers
            .get("content-security-policy")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(
            extract_form_action(csp),
            "form-action 'self' https://accounts.google.com"
        );
    }

    #[tokio::test]
    async fn test_csp_form_action_oidc_custom_port() {
        let state = test_app_state().await;
        let config = state.config();
        let idps = make_oidc_idps("https://idp.example.com:8443/auth");
        let router = apply_security_layers_to_test_router(state.clone(), &config, &idps);

        let resp = http_get_full(&router, "/health", &[]).await;
        let csp = resp
            .headers
            .get("content-security-policy")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(
            extract_form_action(csp),
            "form-action 'self' https://idp.example.com:8443"
        );
    }

    #[tokio::test]
    async fn test_csp_form_action_includes_saml_post_origin() {
        let state = test_app_state().await;
        let config = state.config();
        let idps = make_saml_idps(Some("https://idp.example.com/sso/post"), None);
        let router = apply_security_layers_to_test_router(state.clone(), &config, &idps);

        let resp = http_get_full(&router, "/health", &[]).await;
        let csp = resp
            .headers
            .get("content-security-policy")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(
            extract_form_action(csp),
            "form-action 'self' https://idp.example.com"
        );
    }

    #[tokio::test]
    async fn test_csp_form_action_saml_two_distinct_hosts() {
        let state = test_app_state().await;
        let config = state.config();
        let idps = make_saml_idps(
            Some("https://idp-a.example.com/sso/post"),
            Some("https://idp-b.example.com/sso/redirect"),
        );
        let router = apply_security_layers_to_test_router(state.clone(), &config, &idps);

        let resp = http_get_full(&router, "/health", &[]).await;
        let csp = resp
            .headers
            .get("content-security-policy")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(
            csp.contains("https://idp-a.example.com"),
            "missing idp-a origin; got: {csp}"
        );
        assert!(
            csp.contains("https://idp-b.example.com"),
            "missing idp-b origin; got: {csp}"
        );
    }

    #[tokio::test]
    async fn test_referrer_policy_header() {
        let state = test_app_state().await;
        let config = state.config();
        let router = apply_security_layers_to_test_router(state.clone(), &config, &[]);

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
        let router = apply_security_layers_to_test_router(state.clone(), &config, &[]);

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
        let router = apply_security_layers_to_test_router(state.clone(), &config, &[]);

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
        idps: &[crate::services::idp::ConfiguredIdp],
    ) -> axum::Router {
        use axum::routing::get;

        let router: axum::Router<std::sync::Arc<crate::AppState>> =
            axum::Router::new().route("/health", get(|| async { "ok" }));

        super::apply_security_layers(router, config, idps)
            .expect("apply_security_layers builds CSP for test router")
            .with_state(state)
    }
}
