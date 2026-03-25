// SPDX-License-Identifier: Apache-2.0 OR MIT
//! HTTP router construction.
//!
//! Assembles API and UI route groups with appropriate CORS policies,
//! rate limiting, body size limits, security headers, and middleware.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, MatchedPath, State},
    http::{HeaderValue, Request, StatusCode, header},
    middleware::Next,
    response::IntoResponse,
    routing::{delete, get, patch, post},
};
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::timeout::TimeoutLayer;

use crate::{
    AppState, config, handlers,
    infra::{httpsig, metrics, rate_limit, request_id, security_headers, static_assets},
};

/// Body limit for credential endpoints (SSH public key is ~500 bytes).
const CREDENTIAL_BODY_LIMIT: usize = 8 * 1024;

/// Body limit for SCIM payloads and authorize query strings.
const SCIM_BODY_LIMIT: usize = 64 * 1024;

/// Body limit for GitHub webhook payloads.
const WEBHOOK_BODY_LIMIT: usize = 1024 * 1024;

/// Body limit for WebAuthn enrollment payloads (attestation objects are typically < 4 KB).
const ENROLL_BODY_LIMIT: usize = 32 * 1024;

/// Body limit for WebAuthn login payloads (assertions are smaller than attestations).
const LOGIN_BODY_LIMIT: usize = 32 * 1024;

/// Body limit for SAML ACS responses (base64-encoded XML, typically 8–32 KB).
const SAML_ACS_BODY_LIMIT: usize = 64 * 1024;

/// Global body size limit (per-route overrides above are more restrictive).
const GLOBAL_BODY_LIMIT: usize = 256 * 1024;

/// Format `SOURCE_DATE_EPOCH` (compile-time) as a date string for the banner.
fn build_date() -> String {
    option_env!("SOURCE_DATE_EPOCH")
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|&ts| ts > 0)
        .and_then(|ts| jiff::Timestamp::from_second(ts).ok())
        .map(|ts| ts.strftime("%Y-%m-%d").to_string())
        .unwrap_or_else(|| "dev".to_string())
}

/// Print an ASCII banner at server startup.
pub fn print_startup_banner() {
    #[allow(clippy::print_stdout)]
    {
        println!(
            r"
                        _     
 /\   /\___  _   _  ___| |__  
 \ \ / / _ \| | | |/ __| '_ \ 
  \ V / (_) | |_| | (__| | | |
   \_/ \___/ \__,_|\___|_| |_|

  Hardware-backed identity server
  https://vouch.sh
  v{} ({})
",
            env!("CARGO_PKG_VERSION"),
            build_date(),
        );
    }
}

/// Build the complete application router with all routes, middleware, and state.
/// # Errors
///
/// Returns an error if rate limiter configuration fails.
pub fn build_app(state: Arc<AppState>, config: &config::ServerConfig) -> anyhow::Result<Router> {
    let httpsig_resolver = Arc::new(httpsig::OAuthClientKeyResolver::new(Arc::clone(&state)));
    let api_routes = build_api_routes(config, Arc::clone(&httpsig_resolver))?;
    let ui_routes = build_ui_routes(config)?;

    // Install Prometheus metrics recorder and optionally expose /metrics endpoint.
    // The endpoint is only registered when VOUCH_METRICS_BEARER_TOKEN is set.
    let metrics_route = if let Some(ref token) = config.metrics_bearer_token {
        match metrics::install_recorder() {
            Ok(handle) => {
                tracing::info!("Prometheus metrics enabled at /metrics (bearer token required)");
                let metrics_state = Arc::new(metrics::MetricsState {
                    handle,
                    bearer_token: token.clone(),
                });
                Router::new().route(
                    "/metrics",
                    get(metrics::authenticated_metrics_handler).with_state(metrics_state),
                )
            }
            Err(e) => {
                tracing::warn!("Failed to install metrics recorder: {e}");
                Router::new()
            }
        }
    } else {
        // Still install the recorder so metrics macros don't no-op
        if let Err(e) = metrics::install_recorder() {
            tracing::debug!("Metrics recorder not installed: {e}");
        }
        tracing::info!(
            "Prometheus /metrics endpoint disabled (VOUCH_METRICS_BEARER_TOKEN not set)"
        );
        Router::new()
    };

    // Register the certification test-mode login endpoint when the secret token
    // is configured. This route MUST NOT be enabled in production deployments.
    let certification_route = if let Some(ref _token) = config.certification_test_token {
        tracing::warn!(
            "Certification test mode ENABLED — \
             GET /certification/complete-login is active. \
             Do NOT run this in production."
        );
        Router::new()
            .route(
                "/certification/complete-login",
                get(handlers::certification::complete_login),
            )
            .layer(rate_limit::build_auth_rate_limiter(
                &config.trusted_proxies,
            )?)
    } else {
        Router::new()
    };

    Ok(security_headers::apply_security_layers(
        api_routes
            .merge(ui_routes)
            .merge(metrics_route)
            .merge(certification_route),
        config,
    )
    .layer(axum::middleware::from_fn(metrics_middleware))
    // Global request timeout: 30 seconds.
    .layer(TimeoutLayer::with_status_code(
        StatusCode::REQUEST_TIMEOUT,
        std::time::Duration::from_secs(30),
    ))
    .layer(DefaultBodyLimit::max(GLOBAL_BODY_LIMIT))
    .layer(request_id::propagate_request_id_layer())
    .layer(request_id::set_request_id_layer())
    .with_state(state))
}

/// Rate-limited auth/token routes.
///
/// These endpoints are brute-force targets so rate limiting is critical.
fn build_rate_limited_routes(
    config: &config::ServerConfig,
    httpsig_resolver: Arc<httpsig::OAuthClientKeyResolver>,
) -> anyhow::Result<Router<Arc<AppState>>> {
    // Key registration routes use HTTP signature verification
    let key_routes = Router::new()
        .route(
            "/v1/keys/register/start",
            post(handlers::keys::register_start),
        )
        .route(
            "/v1/keys/register/complete",
            post(handlers::keys::register_complete),
        )
        .layer(axum::middleware::from_fn_with_state(
            httpsig_resolver,
            vouch_httpsig::middleware::verify_signature::<httpsig::OAuthClientKeyResolver>,
        ));

    Ok(Router::new()
        .merge(key_routes)
        .route("/oauth/token", post(handlers::oidc::token))
        .route("/oauth/par", post(handlers::oidc::par))
        .route("/oauth/register", post(handlers::oidc::register))
        .route(
            "/oauth/register/{client_id}",
            get(handlers::oidc::read_client).delete(handlers::oidc::delete_client),
        )
        .route(
            "/oauth/fido2/challenge",
            post(handlers::oidc::fido2_challenge),
        )
        .route("/oauth/device", post(handlers::device::device_code))
        .layer(rate_limit::build_auth_rate_limiter(
            &config.trusted_proxies,
        )?))
}

/// Rate-limited credential issuance routes.
fn build_credential_routes(
    config: &config::ServerConfig,
    httpsig_resolver: Arc<httpsig::OAuthClientKeyResolver>,
) -> anyhow::Result<Router<Arc<AppState>>> {
    // Credential routes with HTTP signature verification.
    // Layer order (outside→inside): rate_limit → body_limit → httpsig → handler
    // Rate limiting runs first to reject DoS before signature verification.
    let credential_routes = Router::new()
        .route(
            "/v1/credentials/ssh",
            post(handlers::credentials::issue_ssh_certificate),
        )
        .route(
            "/v1/credentials/aws/token",
            get(handlers::credentials::get_aws_token),
        )
        .route(
            "/v1/credentials/kubernetes/token",
            get(handlers::credentials::get_kubernetes_token),
        )
        .route(
            "/v1/credentials/github/token",
            post(handlers::credentials::get_github_token),
        )
        .layer(axum::middleware::from_fn_with_state(
            httpsig_resolver,
            vouch_httpsig::middleware::verify_signature::<httpsig::OAuthClientKeyResolver>,
        ));

    Ok(credential_routes
        .layer(rate_limit::build_credential_rate_limiter(
            &config.trusted_proxies,
        )?)
        .layer(DefaultBodyLimit::max(CREDENTIAL_BODY_LIMIT)))
}

/// Rate-limited general routes (SCIM, admin, authorize).
fn build_general_limited_routes(
    config: &config::ServerConfig,
) -> anyhow::Result<Router<Arc<AppState>>> {
    Ok(Router::new()
        .route(
            "/oauth/authorize",
            get(handlers::oidc::authorize).post(handlers::oidc::authorize_post),
        )
        // Org admin API (JSON, JWT Bearer auth)
        .route(
            "/api/v1/org/scim-tokens",
            get(handlers::admin::list_scim_tokens).post(handlers::admin::create_scim_token),
        )
        .route(
            "/api/v1/org/scim-tokens/{id}",
            delete(handlers::admin::delete_scim_token),
        )
        // CEL validation API (used by admin UI CEL playground)
        .route(
            "/api/v1/org/policies/validate",
            post(handlers::admin::validate_cel_api),
        )
        // SCIM 2.0 endpoints (RFC 7643/7644)
        .route(
            "/scim/v2/ServiceProviderConfig",
            get(handlers::scim::service_provider_config),
        )
        .route("/scim/v2/Schemas", get(handlers::scim::schemas))
        .route(
            "/scim/v2/ResourceTypes",
            get(handlers::scim::resource_types),
        )
        .route(
            "/scim/v2/Users",
            get(handlers::scim::list_users).post(handlers::scim::create_user),
        )
        .route(
            "/scim/v2/Users/{id}",
            get(handlers::scim::get_user)
                .patch(handlers::scim::patch_user)
                .delete(handlers::scim::delete_user),
        )
        .route(
            "/scim/v2/Groups",
            get(handlers::scim::list_groups).post(handlers::scim::create_group),
        )
        .route(
            "/scim/v2/Groups/{id}",
            get(handlers::scim::get_group)
                .patch(handlers::scim::patch_group)
                .delete(handlers::scim::delete_group),
        )
        .layer(rate_limit::build_general_rate_limiter(
            &config.trusted_proxies,
        )?)
        .layer(DefaultBodyLimit::max(SCIM_BODY_LIMIT)))
}

/// Build all API routes with CORS and cache headers.
fn build_api_routes(
    config: &config::ServerConfig,
    httpsig_resolver: Arc<httpsig::OAuthClientKeyResolver>,
) -> anyhow::Result<Router<Arc<AppState>>> {
    Ok(Router::new()
        // OIDC Provider endpoints
        .route(
            "/.well-known/openid-configuration",
            get(handlers::oidc::discovery),
        )
        // RFC 8414 Section 3: OAuth Authorization Server Metadata alias
        .route(
            "/.well-known/oauth-authorization-server",
            get(handlers::oidc::discovery),
        )
        .route("/oauth/jwks", get(handlers::oidc::jwks))
        // OIDC Core Section 5.3.1: UserInfo MUST support GET and POST
        .route(
            "/oauth/userinfo",
            get(handlers::oidc::userinfo).post(handlers::oidc::userinfo),
        )
        .route("/oauth/callback", get(handlers::enroll::oidc_callback))
        // Auth endpoints
        .route("/v1/auth/status", get(handlers::auth::status))
        // Merge rate-limited route groups
        .merge(build_rate_limited_routes(
            config,
            Arc::clone(&httpsig_resolver),
        )?)
        .merge(build_credential_routes(
            config,
            Arc::clone(&httpsig_resolver),
        )?)
        .merge(build_general_limited_routes(config)?)
        .merge(build_api_management_routes(config, httpsig_resolver)?)
        .merge(build_public_read_routes(config)?)
        .layer(security_headers::build_api_cors_layer())
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-cache, no-store, must-revalidate"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::PRAGMA,
            HeaderValue::from_static("no-cache"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::EXPIRES,
            HeaderValue::from_static("0"),
        )))
}

/// Rate-limited public read-only routes.
///
/// SSH CA public key, KRL, and GitHub credential status endpoints are
/// unauthenticated. Rate limiting prevents abuse and DoS.
fn build_public_read_routes(
    config: &config::ServerConfig,
) -> anyhow::Result<Router<Arc<AppState>>> {
    Ok(Router::new()
        .route(
            "/v1/credentials/ssh/ca",
            get(handlers::credentials::get_ssh_ca_public_key),
        )
        .route(
            "/v1/credentials/ssh/krl",
            get(handlers::credentials::get_ssh_krl),
        )
        .route(
            "/v1/credentials/ssh/krl/{serial}",
            get(handlers::credentials::check_ssh_revocation),
        )
        .route(
            "/v1/credentials/github/status",
            get(handlers::credentials::get_github_status),
        )
        .layer(rate_limit::build_general_rate_limiter(
            &config.trusted_proxies,
        )?))
}

/// Rate-limited API management routes.
///
/// Token operations, key management, integration config, webhook, and
/// application CRUD endpoints that need protection from abuse.
fn build_api_management_routes(
    config: &config::ServerConfig,
    httpsig_resolver: Arc<httpsig::OAuthClientKeyResolver>,
) -> anyhow::Result<Router<Arc<AppState>>> {
    // Key management routes use HTTP signature verification
    let key_mgmt_routes = Router::new()
        .route("/v1/keys", get(handlers::keys::list_keys))
        .route(
            "/v1/keys/{id}",
            patch(handlers::keys::rename_key).delete(handlers::keys::delete_key),
        )
        .layer(axum::middleware::from_fn_with_state(
            httpsig_resolver,
            vouch_httpsig::middleware::verify_signature::<httpsig::OAuthClientKeyResolver>,
        ));

    Ok(Router::new()
        // Token operations
        .route("/oauth/revoke", post(handlers::oidc::revoke))
        .route("/oauth/introspect", post(handlers::oidc::introspect))
        // Key management (authenticated API, with HTTP signature verification)
        .merge(key_mgmt_routes)
        // GitHub webhook API
        .route(
            "/api/webhooks/github",
            post(handlers::github::github_webhook).layer(DefaultBodyLimit::max(WEBHOOK_BODY_LIMIT)),
        )
        // Applications API (JSON)
        .route(
            "/api/v1/applications",
            get(handlers::applications::list_applications_api)
                .post(handlers::applications::create_application_api),
        )
        .route(
            "/api/v1/applications/{id}",
            get(handlers::applications::get_application_api)
                .patch(handlers::applications::update_application_api)
                .delete(handlers::applications::delete_application_api),
        )
        .route(
            "/api/v1/applications/{id}/secrets",
            get(handlers::applications::list_secrets_api)
                .post(handlers::applications::add_secret_api),
        )
        .route(
            "/api/v1/applications/{id}/secrets/{secret_id}",
            delete(handlers::applications::delete_secret_api),
        )
        .route(
            "/api/v1/applications/{id}/revoke",
            post(handlers::applications::revoke_tokens_api),
        )
        .layer(rate_limit::build_general_rate_limiter(
            &config.trusted_proxies,
        )?))
}

/// Rate-limited browser WebAuthn routes.
///
/// Login and enrollment WebAuthn endpoints generate server-side state per
/// challenge, so rate limiting prevents memory/storage exhaustion.
fn build_browser_auth_routes(
    config: &config::ServerConfig,
) -> anyhow::Result<Router<Arc<AppState>>> {
    Ok(Router::new()
        .route(
            "/login/webauthn/start",
            post(handlers::browser_login::browser_login_start),
        )
        .route(
            "/login/webauthn/complete",
            post(handlers::browser_login::browser_login_complete)
                .layer(DefaultBodyLimit::max(LOGIN_BODY_LIMIT)),
        )
        .route(
            "/enroll/webauthn/start",
            post(handlers::enroll::browser_register_start),
        )
        .route(
            "/enroll/webauthn/complete",
            post(handlers::enroll::browser_register_complete)
                .layer(DefaultBodyLimit::max(ENROLL_BODY_LIMIT)),
        )
        .layer(rate_limit::build_auth_rate_limiter(
            &config.trusted_proxies,
        )?))
}

/// Rate-limited admin member management routes.
fn build_admin_routes(config: &config::ServerConfig) -> anyhow::Result<Router<Arc<AppState>>> {
    Ok(Router::new()
        .route("/admin", get(handlers::admin::admin_members_page))
        .route(
            "/admin/members/{id}/promote",
            post(handlers::admin::promote_member),
        )
        .route(
            "/admin/members/{id}/demote",
            post(handlers::admin::demote_member),
        )
        .route(
            "/admin/members/{id}/deactivate",
            post(handlers::admin::deactivate_member),
        )
        .route(
            "/admin/members/{id}/activate",
            post(handlers::admin::activate_member),
        )
        .route(
            "/admin/members/{id}/revoke-credentials",
            post(handlers::admin::revoke_member_credentials),
        )
        .route(
            "/admin/members/{id}/remove",
            post(handlers::admin::remove_member),
        )
        .route("/admin/audit", get(handlers::admin::admin_audit_page))
        // Posture policy management UI
        .route("/admin/policies", get(handlers::admin::admin_policies_page))
        .route(
            "/admin/policies/preconfigured/{slug}/toggle",
            post(handlers::admin::toggle_preconfigured_policy),
        )
        .route(
            "/admin/policies/custom",
            post(handlers::admin::create_custom_policy),
        )
        .route(
            "/admin/policies/custom/{id}",
            post(handlers::admin::update_custom_policy),
        )
        .route(
            "/admin/policies/custom/{id}/delete",
            post(handlers::admin::delete_custom_policy),
        )
        .route(
            "/admin/policies/custom/{id}/toggle",
            post(handlers::admin::toggle_custom_policy),
        )
        // SCIM token management UI
        .route(
            "/admin/scim-tokens",
            get(handlers::admin::admin_scim_tokens_page)
                .post(handlers::admin::admin_create_scim_token),
        )
        .route(
            "/admin/scim-tokens/{id}/revoke",
            post(handlers::admin::admin_revoke_scim_token),
        )
        .layer(rate_limit::build_general_rate_limiter(
            &config.trusted_proxies,
        )?))
}

/// Readiness probe handler.
///
/// Checks database connectivity. Returns 200 if ready, 503 if not.
/// Used by Kubernetes readiness and startup probes.
async fn readiness_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.db.is_healthy().await {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({"status": "ready"}))),
        Err(e) => {
            tracing::warn!(error = %e, "Readiness check failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "status": "not_ready",
                    "reason": "database"
                })),
            )
        }
    }
}

/// Build all UI routes with UI CORS.
fn build_ui_routes(config: &config::ServerConfig) -> anyhow::Result<Router<Arc<AppState>>> {
    Ok(Router::new()
        // Landing page with smart routing
        .route("/", get(handlers::home::home_page))
        .route("/install", get(handlers::install::install_page))
        .route("/health", get(|| async { "ok" }))
        .route("/health/ready", get(readiness_handler))
        // Legal pages (redirect to vouch.sh)
        .route("/privacy", get(handlers::legal::privacy_page))
        .route("/terms", get(handlers::legal::terms_page))
        // Integrations page
        .route(
            "/integrations",
            get(handlers::integrations::integrations_page),
        )
        // Browser-based WebAuthn login (RFC 6749, RFC 9207, RFC 9700)
        .route("/login", get(handlers::browser_login::login_page))
        // Browser-based enrollment
        .route("/device", get(handlers::enroll::device_verify_page))
        .route("/device", post(handlers::enroll::device_verify_submit))
        // Direct enrollment (browser-only, no CLI required)
        .route("/enroll/start", get(handlers::enroll::direct_enroll_start))
        // Key management during enrollment (uses cookie for auth)
        .route("/enroll/keys", get(handlers::enroll::enroll_keys_page))
        .route("/logout", post(handlers::auth::logout))
        .route("/enroll/keys/api", get(handlers::enroll_keys::list_keys))
        .route(
            "/enroll/keys/{id}",
            patch(handlers::enroll_keys::rename_key).delete(handlers::enroll_keys::delete_key),
        )
        // GitHub App installation
        .route(
            "/github/connect",
            get(handlers::github::github_connect_page),
        )
        .route("/github/callback", get(handlers::github::github_callback))
        .route("/github/link", get(handlers::github::github_link_start))
        .route(
            "/github/reconnect",
            post(handlers::github::github_reconnect),
        )
        .route(
            "/github/success",
            get(handlers::github::github_success_page),
        )
        // OAuth Application Registration Portal
        .route(
            "/applications",
            get(handlers::applications::list_applications_page),
        )
        .route(
            "/applications/new",
            get(handlers::applications::create_application_page)
                .post(handlers::applications::create_application_form),
        )
        .route(
            "/applications/{id}",
            get(handlers::applications::detail_application_page)
                .post(handlers::applications::update_application_form),
        )
        .route(
            "/applications/{id}/delete",
            post(handlers::applications::delete_application_form),
        )
        .route(
            "/applications/{id}/secrets",
            post(handlers::applications::add_secret_form),
        )
        .route(
            "/applications/{id}/secrets/{secret_id}/delete",
            post(handlers::applications::delete_secret_form),
        )
        // SAML 2.0 SP endpoints
        .route(
            "/saml/acs",
            post(handlers::saml::acs).layer(DefaultBodyLimit::max(SAML_ACS_BODY_LIMIT)),
        )
        .route("/saml/metadata", get(handlers::saml::metadata))
        // Admin member management UI (rate-limited)
        .merge(build_admin_routes(config)?)
        // Rate-limited browser WebAuthn routes
        .merge(build_browser_auth_routes(config)?)
        // Static file serving for CSS, JS, and assets
        .route("/static/{*path}", get(static_assets::static_handler))
        // Browsers request /favicon.ico at the root path
        .route("/favicon.ico", get(static_assets::favicon_handler))
        .layer(security_headers::build_ui_cors_layer(config)))
}

/// Middleware that records HTTP request metrics (counter + duration histogram).
async fn metrics_middleware(req: Request<axum::body::Body>, next: Next) -> impl IntoResponse {
    let method = req.method().to_string();
    let path = req
        .extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());
    let start = std::time::Instant::now();

    let response = next.run(req).await;

    let duration = start.elapsed().as_secs_f64();
    let status = response.status().as_u16().to_string();
    let labels = [("method", method), ("path", path), ("status", status)];
    ::metrics::counter!("http_requests_total", &labels).increment(1);
    ::metrics::histogram!("http_request_duration_seconds", &labels[..2]).record(duration);

    response
}
