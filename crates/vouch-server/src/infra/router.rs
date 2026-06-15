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
    infra::{
        httpsig, metrics, rate_limit, request_id, resource_metadata, security_headers,
        static_assets,
    },
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

/// Build a rate limiter, or a no-op passthrough when certification test mode
/// is active (`VOUCH_CERTIFICATION_TEST_TOKEN` is set).
macro_rules! maybe_rate_limit {
    ($builder:path, $config:expr) => {
        tower::util::option_layer(if $config.certification_test_token.is_some() {
            None
        } else {
            Some($builder(&$config.trusted_proxies)?)
        })
    };
}

/// Format `SOURCE_DATE_EPOCH` (compile-time) as a date string for the banner.
fn build_date() -> String {
    option_env!("SOURCE_DATE_EPOCH")
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|&ts| ts > 0)
        .and_then(|ts| jiff::Timestamp::from_second(ts).ok())
        .map_or_else(
            || "dev".to_string(),
            |ts| ts.strftime("%Y-%m-%d").to_string(),
        )
}

/// Print an ASCII banner at server startup.
pub fn print_startup_banner() {
    #[expect(
        clippy::print_stdout,
        reason = "intentional banner output to stdout on server startup"
    )]
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
    let api_routes = build_api_routes(&state, config, Arc::clone(&httpsig_resolver))?;
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
    //
    // Activation is intentionally NOT gated on TLS or any other config: the
    // OpenID conformance suite drives this over HTTPS with self-signed certs,
    // so a TLS-based guard would break the very flow it exists for. The guard
    // is operational discipline plus the loud warning below.
    let certification_route = if let Some(ref _token) = config.certification_test_token {
        tracing::warn!(
            target: "security",
            "CERTIFICATION TEST MODE ENABLED — this is a login bypass and MUST \
             NOT run in production. It activates GET /certification/complete-login \
             (mints a session for a synthetic test user without FIDO2), DISABLES \
             global rate limiting, and relaxes the upstream-IdP requirement. \
             Unset VOUCH_CERTIFICATION_TEST_TOKEN outside conformance testing."
        );
        Router::new()
            .route(
                "/certification/complete-login",
                get(handlers::certification::complete_login),
            )
            .route(
                "/certification/deny-login",
                get(handlers::certification::deny_login),
            )
    } else {
        Router::new()
    };

    Ok(security_headers::apply_security_layers(
        api_routes
            .merge(ui_routes)
            .merge(metrics_route)
            .merge(certification_route),
        config,
        &state.idps,
    )?
    .layer(axum::middleware::from_fn(metrics_middleware))
    // Global request timeout: 30 seconds.
    .layer(TimeoutLayer::with_status_code(
        StatusCode::REQUEST_TIMEOUT,
        std::time::Duration::from_secs(30),
    ))
    .layer(DefaultBodyLimit::max(GLOBAL_BODY_LIMIT))
    .layer(request_id::propagate_request_id_layer())
    .layer(axum::middleware::from_fn(
        request_id::request_span_middleware,
    ))
    .layer(request_id::set_request_id_layer())
    .with_state(state))
}

/// Rate-limited auth/token routes.
///
/// These endpoints are brute-force targets so rate limiting is critical.
fn build_rate_limited_routes(
    state: &Arc<AppState>,
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

    // RFC 7592 dynamic client registration MANAGEMENT endpoints
    // (`GET/PUT/DELETE /oauth/register/{client_id}`) accept a
    // registration access token and are therefore OAuth 2.0 protected
    // resources. They get the RFC 9728 `resource_metadata` middleware.
    //
    // The sibling `POST /oauth/register` is an UNAUTHENTICATED RFC 7591
    // endpoint — a 401 there would be a parameter-validation error,
    // not a missing-credential error, and adding `resource_metadata`
    // would mislead clients. We register it outside the wrapped
    // sub-router below.
    let registration_management_routes = Router::new()
        .route(
            "/oauth/register/{client_id}",
            get(handlers::oidc::read_client)
                .put(handlers::oidc::update_client)
                .delete(handlers::oidc::delete_client),
        )
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(state),
            resource_metadata::layer,
        ));

    Ok(Router::new()
        .merge(key_routes)
        .merge(registration_management_routes)
        // Unauthenticated dynamic client registration (RFC 7591).
        .route("/oauth/register", post(handlers::oidc::register))
        .route("/oauth/token", post(handlers::oidc::token))
        .route("/oauth/par", post(handlers::oidc::par))
        .route(
            "/oauth/fido2/challenge",
            post(handlers::oidc::fido2_challenge),
        )
        .route("/oauth/device", post(handlers::device::device_code))
        .layer(maybe_rate_limit!(
            rate_limit::build_auth_rate_limiter,
            config
        )))
}

/// Rate-limited credential issuance routes.
///
/// These are all OAuth 2.0 protected resources (RFC 9728). The
/// `resource_metadata` middleware attaches the RFC 9728 pointer to
/// any 401 `WWW-Authenticate` header so unauthenticated callers
/// discover the metadata document.
fn build_credential_routes(
    state: &Arc<AppState>,
    config: &config::ServerConfig,
    httpsig_resolver: Arc<httpsig::OAuthClientKeyResolver>,
) -> anyhow::Result<Router<Arc<AppState>>> {
    // Credential routes with HTTP signature verification.
    // Layer order (outside→inside): rate_limit → body_limit →
    //     resource_metadata → httpsig → handler
    // Rate limiting runs first to reject DoS before signature verification.
    // The RFC 9728 middleware wraps the signature middleware so that
    // when either the signature check or the handler returns 401, the
    // response gets a `resource_metadata` parameter.
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
            "/v1/credentials/github/token",
            post(handlers::credentials::get_github_token),
        )
        .layer(axum::middleware::from_fn_with_state(
            httpsig_resolver,
            vouch_httpsig::middleware::verify_signature::<httpsig::OAuthClientKeyResolver>,
        ))
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(state),
            resource_metadata::layer,
        ));

    Ok(credential_routes
        .layer(maybe_rate_limit!(
            rate_limit::build_credential_rate_limiter,
            config
        ))
        .layer(DefaultBodyLimit::max(CREDENTIAL_BODY_LIMIT)))
}

/// Rate-limited general routes (SCIM, admin API, authorize).
///
/// `/api/v1/org/*` and `/scim/v2/*` are OAuth 2.0 protected resources
/// and get the RFC 9728 `resource_metadata` middleware. `/oauth/authorize`
/// is the AS authorization endpoint (not a resource) and therefore
/// stays outside the wrapped group.
fn build_general_limited_routes(
    state: &Arc<AppState>,
    config: &config::ServerConfig,
) -> anyhow::Result<Router<Arc<AppState>>> {
    let protected_api_routes = Router::new()
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
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(state),
            resource_metadata::layer,
        ));

    Ok(Router::new()
        .route(
            "/oauth/authorize",
            get(handlers::oidc::authorize).post(handlers::oidc::authorize_post),
        )
        .merge(protected_api_routes)
        .layer(maybe_rate_limit!(
            rate_limit::build_general_rate_limiter,
            config
        ))
        .layer(DefaultBodyLimit::max(SCIM_BODY_LIMIT)))
}

/// Build all API routes with CORS and cache headers.
///
/// `state` is borrowed; the sub-router builders that need to layer
/// `resource_metadata::layer` clone the `Arc` once internally rather
/// than at every call site here.
fn build_api_routes(
    state: &Arc<AppState>,
    config: &config::ServerConfig,
    httpsig_resolver: Arc<httpsig::OAuthClientKeyResolver>,
) -> anyhow::Result<Router<Arc<AppState>>> {
    // OAuth 2.0 protected resource: UserInfo endpoint (RFC 9728 §5.2 +
    // RFC 6750 §3). The `resource_metadata` middleware appends the
    // RFC 9728 pointer to any 401 `WWW-Authenticate` header produced
    // by the handler.
    let userinfo_routes = Router::new()
        // OIDC Core Section 5.3.1: UserInfo MUST support GET and POST.
        .route(
            "/oauth/userinfo",
            get(handlers::oidc::userinfo).post(handlers::oidc::userinfo),
        )
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(state),
            resource_metadata::layer,
        ));

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
        // RFC 9728 §3.1: OAuth 2.0 Protected Resource Metadata.
        // Root document plus the path-insertion form for per-resource
        // metadata. The wildcard variant is a separate route and does
        // NOT shadow the sibling well-known URLs above (axum 0.8 route
        // matcher prefers literal routes over wildcards).
        .route(
            "/.well-known/oauth-protected-resource",
            get(handlers::oidc::protected_resource_metadata_root),
        )
        .route(
            "/.well-known/oauth-protected-resource/{*path}",
            get(handlers::oidc::protected_resource_metadata_subpath),
        )
        .route("/oauth/jwks", get(handlers::oidc::jwks))
        .merge(userinfo_routes)
        .route("/oauth/callback", get(handlers::enroll::oidc_callback))
        // Auth endpoints
        .route("/v1/auth/status", get(handlers::auth::status))
        // Merge rate-limited route groups
        .merge(build_rate_limited_routes(
            state,
            config,
            Arc::clone(&httpsig_resolver),
        )?)
        .merge(build_credential_routes(
            state,
            config,
            Arc::clone(&httpsig_resolver),
        )?)
        .merge(build_general_limited_routes(state, config)?)
        .merge(build_api_management_routes(
            state,
            config,
            httpsig_resolver,
        )?)
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
        .layer(maybe_rate_limit!(
            rate_limit::build_general_rate_limiter,
            config
        )))
}

/// Rate-limited API management routes.
///
/// Token operations, key management, integration config, webhook, and
/// application CRUD endpoints that need protection from abuse.
///
/// `/oauth/introspect` and the key/application CRUD endpoints are
/// OAuth 2.0 protected resources and get the RFC 9728
/// `resource_metadata` middleware. `/oauth/revoke` is an AS endpoint
/// (not a resource server endpoint per RFC 7009) and is excluded.
/// The GitHub webhook is not an OAuth resource and is excluded.
fn build_api_management_routes(
    state: &Arc<AppState>,
    config: &config::ServerConfig,
    httpsig_resolver: Arc<httpsig::OAuthClientKeyResolver>,
) -> anyhow::Result<Router<Arc<AppState>>> {
    // Key management routes use HTTP signature verification.
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

    // RFC 9728 protected-resource endpoints in this group. Layered with
    // the `resource_metadata` middleware at the inner-most level so
    // the 401 `WWW-Authenticate` injection runs before the outer rate
    // limiter.
    let protected_routes = Router::new()
        .route("/oauth/introspect", post(handlers::oidc::introspect))
        // Key management (authenticated API, with HTTP signature verification)
        .merge(key_mgmt_routes)
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
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(state),
            resource_metadata::layer,
        ));

    Ok(Router::new()
        // Token revocation (AS endpoint per RFC 7009 — not a resource)
        .route("/oauth/revoke", post(handlers::oidc::revoke))
        // GitHub webhook (HMAC-authenticated, not OAuth)
        .route(
            "/api/webhooks/github",
            post(handlers::github::github_webhook).layer(DefaultBodyLimit::max(WEBHOOK_BODY_LIMIT)),
        )
        .merge(protected_routes)
        .layer(maybe_rate_limit!(
            rate_limit::build_general_rate_limiter,
            config
        )))
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
        .layer(maybe_rate_limit!(
            rate_limit::build_auth_rate_limiter,
            config
        )))
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
        // Email domain management UI
        .route(
            "/admin/domains",
            get(handlers::admin::admin_domains_page).post(handlers::admin::admin_add_domain),
        )
        .route(
            "/admin/domains/{domain}/verify",
            post(handlers::admin::admin_verify_domain),
        )
        .route(
            "/admin/domains/{domain}/remove",
            post(handlers::admin::admin_remove_domain),
        )
        .layer(maybe_rate_limit!(
            rate_limit::build_general_rate_limiter,
            config
        )))
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
        // Client-side translation bundle (CSP script-src 'self'); cached via ETag.
        .route("/i18n.js", get(crate::infra::i18n::i18n_js_handler))
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
        // Rename is a browser form POST (server-rendered, redirects back),
        // matching the admin pages' form-POST CRUD pattern.
        .route(
            "/enroll/keys/{id}/rename",
            post(handlers::enroll_keys::rename_key_form),
        )
        .route(
            "/enroll/keys/{id}",
            delete(handlers::enroll_keys::delete_key),
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
        // Install request-scoped i18n: every UI request negotiates a locale
        // via the Accept-Language header and templates pick it up through
        // `PageContext::current()`, so adding a new language is just dropping
        // an `i18n/<tag>/vouch.ftl` catalog.
        .layer(axum::middleware::from_fn(crate::infra::i18n::i18n_layer))
        .layer(security_headers::build_ui_cors_layer(config)))
}

/// Middleware that records HTTP request metrics (counter + duration histogram).
async fn metrics_middleware(req: Request<axum::body::Body>, next: Next) -> impl IntoResponse {
    let method = req.method().to_string();
    let path = req
        .extensions()
        .get::<MatchedPath>()
        .map_or_else(|| req.uri().path().to_string(), |p| p.as_str().to_string());
    let start = std::time::Instant::now();

    let response = next.run(req).await;

    let duration = start.elapsed().as_secs_f64();
    let status = response.status().as_u16().to_string();
    let labels = [("method", method), ("path", path), ("status", status)];
    ::metrics::counter!("http_requests_total", &labels).increment(1);
    ::metrics::histogram!("http_request_duration_seconds", &labels[..2]).record(duration);

    response
}
