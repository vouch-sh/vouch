// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Authorization endpoint handler.
//!
//! Implements RFC 6749 Section 4.1 (Authorization Code Grant) with extensions:
//! - RFC 7636 (PKCE)
//! - RFC 9207 (Authorization Server Issuer Identification)
//! - RFC 9700 (OAuth 2.0 Security Best Current Practice)

use super::{
    build_authorization_success_redirect_url, build_jarm_redirect_url,
    build_redirect_url_with_params,
};
use crate::AppState;
use crate::db::ResponseMode;
use crate::db::{self, Authenticator, CreatePendingOAuthParams, OAuthClient, Session, User};
use crate::impl_template_response;
use crate::services::oidc::ScopeSet;
use crate::services::oidc::authorization::{
    AuthorizationCodeParams, AuthorizationSessionState, AuthorizeRequestParams,
    CodeChallengeMethod, Prompt, ValidatedAuthRequest, check_client_access,
    check_session_for_authorization, issue_authorization_code, require_pkce_for_client,
    validate_authorize_request,
};
use crate::services::oidc::jar::{QueryParamHints, fetch_request_object, validate_request_object};
use askama::Template;
use axum::{
    Form,
    extract::{Query, State},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use std::sync::Arc;

/// Access denied error template.
#[derive(Template)]
#[template(path = "authorize_denied.html")]
pub(super) struct AuthorizeDeniedTemplate {
    pub client_name: String,
    pub error_message: String,
}

impl_template_response!(AuthorizeDeniedTemplate);

/// OAuth 2.0 Form Post Response Mode template.
///
/// Delivers authorization response parameters via an HTML form that auto-submits
/// to the redirect_uri using POST. JavaScript is required; a fallback button is
/// shown when JS is disabled.
#[derive(Template)]
#[template(path = "form_post_response.html")]
struct FormPostResponseTemplate {
    redirect_uri: String,
    params: Vec<(String, String)>,
}

impl_template_response!(FormPostResponseTemplate);

/// Authorization request query parameters (RFC 6749 Section 4.1.1).
#[derive(Debug, Deserialize)]
pub(crate) struct AuthorizeQuery {
    /// RFC 6749 Section 4.1.1: Response type (must be "code").
    response_type: Option<String>,
    /// RFC 6749 Section 4.1.1: Client identifier.
    client_id: Option<String>,
    /// RFC 6749 Section 4.1.1: Redirect URI for the response.
    redirect_uri: Option<String>,
    /// RFC 6749 Section 3.3: Requested scope.
    scope: Option<String>,
    /// RFC 6749 Section 4.1.1: State parameter (opaque, returned unchanged).
    state: Option<String>,
    /// OIDC Core Section 3.1.2.1: Nonce value.
    nonce: Option<String>,
    /// RFC 7636 Section 4.2: PKCE code challenge.
    code_challenge: Option<String>,
    /// RFC 7636 Section 4.3: PKCE code challenge method.
    code_challenge_method: Option<String>,
    /// Pending OAuth authorization ID (when returning from login).
    pending_auth: Option<String>,
    /// RFC 8707 Section 2: Target resource indicator.
    #[serde(default)]
    resource: Option<String>,
    /// RFC 9470: Requested authentication context class references.
    #[serde(default)]
    acr_values: Option<String>,
    /// RFC 9470 / OIDC Core Section 3.1.2.1: Maximum authentication age in seconds.
    #[serde(default)]
    max_age: Option<u64>,
    /// OIDC Core Section 3.1.2.1: Requested prompt behavior.
    #[serde(default)]
    prompt: Option<String>,
    /// RFC 9126: Pushed Authorization Request URI.
    #[serde(default)]
    request_uri: Option<String>,
    /// RFC 9101: JWT-Secured Authorization Request (Request Object).
    #[serde(default)]
    request: Option<String>,
    /// RFC 9449 Section 10: DPoP JWK thumbprint for authorization code binding.
    #[serde(default)]
    dpop_jkt: Option<String>,
    /// RFC 9396: Rich authorization details (JSON string).
    #[serde(default)]
    authorization_details: Option<String>,
    /// JARM (oauth-v2-jarm): Requested authorization response mode.
    #[serde(default)]
    response_mode: Option<String>,
}

// ---------------------------------------------------------------------------
// Security gate types
// ---------------------------------------------------------------------------

/// Security gate: client lookup + active check + redirect_uri validation have
/// all passed. No redirect-based error may be produced before this exists.
///
/// **Phase A (errors → error page, never redirect):**
/// 1. Client lookup
/// 2. Active check
/// 3. redirect_uri validation against registered URIs
///
/// Both constructors return `Result<Self, Response>` where `Err` is always an
/// error *page* response (never a redirect to an unvalidated URI).
struct ResolvedClient {
    client: OAuthClient,
    redirect_uri: String,
    response_mode: ResponseMode,
}

impl ResolvedClient {
    /// Full Phase A pipeline: DB lookup + active check + redirect_uri validation.
    ///
    /// Used for Direct, PAR, and pending_auth flows.
    async fn resolve(
        state: &Arc<AppState>,
        client_id: &str,
        redirect_uri_param: Option<&str>,
        response_mode_param: Option<&str>,
    ) -> Result<Self, Response> {
        let client = lookup_and_check_active(state, client_id).await?;

        let redirect_uri = resolve_redirect_uri(redirect_uri_param, &client)?;

        let response_mode = response_mode_param
            .and_then(ResponseMode::parse)
            .unwrap_or(ResponseMode::Query);

        Ok(Self {
            client,
            redirect_uri,
            response_mode,
        })
    }

    /// Phase A using a pre-loaded client: validates redirect_uri only.
    ///
    /// Used for JAR and request_uri_fetch flows, where the client must be
    /// loaded before JWT verification. The client has already been through
    /// `lookup_and_check_active`.
    #[expect(
        clippy::result_large_err,
        reason = "Err is an HTTP Response; size is acceptable in error path"
    )]
    fn from_validated_client(
        client: OAuthClient,
        redirect_uri: String,
        response_mode: ResponseMode,
    ) -> Result<Self, Response> {
        if !client.is_valid_redirect_uri(&redirect_uri) {
            tracing::warn!(
                client_id = %client.client_id,
                %redirect_uri,
                registered = ?client.redirect_uris,
                "redirect_uri not registered for client"
            );
            let resp = AuthorizeDeniedTemplate {
                client_name: client.name,
                error_message: "Invalid redirect_uri: not registered for this application"
                    .to_string(),
            }
            .into_response();
            return Err(resp);
        }
        Ok(Self {
            client,
            redirect_uri,
            response_mode,
        })
    }

    /// Produce a redirect-based OAuth error using the validated redirect_uri.
    ///
    /// This is the only path to produce a redirect error — the `ResolvedClient`
    /// guarantees the URI is safe to redirect to.
    async fn error_redirect(
        &self,
        state: &Arc<AppState>,
        error: &str,
        description: &str,
        oauth_state: Option<&str>,
    ) -> Response {
        oauth_error_response(
            state,
            &self.client,
            &self.redirect_uri,
            error,
            description,
            oauth_state,
            self.response_mode,
        )
        .await
    }
}

/// Which authorization flow is in use, for `run_security_pipeline()` parameterization.
enum AuthFlowKind {
    /// Normal query-parameter flow: all checks apply.
    Direct,
    /// JWT-Secured Authorization Request (RFC 9101): signed_request_object inherently satisfied.
    Jar,
    /// Pushed Authorization Request (RFC 9126): PAR requirement and signed_request_object
    /// inherently satisfied.
    Par,
    /// Fetched HTTPS request_uri: signed_request_object inherently satisfied.
    RequestUriFetch,
}

// ---------------------------------------------------------------------------
// Shared security pipeline (Phase B)
// ---------------------------------------------------------------------------

/// Run Phase B security checks: PKCE + FAPI + signed-request-object.
///
/// All errors redirect to the validated `resolved.redirect_uri`. Returns `Ok(())`
/// if all checks pass, or `Err(Response)` on the first failure.
async fn run_security_pipeline(
    state: &Arc<AppState>,
    validated: &ValidatedAuthRequest,
    resolved: &ResolvedClient,
    flow: &AuthFlowKind,
) -> Result<(), Response> {
    // PKCE: required for public clients and Native/SPA types (RFC 9700).
    if let Err(e) = require_pkce_for_client(validated, &resolved.client) {
        let description = match &e {
            crate::error::ServiceError::OAuth { description, .. } => description.clone(),
            _ => e.to_string(),
        };
        return Err(resolved
            .error_redirect(state, "invalid_request", &description, validated.state())
            .await);
    }

    // FAPI PAR requirement: skip only for PAR flows (already satisfied).
    if !matches!(flow, AuthFlowKind::Par)
        && let Err(e) = crate::services::oidc::fapi::validate_fapi_authorization_request(
            &resolved.client,
            false,
        )
    {
        let description = match &e {
            crate::error::ServiceError::OAuth { description, .. } => description.clone(),
            _ => e.to_string(),
        };
        return Err(resolved
            .error_redirect(state, "invalid_request", &description, validated.state())
            .await);
    }

    // require_signed_request_object: skip for JAR, PAR, and request_uri_fetch
    // (all three inherently provide a signed request object or satisfy PAR).
    if matches!(flow, AuthFlowKind::Direct)
        && resolved.client.require_signed_request_object == Some(true)
    {
        return Err(resolved
            .error_redirect(
                state,
                "invalid_request",
                "This client requires a signed Request Object (RFC 9101)",
                validated.state(),
            )
            .await);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Shared session check + dispatch (Phase C)
// ---------------------------------------------------------------------------

/// Check session and dispatch to authorization or pending-login.
///
/// Called after Phase A + Phase B have both succeeded.
async fn check_session_and_authorize(
    state: &Arc<AppState>,
    resolved: &ResolvedClient,
    validated: ValidatedAuthRequest,
    jar: &CookieJar,
    reauth_policy: ReauthPolicy,
    par_to_consume: Option<(&str, &str)>,
) -> Response {
    let session_token = jar
        .get(vouch_common::SESSION_COOKIE_NAME)
        .map(|c| c.value());

    match check_session_for_authorization(state, session_token).await {
        Ok(AuthorizationSessionState::Authenticated {
            user,
            session: ref auth_session,
            authenticator,
        }) => {
            authorize_authenticated_user(
                state,
                validated,
                &resolved.client,
                &user,
                auth_session,
                &authenticator,
                reauth_policy,
                par_to_consume,
                resolved.response_mode,
            )
            .await
        }
        Ok(AuthorizationSessionState::NeedsAuth) | Err(_) => {
            if validated.prompt() == Some(Prompt::Silent) {
                return resolved
                    .error_redirect(
                        state,
                        "login_required",
                        "User is not authenticated and prompt=none was requested",
                        validated.state(),
                    )
                    .await;
            }
            store_pending_and_redirect(
                state,
                validated,
                resolved.response_mode,
                None,
                par_to_consume.map(|(uri, _)| uri),
            )
            .await
        }
    }
}

// ---------------------------------------------------------------------------
// Handler entry points
// ---------------------------------------------------------------------------

/// GET /oauth/authorize
///
/// Authorization endpoint - redirects user to login if not authenticated,
/// then issues an authorization code to the redirect_uri.
///
/// ## Flow
///
/// 1. Client redirects user to this endpoint with OAuth parameters
/// 2. If user is not authenticated:
///    a. Store OAuth parameters in `pending_oauth_authorizations` table
///    b. Redirect to `/login?pending_auth=<id>`
/// 3. After user authenticates at `/login`:
///    a. User is redirected back here with `pending_auth` parameter
///    b. Retrieve stored OAuth parameters
///    c. Issue authorization code and redirect to client
///
/// ## RFC Compliance
///
/// - RFC 6749: Authorization Code Grant
/// - RFC 7636: PKCE support
/// - RFC 9207: Includes `iss` parameter in response
/// - RFC 9700: Follows OAuth 2.0 Security BCP
pub(crate) async fn authorize(
    State(state): State<Arc<AppState>>,
    Query(params): Query<AuthorizeQuery>,
    jar: CookieJar,
) -> Response {
    authorize_inner(state, params, jar).await
}

/// Shared authorization logic for both GET and POST.
async fn authorize_inner(state: Arc<AppState>, params: AuthorizeQuery, jar: CookieJar) -> Response {
    // Check if we're returning from login with a pending auth
    if let Some(pending_id) = &params.pending_auth {
        return handle_pending_auth(&state, pending_id, &jar).await;
    }

    // RFC 9101 + RFC 9126: Mutual exclusion — cannot provide both request and request_uri
    if params.request.is_some() && params.request_uri.is_some() {
        return AuthorizeDeniedTemplate {
            client_name: "Unknown Application".to_string(),
            error_message:
                "Invalid request: 'request' and 'request_uri' parameters are mutually exclusive"
                    .to_string(),
        }
        .into_response();
    }

    // RFC 9101: If request parameter is present, validate the Request Object JWT.
    if let Some(ref request_jwt) = params.request {
        let client_id = params.client_id.clone().unwrap_or_default();
        if client_id.is_empty() {
            return AuthorizeDeniedTemplate {
                client_name: "Unknown Application".to_string(),
                error_message: "Invalid request: client_id is required with request parameter"
                    .to_string(),
            }
            .into_response();
        }

        return handle_jar_request(&state, request_jwt, &client_id, &params, jar).await;
    }

    // RFC 9126 / OIDC Core Section 6.2: If request_uri is present, dispatch by scheme.
    if let Some(ref request_uri) = params.request_uri {
        let client_id = params.client_id.clone().unwrap_or_default();
        if client_id.is_empty() {
            return AuthorizeDeniedTemplate {
                client_name: "Unknown Application".to_string(),
                error_message: "Invalid request: client_id is required with request_uri"
                    .to_string(),
            }
            .into_response();
        }

        if request_uri.starts_with("urn:ietf:params:oauth:request_uri:") {
            // RFC 9126: PAR URN — must be reasonably sized.
            if request_uri.len() > 256 {
                return AuthorizeDeniedTemplate {
                    client_name: "Unknown Application".to_string(),
                    error_message: "Invalid request_uri format".to_string(),
                }
                .into_response();
            }
            return handle_par_request(
                &state,
                request_uri,
                &client_id,
                params.redirect_uri.as_deref(),
                jar,
            )
            .await;
        }

        if request_uri.starts_with("https://") {
            // OIDC Core Section 6.2: HTTPS URL — fetch the Request Object JWT.
            return handle_request_uri_fetch(&state, request_uri, &client_id, &params, jar).await;
        }

        // Neither a PAR URN nor an HTTPS URL.
        return AuthorizeDeniedTemplate {
            client_name: "Unknown Application".to_string(),
            error_message: "Invalid request_uri: must be a PAR URN or an HTTPS URL".to_string(),
        }
        .into_response();
    }

    // Normal direct authorization request.
    handle_direct_request(&state, params, jar).await
}

/// POST /oauth/authorize
///
/// RFC 6749 Section 3.1: The authorization endpoint MAY support POST.
/// Accepts `application/x-www-form-urlencoded` parameters and delegates
/// to the same logic as the GET handler.
pub(crate) async fn authorize_post(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Form(params): Form<AuthorizeQuery>,
) -> Response {
    authorize_inner(state, params, jar).await
}

// ---------------------------------------------------------------------------
// Flow handlers
// ---------------------------------------------------------------------------

/// Handle a direct (query-parameter only) authorization request.
///
/// Phase A: resolve client + validate redirect_uri (errors → error page).
/// Phase B: PKCE + FAPI + signed-request-object (errors → redirect).
/// Phase C: session check + code issuance.
async fn handle_direct_request(
    state: &Arc<AppState>,
    params: AuthorizeQuery,
    jar: CookieJar,
) -> Response {
    let client_id = params.client_id.clone().unwrap_or_default();
    if client_id.is_empty() {
        return AuthorizeDeniedTemplate {
            client_name: "Unknown Application".to_string(),
            error_message: "Invalid request: client_id is required".to_string(),
        }
        .into_response();
    }

    // Phase A: client lookup + active + redirect_uri validation (errors → page).
    let resolved = match ResolvedClient::resolve(
        state,
        &client_id,
        params.redirect_uri.as_deref(),
        params.response_mode.as_deref(),
    )
    .await
    {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    // Validate prompt before constructing params — reject unsupported values.
    let parsed_prompt = match params.prompt.as_deref() {
        Some(p) => match Prompt::parse(p) {
            Some(prompt) => Some(prompt),
            None => {
                return resolved
                    .error_redirect(
                        state,
                        "invalid_request",
                        "Unsupported prompt value. Supported values: login, none, consent",
                        params.state.as_deref(),
                    )
                    .await;
            }
        },
        None => None,
    };

    let request_params = AuthorizeRequestParams {
        response_type: params.response_type.unwrap_or_default(),
        client_id: client_id.clone(),
        redirect_uri: resolved.redirect_uri.clone(),
        scope: params.scope.clone(),
        state: params.state.clone(),
        nonce: params.nonce.clone(),
        code_challenge: params.code_challenge.clone(),
        code_challenge_method: params.code_challenge_method.clone(),
        resource: params.resource.clone(),
        acr_values: params.acr_values.clone(),
        max_age: params.max_age,
        prompt: parsed_prompt,
        dpop_jkt: params.dpop_jkt.clone(),
        authorization_details: params.authorization_details.clone(),
        response_mode: None,
    };

    let validated = match validate_authorize_request(request_params) {
        Ok(v) => v,
        Err(e) => {
            let (error_code, description) = match &e {
                crate::error::ServiceError::OAuth { code, description } => {
                    (code.as_str(), description.clone())
                }
                _ => ("server_error", e.to_string()),
            };
            return resolved
                .error_redirect(state, error_code, &description, params.state.as_deref())
                .await;
        }
    };

    // Phase B: PKCE + FAPI + signed-request-object (errors → redirect).
    if let Err(resp) =
        run_security_pipeline(state, &validated, &resolved, &AuthFlowKind::Direct).await
    {
        return resp;
    }

    // Phase C: session check + dispatch.
    check_session_and_authorize(
        state,
        &resolved,
        validated,
        &jar,
        ReauthPolicy::OnDemand,
        None,
    )
    .await
}

/// Handle an authorization request using a JWT-Secured Authorization Request (RFC 9101).
///
/// Phase A: lookup_and_check_active → validate_request_object → from_validated_client.
/// Phase B: run_security_pipeline (Jar kind — skips signed_request_object check).
/// Phase C: session check + code issuance.
async fn handle_jar_request(
    state: &Arc<AppState>,
    request_jwt: &str,
    client_id: &str,
    query: &AuthorizeQuery,
    jar: CookieJar,
) -> Response {
    // Phase A step 1: client lookup + active check (errors → page).
    let oauth_client = match lookup_and_check_active(state, client_id).await {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    // Phase A step 2: validate the Request Object JWT (client already loaded).
    let query_hints = QueryParamHints {
        client_id: Some(client_id),
        response_type: query.response_type.as_deref(),
        scope: query.scope.as_deref(),
    };

    let request_params = match validate_request_object(
        state,
        request_jwt,
        &oauth_client,
        Some(&query_hints),
    )
    .await
    {
        Ok(params) => params,
        Err(e) => {
            let description = match &e {
                crate::error::ServiceError::OAuth { description, .. } => description.clone(),
                _ => e.to_string(),
            };
            return AuthorizeDeniedTemplate {
                client_name: oauth_client.name,
                error_message: format!("Invalid Request Object: {description}"),
            }
            .into_response();
        }
    };

    // Extract redirect_uri and response_mode from the Request Object.
    let redirect_uri = request_params.redirect_uri.clone();
    let jar_response_mode = request_params
        .response_mode
        .as_deref()
        .and_then(ResponseMode::parse)
        .unwrap_or(ResponseMode::Query);

    // Phase A step 3: validate redirect_uri against registered URIs (errors → page).
    let resolved = match ResolvedClient::from_validated_client(
        oauth_client,
        redirect_uri,
        jar_response_mode,
    ) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let validated = match validate_authorize_request(request_params) {
        Ok(v) => v,
        Err(e) => {
            let (error_code, description) = match &e {
                crate::error::ServiceError::OAuth { code, description } => {
                    (code.as_str(), description.clone())
                }
                _ => ("server_error", e.to_string()),
            };
            return resolved
                .error_redirect(state, error_code, &description, query.state.as_deref())
                .await;
        }
    };

    // Phase B: PKCE + FAPI PAR requirement (Jar kind — skips signed_request_object).
    if let Err(resp) = run_security_pipeline(state, &validated, &resolved, &AuthFlowKind::Jar).await
    {
        return resp;
    }

    // Phase C: session check + dispatch.
    check_session_and_authorize(
        state,
        &resolved,
        validated,
        &jar,
        ReauthPolicy::OnDemand,
        None,
    )
    .await
}

/// Look up a PAR record by request_uri and client_id.
///
/// Returns `Err(Response)` on failure:
/// - Not found / expired: redirect with error params when `fallback_redirect_uri` is
///   a *registered* URI for the client (OIDC conformance); error page otherwise.
/// - DB error: error page.
///
/// The fallback-redirect path validates `fallback_redirect_uri` against the client's
/// registered URIs before issuing any 302 (RFC 9126 §7.2, RFC 6749 §4.1.2.1).
async fn lookup_par(
    state: &Arc<AppState>,
    request_uri: &str,
    client_id: &str,
    fallback_redirect_uri: Option<&str>,
) -> Result<db::PushedAuthorizationRequest, Response> {
    match db::get_pushed_authorization_request(&state.store, request_uri, client_id).await {
        Ok(Some(p)) => Ok(p),
        Ok(None) => {
            tracing::warn!(
                request_uri,
                client_id,
                "PAR not found, expired, or wrong client"
            );
            // Only redirect when the fallback URI is registered for the client.
            // An unregistered URI is an open-redirect risk — serve the error page instead.
            if let Some(uri) = fallback_redirect_uri {
                match db::get_oauth_client_by_client_id(&state.store, client_id).await {
                    Ok(Some(client)) if client.is_valid_redirect_uri(uri) => {
                        if let Ok(mut redirect) = url::Url::parse(uri) {
                            {
                                let mut q = redirect.query_pairs_mut();
                                q.append_pair("error", "invalid_request_uri");
                                q.append_pair(
                                    "error_description",
                                    "Invalid or expired request_uri",
                                );
                                q.append_pair("iss", &state.config().base_url);
                            }
                            return Err(
                                axum::response::Redirect::to(redirect.as_str()).into_response()
                            );
                        }
                    }
                    Ok(Some(_)) => {
                        // URI not registered — fall through to error page.
                        tracing::warn!(
                            client_id,
                            redirect_uri = uri,
                            "fallback_redirect_uri is not registered; suppressing redirect \
                             to prevent open redirect"
                        );
                    }
                    Ok(None) | Err(_) => {
                        // Client not found or DB error — fall through to error page.
                    }
                }
            }
            Err(AuthorizeDeniedTemplate {
                client_name: "Unknown Application".to_string(),
                error_message:
                    "Invalid or expired request_uri. Please restart the authorization flow."
                        .to_string(),
            }
            .into_response())
        }
        Err(e) => {
            tracing::error!("Failed to look up PAR: {}", e);
            Err(AuthorizeDeniedTemplate {
                client_name: "Unknown Application".to_string(),
                error_message: "An error occurred. Please try again.".to_string(),
            }
            .into_response())
        }
    }
}

/// Handle an authorization request using a pushed authorization request URI (RFC 9126).
///
/// Phase A: consume PAR → resolve client (lookup + active + redirect_uri).
/// Phase B: run_security_pipeline (Par kind — skips FAPI PAR requirement + signed_request_object).
/// Phase C: session check + code issuance.
async fn handle_par_request(
    state: &Arc<AppState>,
    request_uri: &str,
    client_id: &str,
    fallback_redirect_uri: Option<&str>,
    jar: CookieJar,
) -> Response {
    // FAPI 2.0 Section 5.3.2.2 Note 3: Look up the PAR without consuming it.
    let par = match lookup_par(state, request_uri, client_id, fallback_redirect_uri).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };

    // Phase A: client lookup + active check + redirect_uri validation (errors → page).
    // Client lookup happens here (after PAR lookup) to catch deactivated clients.
    let resolved = match ResolvedClient::resolve(
        state,
        &par.client_id,
        Some(&par.redirect_uri),
        None, // PAR response_mode handled below
    )
    .await
    {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    // Build the ValidatedAuthRequest from PAR fields.
    let parsed_prompt = par.prompt.as_deref().and_then(Prompt::parse);
    let request_params = AuthorizeRequestParams {
        response_type: par.response_type.clone(),
        client_id: par.client_id.clone(),
        redirect_uri: par.redirect_uri.clone(),
        scope: par.scope.clone(),
        state: par.state.clone(),
        nonce: par.nonce.clone(),
        code_challenge: par.code_challenge.clone(),
        code_challenge_method: par.code_challenge_method.clone(),
        resource: par.resource.clone(),
        acr_values: par.acr_values.clone(),
        max_age: par.max_age.and_then(|v| u64::try_from(v).ok()),
        prompt: parsed_prompt,
        dpop_jkt: par.dpop_jkt.clone(),
        authorization_details: par
            .authorization_details
            .as_ref()
            .and_then(|v| serde_json::to_string(v).ok()),
        response_mode: None,
    };

    let validated = match validate_authorize_request(request_params) {
        Ok(v) => v,
        Err(e) => {
            let (error_code, description) = match &e {
                crate::error::ServiceError::OAuth { code, description } => {
                    (code.as_str(), description.clone())
                }
                _ => ("server_error", e.to_string()),
            };
            return resolved
                .error_redirect(state, error_code, &description, par.state.as_deref())
                .await;
        }
    };

    // Overlay the PAR response_mode (resolve() used None above).
    let resolved = ResolvedClient {
        client: resolved.client,
        redirect_uri: resolved.redirect_uri,
        response_mode: par.response_mode,
    };

    // Phase B: PKCE only (PAR kind skips FAPI PAR requirement + signed_request_object).
    if let Err(resp) = run_security_pipeline(state, &validated, &resolved, &AuthFlowKind::Par).await
    {
        return resp;
    }

    // Phase C: PAR always requires a fresh FIDO2 assertion (FAPI 2.0 Section 5.3.2.2 Note 3).
    check_session_and_authorize(
        state,
        &resolved,
        validated,
        &jar,
        ReauthPolicy::Always,
        Some((request_uri, client_id)),
    )
    .await
}

/// Handle an authorization request using an OIDC Core Section 6.2 `request_uri` URL.
///
/// Phase A: lookup_and_check_active → FAPI check → allowlist → fetch+validate JWT
///          → from_validated_client.
/// Phase B: run_security_pipeline (RequestUriFetch kind).
/// Phase C: session check + code issuance.
async fn handle_request_uri_fetch(
    state: &Arc<AppState>,
    request_uri: &str,
    client_id: &str,
    query: &AuthorizeQuery,
    jar: CookieJar,
) -> Response {
    // Phase A steps 1-6: lookup + FAPI + allowlist + fetch + validate + redirect_uri.
    let (resolved, request_params) =
        match fetch_and_resolve_request_uri(state, request_uri, client_id, query).await {
            Ok(pair) => pair,
            Err(resp) => return resp,
        };

    let validated = match validate_authorize_request(request_params) {
        Ok(v) => v,
        Err(e) => {
            let (error_code, description) = match &e {
                crate::error::ServiceError::OAuth { code, description } => {
                    (code.as_str(), description.clone())
                }
                _ => ("server_error", e.to_string()),
            };
            return resolved
                .error_redirect(state, error_code, &description, query.state.as_deref())
                .await;
        }
    };

    // Phase B: PKCE + FAPI PAR requirement (RequestUriFetch skips signed_request_object).
    if let Err(resp) =
        run_security_pipeline(state, &validated, &resolved, &AuthFlowKind::RequestUriFetch).await
    {
        return resp;
    }

    // Phase C: session check + dispatch.
    check_session_and_authorize(
        state,
        &resolved,
        validated,
        &jar,
        ReauthPolicy::OnDemand,
        None,
    )
    .await
}

/// Phase A steps 1-6 for the request_uri_fetch flow.
///
/// Performs: client lookup + active check, FAPI check, allowlist check,
/// fetch JWT, validate JWT, redirect_uri validation.
///
/// Returns `Ok((ResolvedClient, AuthorizeRequestParams))` on success,
/// or `Err(Response)` (always an error page) on failure.
async fn fetch_and_resolve_request_uri(
    state: &Arc<AppState>,
    request_uri: &str,
    client_id: &str,
    query: &AuthorizeQuery,
) -> Result<(ResolvedClient, AuthorizeRequestParams), Response> {
    // Step 1: client lookup + active check (errors → page).
    let oauth_client = lookup_and_check_active(state, client_id).await?;

    // Step 2: FAPI 2.0 clients must use PAR; URL request_uri is not permitted.
    if let Err(e) =
        crate::services::oidc::fapi::validate_fapi_authorization_request(&oauth_client, false)
    {
        let description = match &e {
            crate::error::ServiceError::OAuth { description, .. } => description.clone(),
            _ => e.to_string(),
        };
        return Err(AuthorizeDeniedTemplate {
            client_name: oauth_client.name,
            error_message: format!("Invalid request: {description}"),
        }
        .into_response());
    }

    // Step 3: allowlist check.
    if let Some(ref allowed) = oauth_client.request_uris
        && !allowed.iter().any(|u| u == request_uri)
    {
        return Err(AuthorizeDeniedTemplate {
            client_name: oauth_client.name,
            error_message: "Invalid request: request_uri is not registered for this client"
                .to_string(),
        }
        .into_response());
    }

    // Step 4: fetch the Request Object JWT from the URL.
    // Loopback request_uri destinations are permitted only in local development
    // (no TLS configured); private/link-local targets stay blocked.
    let allow_loopback = !state.config().tls_configured();
    let fetched_jwt =
        match fetch_request_object(request_uri, allow_loopback, &state.http_client).await {
            Ok(jwt) => jwt,
            Err(e) => {
                let description = match &e {
                    crate::error::ServiceError::OAuth { description, .. } => description.clone(),
                    _ => e.to_string(),
                };
                return Err(AuthorizeDeniedTemplate {
                    client_name: oauth_client.name,
                    error_message: format!("Failed to fetch Request Object: {description}"),
                }
                .into_response());
            }
        };

    // Step 5: validate the JWT.
    let query_hints = QueryParamHints {
        client_id: Some(client_id),
        response_type: query.response_type.as_deref(),
        scope: query.scope.as_deref(),
    };
    let request_params =
        match validate_request_object(state, &fetched_jwt, &oauth_client, Some(&query_hints)).await
        {
            Ok(params) => params,
            Err(e) => {
                let (error_code, description) = match &e {
                    crate::error::ServiceError::OAuth { code, description } => {
                        (code.as_str(), description.clone())
                    }
                    _ => ("invalid_request_object", e.to_string()),
                };
                return Err(AuthorizeDeniedTemplate {
                    client_name: oauth_client.name,
                    error_message: format!("Invalid Request Object ({error_code}): {description}"),
                }
                .into_response());
            }
        };

    // Step 6: extract redirect_uri and validate against registered URIs.
    let redirect_uri = request_params.redirect_uri.clone();
    let jar_response_mode = request_params
        .response_mode
        .as_deref()
        .and_then(ResponseMode::parse)
        .unwrap_or(ResponseMode::Query);
    let resolved =
        ResolvedClient::from_validated_client(oauth_client, redirect_uri, jar_response_mode)?;

    Ok((resolved, request_params))
}

/// Handle returning from login with a pending auth ID.
///
/// Phase A: consume pending → resolve client (lookup + active + redirect_uri re-validation).
/// Phase C: session check + max_age check + code issuance.
async fn handle_pending_auth(state: &Arc<AppState>, pending_id: &str, jar: &CookieJar) -> Response {
    // Consume the pending auth (single-use). The `_claim` witness is
    // bound to satisfy `#[must_use]`; downstream code uses `pending`
    // (the consumed record's data) directly.
    let (pending, _claim) =
        match db::consume_pending_oauth_authorization(&state.store, pending_id).await {
            Ok(pair) => pair,
            Err(db::claim::ClaimError::AlreadyConsumed) => {
                tracing::warn!(
                    pending_id,
                    "Pending OAuth authorization not found or expired"
                );
                return AuthorizeDeniedTemplate {
                    client_name: "Unknown Application".to_string(),
                    error_message: "Authorization session expired. Please try again.".to_string(),
                }
                .into_response();
            }
            Err(e) => {
                tracing::error!("Failed to retrieve pending OAuth authorization: {}", e);
                return AuthorizeDeniedTemplate {
                    client_name: "Unknown Application".to_string(),
                    error_message: "An error occurred. Please try again.".to_string(),
                }
                .into_response();
            }
        };

    // Phase A: re-validate client active + redirect_uri (errors → page).
    // This guards against the client being deactivated or redirect_uri removed
    // between when the pending auth was stored and when the user completed login.
    let resolved = match ResolvedClient::resolve(
        state,
        &pending.client_id,
        Some(&pending.redirect_uri),
        None, // response_mode set from pending record below
    )
    .await
    {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    // Overlay the pending record's response_mode.
    let resolved = ResolvedClient {
        client: resolved.client,
        redirect_uri: resolved.redirect_uri,
        response_mode: pending.response_mode,
    };

    // Get session from cookie (should exist after login).
    let session_token = jar
        .get(vouch_common::SESSION_COOKIE_NAME)
        .map(|c| c.value());

    let auth_code_lifetime: i64 =
        crate::services::oidc::fapi::auth_code_lifetime_seconds(&resolved.client);

    match check_session_for_authorization(state, session_token).await {
        Ok(AuthorizationSessionState::Authenticated {
            user,
            session: ref auth_session,
            authenticator,
        }) => {
            complete_pending_auth(
                state,
                &resolved,
                &pending,
                &user,
                auth_session,
                &authenticator,
                auth_code_lifetime,
            )
            .await
        }
        Ok(AuthorizationSessionState::NeedsAuth) | Err(_) => {
            tracing::warn!("User not authenticated after returning from login");
            AuthorizeDeniedTemplate {
                client_name: resolved.client.name.clone(),
                error_message: "Authentication failed. Please try again.".to_string(),
            }
            .into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Pending auth completion (extracted to keep handle_pending_auth under 100 lines)
// ---------------------------------------------------------------------------

/// Complete the pending auth flow: check access, check max_age, issue code.
async fn complete_pending_auth(
    state: &Arc<AppState>,
    resolved: &ResolvedClient,
    pending: &db::PendingOAuthAuthorization,
    user: &User,
    auth_session: &Session,
    authenticator: &Authenticator,
    auth_code_lifetime: i64,
) -> Response {
    // Check client access for the authenticated user.
    if let Err(e) = check_client_access(&resolved.client, user) {
        let error_message = match e {
            crate::error::ServiceError::OAuth { description, .. } => description,
            _ => "You don't have access to this application".to_string(),
        };
        return AuthorizeDeniedTemplate {
            client_name: resolved.client.name.clone(),
            error_message,
        }
        .into_response();
    }

    // Validate max_age: if the pending request specified max_age,
    // verify the session is not older than that threshold (RFC 9470).
    if let Some(max_age) = pending.max_age {
        let age_secs = jiff::Timestamp::now()
            .duration_since(auth_session.created_at)
            .as_secs()
            .max(0);
        let max_age_u64 = u64::try_from(max_age).unwrap_or(0);
        let age_u64 = u64::try_from(age_secs).unwrap_or(u64::MAX);
        if age_u64 >= max_age_u64 {
            return resolved
                .error_redirect(
                    state,
                    "login_required",
                    "Session exceeds requested max_age",
                    pending.state.as_deref(),
                )
                .await;
        }
    }

    if let Some(ref request_uri) = pending.par_request_uri {
        match db::consume_pushed_authorization_request(
            &state.store,
            request_uri,
            &pending.client_id,
            db::ParConsumptionMode::SkipExpiry,
        )
        .await
        {
            Ok(_claim) => {} // successfully consumed
            Err(db::claim::ClaimError::AlreadyConsumed) => {
                return resolved
                    .error_redirect(
                        state,
                        "invalid_request",
                        "The request_uri has already been used",
                        pending.state.as_deref(),
                    )
                    .await;
            }
            Err(e) => {
                tracing::error!("Failed to consume PAR at code issuance: {e}");
                return resolved
                    .error_redirect(
                        state,
                        "server_error",
                        "Failed to process pushed authorization request",
                        pending.state.as_deref(),
                    )
                    .await;
            }
        }
    }

    let scope_set = ScopeSet::parse(pending.scope.as_deref().unwrap_or("openid"));
    let code_params = AuthorizationCodeParams {
        client_id: &pending.client_id,
        redirect_uri: &resolved.redirect_uri,
        user_id: &user.id,
        email: &user.email,
        authenticator_id: &authenticator.id,
        aaguid: authenticator.aaguid.as_deref(),
        scope: &scope_set,
        nonce: pending.nonce.as_deref(),
        code_challenge: pending.code_challenge.as_deref(),
        code_challenge_method: pending
            .code_challenge_method
            .as_deref()
            .and_then(CodeChallengeMethod::parse),
        resource: pending.resource.as_deref(),
        acr_values: pending.acr_values.as_deref(),
        dpop_jkt: pending.dpop_jkt.as_deref(),
        auth_code_lifetime_seconds: auth_code_lifetime,
        authorization_details: pending.authorization_details.as_ref(),
        auth_time: Some(auth_session.created_at.as_second()),
    };

    issue_code_and_redirect(
        state,
        code_params,
        &resolved.redirect_uri,
        pending.state.as_deref(),
        &resolved.client,
        resolved.response_mode,
    )
    .await
}

// ---------------------------------------------------------------------------
// Phase A helpers
// ---------------------------------------------------------------------------

/// Look up a client by client_id and verify it is active.
///
/// Returns `Err(Response)` with an error page on any failure.
async fn lookup_and_check_active(
    state: &Arc<AppState>,
    client_id: &str,
) -> Result<OAuthClient, Response> {
    let client = match db::get_oauth_client_by_client_id(&state.store, client_id).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return Err(AuthorizeDeniedTemplate {
                client_name: "Unknown Application".to_string(),
                error_message:
                    "Unknown client application. Please contact the application administrator."
                        .to_string(),
            }
            .into_response());
        }
        Err(_) => {
            return Err(AuthorizeDeniedTemplate {
                client_name: "Unknown Application".to_string(),
                error_message: "An error occurred. Please try again.".to_string(),
            }
            .into_response());
        }
    };

    if !client.active {
        return Err(AuthorizeDeniedTemplate {
            client_name: client.name,
            error_message: "This application has been deactivated.".to_string(),
        }
        .into_response());
    }

    Ok(client)
}

/// Resolve the redirect_uri from the request parameter or the client's single registered URI.
///
/// Returns `Err(Response)` with an error page when the URI cannot be determined.
#[expect(
    clippy::result_large_err,
    reason = "Err is an HTTP Response; size is acceptable in error path"
)]
fn resolve_redirect_uri(
    redirect_uri_param: Option<&str>,
    client: &OAuthClient,
) -> Result<String, Response> {
    match redirect_uri_param {
        Some(uri) if !uri.is_empty() => {
            if !client.is_valid_redirect_uri(uri) {
                tracing::warn!(
                    client_id = %client.client_id,
                    redirect_uri = %uri,
                    registered = ?client.redirect_uris,
                    "redirect_uri not registered for client"
                );
                return Err(AuthorizeDeniedTemplate {
                    client_name: client.name.clone(),
                    error_message: "Invalid redirect_uri: not registered for this application"
                        .to_string(),
                }
                .into_response());
            }
            Ok(uri.to_string())
        }
        _ if client.redirect_uris.len() == 1 => {
            // OIDC Core 3.1.2.1: auto-select when exactly one URI is registered.
            Ok(client.redirect_uris.first().cloned().unwrap_or_default())
        }
        _ => Err(AuthorizeDeniedTemplate {
            client_name: client.name.clone(),
            error_message: "Invalid request: redirect_uri is required when multiple \
                            redirect URIs are registered"
                .to_string(),
        }
        .into_response()),
    }
}

// ---------------------------------------------------------------------------
// Store pending and redirect to login
// ---------------------------------------------------------------------------

/// Store OAuth params in the database and redirect to login.
///
/// Used when the user needs to (re-)authenticate before authorization can proceed:
/// - No existing session
/// - `prompt=login` requested
/// - `max_age` exceeded (RFC 9470 step-up)
///
/// DPoP key binding is read from `validated.dpop_jkt()` so it survives the
/// browser login redirect regardless of how it entered the authorization flow
/// (direct query param, PAR record, or JAR claim).
async fn store_pending_and_redirect(
    state: &Arc<AppState>,
    validated: crate::services::oidc::authorization::ValidatedAuthRequest,
    response_mode: ResponseMode,
    prompt_override: Option<Prompt>,
    par_request_uri: Option<&str>,
) -> Response {
    // FAPI 2.0 Section 5.3.2.2 Note 3: Do NOT consume the PAR here.
    // The request_uri must remain valid until authorization completes (code issued).
    // Instead, store the PAR request_uri in the pending auth record so it can be
    // consumed when the authorization code is issued in complete_pending_auth.

    let scope_str = validated.scope().to_space_separated();
    let max_age_i64 = validated.max_age().and_then(|v| i64::try_from(v).ok());
    let ad_value = validated.authorization_details_value();
    let prompt_str = prompt_override
        .map(|p| p.as_str())
        .or_else(|| validated.prompt().map(|p| p.as_str()));
    let pending_params = CreatePendingOAuthParams {
        client_id: validated.client_id(),
        redirect_uri: validated.redirect_uri(),
        response_type: "code",
        state: validated.state(),
        scope: Some(&scope_str),
        nonce: validated.nonce(),
        code_challenge: validated.code_challenge(),
        code_challenge_method: validated.code_challenge_method().map(|m| m.as_str()),
        resource: validated.resource(),
        acr_values: validated.acr_values(),
        max_age: max_age_i64,
        prompt: prompt_str,
        dpop_jkt: validated.dpop_jkt(),
        authorization_details: ad_value.as_ref(),
        response_mode,
        par_request_uri,
    };

    match db::create_pending_oauth_authorization(&state.store, pending_params).await {
        Ok(pending_id) => {
            // Extend the PAR's TTL to match the pending-auth's 10-minute window so
            // that the cleanup job does not delete the PAR before login completes (#542).
            if let Some(uri) = par_request_uri
                && let Err(e) = db::extend_par_expiration(
                    &state.store,
                    uri,
                    validated.client_id(),
                    jiff::Span::new().minutes(10),
                )
                .await
            {
                tracing::warn!("Failed to extend PAR expiration for deferred flow: {e}");
                // Non-fatal: the deferred flow may still succeed if the PAR has not
                // yet expired.
            }
            Redirect::to(&format!(
                "/login?pending_auth={}",
                urlencoding::encode(&pending_id)
            ))
            .into_response()
        }
        Err(e) => {
            tracing::error!("Failed to create pending OAuth authorization: {}", e);
            // At this point the redirect_uri has been validated (ResolvedClient constructed),
            // so it is safe to redirect with the error. However we don't have the
            // ResolvedClient here — use a bare redirect as a best-effort fallback.
            build_authorization_redirect(
                validated.redirect_uri(),
                &[
                    ("error", "server_error"),
                    ("error_description", "Failed to initiate login"),
                    ("iss", &state.config().base_url),
                ],
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Re-authentication policy
// ---------------------------------------------------------------------------

/// Re-authentication policy for the authorization flow.
///
/// Controls whether an existing authenticated session is enough to proceed
/// directly to code issuance, or whether the user must authenticate again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReauthPolicy {
    /// Standard OAuth/OIDC flow: only re-auth when prompt=login or max_age exceeded.
    OnDemand,
    /// PAR/FAPI flow: always re-auth unless prompt=none (hardware presence per authorization).
    Always,
}

// ---------------------------------------------------------------------------
// Authenticated user handler
// ---------------------------------------------------------------------------

/// Handle the authenticated-user path common to all authorization flows.
///
/// Called after session validation confirms the user is authenticated. Checks
/// client access, applies the re-auth policy, validates ACR and resource, optionally
/// consumes a PAR record, and issues the authorization code.
#[expect(
    clippy::too_many_arguments,
    reason = "OAuth authorization for authenticated user requires full validated request context"
)]
async fn authorize_authenticated_user(
    state: &Arc<AppState>,
    validated: ValidatedAuthRequest,
    oauth_client: &OAuthClient,
    user: &User,
    auth_session: &Session,
    authenticator: &Authenticator,
    reauth_policy: ReauthPolicy,
    par_to_consume: Option<(&str, &str)>,
    response_mode: ResponseMode,
) -> Response {
    // Step 1: Check client access.
    if let Err(e) = check_client_access(oauth_client, user) {
        let error_message = match e {
            crate::error::ServiceError::OAuth { description, .. } => description,
            _ => "You don't have access to this application".to_string(),
        };
        return AuthorizeDeniedTemplate {
            client_name: oauth_client.name.clone(),
            error_message,
        }
        .into_response();
    }

    // Step 2: Determine whether re-authentication is required.
    let needs_reauth = match reauth_policy {
        ReauthPolicy::Always => validated.prompt() != Some(Prompt::Silent),
        ReauthPolicy::OnDemand => {
            validated.prompt() == Some(Prompt::Login)
                || validated.max_age().is_some_and(|max_age| {
                    let age_secs = jiff::Timestamp::now()
                        .duration_since(auth_session.created_at)
                        .as_secs()
                        .max(0);
                    let Ok(age) = u64::try_from(age_secs) else {
                        return true;
                    };
                    age >= max_age
                })
        }
    };

    // Step 3: prompt=none + re-auth needed → error (cannot show UI).
    if needs_reauth && validated.prompt() == Some(Prompt::Silent) {
        return oauth_error_response(
            state,
            oauth_client,
            validated.redirect_uri(),
            "login_required",
            "Re-authentication required but prompt=none was requested",
            validated.state(),
            response_mode,
        )
        .await;
    }

    // Step 4: Re-auth needed — store pending request and redirect to login.
    if needs_reauth {
        return store_pending_and_redirect(
            state,
            validated,
            response_mode,
            Some(Prompt::Login),
            par_to_consume.map(|(uri, _)| uri),
        )
        .await;
    }

    // Steps 5-8: ACR + resource + PAR consumption + code issuance.
    issue_code_after_reauth_check(
        state,
        validated,
        oauth_client,
        user,
        auth_session,
        authenticator,
        par_to_consume,
        response_mode,
    )
    .await
}

/// Validate ACR, resource, consume PAR if needed, and issue the authorization code.
///
/// Called after access and re-auth checks have passed in `authorize_authenticated_user`.
#[expect(
    clippy::too_many_arguments,
    reason = "issuing authorization code requires full validated request context"
)]
async fn issue_code_after_reauth_check(
    state: &Arc<AppState>,
    validated: ValidatedAuthRequest,
    oauth_client: &OAuthClient,
    user: &User,
    auth_session: &Session,
    authenticator: &Authenticator,
    par_to_consume: Option<(&str, &str)>,
    response_mode: ResponseMode,
) -> Response {
    // Step 5: Validate requested ACR (RFC 9470).
    if let Some(acr) = validated.acr_values() {
        let acr_ok = acr
            .split_whitespace()
            .any(|v| v == crate::services::auth::ACR_AAL3);
        if !acr_ok {
            return oauth_error_response(
                state,
                oauth_client,
                validated.redirect_uri(),
                "unmet_authentication_requirements",
                "The requested authentication context class is not supported",
                validated.state(),
                response_mode,
            )
            .await;
        }
    }

    // Step 6: Validate resource parameter against registered URIs (RFC 8707).
    if let Some(resource) = validated.resource()
        && !oauth_client.is_valid_resource_uri(resource)
    {
        return oauth_error_response(
            state,
            oauth_client,
            validated.redirect_uri(),
            "invalid_target",
            "The requested resource is not registered for this client",
            validated.state(),
            response_mode,
        )
        .await;
    }

    // Step 7: Consume PAR if applicable (code issuance, not initial authorize visit).
    if let Some((request_uri, client_id)) = par_to_consume {
        match db::consume_pushed_authorization_request(
            &state.store,
            request_uri,
            client_id,
            db::ParConsumptionMode::EnforceExpiry,
        )
        .await
        {
            Ok(_claim) => {} // Successfully consumed
            Err(db::claim::ClaimError::AlreadyConsumed) => {
                return oauth_error_response(
                    state,
                    oauth_client,
                    validated.redirect_uri(),
                    "invalid_request",
                    "The request_uri has already been used or is invalid",
                    validated.state(),
                    response_mode,
                )
                .await;
            }
            Err(e) => {
                tracing::error!("Failed to consume PAR: {e}");
                return oauth_error_response(
                    state,
                    oauth_client,
                    validated.redirect_uri(),
                    "server_error",
                    "Failed to process pushed authorization request",
                    validated.state(),
                    response_mode,
                )
                .await;
            }
        }
    }

    // Step 8: Issue authorization code.
    let auth_code_lifetime = crate::services::oidc::fapi::auth_code_lifetime_seconds(oauth_client);
    let ad_value = validated.authorization_details_value();
    let code_params = AuthorizationCodeParams {
        client_id: validated.client_id(),
        redirect_uri: validated.redirect_uri(),
        user_id: &user.id,
        email: &user.email,
        authenticator_id: &authenticator.id,
        aaguid: authenticator.aaguid.as_deref(),
        scope: validated.scope(),
        nonce: validated.nonce(),
        code_challenge: validated.code_challenge(),
        code_challenge_method: validated.code_challenge_method(),
        resource: validated.resource(),
        acr_values: validated.acr_values(),
        dpop_jkt: validated.dpop_jkt(),
        auth_code_lifetime_seconds: auth_code_lifetime,
        authorization_details: ad_value.as_ref(),
        auth_time: Some(auth_session.created_at.as_second()),
    };

    issue_code_and_redirect(
        state,
        code_params,
        validated.redirect_uri(),
        validated.state(),
        oauth_client,
        response_mode,
    )
    .await
}

// ---------------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------------

/// Issue an authorization code and build the success redirect response.
async fn issue_code_and_redirect(
    state: &Arc<AppState>,
    code_params: AuthorizationCodeParams<'_>,
    redirect_uri: &str,
    oauth_state: Option<&str>,
    oauth_client: &OAuthClient,
    response_mode: ResponseMode,
) -> Response {
    match issue_authorization_code(state, code_params).await {
        Ok(code) => match response_mode {
            ResponseMode::Jwt => {
                match crate::services::oidc::jarm::build_jarm_success_jwt(
                    state,
                    oauth_client,
                    code.as_str(),
                    oauth_state,
                )
                .await
                {
                    Ok(jwt) => {
                        let url = build_jarm_redirect_url(redirect_uri, &jwt);
                        Redirect::to(&url).into_response()
                    }
                    Err(e) => {
                        tracing::error!("Failed to build JARM success JWT: {e}");
                        oauth_error_response(
                            state,
                            oauth_client,
                            redirect_uri,
                            "server_error",
                            "Failed to generate authorization response",
                            oauth_state,
                            response_mode,
                        )
                        .await
                    }
                }
            }
            ResponseMode::FormPost => {
                let base_url = state.config().base_url.clone();
                let mut params = vec![
                    ("code".to_string(), code.to_string()),
                    ("iss".to_string(), base_url),
                ];
                if let Some(s) = oauth_state {
                    params.push(("state".to_string(), s.to_string()));
                }
                FormPostResponseTemplate {
                    redirect_uri: redirect_uri.to_string(),
                    params,
                }
                .into_response()
            }
            ResponseMode::Query => {
                let base_url = state.config().base_url.clone();
                match build_authorization_success_redirect_url(
                    redirect_uri,
                    code.as_str(),
                    oauth_state,
                    &base_url,
                ) {
                    Ok(url) => Redirect::to(&url).into_response(),
                    Err(_) => Redirect::to(redirect_uri).into_response(),
                }
            }
        },
        Err(_) => {
            oauth_error_response(
                state,
                oauth_client,
                redirect_uri,
                "server_error",
                "Failed to generate authorization code",
                oauth_state,
                response_mode,
            )
            .await
        }
    }
}

/// Build an authorization redirect URL with the given query parameters.
fn build_authorization_redirect(redirect_uri: &str, params: &[(&str, &str)]) -> Response {
    match build_redirect_url_with_params(redirect_uri, params) {
        Ok(url) => Redirect::to(&url).into_response(),
        Err(_) => Redirect::to(redirect_uri).into_response(),
    }
}

/// Create an OAuth error response, dispatching on `response_mode`.
///
/// - `Jwt`: wraps error in a JARM signed JWT.
/// - `FormPost`: delivers error via HTML auto-submitting form.
/// - `Query`: delivers via query-string redirect (RFC 6749).
///
/// Includes the `iss` parameter per RFC 9207 in all modes.
async fn oauth_error_response(
    app_state: &Arc<AppState>,
    client: &OAuthClient,
    redirect_uri: &str,
    error: &str,
    description: &str,
    oauth_state: Option<&str>,
    response_mode: ResponseMode,
) -> Response {
    match response_mode {
        ResponseMode::Jwt => {
            oauth_error_redirect_jarm(
                app_state,
                client,
                redirect_uri,
                error,
                description,
                oauth_state,
            )
            .await
        }
        ResponseMode::FormPost => {
            let mut params = vec![
                ("error".to_string(), error.to_string()),
                ("error_description".to_string(), description.to_string()),
                ("iss".to_string(), app_state.config().base_url.clone()),
            ];
            if let Some(s) = oauth_state {
                params.push(("state".to_string(), s.to_string()));
            }
            FormPostResponseTemplate {
                redirect_uri: redirect_uri.to_string(),
                params,
            }
            .into_response()
        }
        ResponseMode::Query => {
            let issuer = &app_state.config().base_url;
            let mut params = vec![("error", error), ("error_description", description)];
            if let Some(state_param) = oauth_state {
                params.push(("state", state_param));
            }
            params.push(("iss", issuer));
            build_authorization_redirect(redirect_uri, &params)
        }
    }
}

/// Create an OAuth error redirect response using JARM encoding.
///
/// Falls back to plain query parameters if JARM JWT signing fails.
async fn oauth_error_redirect_jarm(
    state: &Arc<AppState>,
    client: &OAuthClient,
    redirect_uri: &str,
    error: &str,
    description: &str,
    oauth_state: Option<&str>,
) -> Response {
    match crate::services::oidc::jarm::build_jarm_error_jwt(
        state,
        client,
        error,
        Some(description),
        oauth_state,
    )
    .await
    {
        Ok(jwt) => {
            let url = build_jarm_redirect_url(redirect_uri, &jwt);
            axum::response::Redirect::to(&url).into_response()
        }
        Err(e) => {
            tracing::error!("Failed to build JARM error JWT: {e}");
            let issuer = &state.config().base_url;
            let mut params = vec![("error", error), ("error_description", description)];
            if let Some(state_param) = oauth_state {
                params.push(("state", state_param));
            }
            params.push(("iss", issuer));
            build_authorization_redirect(redirect_uri, &params)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{
        AccessScope, FapiProfile, JwsAlgorithm, OAuthClientType, TokenEndpointAuthMethod,
    };

    fn make_client(redirect_uris: Vec<String>) -> OAuthClient {
        OAuthClient {
            id: "id".to_string(),
            user_id: None,
            client_id: "client_id".to_string(),
            name: "Test App".to_string(),
            description: None,
            application_type: OAuthClientType::Web,
            redirect_uris,
            active: true,
            created_at: jiff::Timestamp::UNIX_EPOCH,
            updated_at: jiff::Timestamp::UNIX_EPOCH,
            last_used_at: None,
            access_scope: AccessScope::Personal,
            org_id: None,
            resource_uris: vec![],
            jwks: None,
            jwks_uri: None,
            token_endpoint_auth_method: TokenEndpointAuthMethod::None,
            request_object_signing_alg: None,
            require_signed_request_object: None,
            fapi_profile: FapiProfile::None,
            dpop_bound_access_tokens: false,
            grant_types: None,
            response_types: None,
            software_id: None,
            software_version: None,
            registration_source: None,
            registration_access_token_hash: None,
            registration_metadata: None,
            id_token_signed_response_alg: JwsAlgorithm::Es256,
            tls_client_auth_subject_dn: None,
            tls_client_auth_san_dns: None,
            tls_client_auth_san_uri: None,
            tls_client_auth_san_ip: None,
            tls_client_auth_san_email: None,
            tls_client_certificate_bound_access_tokens: false,
            authorization_signed_response_alg: None,
            introspection_signed_response_alg: None,
            userinfo_signed_response_alg: None,
            request_uris: None,
            post_logout_redirect_uris: None,
        }
    }

    #[test]
    fn test_resolve_redirect_uri_prefers_param() {
        let client = make_client(vec!["https://example.com/callback".to_string()]);
        let result = resolve_redirect_uri(Some("https://example.com/callback"), &client);
        assert!(result.is_ok());
    }

    #[test]
    fn test_resolve_redirect_uri_auto_selects_single() {
        let client = make_client(vec!["https://example.com/callback".to_string()]);
        let result = resolve_redirect_uri(None, &client);
        assert!(matches!(result, Ok(ref s) if s == "https://example.com/callback"));
    }

    #[test]
    fn test_resolve_redirect_uri_rejects_unregistered() {
        let client = make_client(vec!["https://example.com/callback".to_string()]);
        let result = resolve_redirect_uri(Some("https://evil.com/steal"), &client);
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_redirect_uri_requires_explicit_when_multiple() {
        let client = make_client(vec![
            "https://example.com/callback1".to_string(),
            "https://example.com/callback2".to_string(),
        ]);
        let result = resolve_redirect_uri(None, &client);
        assert!(result.is_err());
    }
}
