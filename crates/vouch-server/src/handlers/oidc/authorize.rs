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
use crate::handlers::HasVersion;
use crate::impl_template_response;
use crate::services::oidc::ScopeSet;
use crate::services::oidc::authorization::{
    AuthorizationCodeParams, AuthorizationSessionState, AuthorizeRequestParams,
    CodeChallengeMethod, Prompt, ValidatedAuthRequest, check_client_access,
    check_session_for_authorization, issue_authorization_code, require_pkce_for_client,
    validate_authorize_request,
};
use crate::services::oidc::jar::{QueryParamHints, validate_request_object};
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
pub struct AuthorizeQuery {
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
pub async fn authorize(
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

    // RFC 9126: If request_uri is present, resolve the PAR and replace parameters.
    if let Some(ref request_uri) = params.request_uri {
        // Validate request_uri format before DB lookup (RFC 9126 Section 2.2).
        // Must start with the standard URN prefix and be reasonably sized.
        if !request_uri.starts_with("urn:ietf:params:oauth:request_uri:") || request_uri.len() > 256
        {
            return AuthorizeDeniedTemplate {
                client_name: "Unknown Application".to_string(),
                error_message: "Invalid request_uri format".to_string(),
            }
            .into_response();
        }

        let client_id = params.client_id.clone().unwrap_or_default();
        if client_id.is_empty() {
            return AuthorizeDeniedTemplate {
                client_name: "Unknown Application".to_string(),
                error_message: "Invalid request: client_id is required with request_uri"
                    .to_string(),
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

    // Normal authorization request - validate parameters
    let response_type = params.response_type.unwrap_or_default();
    let client_id = params.client_id.clone().unwrap_or_default();
    let redirect_uri = params.redirect_uri.clone().unwrap_or_default();

    // Validate redirect_uri is present before any errors that would redirect
    if redirect_uri.is_empty() {
        // Cannot redirect to empty URI - show error page
        return AuthorizeDeniedTemplate {
            client_name: "Unknown Application".to_string(),
            error_message: "Invalid request: redirect_uri is required".to_string(),
        }
        .into_response();
    }

    // Validate prompt before constructing params — reject unsupported values.
    let parsed_prompt = match params.prompt.as_deref() {
        Some(p) => match Prompt::parse(p) {
            Some(prompt) => Some(prompt),
            None => {
                return oauth_error_redirect(
                    &redirect_uri,
                    "invalid_request",
                    "Unsupported prompt value. Supported values: login, none, consent",
                    params.state.as_deref(),
                    &state.config().base_url,
                );
            }
        },
        None => None,
    };

    let request_params = AuthorizeRequestParams {
        response_type,
        client_id: client_id.clone(),
        redirect_uri: redirect_uri.clone(),
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
            // Map the specific error type to the correct OAuth error code
            let (error_code, description) = match &e {
                crate::services::ServiceError::OAuth { code, description } => {
                    (code.as_str(), description.clone())
                }
                _ => ("server_error", e.to_string()),
            };

            // RFC 6749 Section 4.1.2.1: If client_id is unknown, show error page
            if client_id.is_empty() {
                return AuthorizeDeniedTemplate {
                    client_name: "Unknown Application".to_string(),
                    error_message: format!("Invalid request: {description}"),
                }
                .into_response();
            }

            return oauth_error_redirect(
                &redirect_uri,
                error_code,
                &description,
                params.state.as_deref(),
                &state.config().base_url,
            );
        }
    };

    // Look up the OAuth client to get app details
    // RFC 6749 Section 4.1.2.1: If the client identifier is invalid, the authorization
    // server MUST NOT automatically redirect the user-agent to the invalid redirection URI.
    let oauth_client =
        match db::get_oauth_client_by_client_id(&state.store, validated.client_id()).await {
            Ok(Some(client)) => client,
            Ok(None) => {
                return AuthorizeDeniedTemplate {
                    client_name: "Unknown Application".to_string(),
                    error_message:
                        "Unknown client application. Please contact the application administrator."
                            .to_string(),
                }
                .into_response();
            }
            Err(_) => {
                return AuthorizeDeniedTemplate {
                    client_name: "Unknown Application".to_string(),
                    error_message: "An error occurred. Please try again.".to_string(),
                }
                .into_response();
            }
        };

    // Determine the response mode for error redirects in this direct authorize flow.
    // When the client requests response_mode=jwt, errors must also be JARM-encoded
    // so the conformance suite can detect the error via the `response` JWT parameter.
    let direct_response_mode = params
        .response_mode
        .as_deref()
        .and_then(ResponseMode::parse)
        .unwrap_or(ResponseMode::Query);

    // RFC 9700: PKCE required for public clients and Native/SPA types.
    if let Err(e) = require_pkce_for_client(&validated, &oauth_client) {
        let description = match &e {
            crate::services::ServiceError::OAuth { description, .. } => description.clone(),
            _ => e.to_string(),
        };
        if direct_response_mode == ResponseMode::Jwt {
            return oauth_error_redirect_jarm(
                &state,
                &oauth_client,
                validated.redirect_uri(),
                "invalid_request",
                &description,
                validated.state(),
            )
            .await;
        }
        return oauth_error_redirect(
            validated.redirect_uri(),
            "invalid_request",
            &description,
            validated.state(),
            &state.config().base_url,
        );
    }

    // FAPI 2.0: Require PAR for FAPI clients.
    //
    // This catches the case where a FAPI client tries to use the normal
    // authorization flow (no PAR `request_uri`). FAPI 2.0 Section 5.2.2 mandates
    // that all authorization requests use PAR.
    if let Err(e) =
        crate::services::oidc::fapi::validate_fapi_authorization_request(&oauth_client, false)
    {
        let description = match &e {
            crate::services::ServiceError::OAuth { description, .. } => description.clone(),
            _ => e.to_string(),
        };
        if direct_response_mode == ResponseMode::Jwt {
            return oauth_error_redirect_jarm(
                &state,
                &oauth_client,
                validated.redirect_uri(),
                "invalid_request",
                &description,
                validated.state(),
            )
            .await;
        }
        return oauth_error_redirect(
            validated.redirect_uri(),
            "invalid_request",
            &description,
            validated.state(),
            &state.config().base_url,
        );
    }

    // RFC 9101: Enforce require_signed_request_object for this client.
    // If the client requires JAR but the request came through the normal flow
    // (no `request` JWT, no PAR `request_uri`), reject it. The error response
    // uses JARM encoding when response_mode=jwt was requested so the conformance
    // suite can observe the error via the `response` JWT parameter.
    if oauth_client.require_signed_request_object == Some(true) {
        if direct_response_mode == ResponseMode::Jwt {
            return oauth_error_redirect_jarm(
                &state,
                &oauth_client,
                validated.redirect_uri(),
                "invalid_request",
                "This client requires a signed Request Object (RFC 9101)",
                validated.state(),
            )
            .await;
        }
        return oauth_error_redirect(
            validated.redirect_uri(),
            "invalid_request",
            "This client requires a signed Request Object (RFC 9101)",
            validated.state(),
            &state.config().base_url,
        );
    }

    // RFC 6749 Section 10.6: Validate redirect_uri against registered URIs
    // This prevents attackers from redirecting authorization codes to malicious endpoints
    if !oauth_client.is_valid_redirect_uri(validated.redirect_uri()) {
        tracing::warn!(
            "Invalid redirect_uri '{}' for client '{}'. Registered URIs: {:?}",
            validated.redirect_uri(),
            validated.client_id(),
            oauth_client.redirect_uris
        );
        // Show error page instead of redirecting to unregistered URI
        return AuthorizeDeniedTemplate {
            client_name: oauth_client.name,
            error_message: "Invalid redirect_uri: not registered for this application".to_string(),
        }
        .into_response();
    }

    // Try to get existing session from cookie
    let session_token = jar
        .get(vouch_common::SESSION_COOKIE_NAME)
        .map(|c| c.value());

    // Check if we have a valid session
    match check_session_for_authorization(&state, session_token).await {
        Ok(AuthorizationSessionState::Authenticated {
            user,
            session: ref auth_session,
            authenticator,
        }) => {
            authorize_authenticated_user(
                &state,
                validated,
                &oauth_client,
                &user,
                auth_session,
                &authenticator,
                ReauthPolicy::OnDemand,
                None,
                direct_response_mode,
            )
            .await
        }
        Ok(AuthorizationSessionState::NeedsAuth) | Err(_) => {
            // No valid session - store OAuth params and redirect to login.
            // prompt=none means "don't show UI" — return error immediately.
            if validated.prompt() == Some(Prompt::Silent) {
                return oauth_error_response(
                    &state,
                    &oauth_client,
                    validated.redirect_uri(),
                    "login_required",
                    "User is not authenticated and prompt=none was requested",
                    validated.state(),
                    direct_response_mode,
                )
                .await;
            }
            store_pending_and_redirect(&state, validated, direct_response_mode, None).await
        }
    }
}

/// POST /oauth/authorize
///
/// RFC 6749 Section 3.1: The authorization endpoint MAY support POST.
/// Accepts `application/x-www-form-urlencoded` parameters and delegates
/// to the same logic as the GET handler.
pub async fn authorize_post(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Form(params): Form<AuthorizeQuery>,
) -> Response {
    authorize_inner(state, params, jar).await
}

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
) -> Response {
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
    };

    match db::create_pending_oauth_authorization(&state.store, pending_params).await {
        // axum's Redirect::to() produces a 303 See Other, which is correct for
        // FAPI 2.0 and best-practice for POST-redirect-GET patterns (RFC 9700).
        Ok(pending_id) => Redirect::to(&format!(
            "/login?pending_auth={}",
            urlencoding::encode(&pending_id)
        ))
        .into_response(),
        Err(e) => {
            tracing::error!("Failed to create pending OAuth authorization: {}", e);
            oauth_error_redirect(
                validated.redirect_uri(),
                "server_error",
                "Failed to initiate login",
                validated.state(),
                &state.config().base_url,
            )
        }
    }
}

/// Handle returning from login with a pending auth ID.
async fn handle_pending_auth(state: &Arc<AppState>, pending_id: &str, jar: &CookieJar) -> Response {
    // Consume the pending auth (single-use)
    let pending = match db::consume_pending_oauth_authorization(&state.store, pending_id).await {
        Ok(Some(p)) => p,
        Ok(None) => {
            tracing::warn!(
                "Pending OAuth authorization not found or expired: {}",
                pending_id
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

    // Look up the OAuth client
    let oauth_client =
        match db::get_oauth_client_by_client_id(&state.store, &pending.client_id).await {
            Ok(Some(client)) => client,
            Ok(None) => {
                return oauth_error_redirect(
                    &pending.redirect_uri,
                    "invalid_client",
                    "Unknown client_id",
                    pending.state.as_deref(),
                    &state.config().base_url,
                );
            }
            Err(_) => {
                return oauth_error_redirect(
                    &pending.redirect_uri,
                    "server_error",
                    "Database error",
                    pending.state.as_deref(),
                    &state.config().base_url,
                );
            }
        };

    // Get session from cookie (should exist after login)
    let session_token = jar
        .get(vouch_common::SESSION_COOKIE_NAME)
        .map(|c| c.value());

    // Compute auth code lifetime for this client (FAPI 2.0: 60s, standard: 300s).
    let auth_code_lifetime = crate::services::oidc::fapi::auth_code_lifetime_seconds(&oauth_client);

    match check_session_for_authorization(state, session_token).await {
        Ok(AuthorizationSessionState::Authenticated {
            user,
            session: ref auth_session,
            authenticator,
        }) => {
            // Check access
            if let Err(e) = check_client_access(&oauth_client, &user) {
                let error_message = match e {
                    crate::services::ServiceError::OAuth { description, .. } => description,
                    _ => "You don't have access to this application".to_string(),
                };
                return AuthorizeDeniedTemplate {
                    client_name: oauth_client.name,
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
                    return oauth_error_redirect(
                        &pending.redirect_uri,
                        "login_required",
                        "Session exceeds requested max_age",
                        pending.state.as_deref(),
                        &state.config().base_url,
                    );
                }
            }

            // Issue authorization code using stored parameters.
            // Thread dpop_jkt from the pending record through to the auth code so
            // the token endpoint can enforce DPoP key binding (RFC 9449 Section 10).
            let scope_set = ScopeSet::parse(pending.scope.as_deref().unwrap_or("openid"));
            let code_params = AuthorizationCodeParams {
                client_id: &pending.client_id,
                redirect_uri: &pending.redirect_uri,
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
                &pending.redirect_uri,
                pending.state.as_deref(),
                &oauth_client,
                pending.response_mode,
            )
            .await
        }
        Ok(AuthorizationSessionState::NeedsAuth) | Err(_) => {
            // Still not authenticated - something went wrong
            // Redirect back to login (shouldn't happen normally)
            tracing::warn!("User not authenticated after returning from login");
            AuthorizeDeniedTemplate {
                client_name: oauth_client.name,
                error_message: "Authentication failed. Please try again.".to_string(),
            }
            .into_response()
        }
    }
}

/// Handle an authorization request using a JWT-Secured Authorization Request (RFC 9101).
///
/// Validates the Request Object JWT, extracts parameters, and proceeds with the
/// normal authorization flow using the extracted parameters.
async fn handle_jar_request(
    state: &Arc<AppState>,
    request_jwt: &str,
    client_id: &str,
    query: &AuthorizeQuery,
    jar: CookieJar,
) -> Response {
    // Look up the OAuth client
    let oauth_client = match db::get_oauth_client_by_client_id(&state.store, client_id).await {
        Ok(Some(client)) => client,
        Ok(None) => {
            return AuthorizeDeniedTemplate {
                client_name: "Unknown Application".to_string(),
                error_message:
                    "Unknown client application. Please contact the application administrator."
                        .to_string(),
            }
            .into_response();
        }
        Err(_) => {
            return AuthorizeDeniedTemplate {
                client_name: "Unknown Application".to_string(),
                error_message: "An error occurred. Please try again.".to_string(),
            }
            .into_response();
        }
    };

    if !oauth_client.active {
        return AuthorizeDeniedTemplate {
            client_name: oauth_client.name,
            error_message: "This application has been deactivated.".to_string(),
        }
        .into_response();
    }

    // Validate the Request Object JWT with FAPI 2.0 parameter consistency check
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
                crate::services::ServiceError::OAuth { description, .. } => description.clone(),
                _ => e.to_string(),
            };
            // If we have a redirect_uri from query, redirect; otherwise show error page
            if let Some(ref redirect_uri) = query.redirect_uri {
                return oauth_error_redirect(
                    redirect_uri,
                    "invalid_request_object",
                    &description,
                    query.state.as_deref(),
                    &state.config().base_url,
                );
            }
            return AuthorizeDeniedTemplate {
                client_name: oauth_client.name,
                error_message: format!("Invalid Request Object: {description}"),
            }
            .into_response();
        }
    };

    // Continue with the validated parameters from the Request Object
    let redirect_uri = request_params.redirect_uri.clone();

    // Extract response_mode from the Request Object before validate_authorize_request
    // discards it (ValidatedAuthRequest does not carry response_mode).
    let jar_response_mode = request_params
        .response_mode
        .as_deref()
        .and_then(ResponseMode::parse)
        .unwrap_or(ResponseMode::Query);

    let validated = match validate_authorize_request(request_params) {
        Ok(v) => v,
        Err(e) => {
            let (error_code, description) = match &e {
                crate::services::ServiceError::OAuth { code, description } => {
                    (code.as_str(), description.clone())
                }
                _ => ("server_error", e.to_string()),
            };
            return oauth_error_redirect(
                &redirect_uri,
                error_code,
                &description,
                query.state.as_deref(),
                &state.config().base_url,
            );
        }
    };

    // RFC 9700: PKCE required for public clients and Native/SPA types.
    if let Err(e) = require_pkce_for_client(&validated, &oauth_client) {
        let description = match &e {
            crate::services::ServiceError::OAuth { description, .. } => description.clone(),
            _ => e.to_string(),
        };
        return oauth_error_redirect(
            &redirect_uri,
            "invalid_request",
            &description,
            query.state.as_deref(),
            &state.config().base_url,
        );
    }

    // Validate redirect_uri against registered URIs
    if !oauth_client.is_valid_redirect_uri(validated.redirect_uri()) {
        return AuthorizeDeniedTemplate {
            client_name: oauth_client.name,
            error_message: "Invalid redirect_uri: not registered for this application".to_string(),
        }
        .into_response();
    }

    // Try to get existing session from cookie
    let session_token = jar
        .get(vouch_common::SESSION_COOKIE_NAME)
        .map(|c| c.value());

    // Check if we have a valid session
    match check_session_for_authorization(state, session_token).await {
        Ok(AuthorizationSessionState::Authenticated {
            user,
            session: ref auth_session,
            authenticator,
        }) => {
            authorize_authenticated_user(
                state,
                validated,
                &oauth_client,
                &user,
                auth_session,
                &authenticator,
                ReauthPolicy::OnDemand,
                None,
                jar_response_mode,
            )
            .await
        }
        Ok(AuthorizationSessionState::NeedsAuth) | Err(_) => {
            if validated.prompt() == Some(Prompt::Silent) {
                return oauth_error_response(
                    state,
                    &oauth_client,
                    validated.redirect_uri(),
                    "login_required",
                    "User is not authenticated and prompt=none was requested",
                    validated.state(),
                    jar_response_mode,
                )
                .await;
            }
            store_pending_and_redirect(state, validated, jar_response_mode, None).await
        }
    }
}

/// Handle an authorization request using a pushed authorization request URI (RFC 9126).
///
/// Consumes the PAR (single-use) and proceeds with the normal authorization flow
/// using the stored parameters, including any DPoP key binding from the PAR record.
async fn handle_par_request(
    state: &Arc<AppState>,
    request_uri: &str,
    client_id: &str,
    fallback_redirect_uri: Option<&str>,
    jar: CookieJar,
) -> Response {
    // FAPI 2.0 Section 5.3.2.2 Note 3: Look up the PAR without consuming it.
    // The request_uri should be reusable until the authorization is completed
    // (code issued). Consumption happens when the auth code is issued.
    let par = match db::get_pushed_authorization_request(&state.store, request_uri, client_id).await
    {
        Ok(Some(p)) => p,
        Ok(None) => {
            tracing::warn!(
                "PAR not found, expired, consumed, or wrong client: request_uri={}, client_id={}",
                request_uri,
                client_id,
            );
            // If a redirect_uri was provided in the query, redirect with error
            // so the conformance suite's browser can detect the outcome.
            if let Some(uri) = fallback_redirect_uri
                && let Ok(mut redirect) = url::Url::parse(uri)
            {
                {
                    let mut q = redirect.query_pairs_mut();
                    q.append_pair("error", "invalid_request_uri");
                    q.append_pair("error_description", "Invalid or expired request_uri");
                    q.append_pair("iss", &state.config().base_url);
                }
                return axum::response::Redirect::to(redirect.as_str()).into_response();
            }
            return AuthorizeDeniedTemplate {
                client_name: "Unknown Application".to_string(),
                error_message:
                    "Invalid or expired request_uri. Please restart the authorization flow."
                        .to_string(),
            }
            .into_response();
        }
        Err(e) => {
            tracing::error!("Failed to consume PAR: {}", e);
            return AuthorizeDeniedTemplate {
                client_name: "Unknown Application".to_string(),
                error_message: "An error occurred. Please try again.".to_string(),
            }
            .into_response();
        }
    };

    // Reconstruct the authorization parameters from the stored PAR
    let redirect_uri = par.redirect_uri.clone();

    // Validate prompt
    let parsed_prompt = match par.prompt.as_deref() {
        Some(p) => Prompt::parse(p),
        None => None,
    };

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
                crate::services::ServiceError::OAuth { code, description } => {
                    (code.as_str(), description.clone())
                }
                _ => ("server_error", e.to_string()),
            };
            return oauth_error_redirect(
                &redirect_uri,
                error_code,
                &description,
                par.state.as_deref(),
                &state.config().base_url,
            );
        }
    };

    // Look up the OAuth client
    let oauth_client =
        match db::get_oauth_client_by_client_id(&state.store, validated.client_id()).await {
            Ok(Some(client)) => client,
            Ok(None) => {
                return AuthorizeDeniedTemplate {
                    client_name: "Unknown Application".to_string(),
                    error_message:
                        "Unknown client application. Please contact the application administrator."
                            .to_string(),
                }
                .into_response();
            }
            Err(_) => {
                return AuthorizeDeniedTemplate {
                    client_name: "Unknown Application".to_string(),
                    error_message: "An error occurred. Please try again.".to_string(),
                }
                .into_response();
            }
        };

    // RFC 9700: PKCE required for public clients and Native/SPA types.
    if let Err(e) = require_pkce_for_client(&validated, &oauth_client) {
        let description = match &e {
            crate::services::ServiceError::OAuth { description, .. } => description.clone(),
            _ => e.to_string(),
        };
        return oauth_error_redirect(
            validated.redirect_uri(),
            "invalid_request",
            &description,
            par.state.as_deref(),
            &state.config().base_url,
        );
    }

    // Validate redirect_uri against registered URIs
    if !oauth_client.is_valid_redirect_uri(validated.redirect_uri()) {
        return AuthorizeDeniedTemplate {
            client_name: oauth_client.name,
            error_message: "Invalid redirect_uri: not registered for this application".to_string(),
        }
        .into_response();
    }

    // Try to get existing session from cookie
    let session_token = jar
        .get(vouch_common::SESSION_COOKIE_NAME)
        .map(|c| c.value());

    // Check if we have a valid session
    match check_session_for_authorization(state, session_token).await {
        Ok(AuthorizationSessionState::Authenticated {
            user,
            session: ref auth_session,
            authenticator,
        }) => {
            // PAR flows always require a fresh FIDO2 assertion (FAPI 2.0 Section 5.3.2.2 Note 3).
            // ReauthPolicy::Always encodes this: redirect to login unless prompt=none.
            // dpop_jkt flows through ValidatedAuthRequest (set from par.dpop_jkt above)
            // so the token endpoint can enforce DPoP key binding (RFC 9449 Section 10).
            authorize_authenticated_user(
                state,
                validated,
                &oauth_client,
                &user,
                auth_session,
                &authenticator,
                ReauthPolicy::Always,
                Some((request_uri, client_id)),
                par.response_mode,
            )
            .await
        }
        Ok(AuthorizationSessionState::NeedsAuth) | Err(_) => {
            if validated.prompt() == Some(Prompt::Silent) {
                return oauth_error_response(
                    state,
                    &oauth_client,
                    validated.redirect_uri(),
                    "login_required",
                    "User is not authenticated and prompt=none was requested",
                    validated.state(),
                    par.response_mode,
                )
                .await;
            }
            // DPoP key binding is already in validated.dpop_jkt() from par.dpop_jkt.
            store_pending_and_redirect(state, validated, par.response_mode, None).await
        }
    }
}

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

/// Handle the authenticated-user path common to all three authorization flows.
///
/// Called after session validation confirms the user is authenticated.  Checks
/// client access, applies the re-auth policy, validates ACR and resource, optionally
/// consumes a PAR record, and issues the authorization code.
///
/// `reauth_policy` distinguishes PAR flows (always require fresh auth) from
/// standard/JAR flows (only re-auth on prompt=login or max_age exceeded).
///
/// `par_to_consume` is `Some((request_uri, client_id))` only for PAR flows that
/// reached code issuance without re-auth (i.e., prompt=none path).
#[allow(clippy::too_many_arguments)]
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
            crate::services::ServiceError::OAuth { description, .. } => description,
            _ => "You don't have access to this application".to_string(),
        };
        return AuthorizeDeniedTemplate {
            client_name: oauth_client.name.clone(),
            error_message,
        }
        .into_response();
    }

    // Step 2: Determine whether re-authentication is required.
    //
    // PAR flows always require a fresh FIDO2 assertion per authorization
    // (FAPI 2.0 Section 5.3.2.2 Note 3) unless prompt=none is explicitly
    // requested.  Standard/JAR flows only re-auth on prompt=login or when
    // the session age exceeds max_age (RFC 9470).
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
    // Override prompt to Prompt::Login so the login page shows the form instead
    // of auto-redirecting when an old session cookie exists from a previous flow.
    if needs_reauth {
        return store_pending_and_redirect(state, validated, response_mode, Some(Prompt::Login))
            .await;
    }

    // Step 5: Validate requested ACR (RFC 9470).
    // Vouch only provides AAL3 — reject requests for other ACR levels.
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

    // Step 7: Consume PAR if applicable.
    //
    // FAPI 2.0 Section 5.3.2.2 Note 3: consumption happens at code issuance
    // (here), not at the initial authorize endpoint visit.
    if let Some((request_uri, client_id)) = par_to_consume
        && let Err(e) =
            db::consume_pushed_authorization_request(&state.store, request_uri, client_id).await
    {
        tracing::error!("Failed to consume PAR: {e}");
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

/// Issue an authorization code and build the success redirect response.
///
/// When `response_mode` is `ResponseMode::Jwt`, wraps the response in a JARM
/// signed JWT delivered as a single `response` query parameter. When
/// `response_mode` is `ResponseMode::FormPost`, delivers parameters via an
/// HTML form auto-submit (POST to redirect_uri).
///
/// Shared helper used by both direct authorization and pending-auth flows.
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
                    Err(_) => {
                        // Fallback: should not happen since redirect_uri was already validated
                        Redirect::to(redirect_uri).into_response()
                    }
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
///
/// Uses `url::Url` for proper encoding instead of manual string concatenation.
/// axum's `Redirect::to()` produces a 303 See Other, which is correct for
/// FAPI 2.0 and the OAuth best-practice POST-redirect-GET pattern (RFC 9700).
fn build_authorization_redirect(redirect_uri: &str, params: &[(&str, &str)]) -> Response {
    match build_redirect_url_with_params(redirect_uri, params) {
        Ok(url) => Redirect::to(&url).into_response(),
        Err(_) => {
            // Fallback: should not happen since redirect_uri was already validated
            Redirect::to(redirect_uri).into_response()
        }
    }
}

/// Create an OAuth error redirect response.
///
/// Includes the `iss` parameter per RFC 9207.
fn oauth_error_redirect(
    redirect_uri: &str,
    error: &str,
    description: &str,
    state: Option<&str>,
    issuer: &str,
) -> Response {
    let mut params = vec![("error", error), ("error_description", description)];
    if let Some(state_param) = state {
        params.push(("state", state_param));
    }
    // RFC 9207: Include iss parameter even in error responses
    params.push(("iss", issuer));
    build_authorization_redirect(redirect_uri, &params)
}

/// Create an OAuth error response, dispatching on `response_mode`.
///
/// OIDC Core Section 3.1.2.6: when `response_mode=form_post`, the error MUST
/// also be delivered via HTTP POST. When `response_mode=jwt` (JARM), the error
/// MUST be wrapped in a signed JWT. Falls back to query-string for query mode.
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
        ResponseMode::FormPost => {
            let issuer = &app_state.config().base_url;
            let mut params = vec![
                ("error".to_string(), error.to_string()),
                ("error_description".to_string(), description.to_string()),
                ("iss".to_string(), issuer.clone()),
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
        ResponseMode::Query => oauth_error_redirect(
            redirect_uri,
            error,
            description,
            oauth_state,
            &app_state.config().base_url,
        ),
    }
}

/// Create an OAuth error redirect response, using JARM encoding when the client
/// has requested `response_mode=jwt`.
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
            // Fall back to plain query params so the user-agent is not left stranded.
            oauth_error_redirect(
                redirect_uri,
                error,
                description,
                oauth_state,
                &state.config().base_url,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oauth_error_redirect_includes_iss() {
        // This is a compile-time check that the function signature is correct.
        // Integration tests will verify actual behavior.
        let _response = oauth_error_redirect(
            "https://example.com/callback",
            "invalid_request",
            "Something went wrong",
            Some("state123"),
            "https://vouch.example.com",
        );
    }
}
