// SPDX-License-Identifier: BUSL-1.1
//! Authorization endpoint handler.
//!
//! Implements RFC 6749 Section 4.1 (Authorization Code Grant) with extensions:
//! - RFC 7636 (PKCE)
//! - RFC 9207 (Authorization Server Issuer Identification)
//! - RFC 9700 (OAuth 2.0 Security Best Current Practice)

use crate::AppState;
use crate::db::{self, CreatePendingOAuthParams};
use crate::impl_template_response;
use crate::services::oidc::ScopeSet;
use crate::services::oidc::authorization::{
    AuthorizationCodeParams, AuthorizationSessionState, AuthorizeRequestParams,
    CodeChallengeMethod, Prompt, check_client_access, check_session_for_authorization,
    issue_authorization_code, validate_authorize_request,
};
use crate::services::oidc::jar::{QueryParamHints, validate_request_object};
use askama::Template;
use axum::{
    extract::{Query, State},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use std::sync::Arc;

/// Access denied error template.
#[derive(Template)]
#[template(path = "authorize_denied.html")]
pub struct AuthorizeDeniedTemplate {
    pub client_name: String,
    pub error_message: String,
}

impl_template_response!(AuthorizeDeniedTemplate);

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
        let client_id = params.client_id.clone().unwrap_or_default();
        if client_id.is_empty() {
            return AuthorizeDeniedTemplate {
                client_name: "Unknown Application".to_string(),
                error_message: "Invalid request: client_id is required with request_uri"
                    .to_string(),
            }
            .into_response();
        }

        return handle_par_request(&state, request_uri, &client_id, jar).await;
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
                    "Unsupported prompt value. Only 'login' and 'none' are supported",
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
        match db::get_oauth_client_by_client_id(&state.db, validated.client_id()).await {
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
    // (no `request` JWT, no PAR `request_uri`), reject it.
    if oauth_client.require_signed_request_object == Some(true) {
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
            oauth_client.get_redirect_uris()
        );
        // Show error page instead of redirecting to unregistered URI
        return AuthorizeDeniedTemplate {
            client_name: oauth_client.name,
            error_message: "Invalid redirect_uri: not registered for this application".to_string(),
        }
        .into_response();
    }

    // Try to get existing session from cookie
    let session_token = jar.get("vouch_session").map(|c| c.value());

    // Compute auth code lifetime for this client (FAPI 2.0: 60s, standard: 300s).
    let auth_code_lifetime = crate::services::oidc::fapi::auth_code_lifetime_seconds(&oauth_client);

    // Check if we have a valid session
    match check_session_for_authorization(&state, session_token).await {
        Ok(AuthorizationSessionState::Authenticated {
            user,
            session: ref auth_session,
            authenticator,
        }) => {
            // User is authenticated - check access before issuing code
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

            // RFC 9470: Check if re-authentication is required.
            //
            // prompt=login always forces re-auth (even with a fresh session).
            // max_age checks authentication age: if (now - auth_time) > max_age,
            // the user must re-authenticate with their FIDO2 key.
            let needs_reauth = validated.prompt() == Some(Prompt::Login)
                || validated.max_age().is_some_and(|max_age| {
                    let auth_time = auth_session.created_at.to_jiff();
                    let age_secs = jiff::Timestamp::now()
                        .duration_since(auth_time)
                        .as_secs()
                        .max(0);
                    let Ok(age) = u64::try_from(age_secs) else {
                        return true;
                    };
                    age >= max_age
                });

            // prompt=none means "don't show UI"; if re-auth is needed, return error.
            if needs_reauth && validated.prompt() == Some(Prompt::Silent) {
                return oauth_error_redirect(
                    validated.redirect_uri(),
                    "login_required",
                    "Re-authentication required but prompt=none was requested",
                    validated.state(),
                    &state.config().base_url,
                );
            }

            if needs_reauth {
                // Direct authorization flow: no DPoP at the browser endpoint.
                return store_pending_and_redirect(&state, validated, None).await;
            }

            // RFC 9470: Validate requested ACR is satisfiable.
            // Vouch only provides AAL3 — reject requests for other ACR levels.
            if let Some(acr) = validated.acr_values() {
                let acr_ok = acr
                    .split_whitespace()
                    .any(|v| v == crate::services::oidc::amr::ACR_AAL3);
                if !acr_ok {
                    return oauth_error_redirect(
                        validated.redirect_uri(),
                        "unmet_authentication_requirements",
                        "The requested authentication context class is not supported",
                        validated.state(),
                        &state.config().base_url,
                    );
                }
            }

            // RFC 8707: Validate resource parameter against registered URIs
            if let Some(resource) = validated.resource()
                && !oauth_client.is_valid_resource_uri(resource)
            {
                return oauth_error_redirect(
                    validated.redirect_uri(),
                    "invalid_target",
                    "The requested resource is not registered for this client",
                    validated.state(),
                    &state.config().base_url,
                );
            }

            // Access granted - issue authorization code.
            // Direct (non-PAR) authorization requests have no DPoP at the
            // browser authorization endpoint; key binding is not applicable.
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
                dpop_jkt: None,
                auth_code_lifetime_seconds: auth_code_lifetime,
            };

            issue_code_and_redirect(
                &state,
                code_params,
                validated.redirect_uri(),
                validated.state(),
            )
            .await
        }
        Ok(AuthorizationSessionState::NeedsAuth) | Err(_) => {
            // No valid session - store OAuth params and redirect to login.
            // prompt=none means "don't show UI" — return error immediately.
            if validated.prompt() == Some(Prompt::Silent) {
                return oauth_error_redirect(
                    validated.redirect_uri(),
                    "login_required",
                    "User is not authenticated and prompt=none was requested",
                    validated.state(),
                    &state.config().base_url,
                );
            }
            // Direct authorization flow: no DPoP at the browser endpoint.
            store_pending_and_redirect(&state, validated, None).await
        }
    }
}

/// Store OAuth params in the database and redirect to login.
///
/// Used when the user needs to (re-)authenticate before authorization can proceed:
/// - No existing session
/// - `prompt=login` requested
/// - `max_age` exceeded (RFC 9470 step-up)
///
/// The `dpop_jkt` parameter carries the DPoP key thumbprint from the PAR record
/// so that key binding survives the browser login redirect.
async fn store_pending_and_redirect(
    state: &Arc<AppState>,
    validated: crate::services::oidc::authorization::ValidatedAuthRequest,
    dpop_jkt: Option<&str>,
) -> Response {
    let scope_str = validated.scope().to_space_separated();
    let max_age_i64 = validated.max_age().and_then(|v| i64::try_from(v).ok());
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
        prompt: validated.prompt().map(|p| p.as_str()),
        dpop_jkt,
    };

    match db::create_pending_oauth_authorization(&state.db, pending_params).await {
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
    let pending = match db::consume_pending_oauth_authorization(&state.db, pending_id).await {
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
    let oauth_client = match db::get_oauth_client_by_client_id(&state.db, &pending.client_id).await
    {
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
    let session_token = jar.get("vouch_session").map(|c| c.value());

    // Compute auth code lifetime for this client (FAPI 2.0: 60s, standard: 300s).
    let auth_code_lifetime = crate::services::oidc::fapi::auth_code_lifetime_seconds(&oauth_client);

    match check_session_for_authorization(state, session_token).await {
        Ok(AuthorizationSessionState::Authenticated {
            user,
            session: _,
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
            };

            issue_code_and_redirect(
                state,
                code_params,
                &pending.redirect_uri,
                pending.state.as_deref(),
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
    let oauth_client = match db::get_oauth_client_by_client_id(&state.db, client_id).await {
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

    // Validate redirect_uri against registered URIs
    if !oauth_client.is_valid_redirect_uri(validated.redirect_uri()) {
        return AuthorizeDeniedTemplate {
            client_name: oauth_client.name,
            error_message: "Invalid redirect_uri: not registered for this application".to_string(),
        }
        .into_response();
    }

    // Try to get existing session from cookie
    let session_token = jar.get("vouch_session").map(|c| c.value());

    // Compute auth code lifetime for this client (FAPI 2.0: 60s, standard: 300s).
    let auth_code_lifetime = crate::services::oidc::fapi::auth_code_lifetime_seconds(&oauth_client);

    // Check if we have a valid session
    match check_session_for_authorization(state, session_token).await {
        Ok(AuthorizationSessionState::Authenticated {
            user,
            session: ref auth_session,
            authenticator,
        }) => {
            // User is authenticated - check access
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

            // RFC 9470: Check if re-authentication is required
            let needs_reauth = validated.prompt() == Some(Prompt::Login)
                || validated.max_age().is_some_and(|max_age| {
                    let auth_time = auth_session.created_at.to_jiff();
                    let age_secs = jiff::Timestamp::now()
                        .duration_since(auth_time)
                        .as_secs()
                        .max(0);
                    let Ok(age) = u64::try_from(age_secs) else {
                        return true;
                    };
                    age >= max_age
                });

            if needs_reauth && validated.prompt() == Some(Prompt::Silent) {
                return oauth_error_redirect(
                    validated.redirect_uri(),
                    "login_required",
                    "Re-authentication required but prompt=none was requested",
                    validated.state(),
                    &state.config().base_url,
                );
            }

            if needs_reauth {
                // JAR flow: no DPoP key binding at the browser endpoint.
                return store_pending_and_redirect(state, validated, None).await;
            }

            // RFC 9470: Validate requested ACR
            if let Some(acr) = validated.acr_values() {
                let acr_ok = acr
                    .split_whitespace()
                    .any(|v| v == crate::services::oidc::amr::ACR_AAL3);
                if !acr_ok {
                    return oauth_error_redirect(
                        validated.redirect_uri(),
                        "unmet_authentication_requirements",
                        "The requested authentication context class is not supported",
                        validated.state(),
                        &state.config().base_url,
                    );
                }
            }

            // RFC 8707: Validate resource parameter
            if let Some(resource) = validated.resource()
                && !oauth_client.is_valid_resource_uri(resource)
            {
                return oauth_error_redirect(
                    validated.redirect_uri(),
                    "invalid_target",
                    "The requested resource is not registered for this client",
                    validated.state(),
                    &state.config().base_url,
                );
            }

            // Issue authorization code. JAR flow has no DPoP key binding at
            // the browser authorization endpoint.
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
                dpop_jkt: None,
                auth_code_lifetime_seconds: auth_code_lifetime,
            };

            issue_code_and_redirect(
                state,
                code_params,
                validated.redirect_uri(),
                validated.state(),
            )
            .await
        }
        Ok(AuthorizationSessionState::NeedsAuth) | Err(_) => {
            if validated.prompt() == Some(Prompt::Silent) {
                return oauth_error_redirect(
                    validated.redirect_uri(),
                    "login_required",
                    "User is not authenticated and prompt=none was requested",
                    validated.state(),
                    &state.config().base_url,
                );
            }
            // JAR flow: no DPoP key binding at the browser endpoint.
            store_pending_and_redirect(state, validated, None).await
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
    jar: CookieJar,
) -> Response {
    // Consume the PAR (single-use, client-bound)
    let par = match db::consume_pushed_authorization_request(&state.db, request_uri, client_id)
        .await
    {
        Ok(Some(p)) => p,
        Ok(None) => {
            tracing::warn!(
                "PAR not found, expired, consumed, or wrong client: request_uri={}, client_id={}",
                request_uri,
                client_id,
            );
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
        match db::get_oauth_client_by_client_id(&state.db, validated.client_id()).await {
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

    // Validate redirect_uri against registered URIs
    if !oauth_client.is_valid_redirect_uri(validated.redirect_uri()) {
        return AuthorizeDeniedTemplate {
            client_name: oauth_client.name,
            error_message: "Invalid redirect_uri: not registered for this application".to_string(),
        }
        .into_response();
    }

    // Try to get existing session from cookie
    let session_token = jar.get("vouch_session").map(|c| c.value());

    // Compute auth code lifetime for this client (FAPI 2.0: 60s, standard: 300s).
    let auth_code_lifetime = crate::services::oidc::fapi::auth_code_lifetime_seconds(&oauth_client);

    // Check if we have a valid session
    match check_session_for_authorization(state, session_token).await {
        Ok(AuthorizationSessionState::Authenticated {
            user,
            session: ref auth_session,
            authenticator,
        }) => {
            // User is authenticated - check access
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

            // RFC 9470: Check if re-authentication is required
            let needs_reauth = validated.prompt() == Some(Prompt::Login)
                || validated.max_age().is_some_and(|max_age| {
                    let auth_time = auth_session.created_at.to_jiff();
                    let age_secs = jiff::Timestamp::now()
                        .duration_since(auth_time)
                        .as_secs()
                        .max(0);
                    let Ok(age) = u64::try_from(age_secs) else {
                        return true;
                    };
                    age >= max_age
                });

            if needs_reauth && validated.prompt() == Some(Prompt::Silent) {
                return oauth_error_redirect(
                    validated.redirect_uri(),
                    "login_required",
                    "Re-authentication required but prompt=none was requested",
                    validated.state(),
                    &state.config().base_url,
                );
            }

            if needs_reauth {
                // Preserve DPoP key binding from PAR through the login redirect.
                return store_pending_and_redirect(state, validated, par.dpop_jkt.as_deref()).await;
            }

            // RFC 9470: Validate requested ACR
            if let Some(acr) = validated.acr_values() {
                let acr_ok = acr
                    .split_whitespace()
                    .any(|v| v == crate::services::oidc::amr::ACR_AAL3);
                if !acr_ok {
                    return oauth_error_redirect(
                        validated.redirect_uri(),
                        "unmet_authentication_requirements",
                        "The requested authentication context class is not supported",
                        validated.state(),
                        &state.config().base_url,
                    );
                }
            }

            // RFC 8707: Validate resource parameter against registered URIs
            if let Some(resource) = validated.resource()
                && !oauth_client.is_valid_resource_uri(resource)
            {
                return oauth_error_redirect(
                    validated.redirect_uri(),
                    "invalid_target",
                    "The requested resource is not registered for this client",
                    validated.state(),
                    &state.config().base_url,
                );
            }

            // Issue authorization code. Thread dpop_jkt from the PAR record so the
            // token endpoint can enforce DPoP key binding (RFC 9449 Section 10).
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
                dpop_jkt: par.dpop_jkt.as_deref(),
                auth_code_lifetime_seconds: auth_code_lifetime,
            };

            issue_code_and_redirect(
                state,
                code_params,
                validated.redirect_uri(),
                validated.state(),
            )
            .await
        }
        Ok(AuthorizationSessionState::NeedsAuth) | Err(_) => {
            if validated.prompt() == Some(Prompt::Silent) {
                return oauth_error_redirect(
                    validated.redirect_uri(),
                    "login_required",
                    "User is not authenticated and prompt=none was requested",
                    validated.state(),
                    &state.config().base_url,
                );
            }
            // Preserve DPoP key binding from PAR through the login redirect.
            store_pending_and_redirect(state, validated, par.dpop_jkt.as_deref()).await
        }
    }
}

/// Issue an authorization code and build the success redirect response.
///
/// Shared helper used by both direct authorization and pending-auth flows.
async fn issue_code_and_redirect(
    state: &Arc<AppState>,
    code_params: AuthorizationCodeParams<'_>,
    redirect_uri: &str,
    oauth_state: Option<&str>,
) -> Response {
    match issue_authorization_code(state, code_params).await {
        Ok(code) => {
            // RFC 9207: Include iss parameter in authorization response
            let mut params = vec![("code", code.as_str())];
            let state_owned;
            if let Some(state_param) = oauth_state {
                state_owned = state_param.to_string();
                params.push(("state", &state_owned));
            }
            let base_url = state.config().base_url.clone();
            params.push(("iss", &base_url));
            build_authorization_redirect(redirect_uri, &params)
        }
        Err(_) => oauth_error_redirect(
            redirect_uri,
            "server_error",
            "Failed to generate authorization code",
            oauth_state,
            &state.config().base_url,
        ),
    }
}

/// Build an authorization redirect URL with the given query parameters.
///
/// Uses `url::Url` for proper encoding instead of manual string concatenation.
/// axum's `Redirect::to()` produces a 303 See Other, which is correct for
/// FAPI 2.0 and the OAuth best-practice POST-redirect-GET pattern (RFC 9700).
fn build_authorization_redirect(redirect_uri: &str, params: &[(&str, &str)]) -> Response {
    match url::Url::parse(redirect_uri) {
        Ok(mut url) => {
            {
                let mut query = url.query_pairs_mut();
                for (key, value) in params {
                    query.append_pair(key, value);
                }
            }
            Redirect::to(url.as_str()).into_response()
        }
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
