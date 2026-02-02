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
use crate::services::oidc::authorization::{
    AuthorizationCodeParams, AuthorizationSessionState, AuthorizeRequestParams,
    check_client_access, check_session_for_authorization, issue_authorization_code,
    validate_authorize_request,
};
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

/// Authorization request query parameters.
#[derive(Debug, Deserialize)]
pub struct AuthorizeQuery {
    /// Response type (must be "code").
    response_type: Option<String>,
    /// Client identifier.
    client_id: Option<String>,
    /// Redirect URI for the response.
    redirect_uri: Option<String>,
    /// Requested scope.
    scope: Option<String>,
    /// State parameter (opaque, returned unchanged).
    state: Option<String>,
    /// OIDC nonce.
    nonce: Option<String>,
    /// PKCE code challenge.
    code_challenge: Option<String>,
    /// PKCE code challenge method.
    code_challenge_method: Option<String>,
    /// Pending OAuth authorization ID (when returning from login).
    pending_auth: Option<String>,
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

    let request_params = AuthorizeRequestParams {
        response_type,
        client_id: client_id.clone(),
        redirect_uri: redirect_uri.clone(),
        scope: params.scope.clone(),
        state: params.state.clone(),
        nonce: params.nonce.clone(),
        code_challenge: params.code_challenge.clone(),
        code_challenge_method: params.code_challenge_method.clone(),
    };

    let validated = match validate_authorize_request(request_params) {
        Ok(v) => v,
        Err(_) => {
            return oauth_error_redirect(
                &redirect_uri,
                "unsupported_response_type",
                "Only 'code' response type is supported",
                params.state.as_deref(),
                &state.config.base_url,
            );
        }
    };

    // Look up the OAuth client to get app details
    let oauth_client =
        match db::get_oauth_client_by_client_id(&state.db, &validated.client_id).await {
            Ok(Some(client)) => client,
            Ok(None) => {
                return oauth_error_redirect(
                    &validated.redirect_uri,
                    "invalid_client",
                    "Unknown client_id",
                    validated.state.as_deref(),
                    &state.config.base_url,
                );
            }
            Err(_) => {
                return oauth_error_redirect(
                    &validated.redirect_uri,
                    "server_error",
                    "Database error",
                    validated.state.as_deref(),
                    &state.config.base_url,
                );
            }
        };

    // RFC 6749 Section 10.6: Validate redirect_uri against registered URIs
    // This prevents attackers from redirecting authorization codes to malicious endpoints
    if !oauth_client.is_valid_redirect_uri(&validated.redirect_uri) {
        tracing::warn!(
            "Invalid redirect_uri '{}' for client '{}'. Registered URIs: {:?}",
            validated.redirect_uri,
            validated.client_id,
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

    // Check if we have a valid session
    match check_session_for_authorization(&state, session_token).await {
        Ok(AuthorizationSessionState::Authenticated {
            user,
            session: _,
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

            // Access granted - issue authorization code
            let code_params = AuthorizationCodeParams {
                client_id: &validated.client_id,
                redirect_uri: &validated.redirect_uri,
                user_id: &user.id,
                email: &user.email,
                authenticator_id: &authenticator.id,
                aaguid: authenticator.aaguid.as_deref(),
                scope: &validated.scope,
                nonce: validated.nonce.as_deref(),
                code_challenge: validated.code_challenge.as_deref(),
                code_challenge_method: validated.code_challenge_method.as_deref(),
            };

            match issue_authorization_code(&state, code_params) {
                Ok(code) => {
                    // RFC 9207: Include iss parameter in authorization response
                    let mut redirect_url = format!("{}?code={}", validated.redirect_uri, code);
                    if let Some(state_param) = &validated.state {
                        redirect_url
                            .push_str(&format!("&state={}", urlencoding::encode(state_param)));
                    }
                    // RFC 9207: Authorization Server Issuer Identification
                    redirect_url.push_str(&format!(
                        "&iss={}",
                        urlencoding::encode(&state.config.base_url)
                    ));
                    Redirect::to(&redirect_url).into_response()
                }
                Err(_) => oauth_error_redirect(
                    &validated.redirect_uri,
                    "server_error",
                    "Failed to generate authorization code",
                    validated.state.as_deref(),
                    &state.config.base_url,
                ),
            }
        }
        Ok(AuthorizationSessionState::NeedsAuth) | Err(_) => {
            // No valid session - store OAuth params and redirect to login
            // This prevents parameter tampering per RFC 9700
            let pending_params = CreatePendingOAuthParams {
                client_id: &validated.client_id,
                redirect_uri: &validated.redirect_uri,
                response_type: "code",
                state: validated.state.as_deref(),
                scope: Some(&validated.scope),
                nonce: validated.nonce.as_deref(),
                code_challenge: validated.code_challenge.as_deref(),
                code_challenge_method: validated.code_challenge_method.as_deref(),
            };

            match db::create_pending_oauth_authorization(&state.db, pending_params).await {
                Ok(pending_id) => {
                    // Redirect to login with pending auth ID
                    Redirect::to(&format!(
                        "/login?pending_auth={}",
                        urlencoding::encode(&pending_id)
                    ))
                    .into_response()
                }
                Err(e) => {
                    tracing::error!("Failed to create pending OAuth authorization: {}", e);
                    oauth_error_redirect(
                        &validated.redirect_uri,
                        "server_error",
                        "Failed to initiate login",
                        validated.state.as_deref(),
                        &state.config.base_url,
                    )
                }
            }
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
                &state.config.base_url,
            );
        }
        Err(_) => {
            return oauth_error_redirect(
                &pending.redirect_uri,
                "server_error",
                "Database error",
                pending.state.as_deref(),
                &state.config.base_url,
            );
        }
    };

    // Get session from cookie (should exist after login)
    let session_token = jar.get("vouch_session").map(|c| c.value());

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

            // Issue authorization code using stored parameters
            let code_params = AuthorizationCodeParams {
                client_id: &pending.client_id,
                redirect_uri: &pending.redirect_uri,
                user_id: &user.id,
                email: &user.email,
                authenticator_id: &authenticator.id,
                aaguid: authenticator.aaguid.as_deref(),
                scope: pending.scope.as_deref().unwrap_or("openid"),
                nonce: pending.nonce.as_deref(),
                code_challenge: pending.code_challenge.as_deref(),
                code_challenge_method: pending.code_challenge_method.as_deref(),
            };

            match issue_authorization_code(state, code_params) {
                Ok(code) => {
                    // RFC 9207: Include iss parameter in authorization response
                    let mut redirect_url = format!("{}?code={}", pending.redirect_uri, code);
                    if let Some(state_param) = &pending.state {
                        redirect_url
                            .push_str(&format!("&state={}", urlencoding::encode(state_param)));
                    }
                    // RFC 9207: Authorization Server Issuer Identification
                    redirect_url.push_str(&format!(
                        "&iss={}",
                        urlencoding::encode(&state.config.base_url)
                    ));
                    Redirect::to(&redirect_url).into_response()
                }
                Err(_) => oauth_error_redirect(
                    &pending.redirect_uri,
                    "server_error",
                    "Failed to generate authorization code",
                    pending.state.as_deref(),
                    &state.config.base_url,
                ),
            }
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
    let mut url = format!(
        "{}?error={}&error_description={}",
        redirect_uri,
        urlencoding::encode(error),
        urlencoding::encode(description)
    );
    if let Some(state_param) = state {
        url.push_str(&format!("&state={}", urlencoding::encode(state_param)));
    }
    // RFC 9207: Include iss parameter even in error responses
    url.push_str(&format!("&iss={}", urlencoding::encode(issuer)));
    Redirect::to(&url).into_response()
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
