// SPDX-License-Identifier: BUSL-1.1
//! Authorization endpoint handler.

use crate::AppState;
use crate::db;
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

/// Authorization page template.
#[derive(Template)]
#[template(path = "authorize.html")]
pub struct AuthorizeTemplate {
    pub client_id: String,
    pub client_name: Option<String>,
    pub is_org_app: bool,
    pub org_name: Option<String>,
}

/// Access denied error template.
#[derive(Template)]
#[template(path = "authorize_denied.html")]
pub struct AuthorizeDeniedTemplate {
    pub client_name: String,
    pub error_message: String,
}

impl_template_response!(AuthorizeTemplate, AuthorizeDeniedTemplate);

/// Authorization request query parameters.
#[derive(Debug, Deserialize)]
pub struct AuthorizeQuery {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    scope: Option<String>,
    state: Option<String>,
    nonce: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
}

/// GET /oauth/authorize
///
/// Authorization endpoint - redirects user to login if not authenticated,
/// then issues an authorization code to the redirect_uri.
pub async fn authorize(
    State(state): State<Arc<AppState>>,
    Query(params): Query<AuthorizeQuery>,
    jar: CookieJar,
) -> Response {
    // Validate the authorization request
    let request_params = AuthorizeRequestParams {
        response_type: params.response_type,
        client_id: params.client_id.clone(),
        redirect_uri: params.redirect_uri.clone(),
        scope: params.scope.clone(),
        state: params.state.clone(),
        nonce: params.nonce.clone(),
        code_challenge: params.code_challenge.clone(),
        code_challenge_method: params.code_challenge_method.clone(),
    };

    let validated = match validate_authorize_request(request_params) {
        Ok(v) => v,
        Err(_) => {
            return Redirect::to(&format!(
                "{}?error=unsupported_response_type&error_description=Only%20code%20response%20type%20is%20supported",
                params.redirect_uri
            ))
            .into_response();
        }
    };

    // Look up the OAuth client to get app details for display and access check
    let oauth_client =
        match db::get_oauth_client_by_client_id(&state.db, &validated.client_id).await {
            Ok(Some(client)) => client,
            Ok(None) => {
                return Redirect::to(&format!(
                    "{}?error=invalid_client&error_description=Unknown%20client_id",
                    validated.redirect_uri
                ))
                .into_response();
            }
            Err(_) => {
                return Redirect::to(&format!(
                    "{}?error=server_error&error_description=Database%20error",
                    validated.redirect_uri
                ))
                .into_response();
            }
        };

    // Get organization name for org-scoped apps
    let org_name: Option<String> = if let Some(ref org_id) = oauth_client.org_id {
        match db::get_org_by_id(&state.db, org_id).await {
            Ok(Some(org)) => org.name,
            _ => None,
        }
    } else {
        None
    };

    let is_org_app = oauth_client.get_access_scope() == db::AccessScope::Organization;

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
                // Access denied - show error page
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
                    let mut redirect_url = format!("{}?code={}", validated.redirect_uri, code);
                    if let Some(state_param) = &validated.state {
                        redirect_url
                            .push_str(&format!("&state={}", urlencoding::encode(state_param)));
                    }
                    Redirect::to(&redirect_url).into_response()
                }
                Err(_) => Redirect::to(&format!(
                    "{}?error=server_error&error_description=Failed%20to%20generate%20authorization%20code",
                    validated.redirect_uri
                ))
                .into_response(),
            }
        }
        Ok(AuthorizationSessionState::NeedsAuth) | Err(_) => {
            // No valid session - show login page
            AuthorizeTemplate {
                client_id: params.client_id,
                client_name: Some(oauth_client.name),
                is_org_app,
                org_name,
            }
            .into_response()
        }
    }
}
