// SPDX-License-Identifier: BUSL-1.1
//! Authorization code flow operations.
//!
//! Implements:
//! - RFC 6749 Section 4.1 - Authorization Code Grant
//! - RFC 7636 - PKCE (Proof Key for Code Exchange)

use crate::AppState;
use crate::db::{AccessScope, Authenticator, OAuthClient, Session, User};
use crate::services::{OAuthErrorCode, ServiceError, ServiceResult};
use jiff::{Span, Timestamp};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, encode};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use super::token::validate_session_token;

/// Parameters for creating an authorization code.
#[derive(Debug)]
pub struct AuthorizationCodeParams<'a> {
    /// The client ID requesting authorization.
    pub client_id: &'a str,
    /// The redirect URI for the response.
    pub redirect_uri: &'a str,
    /// User ID to authorize.
    pub user_id: &'a str,
    /// User email.
    pub email: &'a str,
    /// Authenticator ID used for authentication.
    pub authenticator_id: &'a str,
    /// Authenticator AAGUID.
    pub aaguid: Option<&'a str>,
    /// Requested scope.
    pub scope: &'a str,
    /// OIDC nonce.
    pub nonce: Option<&'a str>,
    /// PKCE code challenge.
    pub code_challenge: Option<&'a str>,
    /// PKCE code challenge method.
    pub code_challenge_method: Option<&'a str>,
}

/// Authorization request parameters (from query string).
#[derive(Debug)]
pub struct AuthorizeRequestParams {
    /// Response type (must be "code").
    pub response_type: String,
    /// Client ID.
    pub client_id: String,
    /// Redirect URI.
    pub redirect_uri: String,
    /// Requested scope.
    pub scope: Option<String>,
    /// State parameter (opaque to server).
    pub state: Option<String>,
    /// OIDC nonce.
    pub nonce: Option<String>,
    /// PKCE code challenge.
    pub code_challenge: Option<String>,
    /// PKCE code challenge method.
    pub code_challenge_method: Option<String>,
}

/// Validated authorization request ready for code issuance.
#[derive(Debug)]
pub struct ValidatedAuthRequest {
    /// Client ID.
    pub client_id: String,
    /// Redirect URI.
    pub redirect_uri: String,
    /// Requested scope.
    pub scope: String,
    /// State parameter.
    pub state: Option<String>,
    /// OIDC nonce.
    pub nonce: Option<String>,
    /// PKCE code challenge.
    pub code_challenge: Option<String>,
    /// PKCE code challenge method.
    pub code_challenge_method: Option<String>,
}

/// Result of checking session state for authorization.
pub enum AuthorizationSessionState {
    /// User is authenticated with valid session.
    Authenticated {
        /// The authenticated user.
        user: Box<User>,
        /// The session.
        session: Box<Session>,
        /// The authenticator used.
        authenticator: Box<Authenticator>,
    },
    /// User needs to authenticate.
    NeedsAuth,
}

/// Authorization code stored temporarily (JWT-encoded).
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthorizationCode {
    pub client_id: String,
    pub redirect_uri: String,
    pub user_id: String,
    pub email: String,
    pub authenticator_id: String,
    pub aaguid: Option<String>,
    pub scope: String,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub iat: i64,
    pub exp: i64,
}

impl AuthorizationCode {
    /// Encode the authorization code as a JWT.
    pub fn encode(&self, secret: &str) -> Result<String, jsonwebtoken::errors::Error> {
        encode(
            &Header::default(),
            self,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
    }

    /// Decode an authorization code from a JWT.
    pub fn decode(token: &str, secret: &str) -> Result<Self, jsonwebtoken::errors::Error> {
        let mut validation = Validation::default();
        validation.required_spec_claims.clear();
        let data = jsonwebtoken::decode::<Self>(
            token,
            &DecodingKey::from_secret(secret.as_bytes()),
            &validation,
        )?;
        Ok(data.claims)
    }
}

/// Validate an authorization request.
///
/// # Arguments
/// * `params` - The authorization request parameters
///
/// # Returns
/// A validated request ready for code issuance, or an error.
///
/// # Errors
/// Returns `ServiceError::OAuth` for invalid requests.
pub fn validate_authorize_request(
    params: AuthorizeRequestParams,
) -> ServiceResult<ValidatedAuthRequest> {
    // RFC 6749 Section 4.1.1: response_type must be "code"
    if params.response_type != "code" {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidRequest,
            "Only 'code' response type is supported",
        ));
    }

    // Validate redirect_uri is present
    if params.redirect_uri.is_empty() {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidRequest,
            "redirect_uri is required",
        ));
    }

    // Validate client_id is present
    if params.client_id.is_empty() {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidRequest,
            "client_id is required",
        ));
    }

    Ok(ValidatedAuthRequest {
        client_id: params.client_id,
        redirect_uri: params.redirect_uri,
        scope: params.scope.unwrap_or_else(|| "openid".to_string()),
        state: params.state,
        nonce: params.nonce,
        code_challenge: params.code_challenge,
        code_challenge_method: params.code_challenge_method,
    })
}

/// Check if the user has a valid session for authorization.
///
/// # Arguments
/// * `state` - Application state
/// * `session_token` - The session token from cookie
///
/// # Returns
/// The session state (authenticated or needs auth).
pub async fn check_session_for_authorization(
    state: &Arc<AppState>,
    session_token: Option<&str>,
) -> ServiceResult<AuthorizationSessionState> {
    let Some(token) = session_token else {
        return Ok(AuthorizationSessionState::NeedsAuth);
    };

    match validate_session_token(state, token).await? {
        Some((user, session, authenticator)) => Ok(AuthorizationSessionState::Authenticated {
            user: Box::new(user),
            session: Box::new(session),
            authenticator: Box::new(authenticator),
        }),
        None => Ok(AuthorizationSessionState::NeedsAuth),
    }
}

/// Issue an authorization code for a validated request.
///
/// # Arguments
/// * `state` - Application state
/// * `params` - Parameters for the authorization code
///
/// # Returns
/// The encoded authorization code (JWT).
///
/// # Errors
/// Returns `ServiceError` if encoding fails.
pub fn issue_authorization_code(
    state: &Arc<AppState>,
    params: AuthorizationCodeParams<'_>,
) -> ServiceResult<String> {
    let now = Timestamp::now();
    let exp = now
        .checked_add(Span::new().minutes(5))
        .map(|t| t.as_second())
        .unwrap_or(now.as_second() + 300);

    let auth_code = AuthorizationCode {
        client_id: params.client_id.to_string(),
        redirect_uri: params.redirect_uri.to_string(),
        user_id: params.user_id.to_string(),
        email: params.email.to_string(),
        authenticator_id: params.authenticator_id.to_string(),
        aaguid: params.aaguid.map(String::from),
        scope: params.scope.to_string(),
        nonce: params.nonce.map(String::from),
        code_challenge: params.code_challenge.map(String::from),
        code_challenge_method: params.code_challenge_method.map(String::from),
        iat: now.as_second(),
        exp,
    };

    auth_code
        .encode(state.config.jwt_secret.expose_secret())
        .map_err(|e| {
            tracing::error!("Failed to encode authorization code: {}", e);
            ServiceError::Internal("Failed to generate authorization code".to_string())
        })
}

/// Decode and validate an authorization code.
///
/// # Arguments
/// * `state` - Application state
/// * `code` - The encoded authorization code
///
/// # Returns
/// The decoded authorization code.
///
/// # Errors
/// Returns `ServiceError::OAuth` with `invalid_grant` if the code is invalid or expired.
pub fn decode_authorization_code(
    state: &Arc<AppState>,
    code: &str,
) -> ServiceResult<AuthorizationCode> {
    let auth_code = AuthorizationCode::decode(code, state.config.jwt_secret.expose_secret())
        .map_err(|_| {
            ServiceError::oauth(
                OAuthErrorCode::InvalidGrant,
                "Invalid or expired authorization code",
            )
        })?;

    // Check expiration
    let now = Timestamp::now().as_second();
    if auth_code.exp < now {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidGrant,
            "Authorization code has expired",
        ));
    }

    Ok(auth_code)
}

// ============================================================================
// Access Control
// ============================================================================

/// Check if a user has access to an OAuth client based on its access scope.
///
/// # Arguments
/// * `client` - The OAuth client to check access for
/// * `user` - The user attempting to access the client
///
/// # Returns
/// `Ok(())` if the user has access, or an appropriate error.
///
/// # Access Rules
/// - **Public**: Any authenticated Vouch user can access
/// - **Personal**: Only the application creator can access
/// - **Organization**: Only users in the same organization can access
pub fn check_client_access(client: &OAuthClient, user: &User) -> ServiceResult<()> {
    let access_scope = client.get_access_scope();

    match access_scope {
        AccessScope::Public => {
            // Any authenticated user can access public apps
            Ok(())
        }
        AccessScope::Personal => {
            // Only the creator can access personal apps
            if user.id == client.user_id {
                Ok(())
            } else {
                Err(ServiceError::oauth(
                    OAuthErrorCode::AccessDenied,
                    "You don't have access to this application",
                ))
            }
        }
        AccessScope::Organization => {
            // User must be in the same organization as the app
            match (&client.org_id, &user.org_id) {
                (Some(app_org), Some(user_org)) if app_org == user_org => Ok(()),
                (Some(_), Some(_)) => {
                    // Different organizations
                    Err(ServiceError::oauth(
                        OAuthErrorCode::AccessDenied,
                        "This application is only available to members of a different organization",
                    ))
                }
                (Some(_), None) => {
                    // User has no organization
                    Err(ServiceError::oauth(
                        OAuthErrorCode::AccessDenied,
                        "This application requires organization membership",
                    ))
                }
                (None, _) => {
                    // App has no org_id (shouldn't happen for org-scoped apps, but handle gracefully)
                    // Fall back to personal scope behavior
                    if user.id == client.user_id {
                        Ok(())
                    } else {
                        Err(ServiceError::oauth(
                            OAuthErrorCode::AccessDenied,
                            "You don't have access to this application",
                        ))
                    }
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use jiff_sqlx::ToSqlx;

    // Helper to create a test OAuthClient
    fn test_client(user_id: &str, access_scope: &str, org_id: Option<&str>) -> OAuthClient {
        let ts = jiff::Timestamp::now().to_sqlx();
        OAuthClient {
            id: "client-1".to_string(),
            user_id: user_id.to_string(),
            client_id: "test-client-id".to_string(),
            name: "Test App".to_string(),
            description: None,
            application_type: "web".to_string(),
            redirect_uris: "[]".to_string(),
            active: true,
            created_at: ts,
            updated_at: ts,
            last_used_at: None,
            access_scope: access_scope.to_string(),
            org_id: org_id.map(String::from),
        }
    }

    // Helper to create a test User
    fn test_user(id: &str, org_id: Option<&str>) -> User {
        User {
            id: id.to_string(),
            email: format!("{}@example.com", id),
            name: Some("Test User".to_string()),
            org_id: org_id.map(String::from),
            is_org_admin: false,
        }
    }

    #[test]
    fn test_validate_authorize_request_valid() {
        let params = AuthorizeRequestParams {
            response_type: "code".to_string(),
            client_id: "test-client".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            scope: Some("openid email".to_string()),
            state: Some("abc123".to_string()),
            nonce: Some("nonce123".to_string()),
            code_challenge: Some("challenge".to_string()),
            code_challenge_method: Some("S256".to_string()),
        };

        let result = validate_authorize_request(params);
        assert!(result.is_ok());
        let validated = result.unwrap();
        assert_eq!(validated.client_id, "test-client");
        assert_eq!(validated.scope, "openid email");
    }

    #[test]
    fn test_validate_authorize_request_invalid_response_type() {
        let params = AuthorizeRequestParams {
            response_type: "token".to_string(),
            client_id: "test-client".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            scope: None,
            state: None,
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
        };

        let result = validate_authorize_request(params);
        assert!(result.is_err());
        match result.unwrap_err() {
            ServiceError::OAuth { code, .. } => {
                assert_eq!(code, OAuthErrorCode::InvalidRequest);
            }
            _ => panic!("Expected OAuth error"),
        }
    }

    #[test]
    fn test_validate_authorize_request_missing_client_id() {
        let params = AuthorizeRequestParams {
            response_type: "code".to_string(),
            client_id: "".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            scope: None,
            state: None,
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
        };

        let result = validate_authorize_request(params);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_authorize_request_default_scope() {
        let params = AuthorizeRequestParams {
            response_type: "code".to_string(),
            client_id: "test-client".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            scope: None, // No scope provided
            state: None,
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
        };

        let result = validate_authorize_request(params);
        assert!(result.is_ok());
        let validated = result.unwrap();
        assert_eq!(validated.scope, "openid"); // Default scope
    }

    // =========================================================================
    // Access Control Tests
    // =========================================================================

    #[test]
    fn test_access_check_public_allows_anyone() {
        let client = test_client("user-1", "public", None);
        let user = test_user("user-2", None); // Different user

        let result = check_client_access(&client, &user);
        assert!(result.is_ok());
    }

    #[test]
    fn test_access_check_personal_allows_only_creator() {
        let client = test_client("user-1", "personal", None);
        let creator = test_user("user-1", None);

        let result = check_client_access(&client, &creator);
        assert!(result.is_ok());
    }

    #[test]
    fn test_access_check_personal_denies_others() {
        let client = test_client("user-1", "personal", None);
        let other_user = test_user("user-2", None);

        let result = check_client_access(&client, &other_user);
        assert!(result.is_err());
        match result.unwrap_err() {
            ServiceError::OAuth { code, .. } => {
                assert_eq!(code, OAuthErrorCode::AccessDenied);
            }
            _ => panic!("Expected OAuth AccessDenied error"),
        }
    }

    #[test]
    fn test_access_check_organization_allows_same_org() {
        let client = test_client("user-1", "organization", Some("org-1"));
        let same_org_user = test_user("user-2", Some("org-1"));

        let result = check_client_access(&client, &same_org_user);
        assert!(result.is_ok());
    }

    #[test]
    fn test_access_check_organization_denies_different_org() {
        let client = test_client("user-1", "organization", Some("org-1"));
        let diff_org_user = test_user("user-2", Some("org-2"));

        let result = check_client_access(&client, &diff_org_user);
        assert!(result.is_err());
        match result.unwrap_err() {
            ServiceError::OAuth { code, .. } => {
                assert_eq!(code, OAuthErrorCode::AccessDenied);
            }
            _ => panic!("Expected OAuth AccessDenied error"),
        }
    }

    #[test]
    fn test_access_check_organization_denies_no_org_user() {
        let client = test_client("user-1", "organization", Some("org-1"));
        let no_org_user = test_user("user-2", None);

        let result = check_client_access(&client, &no_org_user);
        assert!(result.is_err());
        match result.unwrap_err() {
            ServiceError::OAuth { code, .. } => {
                assert_eq!(code, OAuthErrorCode::AccessDenied);
            }
            _ => panic!("Expected OAuth AccessDenied error"),
        }
    }

    #[test]
    fn test_access_check_organization_creator_in_same_org() {
        // Creator should also have access if they're in the same org
        let client = test_client("user-1", "organization", Some("org-1"));
        let creator = test_user("user-1", Some("org-1"));

        let result = check_client_access(&client, &creator);
        assert!(result.is_ok());
    }
}
