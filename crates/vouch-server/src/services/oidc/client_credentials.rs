// SPDX-License-Identifier: Apache-2.0 OR MIT
//! OAuth 2.0 Client Credentials Grant (RFC 6749 Section 4.4).
//!
//! Allows confidential clients to obtain access tokens using only their
//! client credentials, without any user involvement. Tokens issued via
//! this grant have `hardware_verified: false` and use the client_id as
//! the subject (`sub`) claim per RFC 9068 Section 2.2.
//!
//! Per RFC 6749 Section 4.4.3, no refresh token is included in the response.

use crate::AppState;
use crate::db::{OAuthClient, SessionPurpose};
use crate::services::auth::{CreateOAuthTokenParams, create_oauth_access_token};
use crate::services::oidc::scope::ScopeSet;
use crate::services::{OAuthErrorCode, ServiceError, ServiceResult};
use secrecy::ExposeSecret;
use std::sync::Arc;

/// Result of a client credentials grant exchange.
pub struct ClientCredentialsResult {
    /// The issued access token.
    pub access_token: String,
    /// Token type ("Bearer").
    pub token_type: String,
    /// Expiration in seconds.
    pub expires_in: u64,
    /// Granted scope (None for M2M — openid/email are filtered out).
    pub scope: Option<ScopeSet>,
}

/// Exchange client credentials for an access token (RFC 6749 Section 4.4).
///
/// # Arguments
/// * `state` - Application state
/// * `client` - The authenticated OAuth client
/// * `requested_scope` - Optional scope requested by the client
///
/// # Errors
/// Returns `unauthorized_client` if the client does not have the
/// `client_credentials` grant type registered.
pub async fn exchange_client_credentials(
    state: &Arc<AppState>,
    client: &OAuthClient,
    requested_scope: Option<&str>,
) -> ServiceResult<ClientCredentialsResult> {
    // Verify client has client_credentials in its registered grant_types
    let has_grant = client
        .grant_types
        .as_ref()
        .is_some_and(|gts| gts.iter().any(|g| g == "client_credentials"));
    if !has_grant {
        return Err(ServiceError::oauth(
            OAuthErrorCode::UnauthorizedClient,
            "Client is not authorized for client_credentials grant",
        ));
    }

    // Filter out openid and email scopes — neither is meaningful without a user.
    let scope = requested_scope.map(|s| {
        let requested = ScopeSet::parse(s);
        requested.without_user_scopes()
    });

    // Flatten empty scope to None
    let scope = scope.and_then(|s| if s.is_empty() { None } else { Some(s) });

    // Issue access token with client_id as the subject (RFC 9068 Section 2.2)
    let session_result = create_oauth_access_token(
        state,
        CreateOAuthTokenParams {
            user_id: &client.client_id,
            email: "",
            authenticator_id: None,
            client_id: &client.client_id,
            scope: scope.clone(),
            dpop_jkt: None,
            mtls_cert_thumbprint: None,
            act: None,
            audience: None,
            auth_time: None,
            amr: None,
            acr: None,
            hardware_verified: false,
            session_purpose: SessionPurpose::M2MAccessToken,
            authorization_details: None,
        },
    )
    .await?;

    tracing::info!(
        "Issued client_credentials token for client {}",
        client.client_id
    );

    Ok(ClientCredentialsResult {
        access_token: session_result.token.expose_secret().to_string(),
        token_type: "Bearer".to_string(),
        expires_in: session_result.expires_in,
        scope,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::services::oidc::scope::OAuthScope;

    #[test]
    fn test_scope_filters_openid_and_email() {
        let scope = ScopeSet::parse("openid email");
        let filtered = scope.without_user_scopes();
        assert!(filtered.is_empty());
        assert!(!filtered.contains(OAuthScope::OpenId));
        assert!(!filtered.contains(OAuthScope::Email));
    }

    #[test]
    fn test_scope_empty_when_only_user_scopes() {
        let scope = ScopeSet::parse("openid");
        let filtered = scope.without_user_scopes();
        assert!(filtered.is_empty());
    }
}
