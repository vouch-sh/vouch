// SPDX-License-Identifier: BUSL-1.1
//! Token exchange operations (RFC 8693).
//!
//! Implements:
//! - RFC 8693 - OAuth 2.0 Token Exchange

use crate::AppState;
use crate::db;
use crate::handlers::hash_token;
use crate::services::auth::SessionClaims;
use crate::services::{OAuthErrorCode, ServiceError, ServiceResult};
use jiff::Timestamp;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, encode};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;

/// Token type URNs for RFC 8693.
pub mod token_types {
    /// Access token type.
    pub const ACCESS_TOKEN: &str = "urn:ietf:params:oauth:token-type:access_token";
    /// ID token type.
    pub const ID_TOKEN: &str = "urn:ietf:params:oauth:token-type:id_token";
    /// JWT type.
    pub const JWT: &str = "urn:ietf:params:oauth:token-type:jwt";
}

/// Parameters for token exchange.
#[derive(Debug)]
pub struct TokenExchangeParams<'a> {
    /// The subject token to exchange.
    pub subject_token: &'a str,
    /// Type of the subject token.
    pub subject_token_type: &'a str,
    /// Optional actor token (for delegation chains).
    pub actor_token: Option<&'a str>,
    /// Type of the actor token.
    pub actor_token_type: Option<&'a str>,
    /// Requested audience for the new token.
    pub audience: Option<&'a str>,
    /// Requested scope for the new token.
    pub scope: Option<&'a str>,
}

/// Result of a token exchange.
#[derive(Debug)]
pub struct TokenExchangeResult {
    /// The exchanged access token.
    pub access_token: String,
    /// Type of the issued token.
    pub issued_token_type: String,
    /// Token type (typically "Bearer").
    pub token_type: String,
    /// Token expiration in seconds.
    pub expires_in: u64,
    /// Granted scope (may be subset of requested).
    pub scope: Option<String>,
}

/// Actor claim for delegation chains.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActorClaim {
    /// Subject identifier of the actor.
    pub sub: String,
    /// Nested actor (for multi-hop delegation).
    #[serde(rename = "act", skip_serializing_if = "Option::is_none")]
    pub actor: Option<Box<ActorClaim>>,
}

/// Claims for exchanged tokens.
#[derive(Debug, Serialize, Deserialize)]
struct ExchangedTokenClaims {
    /// Subject (original user).
    pub sub: String,
    /// Issuer.
    pub iss: String,
    /// Audience.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    /// Expiration time.
    pub exp: i64,
    /// Issued at time.
    pub iat: i64,
    /// Scope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Actor claim (for delegation).
    #[serde(rename = "act", skip_serializing_if = "Option::is_none")]
    pub actor: Option<ActorClaim>,
    /// Email from original token.
    pub email: String,
}

/// Exchange a token for a new token (RFC 8693).
///
/// # Arguments
/// * `state` - Application state
/// * `params` - Exchange parameters
///
/// # Returns
/// The exchanged token response.
///
/// # Errors
/// Returns `ServiceError` for invalid requests.
#[allow(clippy::too_many_lines)]
pub async fn exchange_token(
    state: &Arc<AppState>,
    params: TokenExchangeParams<'_>,
) -> ServiceResult<TokenExchangeResult> {
    // Validate subject token type
    let valid_token_types = [
        token_types::ACCESS_TOKEN,
        token_types::ID_TOKEN,
        token_types::JWT,
    ];
    if !valid_token_types.contains(&params.subject_token_type) {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidRequest,
            "Unsupported subject_token_type",
        ));
    }

    // Decode and validate the subject token
    let subject_claims = jsonwebtoken::decode::<SessionClaims>(
        params.subject_token,
        &DecodingKey::from_secret(state.config().jwt_secret_bytes()),
        &Validation::default(),
    )
    .map_err(|_| {
        ServiceError::oauth(
            OAuthErrorCode::InvalidGrant,
            "Invalid or expired subject token",
        )
    })?
    .claims;

    // Verify the subject token's session exists
    let subject_token_hash = hash_token(params.subject_token);
    let subject_session = db::get_session_by_token_hash(&state.db, &subject_token_hash)
        .await
        .map_err(|e| ServiceError::Internal(format!("Database error: {e}")))?
        .ok_or_else(|| {
            ServiceError::oauth(
                OAuthErrorCode::InvalidGrant,
                "Subject token session not found",
            )
        })?;

    // Handle actor token if present (for delegation chains)
    let actor_claim = if let Some(actor_token) = params.actor_token {
        // Validate actor token type
        if params.actor_token_type != Some(token_types::ACCESS_TOKEN)
            && params.actor_token_type != Some(token_types::JWT)
        {
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidRequest,
                "Invalid actor_token_type",
            ));
        }

        // Decode actor token
        let actor_claims = jsonwebtoken::decode::<SessionClaims>(
            actor_token,
            &DecodingKey::from_secret(state.config().jwt_secret_bytes()),
            &Validation::default(),
        )
        .map_err(|_| ServiceError::oauth(OAuthErrorCode::InvalidGrant, "Invalid actor token"))?;

        Some(ActorClaim {
            sub: actor_claims.claims.email,
            actor: None, // Could recursively parse nested actors
        })
    } else {
        None
    };

    // Check delegation policy if audience is specified
    let max_ttl_override = if params.audience.is_some() {
        let policy = db::check_delegation_policy(&state.db, &subject_claims.email, params.audience)
            .await
            .map_err(|e| ServiceError::Internal(format!("Database error: {e}")))?;

        match policy {
            Some(p) => {
                tracing::debug!(
                    "Token exchange allowed by policy '{}' for {} -> {:?}",
                    p.name,
                    subject_claims.email,
                    params.audience
                );
                p.max_ttl_seconds
            }
            None => {
                // No matching policy - check if any policies exist
                let all_policies = db::get_delegation_policies(&state.db)
                    .await
                    .unwrap_or_default();

                if all_policies.iter().any(|p| p.enabled) {
                    // Policies exist but none match - deny
                    return Err(ServiceError::oauth(
                        OAuthErrorCode::AccessDenied,
                        "No delegation policy allows this token exchange",
                    ));
                }
                // No policies configured - allow by default (open mode)
                None
            }
        }
    } else {
        None
    };

    // Calculate granted scope (intersection of requested and available)
    let granted_scope = calculate_granted_scope(params.scope);

    // Generate the exchanged token
    let now = Timestamp::now();
    let default_expires_in = state.config().session_hours * 3600;

    // Apply policy TTL limit if specified
    let expires_in = match max_ttl_override {
        Some(max_ttl) => {
            let max_ttl_u64 = u64::try_from(max_ttl).unwrap_or(default_expires_in);
            default_expires_in.min(max_ttl_u64)
        }
        None => default_expires_in,
    };
    let exp = now.as_second() + i64::try_from(expires_in).unwrap_or(28800);

    let exchanged_claims = ExchangedTokenClaims {
        sub: subject_claims.email.clone(),
        iss: state.config().base_url.clone(),
        aud: params.audience.map(String::from),
        exp,
        iat: now.as_second(),
        scope: granted_scope.clone(),
        actor: actor_claim,
        email: subject_claims.email.clone(),
    };

    let exchanged_token = encode(
        &Header::default(),
        &exchanged_claims,
        &EncodingKey::from_secret(state.config().jwt_secret_bytes()),
    )
    .map_err(|e| ServiceError::Internal(format!("Failed to generate token: {e}")))?;

    // Log the token exchange for audit
    let issued_token_hash = hash_token(&exchanged_token);
    if let Err(e) = db::insert_token_exchange(
        &state.db,
        &subject_session.user_id,
        &subject_token_hash,
        None, // actor_user_id
        &issued_token_hash,
        params.audience,
        granted_scope.as_deref(),
        &Timestamp::from_second(exp).unwrap_or(now).to_string(),
    )
    .await
    {
        tracing::warn!("Failed to log token exchange: {e}");
    }

    tracing::info!(
        "Token exchanged for user {} (audience: {:?})",
        subject_claims.email,
        params.audience
    );

    Ok(TokenExchangeResult {
        access_token: exchanged_token,
        issued_token_type: token_types::ACCESS_TOKEN.to_string(),
        token_type: "Bearer".to_string(),
        expires_in,
        scope: granted_scope,
    })
}

/// Calculate the granted scope based on requested and available scopes.
fn calculate_granted_scope(requested: Option<&str>) -> Option<String> {
    let available_scope = "openid email profile";

    if let Some(requested) = requested {
        // Only grant scopes that are both requested and available
        let available: HashSet<&str> = available_scope.split_whitespace().collect();
        let requested_scopes: Vec<&str> = requested
            .split_whitespace()
            .filter(|s| available.contains(s))
            .collect();
        if requested_scopes.is_empty() {
            None
        } else {
            Some(requested_scopes.join(" "))
        }
    } else {
        Some(available_scope.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_granted_scope_full() {
        let result = calculate_granted_scope(None);
        assert_eq!(result, Some("openid email profile".to_string()));
    }

    #[test]
    fn test_calculate_granted_scope_subset() {
        let result = calculate_granted_scope(Some("openid email"));
        assert_eq!(result, Some("openid email".to_string()));
    }

    #[test]
    fn test_calculate_granted_scope_invalid() {
        let result = calculate_granted_scope(Some("admin superuser"));
        assert_eq!(result, None);
    }

    #[test]
    fn test_calculate_granted_scope_mixed() {
        let result = calculate_granted_scope(Some("openid admin email"));
        assert_eq!(result, Some("openid email".to_string()));
    }

    #[test]
    fn test_token_type_urns() {
        assert!(token_types::ACCESS_TOKEN.starts_with("urn:ietf:params:oauth:token-type:"));
        assert!(token_types::ID_TOKEN.starts_with("urn:ietf:params:oauth:token-type:"));
        assert!(token_types::JWT.starts_with("urn:ietf:params:oauth:token-type:"));
    }
}
