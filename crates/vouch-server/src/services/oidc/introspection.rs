// SPDX-License-Identifier: BUSL-1.1
//! Token introspection and revocation operations.
//!
//! Implements:
//! - RFC 7009 - OAuth 2.0 Token Revocation
//! - RFC 7662 - OAuth 2.0 Token Introspection

use crate::AppState;
use crate::db;
use crate::handlers::hash_token;
use crate::redact_email;
use crate::services::ServiceResult;
use crate::services::auth::SessionClaims;
use jsonwebtoken::{DecodingKey, Validation};
use serde::Serialize;
use std::sync::Arc;

/// Result of token introspection.
#[derive(Debug, Serialize)]
pub struct IntrospectionResult {
    /// Whether the token is active.
    pub active: bool,
    /// Token scope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Client ID that requested the token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// Username (typically email).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Token type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
    /// Expiration time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    /// Issued at time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
    /// Subject.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    /// Audience.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    /// Issuer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
}

impl IntrospectionResult {
    /// Create an inactive introspection result.
    ///
    /// RFC 7662 Section 2.2: Inactive tokens should return minimal response
    /// to prevent information leakage.
    #[must_use]
    pub fn inactive() -> Self {
        Self {
            active: false,
            scope: None,
            client_id: None,
            username: None,
            token_type: None,
            exp: None,
            iat: None,
            sub: None,
            aud: None,
            iss: None,
        }
    }
}

/// Result of token revocation.
#[derive(Debug)]
pub struct RevocationResult {
    /// Whether a token was actually revoked.
    pub revoked: bool,
    /// The email of the user whose token was revoked (for logging).
    pub user_email: Option<String>,
}

/// Introspect a token (RFC 7662).
///
/// # Arguments
/// * `state` - Application state
/// * `token` - The token to introspect
/// * `_token_type_hint` - Optional hint about token type (ignored but included for compatibility)
///
/// # Returns
/// Introspection result with token metadata if active, or `{"active": false}` if invalid.
pub async fn introspect_token(
    state: &Arc<AppState>,
    token: &str,
    _token_type_hint: Option<&str>,
) -> ServiceResult<IntrospectionResult> {
    // Try to decode the token as a JWT
    let claims = match jsonwebtoken::decode::<SessionClaims>(
        token,
        &DecodingKey::from_secret(state.config().jwt_secret_bytes()),
        &Validation::default(),
    ) {
        Ok(data) => data.claims,
        Err(_) => {
            return Ok(IntrospectionResult::inactive());
        }
    };

    // Verify session exists in database
    let token_hash = hash_token(token);
    let session_exists = matches!(
        db::get_session_by_token_hash(&state.db, &token_hash).await,
        Ok(Some(_))
    );

    if !session_exists {
        return Ok(IntrospectionResult::inactive());
    }

    // Token is valid - return active response with claims
    Ok(IntrospectionResult {
        active: true,
        scope: Some("openid email profile".to_string()),
        client_id: None,
        username: Some(claims.email.clone()),
        token_type: Some("Bearer".to_string()),
        exp: Some(claims.exp),
        iat: Some(claims.iat),
        sub: Some(claims.email),
        aud: None,
        iss: Some(state.config().base_url.clone()),
    })
}

/// Revoke a token (RFC 7009).
///
/// RFC 7009 specifies that the endpoint should always return success,
/// even if the token was invalid, to prevent token oracle attacks.
///
/// # Arguments
/// * `state` - Application state
/// * `token` - The token to revoke
/// * `_token_type_hint` - Optional hint about token type (ignored but included for compatibility)
///
/// # Returns
/// Revocation result (always succeeds per RFC 7009).
pub async fn revoke_token(
    state: &Arc<AppState>,
    token: &str,
    _token_type_hint: Option<&str>,
) -> RevocationResult {
    // Try to decode the token as a JWT to get session info
    let email = if let Ok(data) = jsonwebtoken::decode::<SessionClaims>(
        token,
        &DecodingKey::from_secret(state.config().jwt_secret_bytes()),
        &Validation::default(),
    ) {
        // Hash the token and delete the session
        let token_hash = hash_token(token);
        match db::delete_session_by_token_hash(&state.db, &token_hash).await {
            Ok(deleted) => {
                if deleted {
                    tracing::info!(
                        "Token revoked for user: {}",
                        redact_email(&data.claims.email)
                    );
                    return RevocationResult {
                        revoked: true,
                        user_email: Some(data.claims.email),
                    };
                }
            }
            Err(e) => {
                tracing::warn!("Failed to delete session during revocation: {}", e);
            }
        }
        Some(data.claims.email)
    } else {
        None
    };

    // Per RFC 7009, always return success even if nothing was revoked
    RevocationResult {
        revoked: false,
        user_email: email,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_inactive_result() {
        let result = IntrospectionResult::inactive();
        assert!(!result.active);
        assert!(result.scope.is_none());
        assert!(result.exp.is_none());
        assert!(result.sub.is_none());
    }

    #[test]
    fn test_inactive_result_serialization() {
        let result = IntrospectionResult::inactive();
        let json = serde_json::to_string(&result).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        // Only "active" should be present (others should be skipped)
        assert_eq!(parsed["active"], false);
        // None values should not be serialized
        assert!(parsed.get("exp").is_none());
        assert!(parsed.get("sub").is_none());
    }
}
