// SPDX-License-Identifier: BUSL-1.1
//! Token introspection and revocation operations.
//!
//! Implements:
//! - RFC 7009 - OAuth 2.0 Token Revocation
//! - RFC 7662 - OAuth 2.0 Token Introspection

use crate::AppState;
use crate::db::{self, SessionPurpose};
use crate::handlers::common::hash_token;
use crate::redact_email;
use crate::services::ServiceResult;
use crate::services::auth::{DecodedToken, decode_token};
use crate::services::oidc::scope::ScopeSet;
use serde::Serialize;
use std::sync::Arc;

/// Result of token introspection (RFC 7662 Section 2.2).
#[derive(Debug, Serialize)]
pub struct IntrospectionResult {
    /// RFC 7662 Section 2.2: Whether the token is currently active.
    pub active: bool,
    /// RFC 7662 Section 2.2: Space-separated scope values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<ScopeSet>,
    /// RFC 7662 Section 2.2: Client identifier for the OAuth 2.0 client that requested this token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// RFC 7662 Section 2.2: Human-readable identifier for the resource owner (typically email).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// RFC 7662 Section 2.2: Type of the token (e.g., "Bearer").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
    /// RFC 7662 Section 2.2: Integer timestamp indicating when the token expires.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    /// RFC 7662 Section 2.2: Integer timestamp indicating when the token was issued.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
    /// RFC 7662 Section 2.2: Subject of the token (typically the resource owner).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    /// RFC 7662 Section 2.2: Service-specific string identifying the intended audience.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    /// RFC 7662 Section 2.2: String representing the issuer of the token.
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
/// Supports both HS256 FIDO2 session tokens and ES256 RFC 9068 access tokens
/// via the dual-decode helper.
///
/// # Arguments
/// * `state` - Application state
/// * `token` - The token to introspect
/// * `_token_type_hint` - Optional hint about token type (ignored but included for compatibility)
/// * `caller_client_id` - The authenticated caller's client_id (for `aud` field)
///
/// # Returns
/// Introspection result with token metadata if active, or `{"active": false}` if invalid.
pub async fn introspect_token(
    state: &Arc<AppState>,
    token: &str,
    _token_type_hint: Option<&str>,
    caller_client_id: Option<&str>,
) -> ServiceResult<IntrospectionResult> {
    // Decode the token using the dual-decode helper (HS256 or ES256)
    let config = state.config();
    let decoded = match decode_token(
        token,
        config.jwt_secret_bytes(),
        &state.oidc_key,
        &config.base_url,
    ) {
        Some(d) => d,
        None => {
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

    // Build the introspection response based on the decoded token type
    match &decoded {
        DecodedToken::AccessToken(claims) => {
            // RFC 9068 access token — populate client_id from the JWT
            Ok(IntrospectionResult {
                active: true,
                scope: claims.scope.clone(),
                client_id: Some(claims.client_id.clone()),
                username: claims.email.clone(),
                token_type: Some("Bearer".to_string()),
                exp: Some(claims.exp),
                iat: Some(claims.iat),
                sub: Some(claims.sub.clone()),
                aud: Some(claims.aud.clone()),
                iss: Some(claims.iss.clone()),
            })
        }
        DecodedToken::Session(claims) => {
            // FIDO2 session token — backward compat
            let scope: Option<ScopeSet> = match &claims.scope {
                Some(s) if !s.is_empty() => Some(s.clone()),
                Some(_) => None,
                // Backward compat: OAuth tokens issued before scope tracking
                None if claims.purpose == SessionPurpose::OAuthAccessToken => Some(ScopeSet::all()),
                None => None,
            };

            Ok(IntrospectionResult {
                active: true,
                scope,
                client_id: None, // Session tokens don't track originating client_id
                username: Some(claims.email.clone()),
                token_type: Some("Bearer".to_string()),
                exp: Some(claims.exp),
                iat: Some(claims.iat),
                sub: Some(claims.sub.clone()),
                aud: caller_client_id.map(String::from),
                iss: Some(state.config().base_url.clone()),
            })
        }
    }
}

/// Revoke a token (RFC 7009).
///
/// RFC 7009 specifies that the endpoint should always return success,
/// even if the token was invalid, to prevent token oracle attacks.
///
/// Supports both HS256 FIDO2 session tokens and ES256 RFC 9068 access tokens.
/// Per RFC 7009, always attempts hash-based DB deletion even if JWT decode fails.
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
    // Try to decode to get email for audit logging
    let config = state.config();
    let decoded = decode_token(
        token,
        config.jwt_secret_bytes(),
        &state.oidc_key,
        &config.base_url,
    );

    let email = decoded.as_ref().and_then(|d| d.email().map(String::from));

    // RFC 7009: Always attempt to delete the session by token hash,
    // even if JWT decode fails — revocation should be best-effort.
    let token_hash = hash_token(token);
    match db::delete_session_by_token_hash(&state.db, &token_hash).await {
        Ok(deleted) => {
            if deleted {
                if let Some(ref email) = email {
                    tracing::info!("Token revoked for user: {}", redact_email(email));
                }
                return RevocationResult {
                    revoked: true,
                    user_email: email,
                };
            }
        }
        Err(e) => {
            tracing::warn!("Failed to delete session during revocation: {}", e);
        }
    }

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
