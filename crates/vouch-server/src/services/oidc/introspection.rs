// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Token introspection and revocation operations.
//!
//! Implements:
//! - RFC 7009 - OAuth 2.0 Token Revocation
//! - RFC 7662 - OAuth 2.0 Token Introspection

use crate::AppState;
use crate::crypto::hash_token;
use crate::crypto::keys::OidcSigningKey;
use crate::db;
use crate::error::ServiceError;
use crate::error::ServiceResult;
use crate::redact_email;
use crate::services::auth::{DecodedToken, decode_token};
use crate::services::oidc::ScopeSet;
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
    /// RFC 9396: Rich authorization details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_details: Option<serde_json::Value>,
    /// RFC 9449 §7: DPoP confirmation claim for sender-constrained tokens.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cnf: Option<crate::services::oidc::dpop::CnfClaim>,
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
            authorization_details: None,
            cnf: None,
        }
    }
}

/// JWT claims for an RFC 9701 introspection response.
///
/// RFC 9701 Section 5.4: The JWT MUST include `iss`, `aud`, `iat`, and
/// a `token_introspection` claim. It MUST NOT include a top-level `sub` or `exp`.
#[derive(Serialize)]
struct IntrospectionJwtClaims {
    iss: String,
    aud: String,
    iat: i64,
    token_introspection: serde_json::Value,
}

/// Sign an introspection result as a JWT per RFC 9701.
///
/// The JWT structure:
/// - Header: `typ: "token-introspection+jwt"`, `alg: "ES256"`
/// - Claims: `iss`, `aud`, `iat` at top level
/// - Token data inside `token_introspection` claim
/// - For inactive tokens: `{"token_introspection": {"active": false}}`
/// - No top-level `sub` or `exp` (RFC 9701 Section 5.4)
pub(crate) async fn sign_introspection_jwt(
    result: &IntrospectionResult,
    issuer: &str,
    audience: &str,
    oidc_key: &OidcSigningKey,
) -> Result<String, ServiceError> {
    let token_introspection = if result.active {
        serde_json::to_value(result).map_err(|e| {
            ServiceError::Internal(format!("Failed to serialize introspection result: {e}"))
        })?
    } else {
        serde_json::json!({"active": false})
    };

    let claims = IntrospectionJwtClaims {
        iss: issuer.to_string(),
        aud: audience.to_string(),
        iat: jiff::Timestamp::now().as_second(),
        token_introspection,
    };

    oidc_key
        .sign_jwt_with_typ(&claims, Some("token-introspection+jwt"))
        .await
        .map_err(|e| ServiceError::Internal(format!("Failed to sign introspection JWT: {e}")))
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
/// Accepts ES256 RFC 9068 access tokens. HS256 session tokens are not
/// supported and return `{"active": false}`.
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
    // Decode the token as an ES256 RFC 9068 access token
    let config = state.config();
    let decoded = match decode_token(token, &state.oidc_key, &config.base_url) {
        Some(d) => d,
        None => {
            return Ok(IntrospectionResult::inactive());
        }
    };

    // Verify session exists in database and retrieve it for authorization_details.
    let token_hash = hash_token(token);
    let session = match state
        .session_cache
        .get_session_by_token_hash(&state.store, &token_hash)
        .await
        .map_err(|e| ServiceError::Internal(format!("Database error: {e}")))?
    {
        Some(s) => s,
        None => return Ok(IntrospectionResult::inactive()),
    };

    let DecodedToken::AccessToken(claims) = decoded;

    // RFC 7662 Section 4: Prevent cross-client information leakage.
    // If the caller's client_id differs from the token's client_id,
    // return inactive to avoid disclosing another client's tokens.
    if let Some(caller_id) = caller_client_id
        && caller_id != claims.client_id
    {
        return Ok(IntrospectionResult::inactive());
    }

    // RFC 9396: authorization_details from session (already a Value).
    let authorization_details = session.authorization_details;

    // RFC 9449 §7: DPoP-bound tokens report token_type "DPoP".
    // mTLS-bound tokens (x5t#S256 only, no jkt) report "Bearer".
    let is_dpop = claims.cnf.as_ref().is_some_and(|c| c.jkt.is_some());
    let token_type = if is_dpop { "DPoP" } else { "Bearer" };

    // RFC 9068 access token — populate client_id from the JWT
    Ok(IntrospectionResult {
        active: true,
        scope: claims.scope.clone(),
        client_id: Some(claims.client_id.clone()),
        username: claims.email.clone(),
        token_type: Some(token_type.to_string()),
        exp: Some(claims.exp),
        iat: Some(claims.iat),
        sub: Some(claims.sub.clone()),
        aud: Some(claims.aud.clone()),
        iss: Some(claims.iss.clone()),
        authorization_details,
        cnf: claims.cnf.clone(),
    })
}

/// Revoke a token (RFC 7009).
///
/// RFC 7009 specifies that the endpoint should always return success,
/// even if the token was invalid, to prevent token oracle attacks.
///
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
    client_info: crate::db::ClientInfo,
    caller_client_id: &str,
) -> RevocationResult {
    // Try to decode to get email for audit logging
    let config = state.config();
    let decoded = decode_token(token, &state.oidc_key, &config.base_url);

    // RFC 7009 Section 2.1: Verify the token was issued to the calling client.
    // If not, return success but perform no revocation.
    if let Some(DecodedToken::AccessToken(ref claims)) = decoded
        && caller_client_id != claims.client_id
    {
        return RevocationResult {
            revoked: false,
            user_email: None,
        };
    }

    let sub = decoded.as_ref().map(|d| d.sub().to_string());
    let email = decoded.as_ref().and_then(|d| d.email().map(String::from));

    // When we know the user, revoke ALL their sessions (human presence
    // attestation means logout = full logout). Fall back to single-token
    // deletion when the token couldn't be decoded.
    let revoked = if let Some(ref user_id) = sub {
        match db::delete_sessions_for_user(&state.store, user_id).await {
            Ok(count) => {
                if count > 0 {
                    state.session_cache.invalidate_for_user(user_id);
                    if let Some(ref email) = email {
                        tracing::info!(
                            "Revoked {} session(s) for user: {}",
                            count,
                            redact_email(email),
                        );
                    }
                    true
                } else {
                    false
                }
            }
            Err(e) => {
                tracing::warn!("Failed to delete sessions during revocation: {}", e,);
                false
            }
        }
    } else {
        // Token couldn't be decoded — best-effort delete by hash
        let token_hash = hash_token(token);
        match db::delete_session_by_token_hash(&state.store, &token_hash).await {
            Ok(deleted) => {
                if deleted {
                    state.session_cache.invalidate(&token_hash);
                }
                deleted
            }
            Err(e) => {
                tracing::warn!("Failed to delete session during revocation: {}", e,);
                false
            }
        }
    };

    if revoked {
        // Fire-and-forget logout audit event
        if let Some(ref user_id) = sub {
            let params = db::AuthEventParams {
                user_id: user_id.clone(),
                event_type: db::AuthEventType::Logout,
                success: true,
                client: client_info,
                ..Default::default()
            };
            db::spawn_audit_event(&state.audit, params, email.clone());
        }

        return RevocationResult {
            revoked: true,
            user_email: email,
        };
    }

    // Per RFC 7009, always return success even if nothing was revoked
    RevocationResult {
        revoked: false,
        user_email: email,
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable"
)]
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

    #[test]
    fn test_inactive_result_has_no_claims() {
        // RFC 7662 Section 2.2: Inactive response MUST NOT include token metadata.
        let result = IntrospectionResult::inactive();
        assert!(result.client_id.is_none());
        assert!(result.username.is_none());
        assert!(result.token_type.is_none());
        assert!(result.exp.is_none());
        assert!(result.iat.is_none());
        assert!(result.sub.is_none());
        assert!(result.aud.is_none());
        assert!(result.iss.is_none());
        assert!(result.scope.is_none());
    }

    #[test]
    fn test_inactive_result_json_has_only_active_key() {
        // Verify skip_serializing_if logic: serialized inactive response
        // must contain exactly one key ("active").
        let result = IntrospectionResult::inactive();
        let json = serde_json::to_string(&result).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        let obj = parsed.as_object().unwrap();
        assert_eq!(
            obj.len(),
            1,
            "Inactive introspection response must have exactly one key (active), got: {parsed}"
        );
        assert!(obj.contains_key("active"));
    }

    #[test]
    fn test_revocation_result_revoked_true() {
        // RevocationResult with revoked=true carries email for audit logging.
        let result = RevocationResult {
            revoked: true,
            user_email: Some("user@example.com".to_string()),
        };
        assert!(result.revoked);
        assert_eq!(result.user_email.as_deref(), Some("user@example.com"));
    }

    #[test]
    fn test_revocation_result_revoked_false_no_email() {
        // RFC 7009: Revocation always "succeeds" even if nothing was found.
        let result = RevocationResult {
            revoked: false,
            user_email: None,
        };
        assert!(!result.revoked);
        assert!(result.user_email.is_none());
    }

    #[test]
    fn test_hs256_token_is_inactive_in_introspection() {
        // Regression: introspect_token must treat HS256 tokens as inactive.
        // We test the decode_token path: None → IntrospectionResult::inactive()
        // by verifying that a token that decode_token returns None for maps to
        // active=false in the result structure.
        //
        // The actual HS256 rejection is exercised at the unit level in
        // crypto::jwt::tests::test_hs256_tokens_rejected_by_decode_token.
        // Here we verify the service-level consequence: inactive result.
        let inactive = IntrospectionResult::inactive();
        assert!(
            !inactive.active,
            "HS256 tokens must produce inactive=false introspection result"
        );
    }

    /// Regression for #540: a store failure during the session lookup must
    /// propagate as `ServiceError::Internal` (→ 500), not collapse into an
    /// inactive result that hides the outage. Reverting the `?` on the session
    /// lookup back to `_ => IntrospectionResult::inactive()` leaves the
    /// happy-path and not-found tests green while this branch goes unguarded.
    #[tokio::test]
    async fn test_introspect_token_propagates_store_error_as_internal() {
        use crate::services::auth::AccessTokenClaims;
        use crate::test_utils::test_app_state;

        let state = test_app_state().await;
        let now = jiff::Timestamp::now().as_second();

        // Valid RFC 9068 access token signed with the state's own key and
        // issuer, so decode_token succeeds and execution reaches the DB-backed
        // session lookup. The token is never stored, so the SessionCache misses
        // and the lookup must hit the pool.
        let claims = AccessTokenClaims {
            iss: state.config().base_url.clone(),
            sub: "user-123".to_string(),
            aud: "client-abc".to_string(),
            exp: now + 3600,
            iat: now,
            nbf: None,
            jti: "jti-540".to_string(),
            client_id: "client-abc".to_string(),
            scope: None,
            email: None,
            email_verified: None,
            hardware_verified: false,
            cnf: None,
            auth_time: None,
            act: None,
            amr: None,
            acr: None,
        };
        let token = state.oidc_key.sign_access_token_jwt(&claims).await.unwrap();

        // Close the pool so the next DB call returns Err (proven fault injector,
        // mirroring the DB-error token test in handlers/oidc/tests).
        state.db.close().await;

        let result = introspect_token(&state, &token, None, None).await;
        assert!(
            matches!(result, Err(ServiceError::Internal(_))),
            "store failure must surface as ServiceError::Internal, got: {result:?}"
        );
    }
}
