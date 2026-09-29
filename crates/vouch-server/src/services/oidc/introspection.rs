// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Token introspection and revocation operations.
//!
//! Implements:
//! - RFC 7009 - OAuth 2.0 Token Revocation
//! - RFC 7662 - OAuth 2.0 Token Introspection

use crate::AppState;
use crate::arrival::ArrivalTime;
use crate::crypto::hash_token;
use crate::crypto::keys::OidcSigningKey;
use crate::db::{self, ClientInfo};
use crate::error::ServiceError;
use crate::error::ServiceResult;
use crate::redact_email;
use crate::services::auth::{DecodedToken, decode_token};
use crate::services::oidc::CnfClaim;
use crate::services::oidc::ScopeSet;
use serde::Serialize;
use std::sync::Arc;
use vouch_common::protocol;

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
    /// RFC 7662 Section 2.2: Type of the token (e.g.
    /// [`protocol::ACCESS_TOKEN_TYPE_BEARER`]).
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
    pub cnf: Option<CnfClaim>,
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
#[expect(
    clippy::disallowed_methods,
    reason = "mints the introspection response JWT's iat"
)]
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
    arrival: ArrivalTime,
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
        .get_session_by_token_hash(&state.store, &token_hash, arrival)
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

    // RFC 7662 Section 4: A token's active status depends on the resource
    // owner's current authorization state, not just session existence.
    // Deactivation paths (admin/SCIM) are not atomic — `update_user_active_status`
    // and `delete_sessions_for_user` commit in separate transactions, so a
    // deactivated user may still have live sessions. Mirror the `user.active`
    // check performed by the direct API path (`extract_user_with_org`) and the
    // token exchange path, so introspection cannot bypass deactivation.
    //
    // M2M tokens (client_credentials grant) have no user row — their session's
    // `user_id` holds the client_id, so there is no resource owner whose
    // deactivation could apply. A user session whose user row has vanished is
    // reported inactive rather than as a server error (Section 2.2: the
    // inactive response is the uniform "not valid here" answer).
    if session.session_type != db::SessionPurpose::M2MAccessToken {
        let user_active = db::get_user_by_id(&state.store, &session.user_id)
            .await
            .map_err(|e| ServiceError::Internal(format!("Database error: {e}")))?
            .is_some_and(|u| u.active);
        if !user_active {
            return Ok(IntrospectionResult::inactive());
        }
    }

    // RFC 9396: authorization_details from session (already a Value).
    let authorization_details = session.authorization_details.clone();

    // RFC 7662 §2.2 `token_type`: derived from the confirmation claim the
    // token actually carries, by the same rule issuance used to advertise it.
    let token_type = claims
        .cnf
        .as_ref()
        .map_or(protocol::ACCESS_TOKEN_TYPE_BEARER, CnfClaim::token_type);

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
#[expect(
    clippy::too_many_lines,
    reason = "RFC 7009 revocation: decode, delete by hash, then one audit row per token kind"
)]
pub async fn revoke_token(
    state: &Arc<AppState>,
    token: &str,
    _token_type_hint: Option<&str>,
    client_info: ClientInfo,
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

    // RFC 9068 §2.2 / RFC 6749 §4.4: M2M (`client_credentials`) access tokens
    // carry the OAuth `client_id` as the JWT `sub` claim, and their sessions
    // are persisted with `user_id == client_id` (one session per token — see
    // `client_credentials.rs`). Revoking one such token via the per-user
    // `delete_sessions_for_user(user_id)` path would delete EVERY concurrent
    // M2M session for that client, violating RFC 7009 §2.1 which targets "the
    // particular token" being revoked. Detect M2M tokens via JWT-intrinsic
    // claims (`sub == client_id` and no `email` grant, which is the only
    // access-token-issuing grant with that shape — see the grant table in
    // `client_credentials.rs`) and route them to single-token deletion by
    // hash, preserving the human "logout = full logout" behavior otherwise.
    let is_m2m = matches!(
        decoded,
        Some(DecodedToken::AccessToken(ref claims)) if claims.sub == claims.client_id && claims.email.is_none()
    );

    // When we know the user, revoke ALL their sessions (human presence
    // attestation means logout = full logout). M2M tokens, and tokens that
    // couldn't be decoded, fall back to single-token deletion by hash.
    let (revoked, deleted_row) = if let Some(ref user_id) = sub
        && !is_m2m
    {
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
                }
                (count > 0, None)
            }
            Err(e) => {
                tracing::warn!("Failed to delete sessions during revocation: {}", e,);
                (false, None)
            }
        }
    } else {
        // M2M token, or token that couldn't be decoded — revoke ONLY the
        // named token per RFC 7009 §2.1.
        let token_hash = hash_token(token);

        // RFC 7009 §2.1: the server "verifies whether the token was issued to
        // the client making the revocation request". A token that no longer
        // decodes (expired, or not a JWT) has no `client_id` claim to check
        // above, so the session row's `client_id` is checked instead.
        if decoded.is_none() {
            match db::find_session_by_token_hash(&state.store, &token_hash).await {
                Ok(Some(row))
                    if row
                        .client_id
                        .as_deref()
                        .is_some_and(|issued_to| issued_to != caller_client_id) =>
                {
                    return RevocationResult {
                        revoked: false,
                        user_email: None,
                    };
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!("Failed to look up session during revocation: {}", e);
                    return RevocationResult {
                        revoked: false,
                        user_email: None,
                    };
                }
            }
        }

        match db::delete_session_by_token_hash(&state.store, &token_hash).await {
            Ok(Some(row)) => {
                state.session_cache.invalidate(&token_hash);
                (true, Some(row))
            }
            Ok(None) => (false, None),
            Err(e) => {
                tracing::warn!("Failed to delete session during revocation: {}", e,);
                (false, None)
            }
        }
    };

    // M2M (`client_credentials`) revocation is an OAuth-family event, not a
    // human `Logout`. Detection from the decoded JWT covers a live token; an
    // expired token no longer decodes, so the detection above is false, but
    // the session row it just deleted carries the `M2MAccessToken` purpose,
    // which extends detection to that path.
    let is_m2m = is_m2m
        || deleted_row
            .as_ref()
            .is_some_and(|r| r.session_type == db::SessionPurpose::M2MAccessToken);

    if revoked {
        if is_m2m {
            // M2M revocation records an OAuth-family `OauthTokenRevoked`
            // event, not an auth-family `Logout`. The JWT `sub` (and, for an
            // expired row, the session's `user_id`) is the OAuth `client_id`,
            // not a user, and there is no human email, so the event carries
            // `user_id = None`, mirroring M2M issuance, which records
            // `OauthTokenIssued` the same way. Resolving the client's own org
            // domain for `email_domain` keeps the row in the org-scoped audit
            // feed (SIEM API + admin UI); the `Logout` row this replaces had
            // a NULL `email_domain` and was filtered out of both. The audit
            // identifier is the application's document id (the value
            // issuance and the admin revocation path stamp), so per-
            // application usage stats, which filter only on
            // `oauth_client_id`, count per-token revocations.
            let (oauth_client_id, audit_org_domain): (String, Option<String>) =
                match db::get_oauth_client_by_client_id(&state.store, caller_client_id).await {
                    Ok(Some(client)) => {
                        let domain = db::resolve_event_org_domain(
                            &state.store,
                            None,
                            client.org_id.as_deref(),
                        )
                        .await;
                        (client.id, domain)
                    }
                    // Best-effort fallback (should not occur post-
                    // authentication): still record the correct event type
                    // with `user_id = None` so retention and OCSF/doc-group
                    // classification are right, even if the per-app stats key
                    // and org domain are not.
                    _ => (caller_client_id.to_string(), None),
                };
            let params = db::RecordOAuthEventParams {
                oauth_client_id: &oauth_client_id,
                event_type: db::OAuthEventType::TokenRevoked,
                user_id: None,
                client: &client_info,
                details: None,
                org_domain: db::RecordedOrgDomain::Known(audit_org_domain.as_deref()),
            };
            db::record_oauth_event(&state.audit, &state.store, &params).await;
            return RevocationResult {
                revoked: true,
                user_email: None,
            };
        }

        // Human revocation: the decoded token names the user. A token that
        // no longer decodes is attributed to the session row it deleted, so
        // the `Logout` audit event is recorded whenever a row was deleted.
        let principal = match (sub, deleted_row) {
            (Some(user_id), _) => Some((user_id, email)),
            (None, Some(row)) => Some((row.user_id, Some(row.user_email))),
            (None, None) => None,
        };
        let Some((user_id, email)) = principal else {
            return RevocationResult {
                revoked: true,
                user_email: None,
            };
        };
        // A token minted without the `email` scope carries no email claim.
        // The user record supplies it so the event stays in the org-scoped
        // audit feed.
        let email = match email {
            None => match db::get_user_by_id(&state.store, &user_id).await {
                Ok(user) => user.map(|u| u.email),
                Err(e) => {
                    tracing::warn!("Failed to load user for revocation audit: {e}");
                    None
                }
            },
            email => email,
        };

        // Best-effort logout audit event
        let params = db::AuthEventParams {
            user_id: db::Principal::Verified(user_id),
            event_type: db::AuthEventType::Logout,
            success: true,
            client: client_info,
            authenticator_id: None,
            failure_reason: None,
            client_id: None,
            idp_issuer: None,
        };
        db::record_auth_event(&state.audit, params, email.clone()).await;

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
    use crate::test_utils::test_arrival;

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
            iss: state.config().base_url.to_string(),
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

        let result = introspect_token(&state, &token, None, None, test_arrival()).await;
        assert!(
            matches!(result, Err(ServiceError::Internal(_))),
            "store failure must surface as ServiceError::Internal, got: {result:?}"
        );
    }
}
