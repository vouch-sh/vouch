// SPDX-License-Identifier: BUSL-1.1
//! Token exchange operations (RFC 8693).
//!
//! Implements:
//! - RFC 8693 - OAuth 2.0 Token Exchange

use crate::AppState;
use crate::crypto::hash_token;
use crate::db;
use crate::redact_email;
use crate::services::auth::{
    ActorClaim, CreateOAuthTokenParams, MAX_DELEGATION_DEPTH, create_oauth_access_token,
    decode_token,
};
use crate::services::oidc::scope::ScopeSet;
use crate::services::{OAuthErrorCode, ServiceError, ServiceResult};
use jiff::Timestamp;
use secrecy::ExposeSecret;
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

/// Parameters for token exchange (RFC 8693 Section 2.1).
#[derive(Debug)]
pub struct TokenExchangeParams<'a> {
    /// RFC 8693 Section 2.1: The subject token (REQUIRED).
    pub subject_token: &'a str,
    /// RFC 8693 Section 2.1: An identifier for the type of the subject token (REQUIRED).
    pub subject_token_type: &'a str,
    /// RFC 8693 Section 2.1: Optional actor token for delegation chains.
    pub actor_token: Option<&'a str>,
    /// RFC 8693 Section 2.1: An identifier for the type of the actor token.
    pub actor_token_type: Option<&'a str>,
    /// RFC 8693 Section 2.1: The logical name of the target service (OPTIONAL).
    pub audience: Option<&'a str>,
    /// RFC 8693 Section 2.1: The requested scope for the new token (OPTIONAL).
    pub scope: Option<&'a str>,
    /// RFC 8693 Section 2.1: The desired type of the requested security token (OPTIONAL).
    pub requested_token_type: Option<&'a str>,
    /// OAuth client_id of the requesting client.
    pub client_id: &'a str,
    /// RFC 9449: DPoP JWK thumbprint for sender-constrained token binding.
    pub dpop_jkt: Option<&'a str>,
}

/// Result of a token exchange (RFC 8693 Section 2.2).
#[derive(Debug)]
pub struct TokenExchangeResult {
    /// The security token issued by the authorization server.
    pub access_token: String,
    /// RFC 8693 Section 2.2.1: The type of the issued security token.
    pub issued_token_type: String,
    /// RFC 6749 Section 7.1: The type of the token issued (e.g., "Bearer").
    pub token_type: String,
    /// The lifetime in seconds of the access token.
    pub expires_in: u64,
    /// RFC 8693 Section 2.2: Granted scope (may be subset of requested).
    pub scope: Option<ScopeSet>,
}

/// Exchange a token for a new token (RFC 8693).
///
/// Supports both HS256 FIDO2 session tokens and ES256 OAuth access tokens
/// as subject tokens via the dual-decode helper.
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

    // RFC 8693 Section 2.1: Validate requested_token_type if provided
    if let Some(requested_type) = params.requested_token_type
        && !valid_token_types.contains(&requested_type)
    {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidRequest,
            "Unsupported requested_token_type",
        ));
    }

    // Decode and validate the subject token (supports both HS256 and ES256)
    let config = state.config();
    let subject_decoded = decode_token(params.subject_token, &state.oidc_key, &config.base_url)
        .ok_or_else(|| {
            ServiceError::oauth(
                OAuthErrorCode::InvalidGrant,
                "Invalid or expired subject token",
            )
        })?;

    // Verify the subject token's session exists
    let subject_token_hash = hash_token(params.subject_token);
    let subject_session = db::get_session_by_token_hash(&state.store, &subject_token_hash)
        .await
        .map_err(|e| ServiceError::Internal(format!("Database error: {e}")))?
        .ok_or_else(|| {
            ServiceError::oauth(
                OAuthErrorCode::InvalidGrant,
                "Subject token session not found",
            )
        })?;

    // Look up the user to get the email for delegation policy checks and
    // the exchanged token. For access tokens, the email may not be in the
    // JWT (e.g., when only "openid" scope was granted), so we always use
    // the canonical email from the user record.
    let subject_user = db::get_user_by_id(&state.store, &subject_session.user_id)
        .await
        .map_err(|e| ServiceError::Internal(format!("Database error: {e}")))?
        .ok_or_else(|| {
            ServiceError::oauth(OAuthErrorCode::InvalidGrant, "Subject token user not found")
        })?;
    let subject_email = &subject_user.email;

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

        // Decode actor token (supports both HS256 and ES256)
        let actor_decoded = decode_token(actor_token, &state.oidc_key, &config.base_url)
            .ok_or_else(|| {
                ServiceError::oauth(OAuthErrorCode::InvalidGrant, "Invalid actor token")
            })?;

        // Block self-delegation: actor and subject must be different users
        if actor_decoded.sub() == subject_decoded.sub() {
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidRequest,
                "Self-delegation is not permitted",
            ));
        }

        // Verify the actor token's session exists in the database
        let actor_token_hash = hash_token(actor_token);
        if !matches!(
            db::get_session_by_token_hash(&state.store, &actor_token_hash).await,
            Ok(Some(_))
        ) {
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidGrant,
                "Actor token session not found or revoked",
            ));
        }

        // Use email from the token if available, otherwise look up the user
        let actor_email = if let Some(email) = actor_decoded.email() {
            email.to_string()
        } else {
            let actor_user = db::get_user_by_id(&state.store, actor_decoded.sub())
                .await
                .map_err(|e| ServiceError::Internal(format!("Database error: {e}")))?
                .ok_or_else(|| {
                    ServiceError::oauth(OAuthErrorCode::InvalidGrant, "Actor token user not found")
                })?;
            actor_user.email
        };

        // Preserve the existing actor chain from the subject token (if any)
        // to correctly track multi-hop delegation. The new actor wraps the
        // existing chain from the subject token's `act` claim.
        let existing_chain = subject_decoded.act().cloned().map(Box::new);

        let actor = ActorClaim {
            sub: actor_email,
            actor: existing_chain,
        };

        // Check delegation depth limit
        if actor.depth() > MAX_DELEGATION_DEPTH {
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidRequest,
                "Delegation chain exceeds maximum depth",
            ));
        }

        Some(actor)
    } else {
        None
    };

    // Check delegation policy if audience is specified
    let max_ttl_override = if params.audience.is_some() {
        let policy = db::check_delegation_policy(&state.store, subject_email, params.audience)
            .await
            .map_err(|e| ServiceError::Internal(format!("Database error: {e}")))?;

        match policy {
            Some(p) => {
                tracing::debug!(
                    "Token exchange allowed by policy '{}' for {} -> {:?}",
                    p.name,
                    redact_email(subject_email),
                    params.audience
                );
                p.max_ttl_seconds
            }
            None => {
                // No matching policy - check if any policies exist
                let all_policies = db::get_delegation_policies(&state.store)
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

    // Calculate granted scope (intersection of requested and available).
    // For FIDO2 sessions (scope: None), require explicit scope in the request
    // rather than defaulting to ScopeSet::all() to prevent scope escalation.
    let granted_scope = calculate_granted_scope(params.scope, subject_decoded.scope());

    // Calculate expiration with policy TTL limit and subject token remaining TTL.
    // RFC 8693 Section 2.2: The exchanged token's lifetime should not exceed
    // the remaining lifetime of the subject token.
    let default_expires_in = state.config().session_hours * 3600;
    let mut expires_in = match max_ttl_override {
        Some(max_ttl) => {
            let max_ttl_u64 = u64::try_from(max_ttl).map_err(|_| {
                ServiceError::Internal("Delegation policy max_ttl is negative".to_string())
            })?;
            default_expires_in.min(max_ttl_u64)
        }
        None => default_expires_in,
    };

    // Cap by subject token's remaining TTL
    if let Some(subject_exp) = subject_decoded.exp() {
        let now = Timestamp::now().as_second();
        let remaining = subject_exp.saturating_sub(now);
        if remaining > 0
            && let Ok(remaining_u64) = u64::try_from(remaining)
        {
            expires_in = expires_in.min(remaining_u64);
        }
    }

    // RFC 9068: Audience is the explicit audience param (target resource server),
    // falling back to client_id if no audience specified.
    let audience = params.audience;

    // Get authenticator_id from the session record (server-side, not from JWT)
    let authenticator_id = subject_session.authenticator_id.as_deref();

    // Generate the exchanged token as an RFC 9068 access token (ES256)
    let session_result = create_oauth_access_token(
        state,
        CreateOAuthTokenParams {
            user_id: &subject_session.user_id,
            email: subject_email,
            authenticator_id,
            client_id: params.client_id,
            scope: granted_scope.clone(),
            dpop_jkt: params.dpop_jkt,
            act: actor_claim,
            audience,
            // Token exchange does not carry auth_time from the subject token
            auth_time: None,
            // Hardcoded to FIDO2 values because all Vouch authentication flows
            // require hardware keys. Revisit if non-FIDO2 flows are added.
            amr: Some(crate::services::oidc::amr::AuthMethod::all_fido2().to_vec()),
            acr: Some(crate::services::oidc::amr::ACR_AAL3.to_string()),
            hardware_verified: true,
            session_purpose: crate::db::SessionPurpose::OAuthAccessToken,
        },
    )
    .await?;

    // Log the token exchange for audit (best-effort — failures are non-fatal)
    let now = Timestamp::now();
    let issued_token_hash = hash_token(session_result.token.expose_secret());
    let scope_string = granted_scope.as_ref().map(|s| s.to_space_separated());
    let expires_at = if let Ok(expires_seconds) = i64::try_from(expires_in)
        && let Some(exp) = now.as_second().checked_add(expires_seconds)
        && let Ok(ts) = Timestamp::from_second(exp)
    {
        ts
    } else {
        now
    };
    if let Err(e) = db::insert_token_exchange(
        &state.store,
        &subject_session.user_id,
        &subject_token_hash,
        None, // actor_user_id
        &issued_token_hash,
        params.audience,
        scope_string.as_deref(),
        expires_at,
    )
    .await
    {
        tracing::warn!("Failed to log token exchange: {e}");
    }

    tracing::info!(
        "Token exchanged for user {} (audience: {:?})",
        redact_email(subject_email),
        params.audience
    );

    // RFC 9449 Section 5: token_type is "DPoP" when the token is sender-constrained
    let token_type = if params.dpop_jkt.is_some() {
        "DPoP"
    } else {
        "Bearer"
    };

    Ok(TokenExchangeResult {
        access_token: session_result.token.expose_secret().to_string(),
        issued_token_type: token_types::ACCESS_TOKEN.to_string(),
        token_type: token_type.to_string(),
        expires_in,
        scope: granted_scope,
    })
}

/// Calculate the granted scope based on requested and available scopes.
///
/// For FIDO2 sessions (available = `None`), require explicit scope in the
/// exchange request to prevent scope escalation. Only tokens with an
/// explicit scope set propagate their scope.
fn calculate_granted_scope(
    requested: Option<&str>,
    available: Option<&ScopeSet>,
) -> Option<ScopeSet> {
    let available_set = match available {
        Some(s) => s.clone(),
        // FIDO2 sessions don't carry scope — intersect request with all known
        // scopes to prevent escalation beyond what the server supports.
        None => {
            if let Some(requested) = requested {
                let requested_set = ScopeSet::parse(requested);
                let granted = requested_set.intersection(&ScopeSet::all());
                return if granted.is_empty() {
                    None
                } else {
                    Some(granted)
                };
            }
            // No scope in subject token and no explicit request — grant openid only
            return Some(ScopeSet::parse("openid"));
        }
    };

    if let Some(requested) = requested {
        let requested_set = ScopeSet::parse(requested);
        let granted = requested_set.intersection(&available_set);
        if granted.is_empty() {
            None
        } else {
            Some(granted)
        }
    } else if available_set.is_empty() {
        None
    } else {
        Some(available_set)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_granted_scope_with_available() {
        let available = ScopeSet::parse("openid email");
        let result = calculate_granted_scope(None, Some(&available));
        assert_eq!(result, Some(ScopeSet::parse("openid email")));
    }

    #[test]
    fn test_calculate_granted_scope_subset() {
        let available = ScopeSet::parse("openid email profile");
        let result = calculate_granted_scope(Some("openid email"), Some(&available));
        assert_eq!(result, Some(ScopeSet::parse("openid email")));
    }

    #[test]
    fn test_calculate_granted_scope_invalid() {
        let available = ScopeSet::parse("openid");
        let result = calculate_granted_scope(Some("admin superuser"), Some(&available));
        assert_eq!(result, None);
    }

    #[test]
    fn test_calculate_granted_scope_mixed() {
        let available = ScopeSet::parse("openid email");
        let result = calculate_granted_scope(Some("openid admin email"), Some(&available));
        assert_eq!(result, Some(ScopeSet::parse("openid email")));
    }

    #[test]
    fn test_calculate_granted_scope_respects_available() {
        let available = ScopeSet::parse("openid");
        let result = calculate_granted_scope(Some("openid email"), Some(&available));
        assert_eq!(result, Some(ScopeSet::parse("openid")));
    }

    #[test]
    fn test_calculate_granted_scope_no_request_uses_available() {
        let available = ScopeSet::parse("openid");
        let result = calculate_granted_scope(None, Some(&available));
        assert_eq!(result, Some(ScopeSet::parse("openid")));
    }

    #[test]
    fn test_calculate_granted_scope_fido2_no_scope_defaults_openid() {
        // FIDO2 sessions have no scope — should default to openid
        let result = calculate_granted_scope(None, None);
        assert_eq!(result, Some(ScopeSet::parse("openid")));
    }

    #[test]
    fn test_calculate_granted_scope_fido2_with_explicit_request() {
        // FIDO2 sessions with explicit scope request
        let result = calculate_granted_scope(Some("openid email"), None);
        assert_eq!(result, Some(ScopeSet::parse("openid email")));
    }

    #[test]
    fn test_token_type_urns() {
        assert!(token_types::ACCESS_TOKEN.starts_with("urn:ietf:params:oauth:token-type:"));
        assert!(token_types::ID_TOKEN.starts_with("urn:ietf:params:oauth:token-type:"));
        assert!(token_types::JWT.starts_with("urn:ietf:params:oauth:token-type:"));
    }
}
