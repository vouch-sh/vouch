// SPDX-License-Identifier: Apache-2.0 OR MIT
//! JWT bearer authorization grant (RFC 7523 Section 2.1).
//!
//! A JWT from a trusted external issuer is exchanged directly for a Vouch
//! access token, enabling federated service-to-service auth without
//! browser-based flows.

use super::jwks::{find_matching_key_with_refresh_issuer, resolve_issuer_jwks};
use super::validate::{
    decode_claims_unverified, map_algorithm, parse_assertion_header, validate_jwt_assertion,
};
use crate::AppState;
use crate::db;
use crate::services::auth::{CreateOAuthTokenParams, create_oauth_access_token};
use crate::services::oidc::ScopeSet;
use crate::services::{OAuthErrorCode, ServiceError, ServiceResult};
use jiff::{Timestamp, ToSpan};
use secrecy::ExposeSecret;
use std::sync::Arc;

/// Result of a JWT bearer grant exchange.
#[derive(Debug)]
pub struct JwtBearerGrantResult {
    /// The issued access token.
    pub access_token: String,
    /// Token type ("Bearer").
    pub token_type: String,
    /// Expiration in seconds.
    pub expires_in: u64,
    /// Granted scope.
    pub scope: Option<ScopeSet>,
}

/// Exchange a JWT bearer assertion for a Vouch access token.
///
/// # Arguments
/// * `state` - Application state
/// * `assertion` - The JWT assertion from the trusted issuer
/// * `requested_scope` - Optional scope requested by the client
///
/// # Returns
/// A `JwtBearerGrantResult` containing the issued access token.
pub async fn exchange_jwt_bearer_grant(
    state: &Arc<AppState>,
    assertion: &str,
    requested_scope: Option<&str>,
) -> ServiceResult<JwtBearerGrantResult> {
    // 1. Parse JWT header
    let header = parse_assertion_header(assertion)?;

    // 2. Decode claims without verification to get iss
    let unverified_claims = decode_claims_unverified(assertion)?;

    // 3. Look up trusted issuer by iss
    let issuer = db::get_trusted_jwt_issuer_by_issuer(&state.store, &unverified_claims.iss)
        .await
        .map_err(|e| ServiceError::Internal(format!("Database error: {e}")))?
        .ok_or_else(|| {
            tracing::warn!(
                "JWT bearer grant from unknown issuer: {}",
                unverified_claims.iss
            );
            ServiceError::oauth(
                OAuthErrorCode::InvalidGrant,
                "Unknown or untrusted JWT issuer",
            )
        })?;

    if !issuer.enabled {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidGrant,
            "JWT issuer is disabled",
        ));
    }

    // 4. Resolve issuer's JWKS
    let jwks = resolve_issuer_jwks(
        &state.store,
        &issuer.id,
        &issuer.jwks_uri,
        issuer.jwks_cache.as_ref(),
        issuer.jwks_cached_at.as_deref(),
        &state.http_client,
    )
    .await?;

    // 5. Find matching key, with force-refresh on kid-miss
    let decoding_key = find_matching_key_with_refresh_issuer(
        &state.store,
        &issuer.id,
        &issuer.jwks_uri,
        issuer.jwks_cached_at.as_deref(),
        &state.http_client,
        &jwks,
        &header,
    )
    .await?;

    // 6. Validate JWT assertion (single verification, multiple acceptable audiences)
    let algorithm = map_algorithm(&header.alg)?;
    let config = state.config();
    let base_url = &config.base_url;
    let token_endpoint = format!("{base_url}/oauth/token");

    let validated = validate_jwt_assertion(
        assertion,
        &header,
        &decoding_key,
        algorithm,
        &[base_url, &token_endpoint],
        i64::from(issuer.max_token_lifetime_seconds),
    )?;

    // 7. Cross-check: verified iss must match the trusted issuer we looked up
    if validated.claims.iss != issuer.issuer {
        tracing::warn!(
            "JWT iss mismatch after verification: claims.iss={}, issuer={}",
            validated.claims.iss,
            issuer.issuer
        );
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidGrant,
            "JWT issuer mismatch",
        ));
    }

    // 8. Map subject claim to Vouch user
    let user = match issuer.subject_claim_mapping.as_str() {
        "email" => {
            // sub claim is the user's email
            db::get_user_by_email(&state.store, &validated.claims.sub)
                .await
                .map_err(|e| ServiceError::Internal(format!("Database error: {e}")))?
        }
        "user_id" => db::get_user_by_id(&state.store, &validated.claims.sub)
            .await
            .map_err(|e| ServiceError::Internal(format!("Database error: {e}")))?,
        other => {
            tracing::warn!("Unsupported subject_claim_mapping: {other}");
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidGrant,
                "Unsupported subject claim mapping",
            ));
        }
    };

    let user = user.ok_or_else(|| {
        tracing::warn!(
            "JWT bearer grant: no user found for sub={} with mapping={}",
            validated.claims.sub,
            issuer.subject_claim_mapping
        );
        ServiceError::oauth(OAuthErrorCode::InvalidGrant, "User not found")
    })?;

    // 9. Check JTI for replay (RFC 7523 Section 3)
    //    Deterministic document ID derived from (jti, issuer) ensures the
    //    PRIMARY KEY constraint prevents concurrent duplicate inserts.
    if let Some(ref jti) = validated.claims.jti {
        let max_lifetime = i64::from(issuer.max_token_lifetime_seconds);
        let expires_at = Timestamp::now()
            .checked_add(max_lifetime.seconds())
            .unwrap_or_else(|_| Timestamp::now());

        let is_new = db::store_jwt_assertion_jti(&state.store, jti, &issuer.issuer, expires_at)
            .await
            .map_err(|e| ServiceError::Internal(format!("Database error: {e}")))?;

        if !is_new {
            tracing::warn!(
                target: "security",
                issuer = %issuer.issuer,
                "JWT bearer grant JTI replay detected"
            );
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidGrant,
                "JWT assertion has already been used",
            ));
        }
    }

    // 10. Determine scope
    let scope = compute_granted_scope(requested_scope, issuer.allowed_scopes.as_deref());

    // 11. Issue Vouch access token
    let session_result = create_oauth_access_token(
        state,
        CreateOAuthTokenParams {
            user_id: &user.id,
            email: &user.email,
            authenticator_id: None,
            client_id: &issuer.issuer,
            scope: scope.clone(),
            dpop_jkt: None,
            mtls_cert_thumbprint: None,
            act: None,
            audience: None,
            auth_time: None,
            hardware_verification: crate::services::auth::HardwareVerification::NotVerified,
            session_purpose: crate::db::SessionPurpose::OAuthAccessToken,
            authorization_details: None,
        },
    )
    .await?;

    tracing::info!(
        "Issued JWT bearer grant token for user {} via issuer {}",
        user.id,
        issuer.issuer
    );

    Ok(JwtBearerGrantResult {
        access_token: session_result.token.expose_secret().to_string(),
        token_type: "Bearer".to_string(),
        expires_in: session_result.expires_in,
        scope,
    })
}

/// Compute the granted scope as the intersection of requested and allowed.
fn compute_granted_scope(requested: Option<&str>, allowed: Option<&str>) -> Option<ScopeSet> {
    match (requested, allowed) {
        (Some(req), Some(allowed_str)) => {
            let requested_set = ScopeSet::parse(req);
            let allowed_set = ScopeSet::parse(allowed_str);
            Some(requested_set.intersection(&allowed_set))
        }
        (Some(req), None) => {
            tracing::warn!(
                "JWT bearer grant: no allowed_scopes configured, granting all requested scopes"
            );
            Some(ScopeSet::parse(req))
        }
        (None, Some(allowed_str)) => Some(ScopeSet::parse(allowed_str)),
        (None, None) => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::compute_granted_scope;
    use crate::services::oidc::OAuthScope;

    #[test]
    fn test_compute_granted_scope_intersection() {
        // Both provided: returns intersection of requested and allowed.
        let result = compute_granted_scope(Some("openid email"), Some("openid"));
        let scope = result.unwrap();
        assert!(scope.contains(OAuthScope::OpenId));
        assert!(!scope.contains(OAuthScope::Email));
    }

    #[test]
    fn test_compute_granted_scope_no_allowed_grants_all() {
        // allowed=None: returns all requested scopes.
        let result = compute_granted_scope(Some("openid email"), None);
        let scope = result.unwrap();
        assert!(scope.contains(OAuthScope::OpenId));
        assert!(scope.contains(OAuthScope::Email));
    }

    #[test]
    fn test_compute_granted_scope_no_requested_returns_allowed() {
        // requested=None: returns all allowed scopes.
        let result = compute_granted_scope(None, Some("openid email"));
        let scope = result.unwrap();
        assert!(scope.contains(OAuthScope::OpenId));
        assert!(scope.contains(OAuthScope::Email));
    }

    #[test]
    fn test_compute_granted_scope_both_none() {
        // Both None: returns None.
        let result = compute_granted_scope(None, None);
        assert!(result.is_none());
    }

    #[test]
    fn test_compute_granted_scope_no_overlap() {
        // Disjoint sets: intersection is empty.
        // "openid" requested, "email" allowed — no overlap.
        let result = compute_granted_scope(Some("openid"), Some("email"));
        let scope = result.unwrap();
        assert!(scope.is_empty());
        assert!(!scope.contains(OAuthScope::OpenId));
        assert!(!scope.contains(OAuthScope::Email));
    }
}
