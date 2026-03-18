// SPDX-License-Identifier: Apache-2.0 OR MIT
//! JWT client authentication (RFC 7523 Section 2.2).
//!
//! Clients authenticate at the token endpoint using a signed JWT assertion
//! instead of a shared client secret (`private_key_jwt` method).

use super::jwks::{find_matching_key, resolve_client_jwks};
use super::validate::{
    decode_claims_unverified, map_algorithm, parse_assertion_header, validate_jwt_assertion,
};
use crate::AppState;
use crate::db::{self, TokenEndpointAuthMethod};
use crate::services::oidc::token::{AuthenticatedClient, ClientAuthError};
use jiff::{Timestamp, ToSpan};
use std::sync::Arc;

/// Authenticate a client using a JWT assertion (RFC 7523 Section 2.2).
///
/// # Arguments
/// * `state` - Application state
/// * `client_assertion` - The JWT assertion string
/// * `client_id_hint` - Optional client_id from the request body (for lookup)
///
/// # Returns
/// The authenticated client.
pub async fn authenticate_client_jwt(
    state: &Arc<AppState>,
    client_assertion: &str,
    client_id_hint: Option<&str>,
) -> Result<AuthenticatedClient, ClientAuthError> {
    // 1. Parse JWT header to get algorithm and kid
    let header = parse_assertion_header(client_assertion).map_err(|e| {
        tracing::debug!("JWT assertion header parse failed: {e}");
        ClientAuthError::InvalidCredentials
    })?;

    // 2. Decode claims without verification to get iss/sub for client lookup
    let unverified_claims = decode_claims_unverified(client_assertion).map_err(|e| {
        tracing::debug!("JWT assertion claims decode failed: {e}");
        ClientAuthError::InvalidCredentials
    })?;

    // RFC 7523 Section 3: For client authentication, iss and sub MUST be the client_id
    let assertion_client_id = &unverified_claims.iss;

    // If client_id was provided in the request body, it must match
    if let Some(hint) = client_id_hint
        && hint != assertion_client_id
    {
        tracing::warn!(
            "client_id mismatch: body='{}' vs assertion iss='{}'",
            hint,
            assertion_client_id
        );
        return Err(ClientAuthError::InvalidCredentials);
    }

    // iss must equal sub for client authentication
    if unverified_claims.iss != unverified_claims.sub {
        tracing::warn!(
            "JWT assertion iss ({}) != sub ({})",
            unverified_claims.iss,
            unverified_claims.sub
        );
        return Err(ClientAuthError::InvalidCredentials);
    }

    // 3. Look up client
    let client = db::get_oauth_client_by_client_id(&state.store, assertion_client_id)
        .await
        .map_err(|e| ClientAuthError::DatabaseError(e.to_string()))?
        .ok_or(ClientAuthError::InvalidClient)?;

    if !client.active {
        return Err(ClientAuthError::InvalidClient);
    }

    // 4. Verify client is configured for private_key_jwt
    if client.token_endpoint_auth_method != TokenEndpointAuthMethod::PrivateKeyJwt {
        tracing::warn!(
            "Client {} attempted private_key_jwt but is configured for {}",
            client.client_id,
            client.token_endpoint_auth_method.as_str()
        );
        return Err(ClientAuthError::InvalidCredentials);
    }

    // 5. Resolve client's JWKS (inline or from URI)
    let jwks = resolve_client_jwks(
        &state.store,
        &client.id,
        client.jwks.as_ref(),
        client.jwks_uri.as_deref(),
        client.jwks_uri_cache.as_ref(),
        client
            .jwks_uri_cached_at
            .map(|ts| ts.to_string())
            .as_deref(),
        &state.http_client,
    )
    .await
    .map_err(|e| {
        tracing::debug!(
            "JWKS resolution failed for client {}: {e}",
            client.client_id
        );
        ClientAuthError::InvalidCredentials
    })?;

    // 6. Find matching key
    let decoding_key = find_matching_key(&jwks, &header).map_err(|e| {
        tracing::debug!("No matching key found for client {}: {e}", client.client_id);
        ClientAuthError::InvalidCredentials
    })?;

    // 7. Validate JWT assertion (signature + claims)
    let algorithm = map_algorithm(&header.alg).map_err(|_| ClientAuthError::InvalidCredentials)?;
    let base_url = &state.config().base_url;
    let token_endpoint_url = format!("{base_url}/oauth/token");
    let revoke_endpoint_url = format!("{base_url}/oauth/revoke");
    let max_lifetime = state.config().jwt_assertion_max_lifetime_seconds;

    let validated = validate_jwt_assertion(
        client_assertion,
        &header,
        &decoding_key,
        algorithm,
        &[&token_endpoint_url, &revoke_endpoint_url],
        max_lifetime,
    )
    .map_err(|e| {
        tracing::debug!(
            "JWT assertion validation failed for client {}: {e}",
            client.client_id
        );
        ClientAuthError::InvalidCredentials
    })?;

    // 7b. FAPI 2.0: jti is REQUIRED for replay prevention
    if client.is_fapi() && validated.claims.jti.is_none() {
        tracing::warn!(
            "FAPI 2.0 client {} submitted JWT assertion without jti",
            client.client_id
        );
        return Err(ClientAuthError::InvalidCredentials);
    }

    // 8. Check JTI for replay (RFC 7523 Section 3)
    //    Atomic insert with UNIQUE(jti, client_id) prevents TOCTOU races.
    if let Some(ref jti) = validated.claims.jti {
        let expires_at = Timestamp::now()
            .checked_add(max_lifetime.seconds())
            .unwrap_or_else(|_| Timestamp::now());

        let is_new = db::store_jwt_assertion_jti(&state.store, jti, &client.client_id, expires_at)
            .await
            .map_err(|e| ClientAuthError::DatabaseError(e.to_string()))?;

        if !is_new {
            tracing::warn!(
                target: "security",
                client_id = %client.client_id,
                "JWT assertion JTI replay detected"
            );
            return Err(ClientAuthError::InvalidCredentials);
        }
    }

    // Update last used timestamp
    if let Err(e) = db::update_oauth_client_last_used(&state.store, &client.id).await {
        tracing::warn!("Failed to update OAuth client last_used: {e}");
    }

    tracing::info!(
        "Client {} authenticated via private_key_jwt",
        client.client_id
    );

    Ok(AuthenticatedClient {
        client,
        is_public: false,
    })
}
