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

/// A JTI that has been validated but not yet committed to the database.
///
/// Call [`commit_jti`] after the full request succeeds to prevent replay.
/// If the request fails with a retryable error (e.g., `use_dpop_nonce`),
/// drop this without committing so the client can retry.
pub struct PendingJti {
    jti: Option<String>,
    client_id: String,
    max_lifetime: i64,
}

/// Commit a pending JTI to the replay-prevention database.
///
/// Must be called after the token/PAR request fully succeeds.
pub async fn commit_jti(
    state: &Arc<AppState>,
    pending: &PendingJti,
) -> Result<(), ClientAuthError> {
    let Some(ref jti) = pending.jti else {
        return Ok(());
    };
    let expires_at = Timestamp::now()
        .checked_add(pending.max_lifetime.seconds())
        .unwrap_or_else(|_| Timestamp::now());

    let is_new = db::store_jwt_assertion_jti(&state.store, jti, &pending.client_id, expires_at)
        .await
        .map_err(|e| ClientAuthError::DatabaseError(e.to_string()))?;

    if !is_new {
        tracing::warn!(
            target: "security",
            client_id = %pending.client_id,
            "JWT assertion JTI replay detected"
        );
        return Err(ClientAuthError::InvalidCredentials);
    }
    Ok(())
}

/// Authenticate a client using a JWT assertion (RFC 7523 Section 2.2).
///
/// # Arguments
/// * `state` - Application state
/// * `client_assertion` - The JWT assertion string
/// * `client_id_hint` - Optional client_id from the request body (for lookup)
///
/// # Returns
/// The authenticated client and a pending JTI that MUST be committed
/// via [`commit_jti`] after the request succeeds. If the request fails
/// (e.g., `use_dpop_nonce`), the JTI is NOT consumed and the client
/// can retry with the same assertion.
pub async fn authenticate_client_jwt(
    state: &Arc<AppState>,
    client_assertion: &str,
    client_id_hint: Option<&str>,
) -> Result<(AuthenticatedClient, PendingJti), ClientAuthError> {
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
    let max_lifetime = state.config().jwt_assertion_max_lifetime_seconds;

    // FAPI 2.0 Section 5.3.2.1-8: aud MUST be the issuer URL only.
    // RFC 7523 Section 3: aud SHOULD be the token endpoint URL.
    // We accept both issuer and endpoint URLs for non-FAPI clients,
    // but restrict to issuer-only for FAPI clients.
    let token_endpoint_url = format!("{base_url}/oauth/token");
    let revoke_endpoint_url = format!("{base_url}/oauth/revoke");
    let par_endpoint_url = format!("{base_url}/oauth/par");

    let allowed_audiences: Vec<&str> = if client.is_fapi() {
        vec![base_url]
    } else {
        vec![
            &token_endpoint_url,
            &revoke_endpoint_url,
            &par_endpoint_url,
            base_url,
        ]
    };

    let validated = validate_jwt_assertion(
        client_assertion,
        &header,
        &decoding_key,
        algorithm,
        &allowed_audiences,
        max_lifetime,
    )
    .map_err(|e| {
        tracing::debug!(
            "JWT assertion validation failed for client {}: {e}",
            client.client_id
        );
        ClientAuthError::InvalidCredentials
    })?;

    // 7b. FAPI 2.0 Section 5.3.2.1-8: aud MUST be a single string, not an array.
    if client.is_fapi() && !validated.claims.aud.is_single() {
        tracing::warn!(
            "FAPI 2.0 client {} submitted JWT assertion with array audience",
            client.client_id
        );
        return Err(ClientAuthError::InvalidCredentials);
    }

    // 7c. FAPI 2.0: jti is REQUIRED for replay prevention
    if client.is_fapi() && validated.claims.jti.is_none() {
        tracing::warn!(
            "FAPI 2.0 client {} submitted JWT assertion without jti",
            client.client_id
        );
        return Err(ClientAuthError::InvalidCredentials);
    }

    // 8. Build a PendingJti for the caller to commit after the full
    //    request succeeds. This avoids consuming the JTI on retryable
    //    errors like `use_dpop_nonce`.
    let pending_jti = PendingJti {
        jti: validated.claims.jti.clone(),
        client_id: client.client_id.clone(),
        max_lifetime,
    };

    // Update last used timestamp
    if let Err(e) = db::update_oauth_client_last_used(&state.store, &client.id).await {
        tracing::warn!("Failed to update OAuth client last_used: {e}");
    }

    tracing::info!(
        "Client {} authenticated via private_key_jwt",
        client.client_id
    );

    Ok((
        AuthenticatedClient {
            client,
            is_public: false,
        },
        pending_jti,
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::config::ServerConfig;
    use crate::crypto;
    use crate::db::{self, Pool};
    use crate::services::oidc::OidcSigningKey;
    use arc_swap::ArcSwap;
    use secrecy::SecretString;
    use std::sync::Arc;

    /// Build a minimal `Arc<AppState>` backed by an in-memory SQLite database
    /// with migrations applied.
    ///
    /// Only `state.store` (used by `commit_jti`) is exercised by these tests.
    async fn make_state() -> Arc<crate::AppState> {
        let pool = Pool::connect("sqlite::memory:", &db::pool::PoolConfig::default())
            .await
            .expect("test pool");
        match &pool {
            Pool::Sqlite(p) => sqlx::migrate!("./migrations/sqlite")
                .run(p)
                .await
                .expect("migrations"),
            Pool::Postgres(p) => sqlx::migrate!("./migrations/postgres")
                .run(p)
                .await
                .expect("migrations"),
        }

        let crypto_impl: Arc<dyn crate::crypto::document_crypto::DocumentCrypto> =
            Arc::new(crate::crypto::document_crypto::PlaintextDocumentCrypto);
        let store = db::store::DocumentStore::new(pool.clone(), crypto_impl.clone());
        let audit = db::audit::AuditStore::new(pool.clone(), crypto_impl.clone());

        let config = ServerConfig {
            listen_addr: "127.0.0.1:0".to_string(),
            database_url: "sqlite::memory:".to_string(),
            rp_id: "test.example.com".to_string(),
            rp_name: "Test".to_string(),
            jwt_secret: SecretString::from("test_jwt_secret_must_be_at_least_32_characters_long"),
            session_hours: 8,
            oidc_issuer_url: None,
            oidc_client_id: None,
            oidc_client_secret: None,
            saml_idp_metadata_url: None,
            saml_sp_entity_id: None,
            saml_email_attribute: None,
            saml_domain_attribute: None,
            base_url: "https://test.example.com".to_string(),
            device_code_expires_seconds: 600,
            device_poll_interval_seconds: 5,
            allowed_domains: None,
            org_name: None,
            cli_download_macos: None,
            cli_download_linux: None,
            cli_download_windows: None,
            ssh_ca_key_path: None,
            ssh_ca_key: None,
            ssh_ca_kms_key_id: None,
            oidc_signing_key: None,
            oidc_signing_kms_key_id: None,
            oidc_rsa_signing_key: None,
            oidc_rsa_signing_kms_key_id: None,
            jwt_hmac_kms_key_id: None,
            dpop_max_age_seconds: 300,
            cleanup_interval_minutes: 0,
            auth_events_retention_days: 90,
            oauth_events_retention_days: 30,
            cors_origins: None,
            github_app_id: None,
            github_app_name: None,
            github_app_key: None,
            github_webhook_secret: None,
            github_app_client_id: None,
            github_app_client_secret: None,
            tls_cert: None,
            tls_key: None,
            s3_config_bucket: None,
            s3_config_key: "config/vouch-server.json".to_string(),
            s3_config_region: None,
            s3_config_poll_interval: 60,
            jwt_assertion_max_lifetime_seconds: 300,
            allowed_aaguids: vouch_common::AaguidPolicy::Any,
            require_attestation_cert: false,
            log_format: crate::config::LogFormat::Text,
            trusted_proxies: Vec::new(),
            metrics_bearer_token: None,
            certification_test_token: None,
            pool_config: db::pool::PoolConfig::default(),
            session_cache_max_capacity: 10_000,
            session_cache_ttl_secs: 30,
        };

        let webauthn = webauthn_rs::WebauthnBuilder::new(
            "test.example.com",
            &url::Url::parse("https://test.example.com").unwrap(),
        )
        .unwrap()
        .build()
        .unwrap();

        Arc::new(crate::AppState {
            db: pool,
            store,
            audit,
            config: Arc::new(ArcSwap::from_pointee(config)),
            webauthn,
            ssh_ca: None,
            oidc_key: OidcSigningKey::generate().unwrap(),
            oidc_rsa_key: None,
            state_signer: crypto::jwt::StateTokenSigner::local(
                b"test_jwt_secret_must_be_at_least_32_characters_long".to_vec(),
            ),
            github_app: None,
            http_client: reqwest::Client::new(),
            session_cache: db::SessionCache::new(10_000, 30),
            upstream_idp: None,
        })
    }

    // ========================================================================
    // PendingJti — commit_jti replay prevention
    //
    // The PendingJti pattern delays JTI commitment until after the full
    // request succeeds, so that retryable errors (e.g. use_dpop_nonce) do
    // not consume the JTI and prevent the client from retrying.
    // ========================================================================

    #[tokio::test]
    async fn test_commit_jti_succeeds_on_first_call() {
        let state = make_state().await;
        let pending = PendingJti {
            jti: Some("unique-jti-abc".to_string()),
            client_id: "client-1".to_string(),
            max_lifetime: 300,
        };

        let result = commit_jti(&state, &pending).await;

        assert!(
            result.is_ok(),
            "First commit_jti call must succeed: {result:?}"
        );
    }

    #[tokio::test]
    async fn test_commit_jti_replay_returns_error_on_second_call() {
        let state = make_state().await;
        let pending = PendingJti {
            jti: Some("replay-jti-xyz".to_string()),
            client_id: "client-replay".to_string(),
            max_lifetime: 300,
        };

        // First commit succeeds.
        commit_jti(&state, &pending)
            .await
            .expect("first commit must succeed");

        // Second commit with the same JTI is a replay — must fail.
        let result = commit_jti(&state, &pending).await;

        assert!(
            matches!(result, Err(ClientAuthError::InvalidCredentials)),
            "Replay commit must return InvalidCredentials, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn test_commit_jti_none_jti_is_noop() {
        // When jti is None (e.g. the assertion omitted the jti claim),
        // commit_jti must return Ok without touching the database.
        let state = make_state().await;
        let pending = PendingJti {
            jti: None,
            client_id: "client-no-jti".to_string(),
            max_lifetime: 300,
        };

        let result = commit_jti(&state, &pending).await;

        assert!(
            result.is_ok(),
            "commit_jti with None jti must be a no-op: {result:?}"
        );
    }

    #[tokio::test]
    async fn test_uncommitted_pending_jti_does_not_prevent_later_commit() {
        // Simulates the use_dpop_nonce retry scenario:
        // 1. authenticate_client_jwt returns a PendingJti.
        // 2. The handler returns use_dpop_nonce WITHOUT calling commit_jti.
        // 3. The client retries with the same assertion.
        // 4. commit_jti on the retry must succeed because the JTI was never stored.
        let state = make_state().await;

        let jti = "retry-jti-001".to_string();

        // First attempt: PendingJti is built but NOT committed (dropped here).
        let _first_pending = PendingJti {
            jti: Some(jti.clone()),
            client_id: "client-retry".to_string(),
            max_lifetime: 300,
        };
        // Intentionally do NOT call commit_jti — simulates a retryable error path.
        drop(_first_pending);

        // Second attempt (retry): commit_jti is called with the same JTI.
        // Because the first PendingJti was never committed, this must succeed.
        let second_pending = PendingJti {
            jti: Some(jti),
            client_id: "client-retry".to_string(),
            max_lifetime: 300,
        };
        let result = commit_jti(&state, &second_pending).await;

        assert!(
            result.is_ok(),
            "commit_jti on retry must succeed when the first PendingJti was not committed: {result:?}"
        );
    }
}
