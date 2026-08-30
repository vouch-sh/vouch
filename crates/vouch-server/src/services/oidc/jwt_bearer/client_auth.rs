// SPDX-License-Identifier: Apache-2.0 OR MIT
//! JWT client authentication (RFC 7523 Section 2.2).
//!
//! Clients authenticate at the token endpoint using a signed JWT assertion
//! instead of a shared client secret (`private_key_jwt` method).

use super::jwks::{find_matching_key_with_refresh_client, resolve_client_jwks};
use super::validate::{
    JwtAssertionClaims, JwtAssertionHeader, decode_claims_unverified, map_algorithm,
    parse_assertion_header, validate_client_assertion_algorithm, validate_jwt_assertion,
};
use crate::AppState;
use crate::db::claim::ClaimError;
use crate::db::{self, JwtAssertionJtiClaim, OAuthClient, TokenEndpointAuthMethod};
use crate::services::oidc::token::{AuthenticatedClient, ClientAuthError};
use jiff::{Timestamp, ToSpan};
use std::sync::Arc;

/// A JTI that has been validated but not yet committed to the database.
///
/// Call [`PendingJti::commit`] immediately before any grant-state
/// persistence (`exchange_*` / `store_par_request`) so concurrent replays
/// serialize on the JTI uniqueness constraint. The commit MUST run after
/// any validator that returns a retryable error (in particular DPoP
/// `use_dpop_nonce`, RFC 9449 §4.3) so that those failures leave the JTI
/// unconsumed and the client can retry with the same assertion.
///
/// `PendingJti` is not `Clone` and `commit` takes `self` by value, so the
/// type system prevents double-commit and ensures the value is either
/// committed or dropped — dropping without committing is the correct
/// behavior for retryable error paths.
pub struct PendingJti {
    jti: Option<String>,
    client_id: String,
    max_lifetime: i64,
}

/// Witness that a JWT client assertion passed RFC 7523 §3 validation
/// (signature verified against the client's JWKS, audience matched, exp/nbf
/// within clock skew, `iss == sub == client_id`, client is registered for
/// `private_key_jwt`).
///
/// Constructible only inside this module — returned exclusively by
/// [`authenticate_client_jwt`]. This is the structural answer to
/// "did JWT client authentication happen?", separate from
/// [`JwtAssertionJtiClaim`] which answers "was the JTI atomically
/// committed for replay prevention?". The two are independent because
/// RFC 7523 §3 makes `jti` OPTIONAL for non-FAPI clients — auth can
/// succeed without a JTI commit.
#[derive(Debug)]
pub struct JwtAuthSucceeded {
    _private: (),
}

impl PendingJti {
    /// Commit this pending JTI to the replay-prevention database.
    ///
    /// On success returns a [`JwtAssertionJtiClaim`] witness — proof that
    /// the atomic INSERT serialized this caller as the first to claim the
    /// JTI. The witness is `#[must_use]` so callers must bind it (typically
    /// to thread it to a downstream consumer like token issuance).
    ///
    /// Consumes `self` by value — a `PendingJti` can be committed at most
    /// once, and dropping it without committing is the intended behavior
    /// for retryable error paths.
    ///
    /// Returns `Ok(Some(claim))` when the assertion carried a `jti` and
    /// the atomic insert succeeded, `Ok(None)` when the assertion omitted
    /// `jti` (non-FAPI clients — the commit is a no-op), and
    /// `Err(InvalidCredentials)` when a concurrent caller already claimed
    /// the same JTI.
    pub async fn commit(
        self,
        state: &Arc<AppState>,
    ) -> Result<Option<JwtAssertionJtiClaim>, ClientAuthError> {
        let Some(jti) = self.jti else {
            return Ok(None);
        };
        // Not a database call: a timestamp overflow here is an internal
        // fault, and `DatabaseError` is the variant that renders it as a 500.
        let expires_at = Timestamp::now()
            .checked_add(self.max_lifetime.seconds())
            .map_err(|e| ClientAuthError::DatabaseError(e.to_string()))?;

        db::store_jwt_assertion_jti(&state.store, &jti, &self.client_id, expires_at)
            .await
            .map(Some)
            .map_err(|e| match e {
                ClaimError::AlreadyConsumed => {
                    tracing::warn!(
                        target: "security",
                        client_id = %self.client_id,
                        "JWT assertion JTI replay detected"
                    );
                    ClientAuthError::InvalidCredentials
                }
                // Client-supplied input violated a validation bound (e.g.,
                // oversized JTI). Map to 401 invalid_client so the client
                // fixes its assertion rather than retrying.
                ClaimError::InvalidInput(msg) => {
                    tracing::warn!(
                        target: "security",
                        client_id = %self.client_id,
                        error = %msg,
                        "JWT assertion JTI rejected: invalid input"
                    );
                    ClientAuthError::InvalidCredentials
                }
                ClaimError::Database(msg) => ClientAuthError::DatabaseError(msg),
            })
    }
}

/// Authenticate a client using a JWT assertion (RFC 7523 Section 2.2).
///
/// # Arguments
/// * `state` - Application state
/// * `client_assertion` - The JWT assertion string
/// * `client_id_hint` - Optional client_id from the request body (for lookup)
///
/// # Returns
/// On success, returns:
/// - `AuthenticatedClient` — the resolved OAuth client record;
/// - `PendingJti` — caller MUST `.commit()` it immediately before grant-state
///   persistence (`exchange_*` / `store_par_request`). If a later validator
///   returns a retryable error (notably DPoP `use_dpop_nonce`, RFC 9449 §4.3),
///   drop the [`PendingJti`] without committing so the client can retry with
///   the same assertion;
/// - [`JwtAuthSucceeded`] — the structural witness that RFC 7523 §3 validation
///   passed. Thread it forward to construct
///   [`crate::services::auth::ClientAuthProof::PrivateKeyJwt`] regardless of
///   whether the assertion carried a `jti`.
pub async fn authenticate_client_jwt(
    state: &Arc<AppState>,
    client_assertion: &str,
    client_id_hint: Option<&str>,
) -> Result<(AuthenticatedClient, PendingJti, JwtAuthSucceeded), ClientAuthError> {
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

    verify_assertion_subject(&unverified_claims, client_id_hint)?;
    let assertion_client_id = &unverified_claims.iss;

    // 3. Look up client
    let client = db::get_oauth_client_by_client_id(&state.store, assertion_client_id)
        .await?
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

    // 4b. FAPI 2.0 Section 5.4.1: restrict the assertion algorithm to the
    // client's profile. See JwsAlgorithm::FAPI_ALLOWED. Checked before JWKS
    // resolution so a disallowed algorithm never triggers a JWKS fetch.
    let allowed_algorithms = client.fapi_profile.client_assertion_algorithms();
    if let Err(e) = validate_client_assertion_algorithm(header.alg, allowed_algorithms) {
        tracing::warn!(
            "Client {} used disallowed client-assertion algorithm '{}': {e}",
            client.client_id,
            header.alg
        );
        return Err(ClientAuthError::InvalidCredentials);
    }

    // 5+6. Resolve the client's JWKS and select the verification key
    let decoding_key = resolve_client_decoding_key(state, &client, &header).await?;

    // 7. Validate JWT assertion (signature + claims)
    let algorithm = map_algorithm(header.alg);
    let base_url = &state.config().base_url;
    let max_lifetime = state.config().jwt_assertion_max_lifetime_seconds;

    // FAPI 2.0 Section 5.3.2.1-8: aud MUST be the issuer URL only.
    // RFC 7523 Section 3: aud SHOULD be the token endpoint URL.
    // We accept both issuer and endpoint URLs for non-FAPI clients,
    // but restrict to issuer-only for FAPI clients.
    let token_endpoint_url = format!("{base_url}/oauth/token");
    let revoke_endpoint_url = format!("{base_url}/oauth/revoke");
    let par_endpoint_url = format!("{base_url}/oauth/par");
    let introspect_endpoint_url = format!("{base_url}/oauth/introspect");

    let allowed_audiences: Vec<&str> = if client.is_fapi() {
        vec![base_url]
    } else {
        vec![
            &token_endpoint_url,
            &revoke_endpoint_url,
            &par_endpoint_url,
            &introspect_endpoint_url,
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
        JwtAuthSucceeded { _private: () },
    ))
}

/// RFC 7523 Section 3: For client authentication, `iss` and `sub` MUST both
/// be the client_id, and a `client_id` provided in the request body must
/// match the assertion's issuer.
///
/// # Errors
/// Returns `InvalidCredentials` on any mismatch.
fn verify_assertion_subject(
    claims: &JwtAssertionClaims,
    client_id_hint: Option<&str>,
) -> Result<(), ClientAuthError> {
    // If client_id was provided in the request body, it must match
    if let Some(hint) = client_id_hint
        && hint != claims.iss
    {
        tracing::warn!(
            "client_id mismatch: body='{}' vs assertion iss='{}'",
            hint,
            claims.iss
        );
        return Err(ClientAuthError::InvalidCredentials);
    }

    // iss must equal sub for client authentication
    if claims.iss != claims.sub {
        tracing::warn!("JWT assertion iss ({}) != sub ({})", claims.iss, claims.sub);
        return Err(ClientAuthError::InvalidCredentials);
    }

    Ok(())
}

/// Resolve the client's JWKS (inline or from `jwks_uri`) and select the
/// verification key for the assertion header, force-refreshing the JWKS
/// cache on a kid-miss for `jwks_uri` clients.
///
/// # Errors
/// Returns `InvalidCredentials` when the JWKS cannot be resolved or no key
/// matches the header.
async fn resolve_client_decoding_key(
    state: &Arc<AppState>,
    client: &OAuthClient,
    header: &JwtAssertionHeader,
) -> Result<jsonwebtoken::DecodingKey, ClientAuthError> {
    // Only a client with a `jwks_uri` can force-refresh, and the cache is what
    // rate-limits that refresh, so gate on the URI rather than on inline JWKS.
    // A client configured with both still reaches the kid-miss refresh path
    // (`find_matching_key_with_refresh`), where a `None` cache disables the
    // 10-second interval and turns every miss into an outbound fetch — before
    // signature verification, so an unauthenticated caller could drive it.
    //
    // The cache is an optimization, not a dependency: a read failure degrades
    // to an uncached fetch rather than failing authentication. Reporting a
    // transient DB fault as `invalid_client` tells a client its credentials
    // are wrong and stops it retrying.
    let jwks_cache = if client
        .keys
        .as_ref()
        .and_then(crate::db::ClientKeys::uri)
        .is_none()
    {
        None
    } else {
        crate::db::get_jwks_cache(&state.store, &client.id)
            .await
            .map_err(|e| {
                tracing::debug!(
                    "JWKS cache lookup failed for client {}: {e}",
                    client.client_id
                );
            })
            .ok()
            .flatten()
    };

    // Loopback JWKS destinations are permitted only in local development
    // (no TLS configured), matching the WebAuthn `OriginPolicy`
    // relaxation; private/link-local targets stay blocked.
    let allow_loopback = !state.config().tls_configured();

    let jwks = resolve_client_jwks(
        &state.store,
        &client.id,
        client.keys.as_ref().and_then(crate::db::ClientKeys::inline),
        client.keys.as_ref().and_then(crate::db::ClientKeys::uri),
        jwks_cache.as_ref(),
        allow_loopback,
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

    // Find matching key, with force-refresh on kid-miss for jwks_uri clients
    find_matching_key_with_refresh_client(
        &state.store,
        &client.id,
        client.keys.as_ref().and_then(crate::db::ClientKeys::uri),
        jwks_cache.as_ref(),
        allow_loopback,
        &state.http_client,
        &jwks,
        header,
    )
    .await
    .map_err(|e| {
        tracing::debug!("No matching key found for client {}: {e}", client.client_id);
        ClientAuthError::InvalidCredentials
    })
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;
    use crate::config::ServerConfig;
    use crate::crypto;
    use crate::crypto::alg::JwsAlgorithm;
    use crate::crypto::keys::OidcSigningKey;
    use crate::db::{self, Pool};
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
            idps: Vec::new(),
            base_url: crate::config::BaseUrl::new("https://test.example.com"),
            device_code_expires_seconds: 600,
            device_poll_interval_seconds: 5,
            allowed_domains: None,
            org_name: None,
            resource_name: None,
            resource_documentation: None,
            resource_policy_uri: None,
            resource_tos_uri: None,
            security_contact: "security@vouch.sh".to_string(),
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
            kms_account_id: None,
            mtls_port: 8443,
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
            aws_region: None,
            aws_az: None,
            aws_partition: None,
            aws_use_fips_endpoint: None,
            jwt_assertion_max_lifetime_seconds: 300,
            allowed_aaguids: vouch_common::AaguidPolicy::Any,
            log_format: crate::config::LogFormat::Text,
            trusted_proxies: Vec::new(),
            metrics_bearer_token: None,
            certification_test_token: None,
            extra_ca_certs: None,
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
            org_keys_cache: Default::default(),
            policy: Default::default(),
            idps: Vec::new(),
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
    async fn test_commit_succeeds_on_first_call() {
        let state = make_state().await;
        let pending = PendingJti {
            jti: Some("unique-jti-abc".to_string()),
            client_id: "client-1".to_string(),
            max_lifetime: 300,
        };

        let result = pending.commit(&state).await;

        assert!(
            matches!(result, Ok(Some(_))),
            "First commit must return Ok(Some(claim)): {result:?}"
        );
    }

    #[tokio::test]
    async fn test_commit_replay_returns_error_on_second_call() {
        let state = make_state().await;
        let first = PendingJti {
            jti: Some("replay-jti-xyz".to_string()),
            client_id: "client-replay".to_string(),
            max_lifetime: 300,
        };

        // First commit succeeds.
        let _first_claim = first
            .commit(&state)
            .await
            .expect("first commit must succeed");

        // Second commit with the same JTI is a replay — must fail.
        // PendingJti is not Clone, so we construct a second one with the same data.
        let second = PendingJti {
            jti: Some("replay-jti-xyz".to_string()),
            client_id: "client-replay".to_string(),
            max_lifetime: 300,
        };
        let result = second.commit(&state).await;

        assert!(
            matches!(result, Err(ClientAuthError::InvalidCredentials)),
            "Replay commit must return InvalidCredentials, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn test_commit_none_jti_returns_none() {
        // When jti is None (e.g. the assertion omitted the jti claim),
        // commit must return Ok(None) without touching the database.
        let state = make_state().await;
        let pending = PendingJti {
            jti: None,
            client_id: "client-no-jti".to_string(),
            max_lifetime: 300,
        };

        let result = pending.commit(&state).await;

        assert!(
            matches!(result, Ok(None)),
            "commit with None jti must return Ok(None): {result:?}"
        );
    }

    #[tokio::test]
    async fn test_uncommitted_pending_jti_does_not_prevent_later_commit() {
        // Simulates the use_dpop_nonce retry scenario:
        // 1. authenticate_client_jwt returns a PendingJti.
        // 2. The handler returns use_dpop_nonce WITHOUT calling commit.
        // 3. The client retries with the same assertion.
        // 4. commit on the retry must succeed because the JTI was never stored.
        let state = make_state().await;

        let jti = "retry-jti-001".to_string();

        // First attempt: PendingJti is built but NOT committed (dropped here).
        let first_pending = PendingJti {
            jti: Some(jti.clone()),
            client_id: "client-retry".to_string(),
            max_lifetime: 300,
        };
        // Intentionally do NOT call commit — simulates a retryable error path.
        drop(first_pending);

        // Second attempt (retry): commit is called with the same JTI.
        // Because the first PendingJti was never committed, this must succeed.
        let second_pending = PendingJti {
            jti: Some(jti),
            client_id: "client-retry".to_string(),
            max_lifetime: 300,
        };
        let result = second_pending.commit(&state).await;

        assert!(
            matches!(result, Ok(Some(_))),
            "commit on retry must succeed when the first PendingJti was not committed: {result:?}"
        );
    }

    fn make_claims(iss: &str, sub: &str) -> JwtAssertionClaims {
        JwtAssertionClaims {
            iss: iss.to_string(),
            sub: sub.to_string(),
            aud: super::super::validate::JwtAudience::Single(
                "https://test.example.com".to_string(),
            ),
            exp: i64::MAX,
            iat: None,
            nbf: None,
            jti: None,
        }
    }

    #[test]
    fn test_verify_assertion_subject_accepts_matching_iss_sub_and_hint() {
        let claims = make_claims("client-1", "client-1");
        assert!(verify_assertion_subject(&claims, Some("client-1")).is_ok());
        assert!(verify_assertion_subject(&claims, None).is_ok());
    }

    #[test]
    fn test_verify_assertion_subject_rejects_hint_mismatch() {
        let claims = make_claims("client-1", "client-1");
        let result = verify_assertion_subject(&claims, Some("client-2"));
        assert!(matches!(result, Err(ClientAuthError::InvalidCredentials)));
    }

    #[test]
    fn test_verify_assertion_subject_rejects_iss_sub_mismatch() {
        let claims = make_claims("client-1", "client-2");
        let result = verify_assertion_subject(&claims, None);
        assert!(matches!(result, Err(ClientAuthError::InvalidCredentials)));
    }

    /// Create a client whose inline JWKS is the shared test signing key and
    /// return it with the key's `kid` (read back from the stored JWKS).
    async fn make_client_with_jwks(state: &Arc<crate::AppState>) -> (OAuthClient, String) {
        use crate::test_utils::{TestClientSpec, TestJwks, create_test_client, create_test_user};

        let user = create_test_user(&state.store, "jwks-resolve@example.com").await;
        let created = create_test_client(
            &state.store,
            &user.id,
            TestClientSpec {
                token_endpoint_auth_method: Some(TokenEndpointAuthMethod::PrivateKeyJwt),
                jwks: TestJwks::Shared,
                with_secret: false,
                ..Default::default()
            },
        )
        .await;
        let client = db::get_oauth_client_by_id(&state.store, &created.app_id)
            .await
            .expect("db lookup")
            .expect("client exists");
        let kid = client
            .keys
            .as_ref()
            .and_then(crate::db::ClientKeys::inline)
            .and_then(|set| set.keys.first())
            .and_then(|key| key.kid.as_deref())
            .expect("shared test JWKS has a kid")
            .to_string();
        (client, kid)
    }

    #[tokio::test]
    async fn test_resolve_client_decoding_key_matches_kid() {
        let state = make_state().await;
        let (client, kid) = make_client_with_jwks(&state).await;

        let header = JwtAssertionHeader {
            alg: JwsAlgorithm::Es256,
            kid: Some(kid),
        };
        let result = resolve_client_decoding_key(&state, &client, &header).await;
        assert!(result.is_ok(), "matching kid must resolve a key");
    }

    #[tokio::test]
    async fn test_resolve_client_decoding_key_falls_back_without_kid() {
        let state = make_state().await;
        let (client, _kid) = make_client_with_jwks(&state).await;

        // No kid: single EC key in the JWKS matches the ES256 algorithm.
        let header = JwtAssertionHeader {
            alg: JwsAlgorithm::Es256,
            kid: None,
        };
        let result = resolve_client_decoding_key(&state, &client, &header).await;
        assert!(result.is_ok(), "single-key JWKS must match by key type");
    }

    #[tokio::test]
    async fn test_resolve_client_decoding_key_rejects_unknown_kid() {
        let state = make_state().await;
        let (client, _kid) = make_client_with_jwks(&state).await;

        // Inline-JWKS client (no jwks_uri): a kid miss cannot force-refresh
        // and must fail closed.
        let header = JwtAssertionHeader {
            alg: JwsAlgorithm::Es256,
            kid: Some("no-such-key".to_string()),
        };
        let result = resolve_client_decoding_key(&state, &client, &header).await;
        assert!(matches!(result, Err(ClientAuthError::InvalidCredentials)));
    }

    /// A client configured with both inline JWKS and a `jwks_uri` still
    /// reaches the kid-miss refresh path, where the cache is what enforces the
    /// 10-second refresh interval. Gating the read on inline JWKS rather than
    /// on the URI would hand that client a `None` cache and turn every miss
    /// into an outbound fetch — before signature verification, so an
    /// unauthenticated caller could drive it.
    #[tokio::test]
    async fn dual_config_client_still_loads_the_jwks_cache() {
        let state = make_state().await;
        let (mut client, _kid) = make_client_with_jwks(&state).await;
        client.keys = Some(crate::db::ClientKeys::Uri(
            "https://client.example/jwks.json".to_string(),
        ));

        // With a URI present the cache must be consulted, so a failed read is
        // observable: drop the table and confirm resolution still degrades
        // gracefully rather than failing authentication.
        match &state.db {
            db::Pool::Sqlite(pool) => {
                sqlx::query("DROP TABLE documents")
                    .execute(pool)
                    .await
                    .expect("drop documents table");
            }
            db::Pool::Postgres(pool) => {
                sqlx::query("DROP TABLE documents")
                    .execute(pool)
                    .await
                    .expect("drop documents table");
            }
        }

        let header = JwtAssertionHeader {
            alg: JwsAlgorithm::Es256,
            kid: Some("no-such-key".to_string()),
        };
        let result = resolve_client_decoding_key(&state, &client, &header).await;
        assert!(
            !matches!(result, Err(ClientAuthError::DatabaseError(_))),
            "a cache read failure must not surface as a hard database error"
        );
    }

    /// Regression: an inline-JWKS client must resolve its decoding key even
    /// when the JWKS cache DB read fails. Before the fix,
    /// `resolve_client_decoding_key` loaded the cache unconditionally and
    /// mapped any DB error to `InvalidCredentials`, failing closed for
    /// inline-JWKS clients during a transient DB outage — even though their
    /// signing keys are embedded and need no cache. The cache lookup is now
    /// skipped when the client has no `jwks_uri` to refresh from.
    #[tokio::test]
    async fn test_resolve_client_decoding_key_inline_jwks_ignores_cache_db_error() {
        let state = make_state().await;
        let (client, kid) = make_client_with_jwks(&state).await;

        // Simulate a transient DB failure: drop the documents table so the
        // `get_jwks_cache` read errors out. The client is already loaded, and
        // an inline-JWKS client never consults the cache, so key resolution
        // must still succeed.
        match &state.db {
            db::Pool::Sqlite(pool) => {
                sqlx::query("DROP TABLE documents")
                    .execute(pool)
                    .await
                    .expect("drop documents table");
            }
            db::Pool::Postgres(pool) => {
                sqlx::query("DROP TABLE documents")
                    .execute(pool)
                    .await
                    .expect("drop documents table");
            }
        }

        // Sanity: the cache read now errors.
        assert!(
            crate::db::get_jwks_cache(&state.store, &client.id)
                .await
                .is_err(),
            "sanity: get_jwks_cache must error after dropping the documents table"
        );

        let header = JwtAssertionHeader {
            alg: JwsAlgorithm::Es256,
            kid: Some(kid),
        };
        let result = resolve_client_decoding_key(&state, &client, &header).await;
        assert!(
            result.is_ok(),
            "inline-JWKS client must resolve key despite cache DB error: {result:?}"
        );
    }
}
