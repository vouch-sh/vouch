// SPDX-License-Identifier: Apache-2.0 OR MIT
//! JWT client authentication (RFC 7523 Section 2.2).
//!
//! Clients authenticate at the token endpoint using a signed JWT assertion
//! instead of a shared client secret (`private_key_jwt` method).

use super::jwks::{find_matching_key_with_refresh_client, resolve_client_jwks};
use super::validate::{
    CLOCK_SKEW_SECONDS, JwtAssertionClaims, JwtAssertionHeader, decode_claims_unverified,
    map_algorithm, parse_assertion_header, validate_client_assertion_algorithm,
    validate_jwt_assertion,
};
use crate::AppState;
use crate::arrival::ArrivalTime;
use crate::db::claim::ClaimError;
use crate::db::{self, ClientKeys, JwtAssertionJtiClaim, OAuthClient, TokenEndpointAuthMethod};
use crate::services::oidc::token::ClientAuthError;
use jiff::{Timestamp, ToSpan};
use std::sync::Arc;

/// A JTI from a validated assertion, about to be committed to the database.
///
/// [`authenticate_client_jwt`] commits it before returning, so an assertion
/// that authenticates is spent whatever the request's outcome, and
/// concurrent replays serialize on the JTI uniqueness constraint. RFC 7523
/// §3 item 7 (a MAY): "The authorization server MAY ensure that JWTs are
/// not replayed by maintaining the set of used "jti" values for the length
/// of time for which the JWT would be considered valid based on the
/// applicable "exp" instant." The assertion audience is the issuer, shared
/// by every endpoint that accepts one, so a JTI left uncommitted by a
/// rejected request would stay valid at the others.
///
/// The replay-prevention record's retention horizon is derived from the
/// validated assertion's own `exp` claim (see [`PendingJti::commit`]),
/// satisfying RFC 7523 §3 item 7: the used `jti` is retained *"for the
/// length of time for which the JWT would be considered valid based on the
/// applicable `exp` instant"* — which, with the validator's clock-skew
/// tolerance, is `exp + CLOCK_SKEW_SECONDS`. Retaining for `now +
/// max_lifetime` instead would let the record become cleanup-eligible
/// while the validator still accepts the assertion, opening a replay
/// window (see `commit` for the arithmetic).
struct PendingJti {
    jti: Option<String>,
    client_id: String,
    /// The validated assertion's `exp` claim. Only the *validated* `exp` is
    /// safe to retain against: it
    /// has already cleared the `exp - iat ≤ max_lifetime` bound in the
    /// validator, so deriving `expires_at` from it cannot extend the
    /// record beyond what the assertion's own validity permits.
    assertion_exp: Timestamp,
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
    /// JTI.
    ///
    /// Returns `Ok(Some(claim))` when the assertion carried a `jti` and
    /// the atomic insert succeeded, `Ok(None)` when the assertion omitted
    /// `jti` (non-FAPI clients — the commit is a no-op), and
    /// `Err(InvalidCredentials)` when a concurrent caller already claimed
    /// the same JTI.
    ///
    /// # Replay-window invariant (RFC 7523 §3 item 7)
    ///
    /// The record's `expires_at` is set to `assertion_exp +
    /// CLOCK_SKEW_SECONDS`, not `now + max_lifetime`. `assertion_exp` is
    /// the validated `exp` of the assertion that produced this `PendingJti`
    /// — it has already cleared the validator's `exp - iat ≤ max_lifetime`
    /// bound, so this cannot retain the row beyond what the assertion's
    /// own validity permits. The periodic cleanup task deletes rows as
    /// soon as `expires_at < now`, while the validator
    /// ([`validate_jwt_assertion`]) accepts an assertion until `now ≤ exp +
    /// CLOCK_SKEW_SECONDS`. Deriving `expires_at` from `exp` (rather than
    /// from `now + max_lifetime`) keeps the record alive until *at least*
    /// the moment the validator stops accepting the assertion, so a
    /// cleanup tick can never open a window in which a verbatim replay
    /// would re-issue a token. The two `CLOCK_SKEW_SECONDS` terms that
    /// compose the replay-acceptance interval — `exp`-skew at replay time
    /// (the `+ CLOCK_SKEW_SECONDS` below) and `iat`-skew at mint time
    /// (already folded into `exp = iat + lifetime`) — are both covered,
    /// because `exp` is the assertion's actual expiry, not a server-now
    /// proxy that diverges from it.
    async fn commit(
        self,
        state: &Arc<AppState>,
    ) -> Result<Option<JwtAssertionJtiClaim>, ClientAuthError> {
        let Some(jti) = self.jti else {
            return Ok(None);
        };
        // Not a database call: a timestamp overflow here is an internal
        // fault, and `DatabaseError` is the variant that renders it as a 500.
        // `assertion_exp` is the validated `exp`;
        // `CLOCK_SKEW_SECONDS` is the same constant the validator applies
        // to `exp`, so the record outlives the validator's acceptance
        // window exactly.
        let expires_at = self
            .assertion_exp
            .checked_add(CLOCK_SKEW_SECONDS.seconds())
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
/// - `OAuthClient` — the resolved OAuth client record;
/// - the committed [`JwtAssertionJtiClaim`], or `None` when the assertion
///   carried no `jti`. The JTI is spent by the time this returns, so a
///   caller that wants a retryable error to leave the assertion reusable
///   (DPoP `use_dpop_nonce`, RFC 9449 §8) must raise it before calling;
/// - [`JwtAuthSucceeded`] — the structural witness that RFC 7523 §3 validation
///   passed. Thread it forward to construct
///   [`crate::services::auth::ClientAuthProof::PrivateKeyJwt`] regardless of
///   whether the assertion carried a `jti`.
pub async fn authenticate_client_jwt(
    state: &Arc<AppState>,
    client_assertion: &str,
    client_id_hint: Option<&str>,
    arrival: ArrivalTime,
) -> Result<(OAuthClient, Option<JwtAssertionJtiClaim>, JwtAuthSucceeded), ClientAuthError> {
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
    // RFC 7523 Section 3: "The token endpoint URL of the authorization server
    // MAY be used as a value for an "aud" element". Non-FAPI clients may name
    // the issuer or any endpoint that authenticates them; FAPI clients the
    // issuer only.
    let token_endpoint_url = format!("{base_url}/oauth/token");
    let revoke_endpoint_url = format!("{base_url}/oauth/revoke");
    let par_endpoint_url = format!("{base_url}/oauth/par");
    let introspect_endpoint_url = format!("{base_url}/oauth/introspect");
    let device_endpoint_url = format!("{base_url}/oauth/device");
    let fido2_challenge_endpoint_url = format!("{base_url}/oauth/fido2/challenge");

    let allowed_audiences: Vec<&str> = if client.is_fapi() {
        vec![base_url]
    } else {
        vec![
            &token_endpoint_url,
            &revoke_endpoint_url,
            &par_endpoint_url,
            &introspect_endpoint_url,
            &device_endpoint_url,
            &fido2_challenge_endpoint_url,
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
        arrival.timestamp(),
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

    // 8. Spend the JTI. The record's retention horizon is derived from the
    //    validated `exp` (see `PendingJti::commit`), not from
    //    `now + max_lifetime`, so the record outlives the validator's
    //    `exp + CLOCK_SKEW_SECONDS` acceptance window and a cleanup tick can
    //    never open a replay window (RFC 7523 §3 item 7).
    let jti_claim = PendingJti {
        jti: validated.claims.jti.clone(),
        client_id: client.client_id.clone(),
        assertion_exp: validated.claims.exp,
    }
    .commit(state)
    .await?;

    // Update last used timestamp
    if let Err(e) = db::update_oauth_client_last_used(&state.store, &client.id).await {
        tracing::warn!("Failed to update OAuth client last_used: {e}");
    }

    tracing::info!(
        "Client {} authenticated via private_key_jwt",
        client.client_id
    );

    Ok((client, jti_claim, JwtAuthSucceeded { _private: () }))
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
    let jwks_cache = if client.keys.as_ref().and_then(ClientKeys::uri).is_none() {
        None
    } else {
        db::get_jwks_cache(&state.store, &client.id)
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

    let (jwks, origin) = resolve_client_jwks(
        &state.store,
        &client.id,
        client.keys.as_ref().and_then(ClientKeys::inline),
        client.keys.as_ref().and_then(ClientKeys::uri),
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

    // Find matching key, with force-refresh on kid-miss for jwks_uri clients.
    // `origin` threads `resolve_client_jwks`'s fetch report into the kid-miss
    // gate, bounding this path to at most one network fetch per request — the
    // same bound the mTLS self-signed path keeps via its `JwksOrigin::Fetched`
    // gate. Without it, two sequential 5s JWKS fetches can consume the 10s
    // `REQUEST_TIMEOUT` and surface as a bare 408 instead of this function's
    // structured 401 `invalid_client`.
    find_matching_key_with_refresh_client(
        &state.store,
        &client.id,
        client.keys.as_ref().and_then(ClientKeys::uri),
        jwks_cache.as_ref(),
        allow_loopback,
        &state.http_client,
        &jwks,
        header,
        origin,
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
    use crate::config::{BaseUrl, LogFormat, ServerConfig};
    use crate::crypto;
    use crate::crypto::alg::JwsAlgorithm;
    use crate::crypto::document_crypto::{DocumentCrypto, PlaintextDocumentCrypto};
    use crate::crypto::keys::OidcSigningKey;
    use crate::db::documents::jwks_cache::JwksCacheDoc;
    use crate::db::store::DocumentStore;
    use crate::db::{self, ClientKeys, Pool};
    use crate::infra::conn_caps::ConnCapConfig;
    use crate::services::oidc::jwt_bearer::validate::JwtAudience;
    use crate::test_utils::{build_test_app_state_with_http_client, test_tls_acceptor};
    use arc_swap::ArcSwap;
    use secrecy::SecretString;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use vouch_common::AaguidPolicy;

    /// Build a minimal `Arc<AppState>` backed by an in-memory SQLite database
    /// with migrations applied.
    ///
    /// Only `state.store` (used by `PendingJti::commit`) is exercised by these tests.
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

        let crypto_impl: Arc<dyn DocumentCrypto> = Arc::new(PlaintextDocumentCrypto);
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
            base_url: BaseUrl::new("https://test.example.com"),
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
            allowed_aaguids: AaguidPolicy::Any,
            log_format: LogFormat::Text,
            trusted_proxies: Vec::new(),
            proxy_protocol: false,
            connection_caps: ConnCapConfig::DEFAULT,
            metrics_bearer_token: None,
            certification_test_token: None,
            extra_ca_certs: None,
            mtls_client_ca_certs: None,
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
            client_cert_trust: None,
        })
    }

    // ========================================================================
    // PendingJti — replay prevention
    // ========================================================================

    #[tokio::test]
    async fn test_commit_succeeds_on_first_call() {
        let state = make_state().await;
        let pending = PendingJti {
            jti: Some("unique-jti-abc".to_string()),
            client_id: "client-1".to_string(),
            assertion_exp: Timestamp::now().checked_add(300.seconds()).unwrap(),
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
            assertion_exp: Timestamp::now().checked_add(300.seconds()).unwrap(),
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
            assertion_exp: Timestamp::now().checked_add(300.seconds()).unwrap(),
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
            assertion_exp: Timestamp::now().checked_add(300.seconds()).unwrap(),
        };

        let result = pending.commit(&state).await;

        assert!(
            matches!(result, Ok(None)),
            "commit with None jti must return Ok(None): {result:?}"
        );
    }

    // ========================================================================
    // Regression: PendingJti::commit MUST derive `expires_at` from the
    // validated assertion's `exp` (specifically `exp + CLOCK_SKEW_SECONDS`),
    // NOT from `now + max_lifetime`. If it used `now + max_lifetime`, a row
    // committed for an assertion minted near `max_lifetime` could become
    // cleanup-eligible while the validator still accepts the assertion
    // (until `exp + CLOCK_SKEW_SECONDS`), opening a replay window once a
    // cleanup tick lands in that interval (RFC 7523 §3 item 7).
    //
    // This test is deterministic and needs no real-time advance: under the
    // fix, `commit` computes `expires_at` purely from `assertion_exp`, so a
    // commit with a past `exp` yields a past `expires_at` (cleanup-eligible
    // immediately) and a commit with a future `exp` yields a future
    // `expires_at` (not cleanup-eligible).
    // ========================================================================
    #[tokio::test]
    async fn test_commit_expires_at_binds_to_assertion_exp_plus_clock_skew() {
        let state = make_state().await;
        let now = Timestamp::now();

        // (a) Commit a JTI whose `exp` is far in the past. Under the fix the
        // row's `expires_at = exp + CLOCK_SKEW_SECONDS` is also in the past,
        // so cleanup must delete it. Under the bug (`now + max_lifetime`),
        // the row would be `now + 300` seconds in the future and would NOT
        // be deleted — this assertion is the one that inverts under the bug.
        let past = PendingJti {
            jti: Some("exp-bound-jti-past".to_string()),
            client_id: "client-exp-bind".to_string(),
            assertion_exp: now.checked_sub(3600.seconds()).unwrap(),
        };
        let _claim = past.commit(&state).await.expect("past-exp commit succeeds");
        let deleted_past = db::delete_expired_jwt_assertion_jtis(&state.store)
            .await
            .expect("cleanup must not error");
        assert_eq!(
            deleted_past, 1,
            "JTI committed with a past exp MUST be cleanup-eligible — \
             this fails if `expires_at` is computed from `now + max_lifetime` \
             instead of `exp + CLOCK_SKEW_SECONDS` (RFC 7523 §3 item 7)"
        );

        // (b) Commit a JTI whose `exp` is in the future. Under the fix the
        // row's `expires_at = exp + CLOCK_SKEW_SECONDS` is in the future, so
        // cleanup must NOT delete it, and a verbatim replay must still
        // collide on the `(jti, client_id)` PRIMARY KEY.
        let future_exp = now.checked_add(3600.seconds()).unwrap();
        let future = PendingJti {
            jti: Some("exp-bound-jti-future".to_string()),
            client_id: "client-exp-bind".to_string(),
            assertion_exp: future_exp,
        };
        let _claim = future
            .commit(&state)
            .await
            .expect("future-exp commit succeeds");
        let deleted_future = db::delete_expired_jwt_assertion_jtis(&state.store)
            .await
            .expect("cleanup must not error");
        assert_eq!(
            deleted_future, 0,
            "JTI committed with a future exp MUST NOT be cleanup-eligible — \
             this fails if `expires_at` is computed from `now + max_lifetime` \
             (the row would be retained but for the wrong reason, and the \
             replay-window arithmetic would still diverge from `exp`)"
        );

        // The future-exp row is still present, so a verbatim replay must
        // collide.
        let replay = PendingJti {
            jti: Some("exp-bound-jti-future".to_string()),
            client_id: "client-exp-bind".to_string(),
            assertion_exp: future_exp,
        };
        let replayed = replay.commit(&state).await;
        assert!(
            matches!(replayed, Err(ClientAuthError::InvalidCredentials)),
            "Replay of a still-retained JTI must be rejected: {replayed:?}"
        );
    }

    fn make_claims(iss: &str, sub: &str) -> JwtAssertionClaims {
        JwtAssertionClaims {
            iss: iss.to_string(),
            sub: sub.to_string(),
            aud: JwtAudience::Single("https://test.example.com".to_string()),
            exp: Timestamp::MAX,
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
            .and_then(ClientKeys::inline)
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
        client.keys = Some(ClientKeys::Uri(
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
            db::get_jwks_cache(&state.store, &client.id).await.is_err(),
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

    // ========================================================================
    // Regression: the RFC 7523 path must perform at most ONE JWKS fetch per
    // request — the within-request `JwksOrigin::Fetched` gate.
    //
    // Before the fix, a `jwks_uri` client whose cache was past the 1h TTL
    // fetched once in `resolve_client_jwks`, then — on a `kid` miss —
    // force-refreshed AGAIN unconditionally, so two sequential 5s fetches
    // could consume the whole 10s `REQUEST_TIMEOUT` and surface a bare 408
    // instead of the structured 401 `invalid_client` the handler returns.
    //
    // `fetch_jwks` requires `https://`, so a plaintext wiremock server cannot
    // drive this path. These helpers stand up a `tokio-rustls` server on the
    // loopback address (the SSRF guard permits loopback in the test default
    // where TLS is not configured) and count how many connections it accepts
    // — the mutation-killing signal the mTLS sibling test
    // (`test_authenticate_client_mtls_self_signed_skips_retry_when_resolution_already_fetched`)
    // could not assert without a counting harness. Mirrors the TLS pattern in
    // `infra::jwks::tests` and `handlers::oidc::tests::rfc9101`.
    // ========================================================================

    /// P-256 EC key x/y coordinates (base64url, RFC 7517 test vectors) for the
    /// counting test's kid-present JWKS — a parseable, buildable EC key the
    /// kid-miss force-refresh successfully verifies against.
    const EC_X: &str = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU";
    const EC_Y: &str = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0";

    /// A `reqwest` client that performs a real TLS handshake but does not
    /// verify the server certificate, so the loopback mock's self-signed cert
    /// is accepted. Kept off the shared `AppState::http_client` to avoid
    /// weakening any other test's trust store.
    fn https_client_trusting_any_cert() -> reqwest::Client {
        reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("build test https client")
    }

    /// Directly seed a `JwksCacheDoc` at a given age — `db::upsert_jwks_cache`
    /// always stamps `cached_at: now`, so a TTL-boundary test needs this
    /// instead. Mirrors `services::oidc::token::tests::seed_jwks_cache`.
    async fn seed_jwks_cache(
        store: &DocumentStore,
        parent_id: &str,
        value: serde_json::Value,
        age_seconds: i64,
    ) {
        let doc = JwksCacheDoc {
            value,
            cached_at: jiff::Timestamp::now()
                .checked_sub(jiff::SignedDuration::from_secs(age_seconds))
                .expect("cache age must be representable"),
        };
        store
            .upsert(&format!("jwks_cache:{parent_id}"), &doc)
            .await
            .expect("seed jwks cache");
    }

    /// Spawn a loopback HTTPS server that serves `body` on every connection
    /// and counts how many TCP connections it accepts, returning the URL.
    /// Each accepted connection is one JWKS fetch initiated by the handler,
    /// so the counter is the mutation-killing signal: it must read `1` after
    /// a request that, before the fix, performed two sequential fetches.
    async fn spawn_counting_jwks_server(body: String, accepted: Arc<AtomicU64>) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let acceptor = test_tls_acceptor();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback listener");
        let port = listener.local_addr().expect("local_addr").port();
        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n\
             {body}",
            body.len()
        );
        tokio::spawn(async move {
            loop {
                let (stream, _peer) = match listener.accept().await {
                    Ok(s) => s,
                    Err(_) => return,
                };
                accepted.fetch_add(1, Ordering::SeqCst);
                let acceptor = acceptor.clone();
                let response = response.clone();
                tokio::spawn(async move {
                    let mut tls = match acceptor.accept(stream).await {
                        Ok(t) => t,
                        Err(_) => return,
                    };
                    // Drain the (small, body-less) GET so the kernel does not
                    // RST before reqwest reads the response. Bounded so a
                    // misbehaving peer cannot wedge the server task. Named
                    // bindings (not `let _ =`) keep `#[must_use]` results
                    // acknowledged without triggering `let_underscore_must_use`.
                    let mut buf = [0u8; 1024];
                    let _read =
                        tokio::time::timeout(std::time::Duration::from_secs(1), tls.read(&mut buf))
                            .await;
                    let _write = tls.write_all(response.as_bytes()).await;
                    let _shutdown = tls.shutdown().await;
                });
            }
        });
        format!("https://127.0.0.1:{port}/jwks")
    }

    /// Helper: build a `jwks_uri` client pointing at `server_url`, registered
    /// for `private_key_jwt`, with no inline JWKS and no secret.
    async fn make_uri_client(
        state: &Arc<crate::AppState>,
        server_url: String,
        email: &str,
    ) -> OAuthClient {
        use crate::test_utils::{TestClientSpec, create_test_client, create_test_user};
        let user = create_test_user(&state.store, email).await;
        let created = create_test_client(
            &state.store,
            &user.id,
            TestClientSpec {
                token_endpoint_auth_method: Some(TokenEndpointAuthMethod::PrivateKeyJwt),
                jwks_uri: Some(server_url),
                with_secret: false,
                ..Default::default()
            },
        )
        .await;
        db::get_oauth_client_by_id(&state.store, &created.app_id)
            .await
            .expect("db lookup")
            .expect("client exists")
    }

    /// Regression for the RFC 7523 two-fetch race: a `jwks_uri` client whose
    /// cache is past the 1h TTL (so `resolve_client_jwks` fetches — fetch #1)
    /// and whose served JWKS lacks the assertion's `kid` (so `find_matching_key`
    /// misses) must NOT perform a second force-refresh fetch in the same request.
    ///
    /// Before the fix, the kid-miss path unconditionally called `fetch_and_cache`
    /// again, so a host that dribbled both 5s fetches could consume the whole
    /// 10s `REQUEST_TIMEOUT` and surface a bare 408 in place of this function's
    /// structured 401 `invalid_client`. The within-request `JwksOrigin::Fetched`
    /// gate bounds the path to one fetch; this test counts the fetches.
    #[tokio::test]
    async fn resolve_client_decoding_key_bounded_to_one_jwks_fetch() {
        let accepted = Arc::new(AtomicU64::new(0));
        // Kid-less but valid JWKS: fetch #1 succeeds, `find_matching_key`
        // misses, and the gate must skip fetch #2.
        let server_url = spawn_counting_jwks_server(
            serde_json::json!({"keys":[]}).to_string(),
            accepted.clone(),
        )
        .await;

        let http_client = https_client_trusting_any_cert();
        let state = build_test_app_state_with_http_client(Vec::new(), |_| {}, http_client).await;
        let client = make_uri_client(&state, server_url, "counting@example.com").await;

        // Seed a STALE cache (2h old: past the 1h TTL so fetch #1 runs, within
        // the 24h stale window so a failed fetch would still fall back). The
        // seeded value lacks the kid, matching what the server serves. The
        // snapshot `resolve_client_decoding_key` loads HERE is the pre-fetch
        // one, so the 10s rate-limit gate (which reads `cached_at`) does not
        // suppress fetch #2 either — the within-request `JwksOrigin` gate is
        // the only bound, which is exactly the bug scenario.
        seed_jwks_cache(
            &state.store,
            &client.id,
            serde_json::json!({"keys":[]}),
            7200,
        )
        .await;

        let header = JwtAssertionHeader {
            alg: JwsAlgorithm::Es256,
            kid: Some("missing-kid".to_string()),
        };
        let result = resolve_client_decoding_key(&state, &client, &header).await;

        // The kid is absent from every JWKS the path sees, so the terminal
        // result is the structured 401 `invalid_client` — never a 408 (which
        // a dropped handler future would produce).
        assert!(
            matches!(result, Err(ClientAuthError::InvalidCredentials)),
            "a kid-miss must resolve to InvalidCredentials (401), not a transport \
             timeout or other error: {result:?}"
        );
        // The fix's mechanism: exactly one network fetch (fetch #1). Without
        // the gate, the kid-miss force-refresh would issue fetch #2 against
        // the same server, so this counter would read 2.
        let fetches = accepted.load(Ordering::SeqCst);
        assert_eq!(
            fetches, 1,
            "the RFC 7523 path must perform exactly one JWKS fetch per request \
             (got {fetches}); a second fetch can race the 10s REQUEST_TIMEOUT and \
             surface a 408 instead of the structured 401 invalid_client"
        );
    }

    /// Control for the gate above: when `resolve_client_jwks` served the JWKS
    /// from a FRESH cache (`JwksOrigin::NoFetch` — no fetch happened), the
    /// kid-miss force-refresh must STILL proceed, fetching the rotated key
    /// exactly once. This proves the gate only suppresses a redundant SECOND
    /// fetch within a request, not the legitimate single refresh the path
    /// exists for (RFC 7523 key rotation: client signs with a new `kid` before
    /// the server's 1h cache has expired).
    #[tokio::test]
    async fn resolve_client_decoding_key_refreshes_once_when_origin_is_no_fetch() {
        let accepted = Arc::new(AtomicU64::new(0));
        // The server serves the kid the assertion uses; the FRESH cache lacks
        // it, so resolution serves a kid-less set from cache (`NoFetch`), the
        // kid-miss force-refresh fetches the rotated set, and `find_matching_key`
        // finds the key — the happy key-rotation path.
        let server_url = spawn_counting_jwks_server(
            serde_json::json!({
                "keys": [{
                    "kty": "EC",
                    "crv": "P-256",
                    "kid": "missing-kid",
                    "x": EC_X,
                    "y": EC_Y
                }]
            })
            .to_string(),
            accepted.clone(),
        )
        .await;

        let http_client = https_client_trusting_any_cert();
        let state = build_test_app_state_with_http_client(Vec::new(), |_| {}, http_client).await;
        let client = make_uri_client(&state, server_url, "rotating@example.com").await;

        // FRESH cache (60s old: within the 1h TTL) holding a kid-less set —
        // `resolve_client_jwks` serves it from cache (`NoFetch`), so the gate
        // does NOT fire and the force-refresh proceeds.
        seed_jwks_cache(&state.store, &client.id, serde_json::json!({"keys":[]}), 60).await;

        let header = JwtAssertionHeader {
            alg: JwsAlgorithm::Es256,
            kid: Some("missing-kid".to_string()),
        };
        let result = resolve_client_decoding_key(&state, &client, &header).await;

        assert!(
            result.is_ok(),
            "the rotated key must verify after a single force-refresh: {result:?}"
        );
        let fetches = accepted.load(Ordering::SeqCst);
        assert_eq!(
            fetches, 1,
            "the legitimate key-rotation refresh fetches exactly once (got {fetches})"
        );
    }
}
