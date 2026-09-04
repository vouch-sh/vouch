// SPDX-License-Identifier: Apache-2.0 OR MIT
//! FIDO2 assertion grant type — `urn:ietf:params:oauth:grant-type:fido2-assertion`.
//!
//! A custom extension grant per RFC 6749 Section 4.5 / RFC 7521. The CLI
//! performs a local CTAP2 assertion (touch YubiKey) and exchanges the
//! assertion for an OAuth access token at the standard token endpoint.
//!
//! ## Flow
//!
//! 1. CLI calls `POST /oauth/fido2/challenge` → receives challenge + state JWT
//! 2. CLI performs local CTAP2 assertion (user touches YubiKey)
//! 3. CLI calls `POST /oauth/token` with `grant_type=urn:ietf:params:oauth:grant-type:fido2-assertion`
//! 4. Server verifies state JWT, authenticates client via `private_key_jwt`,
//!    verifies WebAuthn assertion, and issues an OAuth access token.

use crate::AppState;
use crate::assurance::HardwareVerification;
use crate::crypto::jwt::JwtType;
use crate::db::{self, AuthEventParams, AuthEventType};
use crate::error::{OAuthErrorCode, ServiceError, ServiceResult};
use crate::services::auth::{
    AuthenticatorLookupParams, ClientAuthProof, CreateOAuthTokenParams, GrantProof,
    LoginAssertionParams, SenderConstraintProof, TokenBinding, TokenIssuanceProof,
    create_oauth_access_token, lookup_and_verify_authenticator, verify_login_assertion,
};
use crate::services::oidc::ScopeSet;
use crate::services::oidc::authorization_details::AuthorizationDetails;
use crate::services::oidc::token::AuthenticatedClient;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;
use vouch_common::encoding::Raw;
use vouch_common::fido2_types::Challenge;
use vouch_common::{
    AuthData, Base64Url, ClientDataJson, CredentialId, Signature, StateToken, UserHandle,
};

/// State embedded in the challenge JWT.
///
/// Defined here, in the grant that consumes it, and constructed by the
/// `/oauth/fido2/challenge` handler that issues it. One definition rather
/// than a pair kept in step by hand: the two sides are a serialization
/// contract, and a field added on one side but not the other rejects every
/// login.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Fido2ChallengeState {
    pub(crate) challenge: Challenge<Raw>,
    pub(crate) rp_id: String,
    /// RFC 7519 §4.1.6: Issued at time. Not validated on decode — the token
    /// is minted and consumed by this server on one clock, so `exp` alone
    /// bounds its lifetime.
    pub(crate) iat: i64,
    /// RFC 7519 §4.1.4: Expiration time (5 minutes), enforced on decode.
    pub(crate) exp: i64,
}

/// Parsed FIDO2 assertion payload from the `assertion` form parameter.
///
/// The binary members are typed rather than `String`, so base64url decoding
/// and the WebAuthn length bounds happen while the payload is deserialized —
/// the same guarantee the browser request types get, applied to a payload
/// that arrives nested inside a form parameter.
#[derive(Debug, Deserialize)]
pub struct Fido2AssertionPayload {
    /// State JWT from the challenge endpoint.
    pub state: StateToken,
    /// Credential ID naming the authenticator that signed.
    pub credential_id: CredentialId<Base64Url>,
    /// Authenticator data covered by the signature.
    pub authenticator_data: AuthData<Base64Url>,
    /// The assertion signature.
    pub signature: Signature<Base64Url>,
    /// Client data JSON, as built by the CLI.
    pub client_data_json: ClientDataJson<Base64Url>,
    /// User handle — identifies the user via discoverable credential.
    pub user_handle: UserHandle<Base64Url>,
}

/// A FIDO2 assertion grant with its state token decoded and its user handle
/// parsed.
///
/// Field lengths and base64url decoding are enforced by
/// [`Fido2AssertionPayload`] itself (`vouch_common::encoding::Bounds`). What
/// remains is the state decode and the user-handle parse, and
/// [`AssertionGrant::validate`] is the only way to build a value
/// [`db::try_consume_challenge_state`] will accept — so the challenge state
/// cannot be consumed before those have run.
struct AssertionGrant {
    /// The assertion payload itself.
    payload: Fido2AssertionPayload,
    /// Decoded contents of `payload.state`.
    challenge_state: Fido2ChallengeState,
    /// `challenge_state.exp` as a timestamp, for the consumed row's TTL.
    expires_at: jiff::Timestamp,
    /// `payload.user_handle` parsed as the user's UUID.
    user_id: Uuid,
}

impl db::ChallengeState for AssertionGrant {
    fn state_jwt(&self) -> &str {
        self.payload.state.as_str()
    }

    fn expires_at(&self) -> jiff::Timestamp {
        self.expires_at
    }
}

impl AssertionGrant {
    /// Parse the `assertion` form parameter, decode its state token, and
    /// parse the user handle.
    ///
    /// # Errors
    ///
    /// Returns `ServiceError::OAuth` with `invalid_grant` for malformed
    /// base64url, an assertion payload that fails to deserialize (which
    /// includes a member outside its length bounds), a challenge state that
    /// fails to decode or carries an unrepresentable `exp`, or a user handle
    /// that is not a UUID.
    async fn validate(assertion: &str, state: &Arc<AppState>) -> ServiceResult<Self> {
        let assertion_bytes = URL_SAFE_NO_PAD.decode(assertion).map_err(|_| {
            ServiceError::oauth(
                OAuthErrorCode::InvalidGrant,
                "Invalid base64url encoding in assertion parameter",
            )
        })?;

        let payload: Fido2AssertionPayload =
            serde_json::from_slice(&assertion_bytes).map_err(|e| {
                ServiceError::oauth(
                    OAuthErrorCode::InvalidGrant,
                    format!("Invalid assertion JSON: {e}"),
                )
            })?;

        let challenge_state: Fido2ChallengeState = state
            .state_signer
            .decode_state_token(payload.state.as_str(), JwtType::Fido2ChallengeState)
            .await
            .map_err(|e| {
                ServiceError::oauth(
                    OAuthErrorCode::InvalidGrant,
                    format!("Invalid or expired challenge state: {e}"),
                )
            })?;

        // A malformed `exp` is a security-relevant signal — a captured token
        // with garbage `exp` must not be silently accepted with a "now"
        // fallback that would extend its validity.
        let expires_at = jiff::Timestamp::from_second(challenge_state.exp).map_err(|_| {
            ServiceError::oauth(OAuthErrorCode::InvalidGrant, "Invalid challenge state exp")
        })?;

        let user_id = Uuid::from_slice(payload.user_handle.as_bytes()).map_err(|_| {
            ServiceError::oauth(OAuthErrorCode::InvalidGrant, "Invalid user_handle format")
        })?;

        Ok(Self {
            payload,
            challenge_state,
            expires_at,
            user_id,
        })
    }
}

/// Parameters for the FIDO2 assertion grant exchange.
pub struct Fido2AssertionParams<'a> {
    /// The base64url-encoded JSON assertion payload.
    pub assertion: &'a str,
    /// Authenticated client (via `private_key_jwt`).
    pub client: &'a AuthenticatedClient,
    /// RFC 9449 §6 / RFC 8705 §3: how the issued token is bound.
    pub binding: TokenBinding<'a>,
    /// Requested scope.
    pub scope: Option<&'a str>,
    /// RFC 9396: Raw authorization_details JSON string.
    pub authorization_details: Option<&'a str>,
    /// Client metadata extracted from HTTP headers.
    pub client_info: crate::db::ClientInfo,
}

/// Result of a successful FIDO2 assertion grant exchange.
pub struct Fido2AssertionResult {
    /// The OAuth access token.
    pub access_token: secrecy::SecretString,
    /// Token type ([`protocol::ACCESS_TOKEN_TYPE_DPOP`] or
    /// [`protocol::ACCESS_TOKEN_TYPE_BEARER`]).
    pub token_type: String,
    /// Expires in seconds.
    pub expires_in: u64,
    /// Granted scope.
    pub scope: Option<ScopeSet>,
    /// Authenticated user's email address.
    pub email: String,
    /// RFC 9396: Validated authorization details (if provided).
    pub authorization_details: Option<serde_json::Value>,
}

/// Exchange a FIDO2 assertion for an OAuth access token.
///
/// # Errors
///
/// Returns `ServiceError::OAuth` with appropriate error codes for:
/// - Invalid/expired challenge state
/// - Invalid FIDO2 assertion
/// - Unknown authenticator
/// - User mismatch
#[expect(
    clippy::too_many_lines,
    reason = "FIDO2 grant: parse assertion, verify, bind tokens, audit"
)]
pub(crate) async fn exchange_fido2_assertion(
    state: &Arc<AppState>,
    params: Fido2AssertionParams<'_>,
    client_auth: ClientAuthProof,
    sender_constraint: SenderConstraintProof,
) -> ServiceResult<Fido2AssertionResult> {
    // Parse and check the assertion. This reads only the assertion parameter,
    // so it completes before the challenge state is consumed below.
    let grant = AssertionGrant::validate(params.assertion, state).await?;
    let user_id = grant.user_id;

    // Mark challenge used + look up authenticator in parallel
    // (independent DB operations on different tables). The returned
    // `ChallengeStateClaim` witness is the structural proof threaded
    // into the TokenIssuanceProof below — the only path to
    // `GrantProof::Fido2Assertion`.
    let (challenge_claim, lookup_result) = tokio::try_join!(
        async {
            match db::try_consume_challenge_state(&state.store, &grant).await {
                Ok(claim) => Ok(claim),
                Err(db::ClaimError::AlreadyConsumed) => Err(ServiceError::oauth(
                    OAuthErrorCode::InvalidGrant,
                    "Challenge state has already been used or expired",
                )),
                Err(e) => Err(ServiceError::Internal(format!(
                    "Failed to mark challenge used: {e}"
                ))),
            }
        },
        async {
            lookup_and_verify_authenticator(
                state,
                AuthenticatorLookupParams {
                    credential_id: grant.payload.credential_id.as_bytes(),
                    user_id,
                },
            )
            .await
            .map_err(|e| {
                tracing::warn!("FIDO2 assertion grant: authenticator lookup failed: {e}");
                ServiceError::oauth(OAuthErrorCode::InvalidGrant, "Authentication failed")
            })
        },
    )?;

    let AssertionGrant {
        payload,
        challenge_state,
        ..
    } = grant;
    let authenticator = lookup_result.authenticator;
    let user = lookup_result.user;

    // Verify WebAuthn assertion
    let stored_counter = u32::try_from(authenticator.counter).unwrap_or(0);
    // Cloned for the failure audit event below, since the success path moves
    // `params.client_info` when it records the LoginSuccess event.
    let failure_client_info = params.client_info.clone();
    let assertion_result = match verify_login_assertion(LoginAssertionParams {
        authenticator_data: payload.authenticator_data.into_bytes(),
        client_data_json: payload.client_data_json.into_bytes(),
        signature: payload.signature.into_bytes(),
        public_key: authenticator.public_key.clone(),
        rp_id: challenge_state.rp_id.clone(),
        // CLI flow: clientDataJSON.origin is `https://{rp_id}` since the
        // CLI is not a browser and does not have a page origin.
        expected_origin: format!("https://{}", challenge_state.rp_id),
        challenge: challenge_state.challenge.as_bytes().to_vec(),
        stored_counter,
        // Tolerate loopback origin variations only in development (no TLS).
        origin_policy: state.config().as_ref().into(),
    })
    .await
    {
        Ok(result) => result,
        Err(e) => {
            tracing::warn!(
                "FIDO2 assertion grant: assertion verification failed for user {}: {e}",
                user_id
            );
            // A failed assertion — including clone detection (counter regression)
            // — is a high-signal security event. Record it in the audit trail with
            // the credential and user IDs and the failure reason.
            let failure_event = AuthEventParams {
                user_id: user.id.clone(),
                event_type: AuthEventType::LoginFailed,
                authenticator_id: Some(authenticator.id.clone()),
                success: false,
                failure_reason: Some(e.to_string()),
                client: failure_client_info,
                ..AuthEventParams::default()
            };
            db::record_auth_event(&state.audit, failure_event, Some(user.email.clone())).await;
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidGrant,
                "Authentication failed",
            ));
        }
    };

    tracing::info!(
        "FIDO2 assertion grant: verified for user {}, counter={}, uv={}",
        crate::redact_email(&user.email),
        assertion_result.new_counter,
        assertion_result.user_verified,
    );

    // Update counter in database
    // WebAuthn counter is u32; stored bit-identical as i32. Real authenticators never
    // approach 2^31 uses, and bitwise reinterpret preserves DB monotonicity comparisons.
    db::update_authenticator_counter(
        &state.store,
        &authenticator.id,
        assertion_result.new_counter.cast_signed(),
    )
    .await
    .map_err(|e| ServiceError::Internal(format!("Failed to update counter: {e}")))?;

    // Capture client metadata for the audit events below.
    let client_ip = params.client_info.client_ip;
    let client_user_agent = params.client_info.user_agent.clone();

    // Validate authorization_details if provided (RFC 9396)
    let validated_ad = params
        .authorization_details
        .map(AuthorizationDetails::parse)
        .transpose()?;

    let ad_value = validated_ad.as_ref().map(serde_json::Value::from);

    // Evaluate device posture policies (if org has active policies).
    // The login audit event is written AFTER this gate: a policy-denied
    // attempt records login_failed, never login_success — temporal
    // policies (step-up recency on token exchange) treat login_success as
    // proof of a completed, policy-compliant hardware login.
    if let Some(ref org_id) = user.org_id
        && let Err(denied) = crate::services::policy::evaluate_posture_policies(
            state,
            org_id,
            &user.id,
            &user.email,
            client_ip,
            &params.client.client.client_id,
            ad_value.as_ref(),
        )
        .await
    {
        let failed_event = AuthEventParams {
            user_id: user.id.clone(),
            event_type: AuthEventType::LoginFailed,
            authenticator_id: Some(authenticator.id.clone()),
            success: false,
            failure_reason: Some("posture policy denied".to_string()),
            client: params.client_info,
            ..AuthEventParams::default()
        };
        db::record_auth_event(&state.audit, failed_event, Some(user.email.clone())).await;
        return Err(denied);
    }

    // Log the successful auth event
    let auth_event_params = AuthEventParams {
        user_id: user.id.clone(),
        event_type: AuthEventType::LoginSuccess,
        authenticator_id: Some(authenticator.id.clone()),
        success: true,
        client: params.client_info,
        ..AuthEventParams::default()
    };
    db::record_auth_event(&state.audit, auth_event_params, Some(user.email.clone())).await;

    // Create OAuth access token
    let scope = params.scope.map_or_else(ScopeSet::all, ScopeSet::parse);

    let now = jiff::Timestamp::now().as_second();

    // Org domain, read once at session creation for the federation claims.
    let org_domain = match user.org_id.as_deref() {
        Some(org_id) => {
            db::get_user_org_domain(&state.store, &user.id, org_id, user.org_domain.as_deref())
                .await
                .map_err(|e| ServiceError::Internal(format!("Failed to fetch org domain: {e}")))?
        }
        None => None,
    };

    // Build the chokepoint proof here: `GrantProof::Fido2Assertion` can
    // only be constructed by code that holds a `ChallengeStateClaim`,
    // produced above by `try_consume_challenge_state`.
    let proof = TokenIssuanceProof {
        grant: GrantProof::Fido2Assertion(challenge_claim),
        client_auth,
        sender_constraint,
    };
    let session_result = create_oauth_access_token(
        state,
        CreateOAuthTokenParams {
            user_id: &user.id,
            email: &user.email,
            authenticator_id: Some(&authenticator.id),
            client_id: &params.client.client.client_id,
            scope: Some(scope.clone()),
            binding: params.binding,
            act: None,
            audience: None,
            hardware_verification: HardwareVerification::Verified {
                auth_time: Some(now),
            },
            session_purpose: db::SessionPurpose::OAuthAccessToken,
            authorization_details: ad_value.as_ref(),
            hardware_aaguid: authenticator.aaguid.as_deref(),
            org_domain: org_domain.as_deref(),
            source_code_hash: None,
        },
        proof,
    )
    .await?;

    // Every access-token grant records an oauth_token_issued audit row.
    // The user-org half of `resolve_event_org_domain`'s "prefer user, fall
    // back to client" rule was already resolved above for the session
    // claims, so it's reused here rather than re-derived; the client-org
    // fallback still runs its own lookup when the user has no org, using the
    // client already in scope instead of re-fetching it by id.
    let audit_org_domain = db::resolve_event_org_domain(
        &state.store,
        org_domain.as_deref(),
        params.client.client.org_id.as_deref(),
    )
    .await;
    db::record_oauth_event(
        &state.audit,
        &state.store,
        &db::RecordOAuthEventParams {
            oauth_client_id: &params.client.client.id,
            event_type: db::OAuthEventType::TokenIssued,
            user_id: Some(&user.id),
            ip_address: client_ip,
            user_agent: client_user_agent.as_deref(),
            details: Some("grant_type=fido2-assertion"),
            org_domain: db::RecordedOrgDomain::Known(audit_org_domain.as_deref()),
        },
    )
    .await;

    Ok(Fido2AssertionResult {
        access_token: session_result.token.clone(),
        token_type: session_result.token_type.to_string(),
        expires_in: session_result.expires_in,
        scope: Some(scope),
        email: user.email,
        authorization_details: validated_ad.as_ref().map(serde_json::Value::from),
    })
}

#[cfg(test)]
mod tests {
    // NOTE(mtls-threading): `Fido2AssertionParams::mtls_cert_thumbprint` is a
    // plain `Option<&str>` threaded from the handler through to
    // `create_oauth_access_token` as `CreateOAuthTokenParams::mtls_cert_thumbprint`.
    // Unit-testing the threading in isolation would require a fully mocked AppState
    // (database, signing key, WebAuthn instance, etc.). End-to-end coverage for
    // RFC 8705 token binding through the FIDO2 grant should be added as an
    // integration test in `crates/vouch-tests/` once the mTLS test infrastructure
    // (client cert generation + mTLS test server) is available.
}
