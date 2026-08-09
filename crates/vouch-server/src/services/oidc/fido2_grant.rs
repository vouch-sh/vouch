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
use crate::crypto::jwt::JwtType;
use crate::db::{self, AuthEventParams, AuthEventType};
use crate::error::{OAuthErrorCode, ServiceError, ServiceResult};
use crate::services::auth::{
    AuthenticatorLookupParams, ClientAuthProof, CreateOAuthTokenParams, GrantProof,
    LoginAssertionParams, TokenIssuanceProof, create_oauth_access_token,
    lookup_and_verify_authenticator, verify_login_assertion,
};
use crate::services::oidc::authorization_details::AuthorizationDetails;
use crate::services::oidc::token::AuthenticatedClient;
use crate::services::oidc::{ScopeSet, ValidatedDpopProof};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;
use vouch_common::encoding::Raw;
use vouch_common::fido2_types::Challenge;

/// State embedded in the challenge JWT (must match the challenge endpoint).
#[derive(Debug, Serialize, Deserialize)]
struct Fido2ChallengeState {
    challenge: Challenge<Raw>,
    rp_id: String,
    iat: i64,
    exp: i64,
}

/// Parsed FIDO2 assertion payload from the `assertion` form parameter.
#[derive(Debug, Deserialize)]
pub struct Fido2AssertionPayload {
    /// State JWT from the challenge endpoint.
    pub state: String,
    /// Credential ID (base64url).
    pub credential_id: String,
    /// Authenticator data (base64url).
    pub authenticator_data: String,
    /// Signature (base64url).
    pub signature: String,
    /// Client data JSON (base64url).
    pub client_data_json: String,
    /// User handle (base64url) — identifies the user via discoverable credential.
    pub user_handle: String,
}

/// Parameters for the FIDO2 assertion grant exchange.
pub struct Fido2AssertionParams<'a> {
    /// The base64url-encoded JSON assertion payload.
    pub assertion: &'a str,
    /// Authenticated client (via `private_key_jwt`).
    pub client: &'a AuthenticatedClient,
    /// Validated DPoP proof (if present).
    pub dpop_proof: Option<ValidatedDpopProof>,
    /// Requested scope.
    pub scope: Option<&'a str>,
    /// RFC 9396: Raw authorization_details JSON string.
    pub authorization_details: Option<&'a str>,
    /// Client metadata extracted from HTTP headers.
    pub client_info: crate::db::ClientInfo,
    /// RFC 8705 Section 3: mTLS certificate thumbprint for token binding.
    /// Only set when the client has `tls_client_certificate_bound_access_tokens = true`.
    pub mtls_cert_thumbprint: Option<&'a str>,
}

/// Result of a successful FIDO2 assertion grant exchange.
pub struct Fido2AssertionResult {
    /// The OAuth access token.
    pub access_token: String,
    /// Token type ("DPoP" or "Bearer").
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
) -> ServiceResult<Fido2AssertionResult> {
    // 1. Base64url-decode and parse the assertion JSON
    let assertion_bytes = URL_SAFE_NO_PAD.decode(params.assertion).map_err(|_| {
        ServiceError::oauth(
            OAuthErrorCode::InvalidGrant,
            "Invalid base64url encoding in assertion parameter",
        )
    })?;

    let payload: Fido2AssertionPayload = serde_json::from_slice(&assertion_bytes).map_err(|e| {
        ServiceError::oauth(
            OAuthErrorCode::InvalidGrant,
            format!("Invalid assertion JSON: {e}"),
        )
    })?;

    // 2. Decode and verify the challenge state JWT
    let challenge_state: Fido2ChallengeState = state
        .state_signer
        .decode_state_token(&payload.state, JwtType::Fido2ChallengeState)
        .await
        .map_err(|e| {
            ServiceError::oauth(
                OAuthErrorCode::InvalidGrant,
                format!("Invalid or expired challenge state: {e}"),
            )
        })?;

    // 2b. Prepare single-use challenge check. A malformed `exp` is a
    // security-relevant signal — a captured token with garbage `exp`
    // must not be silently accepted with a "now" fallback that would
    // extend its validity. Reject as InvalidGrant.
    let expires_at = jiff::Timestamp::from_second(challenge_state.exp).map_err(|_| {
        ServiceError::oauth(OAuthErrorCode::InvalidGrant, "Invalid challenge state exp")
    })?;

    // 3. Decode assertion fields from base64url (CPU-only, no I/O)
    let credential_id_bytes = URL_SAFE_NO_PAD
        .decode(&payload.credential_id)
        .map_err(|_| {
            ServiceError::oauth(
                OAuthErrorCode::InvalidGrant,
                "Invalid credential_id encoding",
            )
        })?;

    let authenticator_data_bytes = URL_SAFE_NO_PAD
        .decode(&payload.authenticator_data)
        .map_err(|_| {
            ServiceError::oauth(
                OAuthErrorCode::InvalidGrant,
                "Invalid authenticator_data encoding",
            )
        })?;

    let signature_bytes = URL_SAFE_NO_PAD.decode(&payload.signature).map_err(|_| {
        ServiceError::oauth(OAuthErrorCode::InvalidGrant, "Invalid signature encoding")
    })?;

    let client_data_json_bytes =
        URL_SAFE_NO_PAD
            .decode(&payload.client_data_json)
            .map_err(|_| {
                ServiceError::oauth(
                    OAuthErrorCode::InvalidGrant,
                    "Invalid client_data_json encoding",
                )
            })?;

    let user_handle_bytes = URL_SAFE_NO_PAD.decode(&payload.user_handle).map_err(|_| {
        ServiceError::oauth(OAuthErrorCode::InvalidGrant, "Invalid user_handle encoding")
    })?;

    // 4. Parse user_handle as UUID
    let user_id = Uuid::from_slice(&user_handle_bytes).map_err(|_| {
        ServiceError::oauth(OAuthErrorCode::InvalidGrant, "Invalid user_handle format")
    })?;

    // 5. Mark challenge used + look up authenticator in parallel
    //    (independent DB operations on different tables). The returned
    //    `ChallengeStateClaim` witness is the structural proof threaded
    //    into the TokenIssuanceProof below — the only path to
    //    `GrantProof::Fido2Assertion`.
    let (challenge_claim_result, lookup_result) = tokio::try_join!(
        async {
            match db::try_consume_challenge_state(&state.store, &payload.state, expires_at).await {
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
                    credential_id: &credential_id_bytes,
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

    let challenge_claim = challenge_claim_result;
    let authenticator = lookup_result.authenticator;
    let user = lookup_result.user;

    // 6. Verify WebAuthn assertion
    let stored_counter = u32::try_from(authenticator.counter).unwrap_or(0);
    // Cloned for the failure audit event below, since the success path moves
    // `params.client_info` when it records the LoginSuccess event.
    let failure_client_info = params.client_info.clone();
    let assertion_result = verify_login_assertion(LoginAssertionParams {
        authenticator_data: authenticator_data_bytes,
        client_data_json: client_data_json_bytes,
        signature: signature_bytes,
        public_key: authenticator.public_key.clone(),
        rp_id: challenge_state.rp_id.clone(),
        // CLI flow: clientDataJSON.origin is `https://{rp_id}` since the
        // CLI is not a browser and does not have a page origin.
        expected_origin: format!("https://{}", challenge_state.rp_id),
        challenge: challenge_state.challenge.as_bytes().to_vec(),
        stored_counter,
        // Tolerate loopback origin variations only in development (no TLS).
        allow_localhost_origin: !state.config().tls_configured(),
    })
    .await
    .map_err(|e| {
        tracing::warn!(
            "FIDO2 assertion grant: assertion verification failed for user {}: {e}",
            user_id
        );
        // P3.5: a failed assertion — including clone detection (counter
        // regression) — is a high-signal security event. Record it in the
        // audit trail with the credential and user IDs and the failure reason.
        let failure_event = AuthEventParams {
            user_id: user.id.clone(),
            event_type: AuthEventType::LoginFailed,
            authenticator_id: Some(authenticator.id.clone()),
            success: false,
            failure_reason: Some(e.to_string()),
            client: failure_client_info,
            ..AuthEventParams::default()
        };
        db::spawn_audit_event(&state.audit, failure_event, Some(user.email.clone()));
        ServiceError::oauth(OAuthErrorCode::InvalidGrant, "Authentication failed")
    })?;

    tracing::info!(
        "FIDO2 assertion grant: verified for user {}, counter={}, uv={}",
        crate::redact_email(&user.email),
        assertion_result.new_counter,
        assertion_result.user_verified,
    );

    // 7. Update counter in database
    // WebAuthn counter is u32; stored bit-identical as i32. Real authenticators never
    // approach 2^31 uses, and bitwise reinterpret preserves DB monotonicity comparisons.
    db::update_authenticator_counter(
        &state.store,
        &authenticator.id,
        assertion_result.new_counter.cast_signed(),
    )
    .await
    .map_err(|e| ServiceError::Internal(format!("Failed to update counter: {e}")))?;

    // 8. Capture client metadata for the audit events below.
    let client_ip = params.client_info.client_ip;
    let client_user_agent = params.client_info.user_agent.clone();

    // 9. Validate authorization_details if provided (RFC 9396)
    let validated_ad = params
        .authorization_details
        .map(AuthorizationDetails::parse)
        .transpose()?;

    let ad_value = validated_ad.as_ref().map(serde_json::Value::from);

    // 9b. Evaluate device posture policies (if org has active policies).
    // The login audit event is written AFTER this gate: a policy-denied
    // attempt records login_failed, never login_success — temporal
    // policies (step-up recency on token exchange) treat login_success as
    // proof of a completed, policy-compliant hardware login.
    if let Some(ref org_id) = user.org_id
        && let Err(denied) = crate::services::policy::evaluate_posture_policies(
            state,
            org_id,
            &user.id,
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
        db::spawn_audit_event(&state.audit, failed_event, Some(user.email.clone()));
        return Err(denied);
    }

    // 9c. Log the successful auth event (fire-and-forget)
    let auth_event_params = AuthEventParams {
        user_id: user.id.clone(),
        event_type: AuthEventType::LoginSuccess,
        authenticator_id: Some(authenticator.id.clone()),
        success: true,
        client: params.client_info,
        ..AuthEventParams::default()
    };
    db::spawn_audit_event(&state.audit, auth_event_params, Some(user.email.clone()));

    // 10. Create OAuth access token
    let scope = params.scope.map_or_else(ScopeSet::all, ScopeSet::parse);

    let dpop_jkt = params.dpop_proof.as_ref().map(|p| p.jkt.as_str());
    let now = jiff::Timestamp::now().as_second();

    // Snapshot org domain at session creation so federation claims reflect
    // the user's state at this moment, not whenever the token is issued.
    let org_domain = if let Some(ref org_id) = user.org_id {
        db::get_organization_domain(&state.store, org_id)
            .await
            .map_err(|e| ServiceError::Internal(format!("Failed to fetch org domain: {e}")))?
    } else {
        None
    };

    // Build the chokepoint proof here: `GrantProof::Fido2Assertion` can
    // only be constructed by code that holds a `ChallengeStateClaim`,
    // produced above by `try_consume_challenge_state`.
    let proof = TokenIssuanceProof {
        grant: GrantProof::Fido2Assertion(challenge_claim),
        client_auth,
    };
    let session_result = create_oauth_access_token(
        state,
        CreateOAuthTokenParams {
            user_id: &user.id,
            email: &user.email,
            authenticator_id: Some(&authenticator.id),
            client_id: &params.client.client.client_id,
            scope: Some(scope.clone()),
            dpop_jkt,
            mtls_cert_thumbprint: params.mtls_cert_thumbprint,
            act: None,
            audience: None,
            auth_time: Some(now),
            hardware_verification: crate::services::auth::HardwareVerification::Verified,
            session_purpose: db::SessionPurpose::OAuthAccessToken,
            authorization_details: ad_value.as_ref(),
            hardware_aaguid: authenticator.aaguid.as_deref(),
            org_domain: org_domain.as_deref(),
        },
        proof,
    )
    .await?;

    // Every access-token grant records an oauth_token_issued audit row.
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
        },
    )
    .await;

    let token_type = if params.dpop_proof.is_some() {
        "DPoP"
    } else {
        "Bearer"
    };

    Ok(Fido2AssertionResult {
        access_token: session_result.token.expose_secret().to_string(),
        token_type: token_type.to_string(),
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
