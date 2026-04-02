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
use crate::services::auth::{
    ACR_AAL3, AuthMethod, AuthenticatorLookupParams, CreateOAuthTokenParams, LoginAssertionParams,
    create_oauth_access_token, lookup_and_verify_authenticator, verify_login_assertion,
};
use crate::services::oidc::authorization_details::AuthorizationDetails;
use crate::services::oidc::token::AuthenticatedClient;
use crate::services::oidc::{ScopeSet, ValidatedDpopProof};
use crate::services::{OAuthErrorCode, ServiceError, ServiceResult};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;
use vouch_common::encoding::Raw;
use vouch_common::fido2_types::Challenge;

/// FIDO2 assertion grant URI.
pub const FIDO2_ASSERTION_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:fido2-assertion";

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
    pub client_info: crate::handlers::extractors::ClientInfo,
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
#[allow(clippy::too_many_lines)]
pub async fn exchange_fido2_assertion(
    state: &Arc<AppState>,
    params: Fido2AssertionParams<'_>,
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

    // 2b. Prepare single-use challenge check
    let state_hash = crate::crypto::hash_token(&payload.state);
    let expires_at = jiff::Timestamp::from_second(challenge_state.exp)
        .unwrap_or_else(|_| jiff::Timestamp::now());

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
    //    (independent DB operations on different tables)
    let (consumed_result, lookup_result) = tokio::try_join!(
        async {
            db::try_mark_challenge_used(&state.store, &state_hash, expires_at)
                .await
                .map_err(|e| ServiceError::Internal(format!("Failed to mark challenge used: {e}")))
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

    if !consumed_result {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidGrant,
            "Challenge state has already been used or expired",
        ));
    }

    let authenticator = lookup_result.authenticator;
    let user = lookup_result.user;

    // 6. Verify WebAuthn assertion
    let stored_counter = u32::try_from(authenticator.counter).unwrap_or(0);
    let assertion_result = verify_login_assertion(LoginAssertionParams {
        authenticator_data: authenticator_data_bytes,
        client_data_json: client_data_json_bytes,
        signature: signature_bytes,
        public_key: authenticator.public_key.clone(),
        rp_id: challenge_state.rp_id.clone(),
        challenge: challenge_state.challenge.as_bytes().to_vec(),
        stored_counter,
    })
    .await
    .map_err(|e| {
        tracing::warn!(
            "FIDO2 assertion grant: assertion verification failed for user {}: {e}",
            user_id
        );
        ServiceError::oauth(OAuthErrorCode::InvalidGrant, "Authentication failed")
    })?;

    tracing::info!(
        "FIDO2 assertion grant: verified for user {}, counter={}, uv={}",
        crate::redact_email(&user.email),
        assertion_result.new_counter,
        assertion_result.user_verified,
    );

    // 7. Update counter in database
    db::update_authenticator_counter(
        &state.store,
        &authenticator.id,
        assertion_result.new_counter as i32,
    )
    .await
    .map_err(|e| ServiceError::Internal(format!("Failed to update counter: {e}")))?;

    // 8. Log auth event (fire-and-forget)
    let auth_event_params = AuthEventParams {
        user_id: user.id.clone(),
        event_type: AuthEventType::LoginSuccess,
        authenticator_id: Some(authenticator.id.clone()),
        success: true,
        ..AuthEventParams::default()
    }
    .with_client_info(params.client_info);
    let audit = state.audit.clone();
    let user_email = user.email.clone();
    tokio::spawn(async move {
        if let Err(e) = db::insert_auth_event(&audit, &auth_event_params, Some(&user_email)).await {
            tracing::warn!("Failed to log auth event: {}", e);
        }
    });

    // 9. Validate authorization_details if provided (RFC 9396)
    let validated_ad = params
        .authorization_details
        .map(AuthorizationDetails::parse)
        .transpose()?;

    let ad_value = validated_ad.as_ref().map(serde_json::Value::from);

    // 9b. Evaluate device posture policies (if org has active policies)
    if let Some(ref org_id) = user.org_id {
        crate::services::posture::evaluate_posture_policies(
            &state.store,
            org_id,
            ad_value.as_ref(),
        )
        .await?;
    }

    // 10. Create OAuth access token
    let scope = params
        .scope
        .map(ScopeSet::parse)
        .unwrap_or_else(ScopeSet::all);

    let dpop_jkt = params.dpop_proof.as_ref().map(|p| p.jkt.as_str());
    let now = jiff::Timestamp::now().as_second();

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
            amr: Some(AuthMethod::all_fido2().to_vec()),
            acr: Some(ACR_AAL3.to_string()),
            hardware_verified: true,
            session_purpose: db::SessionPurpose::OAuthAccessToken,
            authorization_details: ad_value.as_ref(),
        },
    )
    .await?;

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
#[allow(clippy::unwrap_used, clippy::expect_used)]
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
