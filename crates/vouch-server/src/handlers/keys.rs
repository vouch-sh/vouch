// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Key management handlers for listing, renaming, removing, and registering security keys.

use crate::AppState;
use crate::db::{self};
use crate::error::ServiceError;
use crate::redact_email;
use crate::services::keys as key_svc;
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use base64::Engine;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;
use vouch_common::{
    DeleteKeyResponse, ListKeysResponse, Raw, RegisterCompleteRequest, RegisterCompleteResponse,
    RegisterStartRequest, RegisterStartResponse, RenameKeyRequest, RenameKeyResponse,
    ResourceLabel, fido2_types::Challenge,
};

use super::extractors::ValidJson;
use super::session::{AuthenticatedToken, SteppedUpToken};
use super::{generate_challenge, validate_registration_attestation};
use crate::crypto::webauthn_verify;

// ============================================================================
// Registration State (stored temporarily between start and complete)
// ============================================================================

/// Registration state stored between start and complete.
#[derive(Debug, Serialize, Deserialize)]
struct RegistrationState {
    user_id: Uuid,
    user_name: String,
    device_name: ResourceLabel,
    challenge: Challenge<Raw>,
    rp_id: String,
    /// RFC 7519 §4.1.6: Issued at time. Not validated on decode — the token
    /// is minted and consumed by this server on one clock, so `exp` alone
    /// bounds its lifetime.
    iat: i64,
    /// RFC 7519 §4.1.4: Expiration time (5 minutes), enforced on decode.
    exp: i64,
}

impl RegistrationState {
    async fn encode(
        &self,
        signer: &crate::crypto::jwt::StateTokenSigner,
    ) -> Result<String, crate::crypto::jwt::StateTokenError> {
        signer
            .encode_state_token(self, crate::crypto::jwt::JwtType::RegistrationState)
            .await
    }

    async fn decode(
        token: &str,
        signer: &crate::crypto::jwt::StateTokenSigner,
    ) -> Result<Self, crate::crypto::jwt::StateTokenError> {
        signer
            .decode_state_token(token, crate::crypto::jwt::JwtType::RegistrationState)
            .await
    }
}

/// A `POST /v1/keys/register/complete` body with its state token decoded.
///
/// Field lengths and encodings are enforced by the request type itself
/// (`vouch_common::encoding::Bounds`). This endpoint has no
/// configuration-dependent body check — the CLI is not a browser, so there is
/// no page origin to compare, and the credential ID comes from the verified
/// authenticator data rather than the body. What remains is the state decode,
/// and [`RegistrationCompletion::validate`] is the only way to build a value the
/// single-use consume will accept.
struct RegistrationCompletion {
    /// The request body itself.
    req: RegisterCompleteRequest,
    /// Decoded contents of `req.state`.
    reg_state: RegistrationState,
    /// `reg_state.exp` as a timestamp, for the consumed row's TTL.
    expires_at: Timestamp,
}

impl db::ChallengeState for RegistrationCompletion {
    fn state_jwt(&self) -> &str {
        self.req.state.as_str()
    }

    fn expires_at(&self) -> Timestamp {
        self.expires_at
    }
}

impl RegistrationCompletion {
    /// Decode the state token the request carries.
    ///
    /// # Errors
    ///
    /// Returns a 400 `ServiceError` if the state token fails to decode.
    async fn validate(
        req: RegisterCompleteRequest,
        state: &AppState,
    ) -> Result<Self, ServiceError> {
        let reg_state = RegistrationState::decode(req.state.as_str(), &state.state_signer)
            .await
            .map_err(|e| {
                ServiceError::api(StatusCode::BAD_REQUEST, "invalid_state", e.to_string())
            })?;

        let expires_at = Timestamp::from_second(reg_state.exp).unwrap_or_else(|_| Timestamp::now());

        Ok(Self {
            req,
            reg_state,
            expires_at,
        })
    }
}

// ============================================================================
// Registration Handlers
// ============================================================================

/// Start registration - generate challenge and return to client
/// (WebAuthn Level 2 Section 7.1, Step 1-3).
///
/// Requires an OAuth access token (FAPI 2.0), but deliberately *not* a
/// hardware-verified one. Registering a key is the recovery path: a user whose
/// security key is lost or broken signs in through the upstream IdP and enrolls
/// a replacement, so requiring possession of an existing key here would lock
/// out exactly the people who need it. The compensating control is the
/// `KeyRegistered` audit event, not a gate.
///
/// Key *deletion* is gated, because it is destructive and has no recovery
/// argument — see `SteppedUpToken`.
pub(crate) async fn register_start(
    State(state): State<Arc<AppState>>,
    AuthenticatedToken(token): AuthenticatedToken,
    Json(req): Json<RegisterStartRequest>,
) -> Result<Json<RegisterStartResponse>, ServiceError> {
    let user_id = Uuid::parse_str(&token.sub).map_err(|e| {
        ServiceError::api(
            StatusCode::INTERNAL_SERVER_ERROR,
            "uuid_error",
            e.to_string(),
        )
    })?;

    let user = super::session::load_active_user(&state, &token.sub).await?;

    tracing::info!(
        "Registration start for authenticated user: {} (adding key: {})",
        redact_email(&user.email),
        req.name
    );

    // Get existing credentials to exclude
    let existing_auths = db::get_authenticators_for_user(&state.store, &user.id).await?;

    let exclude_credential_ids: Vec<vouch_common::CredentialId<vouch_common::Raw>> = existing_auths
        .iter()
        .map(|a| a.credential_id.clone().into())
        .collect();

    // Generate challenge
    let challenge = generate_challenge().map_err(|_| {
        ServiceError::api(
            StatusCode::INTERNAL_SERVER_ERROR,
            "rng_error",
            "Failed to generate challenge",
        )
    })?;

    // Create state token
    let challenge: Challenge<Raw> = challenge.into();
    let now = Timestamp::now();
    let exp = now
        .checked_add(jiff::Span::new().minutes(5))
        .map_or(now.as_second().saturating_add(300), |t| t.as_second());
    // Validate the user-supplied key name at the entry point. Storing it into
    // a `ResourceLabel` field is what forces this parse; the rename path and
    // the enrollment form apply the same 1..=100-character contract.
    let device_name = ResourceLabel::parse(&req.name).map_err(|_| {
        ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_name",
            "Key name must be between 1 and 100 characters",
        )
    })?;
    let reg_state = RegistrationState {
        user_id,
        user_name: user.email.clone(),
        device_name,
        challenge: challenge.clone(),
        rp_id: state.config().rp_id.clone(),
        iat: now.as_second(),
        exp,
    };

    let state_token = reg_state.encode(&state.state_signer).await.map_err(|e| {
        ServiceError::api(
            StatusCode::INTERNAL_SERVER_ERROR,
            "state_error",
            e.to_string(),
        )
    })?;

    Ok(Json(RegisterStartResponse {
        challenge,
        rp_id: state.config().rp_id.clone(),
        rp_name: state.config().rp_name.clone(),
        user_id,
        user_name: user.email,
        algorithms: vec![-7], // ES256
        state: state_token,
        exclude_credential_ids,
    }))
}

/// Complete registration - verify attestation and store credential
/// (WebAuthn Level 2 Section 7.1, Step 4-22).
pub(crate) async fn register_complete(
    State(state): State<Arc<AppState>>,
    client_info: db::ClientInfo,
    ValidJson(req): ValidJson<RegisterCompleteRequest>,
) -> Result<Json<RegisterCompleteResponse>, ServiceError> {
    tracing::info!("Registration complete");

    let checked = RegistrationCompletion::validate(req, &state).await?;

    // Account must be active. A user deactivated after obtaining the
    // registration state (valid for five minutes) must not register a new
    // hardware key (issue #846). Mirrors `browser_register_complete`.
    let account = db::get_user_by_id(&state.store, &checked.reg_state.user_id.to_string())
        .await
        .map_err(|e| {
            ServiceError::api(StatusCode::INTERNAL_SERVER_ERROR, "db_error", e.to_string())
        })?;
    if let Some(account) = account
        && !account.active
    {
        return Err(ServiceError::Forbidden("user_deactivated"));
    }

    // Single-use enforcement: consume the state token before any WebAuthn work.
    // A captured state JWT cannot be replayed within the 5-minute validity window.
    // CLI registration adds an authenticator without issuing a token, so the
    // returned witness is dropped — sealing is enforced by `#[must_use]` plus
    // the binding to `_claim`.
    let _claim = match key_svc::consume_registration_state(&state.store, &checked).await? {
        key_svc::RegistrationStateConsumed::Won(claim) => claim,
        key_svc::RegistrationStateConsumed::Replay => {
            tracing::warn!(
                user_id = %checked.reg_state.user_id,
                "CLI registration state replay rejected"
            );
            let audit_data = crate::db::documents::audit::RegistrationReplayData {
                flow: "cli_register",
                success: false,
                error_code: "state_already_used",
            };
            if let Err(e) = state
                .audit
                .insert_event(
                    db::AuditEventKind::KeyRegistrationReplay,
                    Some(&checked.reg_state.user_id.to_string()),
                    Some(&checked.reg_state.user_name),
                    &audit_data,
                )
                .await
            {
                tracing::warn!(error = %e, "failed to write key_registration_replay audit event");
            }
            return Err(ServiceError::api(
                StatusCode::BAD_REQUEST,
                "state_already_used",
                "This registration link has already been used",
            ));
        }
    };

    let RegistrationCompletion {
        req,
        reg_state,
        expires_at: _,
    } = checked;

    // Server-side WebAuthn attestation verification
    // Verify the attestation object, client data, RP ID, challenge, and origin
    let config = state.config();
    let challenge_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(reg_state.challenge.as_bytes());
    let verified = webauthn_verify::verify_registration(&webauthn_verify::RegistrationParams {
        attestation_object: req.attestation_object.as_bytes(),
        client_data_json: req.client_data_json.as_bytes(),
        expected_rp_id: &reg_state.rp_id,
        expected_challenge: &challenge_b64,
        expected_origin: &config.base_url,
        require_user_verification: true,
        // Loopback origin relaxation is development-only: disabled as soon
        // as TLS is configured, matching assertion verification.
        origin_policy: config.as_ref().into(),
    })
    .map_err(|e| {
        tracing::warn!("Registration attestation verification failed: {e}");
        ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_attestation",
            e.to_string(),
        )
    })?;

    // Use server-verified credential_id from authData (not from request body)
    let verified_cred_id: vouch_common::fido2_types::CredentialId<Raw> =
        verified.credential_id.into();

    // Check for duplicate credential registration
    if let Some(_existing) =
        db::get_authenticator_by_credential_id(&state.store, &verified_cred_id).await?
    {
        tracing::warn!(
            "Rejected duplicate credential registration for user: {}",
            reg_state.user_id
        );
        return Err(ServiceError::api(
            StatusCode::CONFLICT,
            "credential_already_registered",
            "This security key is already registered",
        ));
    }

    // Registration policy: hardware-only, x5c chain, AAGUID policy, device
    // name. Identical call to the browser path in `enroll.rs`, so the two
    // agree by construction.
    let validated =
        validate_registration_attestation(&req.attestation_object, &config.allowed_aaguids)?;

    // The AAGUID comes from the attestation certificate, never from the
    // client-supplied authData that `verified.aaguid` reports.
    let aaguid = validated.aaguid;

    // Use server-verified public key from authData
    let verified_public_key: vouch_common::fido2_types::CoseKey<Raw> =
        verified.public_key_cose.into();

    // Store the authenticator
    // user_handle is the user_id as bytes (for discoverable credentials)
    let user_handle = reg_state.user_id.as_bytes().to_vec();
    let device_id = db::create_authenticator(
        &state.store,
        &db::CreateAuthenticatorParams {
            user_id: &reg_state.user_id.to_string(),
            user_email: &reg_state.user_name,
            name: reg_state.device_name.as_str(),
            credential_id: &verified_cred_id,
            public_key: &verified_public_key,
            aaguid: aaguid.as_deref(),
            user_handle: Some(&user_handle),
            attestation_verified: true,
        },
    )
    .await?;

    tracing::info!("Registered new authenticator: {}", device_id);

    let event = db::AuthEventParams {
        user_id: reg_state.user_id.to_string(),
        event_type: db::AuthEventType::KeyRegistered,
        authenticator_id: Some(device_id.clone()),
        success: true,
        client: client_info,
        ..Default::default()
    };
    db::spawn_audit_event(&state.audit, event, Some(reg_state.user_name.clone()));

    Ok(Json(RegisterCompleteResponse {
        device_id: Uuid::parse_str(&device_id).map_err(|e| {
            ServiceError::api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "uuid_error",
                e.to_string(),
            )
        })?,
        message: "Registration successful".to_string(),
    }))
}

// ============================================================================
// Key Management Handlers
// ============================================================================

/// List all registered keys for the authenticated user.
pub(crate) async fn list_keys(
    State(state): State<Arc<AppState>>,
    AuthenticatedToken(token): AuthenticatedToken,
) -> Result<Json<ListKeysResponse>, ServiceError> {
    let keys =
        key_svc::list_keys_for_user(&state.store, &token.sub, token.authenticator_id.as_deref())
            .await?;

    Ok(Json(ListKeysResponse { keys }))
}

/// Rename a registered key.
pub(crate) async fn rename_key(
    State(state): State<Arc<AppState>>,
    AuthenticatedToken(token): AuthenticatedToken,
    Path(key_id): Path<String>,
    Json(req): Json<RenameKeyRequest>,
) -> Result<Json<RenameKeyResponse>, ServiceError> {
    // Pure validation first — reject malformed input before DB access
    if uuid::Uuid::try_parse(&key_id).is_err() {
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_key_id",
            "Key ID must be a valid UUID",
        ));
    }
    let name = ResourceLabel::parse(&req.name).map_err(|_| {
        ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_name",
            "Key name must be between 1 and 100 characters",
        )
    })?;

    let message = key_svc::rename_key(&state.store, &token.sub, &key_id, &name).await?;

    Ok(Json(RenameKeyResponse { message }))
}

/// Delete a registered key.
pub(crate) async fn delete_key(
    State(state): State<Arc<AppState>>,
    SteppedUpToken(token): SteppedUpToken,
    client_info: db::ClientInfo,
    Path(key_id): Path<String>,
) -> Result<Json<DeleteKeyResponse>, ServiceError> {
    // Pure validation first — reject malformed key IDs before DB access
    if uuid::Uuid::try_parse(&key_id).is_err() {
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_key_id",
            "Key ID must be a valid UUID",
        ));
    }

    // Whether the deleted key is the authenticator the current session is
    // bound to (browser uses this to decide whether to re-authenticate).
    let current_session_revoked = token.authenticator_id.as_deref() == Some(key_id.as_str());

    let (key_name, sessions_revoked) =
        key_svc::delete_key(&state.store, &token.sub, &key_id).await?;

    // Invalidate session cache for this user — authenticator deletion cascades to their sessions
    state.session_cache.invalidate_for_user(&token.sub);

    let event = db::AuthEventParams {
        user_id: token.sub.clone(),
        event_type: db::AuthEventType::KeyRemoved,
        authenticator_id: Some(key_id.clone()),
        success: true,
        client: client_info,
        ..Default::default()
    };
    db::spawn_audit_event(&state.audit, event, token.email.clone());

    Ok(Json(DeleteKeyResponse {
        message: format!("Key '{}' has been deleted", key_name),
        sessions_revoked,
        current_session_revoked,
    }))
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;
    use crate::crypto::jwt::{JwtType, StateTokenSigner};
    use crate::test_utils::TEST_JWT_SECRET;
    use crate::test_utils::*;
    use axum::http::StatusCode;
    use vouch_common::fido2_types::Challenge;

    #[tokio::test]
    async fn test_registration_state_roundtrip() {
        let signer = StateTokenSigner::local(TEST_JWT_SECRET.to_vec());
        let challenge = Challenge::from(vec![1u8; 32]);
        let state = RegistrationState {
            user_id: Uuid::nil(),
            user_name: "test-user".to_string(),
            device_name: ResourceLabel::parse("test-device").expect("valid label"),
            challenge,
            rp_id: "test.example.com".to_string(),
            iat: 1_000_000_000,
            exp: 9_999_999_999,
        };

        let token = state.encode(&signer).await.expect("encode");
        let decoded = RegistrationState::decode(&token, &signer)
            .await
            .expect("decode");

        assert_eq!(decoded.user_id, Uuid::nil());
        assert_eq!(decoded.user_name, "test-user");
        assert_eq!(decoded.device_name.as_str(), "test-device");
        assert_eq!(decoded.rp_id, "test.example.com");
    }

    #[tokio::test]
    async fn test_registration_state_wrong_secret_rejected() {
        let signer_a = StateTokenSigner::local(TEST_JWT_SECRET.to_vec());
        let signer_b =
            StateTokenSigner::local(b"different_secret_at_least_32chars_long!!".to_vec());
        let state = RegistrationState {
            user_id: Uuid::nil(),
            user_name: "test".to_string(),
            device_name: ResourceLabel::parse("dev").expect("valid label"),
            challenge: Challenge::from(vec![1u8; 32]),
            rp_id: "test.example.com".to_string(),
            iat: 1_000_000_000,
            exp: 9_999_999_999,
        };

        let token = state.encode(&signer_a).await.expect("encode");
        let result = RegistrationState::decode(&token, &signer_b).await;
        assert!(result.is_err(), "Wrong secret should be rejected");
    }

    #[tokio::test]
    async fn test_registration_state_wrong_type_rejected() {
        let signer = StateTokenSigner::local(TEST_JWT_SECRET.to_vec());
        let state = RegistrationState {
            user_id: Uuid::nil(),
            user_name: "test".to_string(),
            device_name: ResourceLabel::parse("dev").expect("valid label"),
            challenge: Challenge::from(vec![1u8; 32]),
            rp_id: "test.example.com".to_string(),
            iat: 1_000_000_000,
            exp: 9_999_999_999,
        };

        let token = state.encode(&signer).await.expect("encode");

        // Try decoding with a different JwtType via the raw signer
        let result: Result<RegistrationState, _> = signer
            .decode_state_token(&token, JwtType::BrowserRegistrationState)
            .await;
        assert!(result.is_err(), "Wrong JWT type should be rejected");
    }

    // ========================================================================
    // List Keys — Positive
    // ========================================================================

    #[tokio::test]
    async fn test_list_keys_returns_ok() {
        let (app, state) = test_app().await;
        let user = create_test_user(&state.store, "list@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let token = create_test_session_with(
            &state,
            TestSessionSpec {
                user_id: &user.id,
                email: &user.email,
                auth_id: Some(&auth_id),
                ..Default::default()
            },
        )
        .await;

        let (status, body) = http_get(
            &app,
            "/v1/keys",
            &[("Authorization", &format!("Bearer {token}"))],
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        assert!(json["keys"].is_array(), "response must have a keys array");
    }

    #[tokio::test]
    async fn test_list_keys_includes_registered_key() {
        let (app, state) = test_app().await;
        let user = create_test_user(&state.store, "listkey@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let token = create_test_session_with(
            &state,
            TestSessionSpec {
                user_id: &user.id,
                email: &user.email,
                auth_id: Some(&auth_id),
                ..Default::default()
            },
        )
        .await;

        let (status, body) = http_get(
            &app,
            "/v1/keys",
            &[("Authorization", &format!("Bearer {token}"))],
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        let keys = json["keys"].as_array().expect("keys must be array");
        assert!(
            !keys.is_empty(),
            "authenticated user with a key must see it in the list"
        );
    }

    // ========================================================================
    // List Keys — Negative
    // ========================================================================

    #[tokio::test]
    async fn test_list_keys_requires_auth() {
        let (app, _state) = test_app().await;

        let (status, _body) = http_get(&app, "/v1/keys", &[]).await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_list_keys_rejects_invalid_token() {
        let (app, _state) = test_app().await;

        let (status, _body) = http_get(
            &app,
            "/v1/keys",
            &[("Authorization", "Bearer garbage.token.value")],
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    // ========================================================================
    // Register Start — Positive
    // ========================================================================

    #[tokio::test]
    async fn test_register_start_returns_challenge() {
        let (app, state) = test_app().await;
        let user = create_test_user(&state.store, "start@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let token = create_test_session_with(
            &state,
            TestSessionSpec {
                user_id: &user.id,
                email: &user.email,
                auth_id: Some(&auth_id),
                ..Default::default()
            },
        )
        .await;

        let (status, body) = http_post_json(
            &app,
            "/v1/keys/register/start",
            r#"{"name":"My Key"}"#,
            &[("Authorization", &format!("Bearer {token}"))],
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        // Challenge<Raw> serializes as a byte array
        assert!(
            json["challenge"].is_array(),
            "response must have a challenge array"
        );
        assert!(json["rp_id"].is_string(), "response must have rp_id");
        assert!(json["state"].is_string(), "response must have state");
        assert!(!json["user_id"].is_null(), "response must have user_id");
    }

    // ========================================================================
    // Register Start — Negative
    // ========================================================================

    #[tokio::test]
    async fn test_register_start_requires_auth() {
        let (app, _state) = test_app().await;

        let (status, _body) =
            http_post_json(&app, "/v1/keys/register/start", r#"{"name":"My Key"}"#, &[]).await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_register_start_rejects_deactivated_user() {
        let (app, state) = test_app().await;
        let user = create_test_user(&state.store, "deactivated-register@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let token = create_test_session_with(
            &state,
            TestSessionSpec {
                user_id: &user.id,
                email: &user.email,
                auth_id: Some(&auth_id),
                ..Default::default()
            },
        )
        .await;

        crate::db::update_user_active_status(&state.store, &user.id, false)
            .await
            .expect("deactivate user");

        let (status, body) = http_post_json(
            &app,
            "/v1/keys/register/start",
            r#"{"name":"My Key"}"#,
            &[("Authorization", &format!("Bearer {token}"))],
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert_eq!(error["code"], "unauthorized");
        assert_eq!(error["message"], "User account is deactivated");
    }

    #[tokio::test]
    async fn test_register_start_rejects_invalid_name() {
        // #1133: the CLI register path must enforce the same 1..=100-character
        // key-name contract as rename; empty, whitespace-only, and over-long
        // names are rejected before any state token is minted.
        let (app, state) = test_app().await;
        let user = create_test_user(&state.store, "register-name@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let token = create_test_session_with(
            &state,
            TestSessionSpec {
                user_id: &user.id,
                email: &user.email,
                auth_id: Some(&auth_id),
                ..Default::default()
            },
        )
        .await;

        let over_long = "x".repeat(101);
        for bad in ["", "   ", over_long.as_str()] {
            let body = serde_json::json!({ "name": bad }).to_string();
            let (status, resp) = http_post_json(
                &app,
                "/v1/keys/register/start",
                &body,
                &[("Authorization", &format!("Bearer {token}"))],
            )
            .await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "name {bad:?} must be rejected"
            );
            let error: serde_json::Value = serde_json::from_str(&resp).expect("Valid JSON");
            assert_eq!(error["code"], "invalid_name", "name {bad:?}");
        }
    }

    // ========================================================================
    // Register Complete — Negative
    // ========================================================================

    /// Mint a valid `RegistrationState` JWT for `user`, returning it with its
    /// expiry so a caller can check afterwards whether it was consumed.
    async fn make_reg_state(state: &AppState, user: &crate::db::User) -> (String, i64) {
        let now = jiff::Timestamp::now();
        let exp = now
            .checked_add(jiff::Span::new().minutes(5))
            .map_or(now.as_second().saturating_add(300), |t| t.as_second());
        let reg_state = RegistrationState {
            user_id: Uuid::parse_str(&user.id).expect("user id is a uuid"),
            user_name: user.email.clone(),
            device_name: ResourceLabel::parse("Test Device").expect("valid label"),
            challenge: Challenge::from(vec![7u8; 32]),
            rp_id: "localhost".to_string(),
            iat: now.as_second(),
            exp,
        };
        let jwt = reg_state
            .encode(&state.state_signer)
            .await
            .expect("encode state");
        (jwt, exp)
    }

    /// Post a body to `/v1/keys/register/complete` on behalf of a fresh user,
    /// returning the state token it carried alongside the response.
    async fn post_register_complete(
        email: &str,
        attestation_object: serde_json::Value,
        client_data_json: serde_json::Value,
    ) -> (Arc<AppState>, String, i64, StatusCode, String) {
        let (app, state) = test_app().await;
        let user = create_test_user(&state.store, email).await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let token = create_test_session_with(
            &state,
            TestSessionSpec {
                user_id: &user.id,
                email: &user.email,
                auth_id: Some(&auth_id),
                ..Default::default()
            },
        )
        .await;
        let (state_jwt, exp) = make_reg_state(&state, &user).await;

        let body = serde_json::json!({
            "state": state_jwt,
            "credential_id": vec![9u8; 16],
            "public_key": vec![9u8; 77],
            "attestation_object": attestation_object,
            "client_data_json": client_data_json,
        });
        let (status, resp_body) = http_post_json(
            &app,
            "/v1/keys/register/complete",
            &body.to_string(),
            &[("Authorization", &format!("Bearer {token}"))],
        )
        .await;

        (state, state_jwt, exp, status, resp_body)
    }

    /// Assert the registration state is still unconsumed by spending it directly.
    async fn assert_state_unconsumed(state: &AppState, state_jwt: &str, exp: i64) {
        let expires_at = jiff::Timestamp::from_second(exp).expect("valid exp");
        let consume =
            crate::db::consume_challenge_state_for_test(&state.store, state_jwt, expires_at).await;
        assert!(
            consume.is_ok(),
            "a rejected request consumed the registration state: {consume:?}"
        );
    }

    #[tokio::test]
    async fn test_register_complete_empty_attestation_leaves_state_unconsumed() {
        let (state, state_jwt, exp, status, body) = post_register_complete(
            "cli-empty-attestation@example.com",
            serde_json::json!([]),
            serde_json::json!([4, 5, 6]),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        let json: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(json["code"], "invalid_request");

        assert_state_unconsumed(&state, &state_jwt, exp).await;
    }

    #[tokio::test]
    async fn test_register_complete_oversized_attestation_leaves_state_unconsumed() {
        let (state, state_jwt, exp, status, body) = post_register_complete(
            "cli-huge-attestation@example.com",
            serde_json::json!(vec![
                0u8;
                <vouch_common::AttestationObjectData as vouch_common::Bounds>::MAX_BYTES
                    + 1
            ]),
            serde_json::json!([4, 5, 6]),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        let json: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(json["code"], "invalid_request");

        assert_state_unconsumed(&state, &state_jwt, exp).await;
    }

    #[tokio::test]
    async fn test_register_complete_oversized_client_data_leaves_state_unconsumed() {
        let (state, state_jwt, exp, status, body) = post_register_complete(
            "cli-huge-client-data@example.com",
            serde_json::json!([1, 2, 3]),
            serde_json::json!(vec![
                0u8;
                <vouch_common::ClientDataJsonData as vouch_common::Bounds>::MAX_BYTES
                    + 1
            ]),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        let json: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(json["code"], "invalid_request");

        assert_state_unconsumed(&state, &state_jwt, exp).await;
    }

    #[tokio::test]
    async fn test_register_complete_invalid_state() {
        let (app, state) = test_app().await;

        // register/complete is reached within an authenticated session, so the
        // request must be signed (RFC 9421); the harness signs it transparently.
        let user = create_test_user(&state.store, "invalid-state@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let token = create_test_session_with(
            &state,
            TestSessionSpec {
                user_id: &user.id,
                email: &user.email,
                auth_id: Some(&auth_id),
                ..Default::default()
            },
        )
        .await;

        // All Raw fields deserialize as Vec<u8> (JSON arrays), and their length
        // bounds are applied there, so the binary fields must be in range for
        // the request to reach the state decode. Their contents are unused.
        let body = serde_json::json!({
            "state": "garbage.state.jwt",
            "credential_id": vec![9u8; 16],
            "public_key": vec![9u8; 77],
            "attestation_object": [1, 2, 3],
            "client_data_json": [4, 5, 6],
        })
        .to_string();
        let body = body.as_str();
        let (status, resp_body) = http_post_json(
            &app,
            "/v1/keys/register/complete",
            body,
            &[("Authorization", &format!("Bearer {token}"))],
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        let json: serde_json::Value = serde_json::from_str(&resp_body).expect("valid JSON");
        assert_eq!(json["code"], "invalid_state");
    }

    // ========================================================================
    // Register Complete — Replay Rejection
    // ========================================================================

    #[tokio::test]
    async fn test_register_complete_rejects_replayed_state() {
        let (app, state) = test_app().await;

        // register/complete is reached within an authenticated session, so the
        // request must be signed (RFC 9421); the harness signs it transparently.
        let user = create_test_user(&state.store, "replay-session@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let token = create_test_session_with(
            &state,
            TestSessionSpec {
                user_id: &user.id,
                email: &user.email,
                auth_id: Some(&auth_id),
                ..Default::default()
            },
        )
        .await;

        // Build a valid RegistrationState JWT with a far-future expiry.
        let signer = &state.state_signer;
        let challenge = Challenge::from(vec![2u8; 32]);
        let now = jiff::Timestamp::now();
        let exp = now
            .checked_add(jiff::Span::new().minutes(5))
            .map_or(now.as_second().saturating_add(300), |t| t.as_second());
        let reg_state = RegistrationState {
            user_id: Uuid::new_v4(),
            user_name: "replay-test@example.com".to_string(),
            device_name: ResourceLabel::parse("Test Device").expect("valid label"),
            challenge,
            rp_id: "localhost".to_string(),
            iat: now.as_second(),
            exp,
        };
        let state_jwt = reg_state.encode(signer).await.expect("encode state");

        // Pre-consume the state token to simulate prior use.
        let expires_at = jiff::Timestamp::from_second(exp).expect("valid exp");
        let _claim =
            crate::db::consume_challenge_state_for_test(&state.store, &state_jwt, expires_at)
                .await
                .expect("pre-consume must succeed");

        // POST to register/complete with the already-consumed state. The field
        // bounds precede the replay check, so the binary fields must be
        // well-formed; WebAuthn verification never runs, so dummy bytes suffice.
        let body = serde_json::json!({
            "state": state_jwt,
            "credential_id": vec![9u8; 16],
            "public_key": vec![9u8; 77],
            "attestation_object": [1, 2, 3],
            "client_data_json": [4, 5, 6],
        });
        let (status, resp_body) = http_post_json(
            &app,
            "/v1/keys/register/complete",
            &body.to_string(),
            &[("Authorization", &format!("Bearer {token}"))],
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        let json: serde_json::Value = serde_json::from_str(&resp_body).expect("valid JSON");
        assert_eq!(
            json["code"], "state_already_used",
            "replayed state must return state_already_used, got: {json}"
        );
    }

    // ========================================================================
    // Register Complete — Deactivated User Rejection (issue #846)
    // ========================================================================

    #[tokio::test]
    async fn test_register_complete_refuses_deactivated_user() {
        // A user deactivated after obtaining the registration state (valid
        // for five minutes) must not complete key registration (issue #846).
        // Mirrors `test_browser_register_complete_refuses_deactivated_user`.
        let (app, state) = test_app().await;
        let user = create_test_user(&state.store, "deactivated-complete@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let token = create_test_session_with(
            &state,
            TestSessionSpec {
                user_id: &user.id,
                email: &user.email,
                auth_id: Some(&auth_id),
                ..Default::default()
            },
        )
        .await;
        let user_uuid = Uuid::parse_str(&user.id).expect("user id is a uuid");

        // Build a valid RegistrationState JWT for an (initially) active user.
        let signer = &state.state_signer;
        let challenge = Challenge::from(vec![3u8; 32]);
        let now = jiff::Timestamp::now();
        let exp = now
            .checked_add(jiff::Span::new().minutes(5))
            .map_or(now.as_second().saturating_add(300), |t| t.as_second());
        let reg_state = RegistrationState {
            user_id: user_uuid,
            user_name: user.email.clone(),
            device_name: ResourceLabel::parse("Test Device").expect("valid label"),
            challenge,
            rp_id: "localhost".to_string(),
            iat: now.as_second(),
            exp,
        };
        let state_jwt = reg_state.encode(signer).await.expect("encode state");

        // Admin deactivates the user after the state token was issued.
        crate::db::update_user_active_status(&state.store, &user.id, false)
            .await
            .expect("deactivate user");

        // The field bounds precede the active-user check, so the binary fields
        // must be well-formed; WebAuthn verification never runs, so dummy bytes
        // suffice to trigger the deactivation rejection.
        let body = serde_json::json!({
            "state": state_jwt,
            "credential_id": vec![9u8; 16],
            "public_key": vec![9u8; 77],
            "attestation_object": [1, 2, 3],
            "client_data_json": [4, 5, 6],
        });
        let (status, resp_body) = http_post_json(
            &app,
            "/v1/keys/register/complete",
            &body.to_string(),
            &[("Authorization", &format!("Bearer {token}"))],
        )
        .await;

        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "deactivated user must not complete key registration: {resp_body}"
        );
        let json: serde_json::Value = serde_json::from_str(&resp_body).expect("valid JSON");
        assert_eq!(json["code"], "forbidden");
        assert_eq!(json["message"], "user_deactivated");
    }

    #[tokio::test]
    async fn test_register_complete_allows_active_user_past_active_check() {
        // An active user must not be rejected by the deactivation guard: the
        // request must proceed past the active-user check to subsequent stages
        // (here, WebAuthn verification, which fails on dummy attestation bytes).
        let (app, state) = test_app().await;
        let user = create_test_user(&state.store, "active-complete@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let token = create_test_session_with(
            &state,
            TestSessionSpec {
                user_id: &user.id,
                email: &user.email,
                auth_id: Some(&auth_id),
                ..Default::default()
            },
        )
        .await;
        let user_uuid = Uuid::parse_str(&user.id).expect("user id is a uuid");

        let signer = &state.state_signer;
        let challenge = Challenge::from(vec![4u8; 32]);
        let now = jiff::Timestamp::now();
        let exp = now
            .checked_add(jiff::Span::new().minutes(5))
            .map_or(now.as_second().saturating_add(300), |t| t.as_second());
        let reg_state = RegistrationState {
            user_id: user_uuid,
            user_name: user.email.clone(),
            device_name: ResourceLabel::parse("Test Device").expect("valid label"),
            challenge,
            rp_id: "localhost".to_string(),
            iat: now.as_second(),
            exp,
        };
        let state_jwt = reg_state.encode(signer).await.expect("encode state");

        let body = serde_json::json!({
            "state": state_jwt,
            "credential_id": vec![9u8; 16],
            "public_key": vec![9u8; 77],
            "attestation_object": [],
            "client_data_json": [],
        });
        let (status, resp_body) = http_post_json(
            &app,
            "/v1/keys/register/complete",
            &body.to_string(),
            &[("Authorization", &format!("Bearer {token}"))],
        )
        .await;

        // The active-user check must NOT fire for an active user. Dummy
        // attestation bytes cause WebAuthn verification to fail with a 400
        // invalid_attestation — never a 403 user_deactivated.
        assert_ne!(
            status,
            StatusCode::FORBIDDEN,
            "active user must not be rejected as deactivated: {resp_body}"
        );
        let json: serde_json::Value = serde_json::from_str(&resp_body).expect("valid JSON");
        assert_ne!(
            json["message"], "user_deactivated",
            "active user must not receive user_deactivated: {json}"
        );
    }

    // ========================================================================
    // Rename Key — Positive
    // ========================================================================

    #[tokio::test]
    async fn test_rename_key_succeeds() {
        let (app, state) = test_app().await;
        let user = create_test_user(&state.store, "rename@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let token = create_test_session_with(
            &state,
            TestSessionSpec {
                user_id: &user.id,
                email: &user.email,
                auth_id: Some(&auth_id),
                ..Default::default()
            },
        )
        .await;

        let (status, _body) = http_request(
            &app,
            "PATCH",
            &format!("/v1/keys/{auth_id}"),
            Some(r#"{"name":"New Name"}"#.to_string()),
            &[
                ("Content-Type", "application/json"),
                ("Authorization", &format!("Bearer {token}")),
            ],
        )
        .await;

        assert_eq!(status, StatusCode::OK);
    }

    // ========================================================================
    // Rename Key — Negative
    // ========================================================================

    #[tokio::test]
    async fn test_rename_key_requires_auth() {
        let (app, _state) = test_app().await;
        let key_id = Uuid::new_v4();

        let (status, _body) = http_request(
            &app,
            "PATCH",
            &format!("/v1/keys/{key_id}"),
            Some(r#"{"name":"New Name"}"#.to_string()),
            &[("Content-Type", "application/json")],
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_rename_key_invalid_uuid() {
        let (app, state) = test_app().await;
        let user = create_test_user(&state.store, "renamebaduuid@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let token = create_test_session_with(
            &state,
            TestSessionSpec {
                user_id: &user.id,
                email: &user.email,
                auth_id: Some(&auth_id),
                ..Default::default()
            },
        )
        .await;

        let (status, body) = http_request(
            &app,
            "PATCH",
            "/v1/keys/not-a-valid-uuid",
            Some(r#"{"name":"New Name"}"#.to_string()),
            &[
                ("Content-Type", "application/json"),
                ("Authorization", &format!("Bearer {token}")),
            ],
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        let json: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(json["code"], "invalid_key_id");
    }

    #[tokio::test]
    async fn test_rename_key_empty_name() {
        let (app, state) = test_app().await;
        let user = create_test_user(&state.store, "renameempty@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let token = create_test_session_with(
            &state,
            TestSessionSpec {
                user_id: &user.id,
                email: &user.email,
                auth_id: Some(&auth_id),
                ..Default::default()
            },
        )
        .await;

        let (status, body) = http_request(
            &app,
            "PATCH",
            &format!("/v1/keys/{auth_id}"),
            Some(r#"{"name":""}"#.to_string()),
            &[
                ("Content-Type", "application/json"),
                ("Authorization", &format!("Bearer {token}")),
            ],
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        let json: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(json["code"], "invalid_name");
    }

    #[tokio::test]
    async fn test_rename_key_name_too_long() {
        let (app, state) = test_app().await;
        let user = create_test_user(&state.store, "renametoolong@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let token = create_test_session_with(
            &state,
            TestSessionSpec {
                user_id: &user.id,
                email: &user.email,
                auth_id: Some(&auth_id),
                ..Default::default()
            },
        )
        .await;

        let long_name = "a".repeat(257);
        let body_str = format!(r#"{{"name":"{long_name}"}}"#);
        let (status, body) = http_request(
            &app,
            "PATCH",
            &format!("/v1/keys/{auth_id}"),
            Some(body_str),
            &[
                ("Content-Type", "application/json"),
                ("Authorization", &format!("Bearer {token}")),
            ],
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        let json: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(json["code"], "invalid_name");
    }

    // The guard measures Unicode characters, not UTF-8 bytes, so a multibyte
    // name is bounded by the same number the error message names.
    #[tokio::test]
    async fn test_rename_key_accepts_multibyte_name_within_char_limit() {
        let (app, state) = test_app().await;
        let user = create_test_user(&state.store, "renamecjk@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let token = create_test_session_with(
            &state,
            TestSessionSpec {
                user_id: &user.id,
                email: &user.email,
                auth_id: Some(&auth_id),
                ..Default::default()
            },
        )
        .await;

        // 90 CJK characters = 270 UTF-8 bytes: within the 100-character limit
        // the handler and service share, so the rename succeeds end to end.
        let name = "名".repeat(90);
        assert_eq!(name.chars().count(), 90);
        assert!(name.len() > 256);
        let body = serde_json::json!({ "name": name }).to_string();
        let (status, resp_body) = http_request(
            &app,
            "PATCH",
            &format!("/v1/keys/{auth_id}"),
            Some(body),
            &[
                ("Content-Type", "application/json"),
                ("Authorization", &format!("Bearer {token}")),
            ],
        )
        .await;

        assert_eq!(
            status,
            StatusCode::OK,
            "multibyte name within limits must be accepted: {resp_body}"
        );
    }

    // The character-based guard still bounds multibyte names: a 101-character
    // CJK name is rejected by the handler, before the service sees it.
    #[tokio::test]
    async fn test_rename_key_rejects_multibyte_name_exceeding_char_limit() {
        let (app, state) = test_app().await;
        let user = create_test_user(&state.store, "renamecjklong@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let token = create_test_session_with(
            &state,
            TestSessionSpec {
                user_id: &user.id,
                email: &user.email,
                auth_id: Some(&auth_id),
                ..Default::default()
            },
        )
        .await;

        // 101 CJK characters = 303 bytes: one character over the cap.
        let name = "名".repeat(101);
        assert_eq!(name.chars().count(), 101);
        let body = serde_json::json!({ "name": name }).to_string();
        let (status, resp_body) = http_request(
            &app,
            "PATCH",
            &format!("/v1/keys/{auth_id}"),
            Some(body),
            &[
                ("Content-Type", "application/json"),
                ("Authorization", &format!("Bearer {token}")),
            ],
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        let json: serde_json::Value = serde_json::from_str(&resp_body).expect("valid JSON");
        assert_eq!(json["code"], "invalid_name");
        assert_eq!(
            json["message"],
            "Key name must be between 1 and 100 characters"
        );
    }

    // The handler guard and the service limit are the same number, so no name
    // clears the handler only to be rejected by the service under a different
    // message. The range the error names is the range the endpoint accepts.
    #[tokio::test]
    async fn test_rename_key_rejects_name_over_shared_limit() {
        let (app, state) = test_app().await;
        let user = create_test_user(&state.store, "renamemidrange@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let token = create_test_session_with(
            &state,
            TestSessionSpec {
                user_id: &user.id,
                email: &user.email,
                auth_id: Some(&auth_id),
                ..Default::default()
            },
        )
        .await;

        let name = "a".repeat(150);
        let body = serde_json::json!({ "name": name }).to_string();
        let (status, resp_body) = http_request(
            &app,
            "PATCH",
            &format!("/v1/keys/{auth_id}"),
            Some(body),
            &[
                ("Content-Type", "application/json"),
                ("Authorization", &format!("Bearer {token}")),
            ],
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        let json: serde_json::Value = serde_json::from_str(&resp_body).expect("valid JSON");
        assert_eq!(json["code"], "invalid_name");
        assert_eq!(
            json["message"],
            "Key name must be between 1 and 100 characters"
        );
    }

    // ========================================================================
    // Delete Key — Negative
    // ========================================================================

    #[tokio::test]
    async fn test_delete_key_requires_auth() {
        let (app, _state) = test_app().await;
        let key_id = Uuid::new_v4();

        let (status, _body) = http_delete(&app, &format!("/v1/keys/{key_id}"), &[]).await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_delete_key_invalid_uuid() {
        let (app, state) = test_app().await;
        let user = create_test_user(&state.store, "deletebaduuid@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let token = create_test_session_with(
            &state,
            TestSessionSpec {
                user_id: &user.id,
                email: &user.email,
                auth_id: Some(&auth_id),
                ..Default::default()
            },
        )
        .await;

        let (status, body) = http_delete(
            &app,
            "/v1/keys/not-a-valid-uuid",
            &[("Authorization", &format!("Bearer {token}"))],
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        let json: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(json["code"], "invalid_key_id");
    }

    // ========================================================================
    // Step-up on key deletion (issue #1114)
    //
    // The cookie route is covered by the enroll_keys_api integration tests;
    // these pin the Bearer route, which reaches the same `SteppedUpToken`
    // extractor over the Authorization header.
    // ========================================================================

    /// RFC 9470 Section 3: the challenge names what was missing so the client
    /// can re-authenticate and retry, which is what the keys page does.
    fn assert_step_up_challenge(resp: &HttpResponse) {
        assert_eq!(resp.status, StatusCode::UNAUTHORIZED, "body: {}", resp.body);
        let challenge = resp
            .headers
            .get(axum::http::header::WWW_AUTHENTICATE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert!(
            challenge.contains("insufficient_user_authentication"),
            "expected an RFC 9470 challenge, got: {challenge}"
        );
    }

    async fn surviving_keys(state: &AppState, user_id: &str) -> usize {
        crate::db::get_authenticators_for_user(&state.store, user_id)
            .await
            .expect("list keys")
            .len()
    }

    #[tokio::test]
    async fn test_delete_key_rejects_bootstrap_session_over_bearer() {
        let (app, state) = test_app().await;
        let user = create_test_user(&state.store, "bootstrap-delete@example.com").await;
        let key_a = create_test_authenticator(&state.store, &user.id).await;
        let _key_b = create_test_authenticator(&state.store, &user.id).await;
        // The browser's cookie is a bearer token; presenting it over the
        // Authorization header must not buy more than presenting it as a cookie.
        let token = create_test_session_with(
            &state,
            TestSessionSpec {
                user_id: &user.id,
                email: &user.email,
                auth_id: Some(&key_a),
                verification: TestVerification::NotVerified,
                ..Default::default()
            },
        )
        .await;

        let resp = http_delete_full(
            &app,
            &format!("/v1/keys/{key_a}"),
            &[("Authorization", &format!("Bearer {token}"))],
        )
        .await;

        assert_step_up_challenge(&resp);
        assert_eq!(
            surviving_keys(&state, &user.id).await,
            2,
            "no key may be deleted without a recent assertion"
        );
    }

    #[tokio::test]
    async fn test_delete_key_rejects_stale_hardware_verified_session() {
        let (app, state) = test_app().await;
        let user = create_test_user(&state.store, "stale-delete@example.com").await;
        let key_a = create_test_authenticator(&state.store, &user.id).await;
        let _key_b = create_test_authenticator(&state.store, &user.id).await;
        // Asserted with a key, but long ago: possession is proven, recency is
        // not, and deleting a key demands both.
        let stale = jiff::Timestamp::now()
            .as_second()
            .saturating_sub(key_svc::KEY_DELETE_MAX_AGE_SECS.saturating_mul(10));
        let token = create_test_session_with(
            &state,
            TestSessionSpec {
                user_id: &user.id,
                email: &user.email,
                auth_id: Some(&key_a),
                verification: TestVerification::Verified {
                    auth_time: Some(stale),
                },
                ..Default::default()
            },
        )
        .await;

        let resp = http_delete_full(
            &app,
            &format!("/v1/keys/{key_a}"),
            &[("Authorization", &format!("Bearer {token}"))],
        )
        .await;

        assert_step_up_challenge(&resp);
        assert_eq!(surviving_keys(&state, &user.id).await, 2);
    }

    /// Mirror of the stale-session rejection for the other impossible-timestamp
    /// direction: a hardware-verified session whose `auth_time` is in the
    /// future relative to the server clock (e.g. after an NTP step-back). The
    /// freshness gate must reject an impossibly-timed ceremony just as it
    /// rejects a stale one, instead of admitting the negative `session_age`
    /// as "age 0" fresh — otherwise an older (but unexpired) verified token
    /// could delete keys without a fresh FIDO2 touch.
    #[tokio::test]
    async fn test_delete_key_rejects_future_dated_hardware_verified_session() {
        let (app, state) = test_app().await;
        let user = create_test_user(&state.store, "future-delete@example.com").await;
        let key_a = create_test_authenticator(&state.store, &user.id).await;
        let _key_b = create_test_authenticator(&state.store, &user.id).await;
        // auth_time one hour *ahead* of the server clock: an impossible
        // ceremony the gate must not treat as fresh.
        let future_iat = jiff::Timestamp::now().as_second().saturating_add(3600);
        let token = create_test_session_with(
            &state,
            TestSessionSpec {
                user_id: &user.id,
                email: &user.email,
                auth_id: Some(&key_a),
                verification: TestVerification::Verified {
                    auth_time: Some(future_iat),
                },
                ..Default::default()
            },
        )
        .await;

        let resp = http_delete_full(
            &app,
            &format!("/v1/keys/{key_a}"),
            &[("Authorization", &format!("Bearer {token}"))],
        )
        .await;

        assert_step_up_challenge(&resp);
        assert_eq!(
            surviving_keys(&state, &user.id).await,
            2,
            "a future-dated ceremony must not authorise key deletion"
        );
    }

    /// The gate must ask whether a ceremony happened rather than infer it from
    /// a timestamp. `HardwareVerification` makes a fresh `auth_time` on an
    /// unverified session unconstructible, so this signs one directly: if that
    /// invariant ever breaks, or an older server's token arrives during a
    /// rolling deploy, deletion must still refuse it.
    #[tokio::test]
    async fn test_delete_key_rejects_fresh_auth_time_without_hardware_verification() {
        let (app, state) = test_app().await;
        let user = create_test_user(&state.store, "unverified-fresh@example.com").await;
        let key_a = create_test_authenticator(&state.store, &user.id).await;
        let _key_b = create_test_authenticator(&state.store, &user.id).await;
        let token = create_test_session_with(
            &state,
            TestSessionSpec {
                user_id: &user.id,
                email: &user.email,
                auth_id: Some(&key_a),
                verification: TestVerification::NotVerifiedForgedAuthTime {
                    auth_time: jiff::Timestamp::now().as_second(),
                },
                ..Default::default()
            },
        )
        .await;

        let resp = http_delete_full(
            &app,
            &format!("/v1/keys/{key_a}"),
            &[("Authorization", &format!("Bearer {token}"))],
        )
        .await;

        assert_step_up_challenge(&resp);
        assert_eq!(
            surviving_keys(&state, &user.id).await,
            2,
            "a fresh timestamp is not evidence a ceremony occurred"
        );
    }

    /// The companion success case: a session that did assert, recently, still
    /// deletes. Without this the three rejections above would pass even if the
    /// extractor refused everything.
    #[tokio::test]
    async fn test_delete_key_allows_recent_hardware_verified_session() {
        let (app, state) = test_app().await;
        let user = create_test_user(&state.store, "fresh-delete@example.com").await;
        let key_a = create_test_authenticator(&state.store, &user.id).await;
        let key_b = create_test_authenticator(&state.store, &user.id).await;
        let token = create_test_session_with(
            &state,
            TestSessionSpec {
                user_id: &user.id,
                email: &user.email,
                auth_id: Some(&key_a),
                ..Default::default()
            },
        )
        .await;

        let (status, body) = http_delete(
            &app,
            &format!("/v1/keys/{key_b}"),
            &[("Authorization", &format!("Bearer {token}"))],
        )
        .await;

        assert_eq!(status, StatusCode::OK, "body: {body}");
        assert_eq!(surviving_keys(&state, &user.id).await, 1);
    }
}
