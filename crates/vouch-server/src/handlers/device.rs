// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Device Authorization Grant handlers (RFC 8628).

use crate::AppState;
use crate::db::{self, DeviceAuthStatus};
use crate::services::auth::{
    ClientAuthProof, CreateOAuthTokenParams, GrantProof, TokenIssuanceProof,
    create_oauth_access_token,
};
use crate::services::oidc::ScopeSet;
use aws_lc_rs::digest::{self, SHA256};
use axum::{Json, extract::State, http::StatusCode};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jiff::{Span, Timestamp};
use secrecy::ExposeSecret;
use std::sync::Arc;
use vouch_common::{
    DeviceCodeRequest, DeviceCodeResponse, DeviceTokenRequest, DeviceTokenResponse, OAuthError,
};

use crate::error::{OAuthErrorCode, ServiceError};
use crate::redact_email;

/// Characters used for user code generation (no ambiguous characters).
const USER_CODE_ALPHABET: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ";

/// OAuth error response helper.
fn oauth_error(status: StatusCode, error: OAuthError) -> (StatusCode, Json<OAuthError>) {
    (status, Json(error))
}

/// Generate a random device code (32 bytes, base64url encoded).
///
/// # Errors
///
/// Returns an error if the system RNG fails.
fn generate_device_code() -> Result<String, aws_lc_rs::error::Unspecified> {
    let bytes = crate::crypto::generate_random_bytes(32)?;
    Ok(URL_SAFE_NO_PAD.encode(&bytes))
}

/// Generate a user-friendly code in XXXX-XXXX format.
///
/// # Errors
///
/// Returns an error if the system RNG fails.
fn generate_user_code() -> Result<String, aws_lc_rs::error::Unspecified> {
    let bytes = crate::crypto::generate_random_bytes(8)?;

    let chars: Vec<char> = bytes
        .iter()
        .map(|b| {
            // checked_rem returns None only if alphabet is empty; USER_CODE_ALPHABET is non-empty.
            let idx = (*b as usize)
                .checked_rem(USER_CODE_ALPHABET.len())
                .unwrap_or(0);
            USER_CODE_ALPHABET.get(idx).copied().unwrap_or(b'X') as char
        })
        .collect();

    Ok(format!(
        "{}-{}",
        chars.iter().take(4).collect::<String>(),
        chars.iter().skip(4).collect::<String>()
    ))
}

/// Hash a device code for storage.
fn hash_device_code(code: &str) -> String {
    let hash = digest::digest(&SHA256, code.as_bytes());
    URL_SAFE_NO_PAD.encode(hash.as_ref())
}

/// Start device authorization flow.
/// POST /oauth/device
///
/// RFC 8628 Section 3.1: The client makes a request using
/// "application/x-www-form-urlencoded" format.
pub(crate) async fn device_code(
    State(state): State<Arc<AppState>>,
    axum::Form(req): axum::Form<DeviceCodeRequest>,
) -> Result<Json<DeviceCodeResponse>, ServiceError> {
    tracing::info!("Device authorization request");

    // If a client_id is provided, it must refer to a registered OAuth client.
    if let Some(client_id) = req.client_id.as_deref() {
        let client = db::get_oauth_client_by_client_id(&state.store, client_id)
            .await
            .map_err(|_| {
                ServiceError::api(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "database_error",
                    "Failed to validate client_id",
                )
            })?;
        if client.is_none() {
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidClient,
                "Unknown client_id",
            ));
        }
    }

    // Generate codes
    let device_code = generate_device_code().map_err(|_| {
        ServiceError::api(
            StatusCode::INTERNAL_SERVER_ERROR,
            "rng_error",
            "Failed to generate device code",
        )
    })?;
    let user_code = generate_user_code().map_err(|_| {
        ServiceError::api(
            StatusCode::INTERNAL_SERVER_ERROR,
            "rng_error",
            "Failed to generate user code",
        )
    })?;
    let device_code_hash = hash_device_code(&device_code);

    // Calculate expiration
    let now = Timestamp::now();
    let expires_seconds = i64::try_from(state.config().device_code_expires_seconds).unwrap_or(600);
    let duration = Span::new().seconds(expires_seconds);
    let expires_at = now.checked_add(duration).map_err(|_| {
        ServiceError::api(
            StatusCode::INTERNAL_SERVER_ERROR,
            "time_error",
            "Time overflow",
        )
    })?;

    let interval_seconds = i32::try_from(state.config().device_poll_interval_seconds).unwrap_or(5);

    // Store in database (client_id is validated above when provided)
    db::create_device_auth_request(
        &state.store,
        &device_code_hash,
        &user_code,
        req.client_id.as_deref(),
        expires_at,
        interval_seconds,
    )
    .await?;

    // Build verification URLs
    let verification_uri = format!("{}/device", state.config().base_url);
    // RFC 8628 §3.2: Include verification_uri_complete with embedded user_code
    let verification_uri_complete = Some(format!("{verification_uri}?user_code={user_code}"));

    tracing::info!("Created device auth request, user_code: {}", user_code);

    Ok(Json(DeviceCodeResponse {
        device_code,
        user_code,
        verification_uri,
        verification_uri_complete,
        expires_in: state.config().device_code_expires_seconds,
        interval: state.config().device_poll_interval_seconds,
    }))
}

/// Revoke all OAuth sessions for the user that authorized a replayed device
/// code, and drop them from the session cache.
///
/// The caller is already returning `invalid_grant` for the replay; a failed
/// revocation must not mask that response, but it is a security event that
/// must stay visible, so it is logged at error level rather than propagated.
async fn revoke_sessions_for_device_replay(state: &AppState, user_id: &str) {
    tracing::warn!(
        target: "security",
        "Device code replay detected — revoking tokens for user"
    );
    match db::delete_oauth_sessions_for_user(&state.store, user_id).await {
        Ok(count) => {
            if count > 0 {
                state.session_cache.invalidate_for_user(user_id);
                tracing::warn!(
                    target: "security",
                    user_id = %user_id,
                    revoked_count = count,
                    "Revoked tokens due to device code replay"
                );
            }
        }
        Err(e) => {
            tracing::error!(
                target: "security",
                user_id = %user_id,
                error = %e,
                "Failed to revoke tokens after device code replay"
            );
        }
    }
}

/// Poll for device token (RFC 8628 Section 3.4).
/// POST /oauth/token
///
/// RFC 8628 Section 3.5: The server responds with one of:
/// - `authorization_pending` — the user hasn't completed authorization yet
/// - `slow_down` — the client is polling too frequently
/// - `expired_token` — the device code has expired
/// - `access_denied` — the user denied the authorization request
/// - A successful token response when the user has authorized
#[expect(
    clippy::too_many_lines,
    reason = "linear RFC 8628 device token grant validation sequence"
)]
pub(crate) async fn device_token(
    State(state): State<Arc<AppState>>,
    client_info: db::ClientInfo,
    Json(req): Json<DeviceTokenRequest>,
) -> Result<Json<DeviceTokenResponse>, (StatusCode, Json<OAuthError>)> {
    // Validate grant type
    if req.grant_type != "urn:ietf:params:oauth:grant-type:device_code" {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            OAuthError {
                error: "unsupported_grant_type".to_string(),
                error_description: Some("Expected device_code grant type".to_string()),
            },
        ));
    }

    // Validate device_code format before hashing and DB lookup.
    // Generated codes are 32 random bytes base64url-encoded (43 chars).
    // Reject obviously invalid inputs to avoid unnecessary work.
    if req.device_code.is_empty() || req.device_code.len() > 128 {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            OAuthError::invalid_grant(),
        ));
    }

    // Hash the device code and look it up
    let device_code_hash = hash_device_code(&req.device_code);
    let request = db::get_device_auth_by_code_hash(&state.store, &device_code_hash)
        .await
        .map_err(|_| {
            oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                OAuthError::invalid_grant(),
            )
        })?
        .ok_or_else(|| oauth_error(StatusCode::BAD_REQUEST, OAuthError::invalid_grant()))?;

    // Check if expired
    let now = Timestamp::now();

    if now > request.expires_at {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            OAuthError::expired_token(),
        ));
    }

    // Check polling rate
    let allowed =
        db::update_device_auth_poll_time(&state.store, &request.id, request.interval_seconds)
            .await
            .map_err(|_| {
                oauth_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    OAuthError::invalid_grant(),
                )
            })?;

    if !allowed {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            OAuthError::slow_down(),
        ));
    }

    match request.status {
        DeviceAuthStatus::Pending => Err(oauth_error(
            StatusCode::BAD_REQUEST,
            OAuthError::authorization_pending(),
        )),
        DeviceAuthStatus::Denied => Err(oauth_error(
            StatusCode::BAD_REQUEST,
            OAuthError::access_denied(),
        )),
        DeviceAuthStatus::Consumed => {
            // RFC 8628 Section 3.5: Device code already used.
            // Replay detected — revoke all tokens for the affected user.
            if let Some(ref user_id) = request.user_id {
                revoke_sessions_for_device_replay(&state, user_id).await;
            }
            Err(oauth_error(
                StatusCode::BAD_REQUEST,
                OAuthError::invalid_grant(),
            ))
        }
        DeviceAuthStatus::Authorized => {
            // RFC 8628 Section 3.5: Atomically consume the device
            // code before issuing a token. The returned claim is the
            // structural proof that this caller won the consume; it is
            // threaded into TokenIssuanceProof below.
            //
            // `AlreadyConsumed` is deliberately indistinguishable between a
            // code that was consumed earlier (replay) and a code that a
            // concurrent caller just consumed (race loser) — see
            // `try_consume_device_auth`. Match the authorization code flow's
            // defensive "replay = full logout" posture and revoke all of the
            // user's OAuth sessions in either case. We use `request.user_id`
            // (read at the top of the handler, set when the device was
            // authorized) rather than a fresh lookup, since it is already
            // available and immune to read-snapshot timing under WAL.
            let device_claim =
                match db::try_consume_device_auth(&state.store, &device_code_hash).await {
                    Ok(claim) => claim,
                    Err(db::claim::ClaimError::AlreadyConsumed) => {
                        if let Some(ref user_id) = request.user_id {
                            revoke_sessions_for_device_replay(&state, user_id).await;
                        }
                        return Err(oauth_error(
                            StatusCode::BAD_REQUEST,
                            OAuthError::invalid_grant(),
                        ));
                    }
                    Err(_) => {
                        return Err(oauth_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            OAuthError::invalid_grant(),
                        ));
                    }
                };

            // Get user info and create OAuth access token
            let user_id = request.user_id.ok_or_else(|| {
                oauth_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    OAuthError::invalid_grant(),
                )
            })?;
            let user_email = request.user_email.ok_or_else(|| {
                oauth_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    OAuthError::invalid_grant(),
                )
            })?;
            let authenticator_id = request.authenticator_id.ok_or_else(|| {
                oauth_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    OAuthError::invalid_grant(),
                )
            })?;

            // Use the registered client_id from the device auth request.
            let client_id = request
                .client_id
                .unwrap_or_else(|| state.config().base_url.clone());
            let now_secs = now.as_second();

            // The device auth request doesn't carry aaguid/org_domain, so look
            // them up once here. These reads happen at session creation and
            // eliminate per-issuance lookups for every downstream token.
            //
            // Fail closed on DB errors: the snapshot is captured exactly once,
            // so silently dropping a transient failure would permanently
            // degrade the federation claims for this session's whole lifetime.
            let db_error = || {
                oauth_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    OAuthError::invalid_grant(),
                )
            };
            let hardware_aaguid = db::get_authenticator_by_id(&state.store, &authenticator_id)
                .await
                .map_err(|_| db_error())?
                .and_then(|a| a.aaguid);
            // A user deactivated (or deleted) after approving the device
            // authorization must not receive a token — the same `active`
            // guard every other grant path applies. The device code was
            // already consumed above, so the refusal burns it.
            let user = db::get_user_by_id(&state.store, &user_id)
                .await
                .map_err(|_| db_error())?
                .ok_or_else(|| oauth_error(StatusCode::BAD_REQUEST, OAuthError::invalid_grant()))?;
            if !user.active {
                tracing::warn!(
                    target: "security",
                    user_id = %user_id,
                    "Refusing device-flow token for deactivated user"
                );
                return Err(oauth_error(
                    StatusCode::BAD_REQUEST,
                    OAuthError::invalid_grant(),
                ));
            }
            let org_domain = match user.org_id {
                Some(org_id) => db::get_organization_domain(&state.store, &org_id)
                    .await
                    .map_err(|_| db_error())?,
                None => None,
            };

            let session_result = create_oauth_access_token(
                &state,
                CreateOAuthTokenParams {
                    user_id: &user_id,
                    email: &user_email,
                    authenticator_id: Some(&authenticator_id),
                    client_id: &client_id,
                    scope: Some(ScopeSet::all()),
                    dpop_jkt: None,
                    mtls_cert_thumbprint: None,
                    act: None,
                    audience: None,
                    auth_time: Some(now_secs),
                    hardware_verification: crate::services::auth::HardwareVerification::Verified,
                    session_purpose: crate::db::SessionPurpose::OAuthAccessToken,
                    authorization_details: None,
                    hardware_aaguid: hardware_aaguid.as_deref(),
                    org_domain: org_domain.as_deref(),
                },
                TokenIssuanceProof {
                    grant: GrantProof::DeviceCode(device_claim),
                    // RFC 8628 device authorization grant: the consumed
                    // `device_code` is itself the client credential at
                    // this endpoint — see GrantProof::DeviceCode above.
                    // No separate external client-auth step takes place.
                    client_auth: ClientAuthProof::NoAuth(
                        crate::services::auth::NoClientAuth::internal_endpoint(),
                    ),
                },
            )
            .await
            .map_err(|_| {
                oauth_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    OAuthError::invalid_grant(),
                )
            })?;

            let token = session_result.token;
            let expires_in = session_result.expires_in;

            // Record issuance like the other token-endpoint grants; the
            // device-code grant otherwise leaves no oauth_token_issued trail.
            // Usage stats correlate on the client's doc id, so resolve it for
            // registered clients; the built-in CLI flow (base_url fallback)
            // keeps the raw identifier.
            let audit_client_id =
                match db::get_oauth_client_by_client_id(&state.store, &client_id).await {
                    Ok(Some(c)) => c.id,
                    _ => client_id.clone(),
                };
            db::record_oauth_event(
                &state.audit,
                &state.store,
                &db::RecordOAuthEventParams {
                    oauth_client_id: &audit_client_id,
                    event_type: db::OAuthEventType::TokenIssued,
                    user_id: Some(&user_id),
                    ip_address: client_info.client_ip,
                    user_agent: client_info.user_agent.as_deref(),
                    details: Some("grant_type=device_code"),
                },
            )
            .await;

            tracing::info!(
                "Device authorization complete for: {}",
                redact_email(&user_email)
            );

            Ok(Json(DeviceTokenResponse {
                access_token: token.expose_secret().to_string(),
                token_type: "Bearer".to_string(),
                expires_in,
                email: user_email,
            }))
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;
    use crate::test_utils::*;

    // ========================================================================
    // RFC 8628 Section 3.2 - Device Code Response Format Tests
    // ========================================================================

    #[tokio::test]
    async fn test_rfc8628_device_code_response_format() {
        // RFC 8628 Section 3.2: Device code response must contain required fields
        let (app, _state) = test_app().await;

        // RFC 8628 Section 3.1: Request uses application/x-www-form-urlencoded
        let (status, body) = http_post_form(&app, "/oauth/device", "scope=openid", &[]).await;

        assert_eq!(status, StatusCode::OK);
        let resp: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

        // RFC 8628 Section 3.2 - Required fields
        assert!(resp.get("device_code").is_some(), "device_code is REQUIRED");
        assert!(resp.get("user_code").is_some(), "user_code is REQUIRED");
        assert!(
            resp.get("verification_uri").is_some(),
            "verification_uri is REQUIRED"
        );
        assert!(resp.get("expires_in").is_some(), "expires_in is REQUIRED");

        // Verify types
        assert!(
            resp["device_code"].is_string(),
            "device_code must be a string"
        );
        assert!(resp["user_code"].is_string(), "user_code must be a string");
        assert!(
            resp["verification_uri"].is_string(),
            "verification_uri must be a string"
        );
        assert!(
            resp["expires_in"].is_number(),
            "expires_in must be a number"
        );
    }

    #[tokio::test]
    async fn test_rfc8628_device_code_interval() {
        // RFC 8628 Section 3.2: interval field is OPTIONAL but recommended
        let (app, _state) = test_app().await;

        // RFC 8628 Section 3.1: Request uses application/x-www-form-urlencoded
        let (status, body) = http_post_form(&app, "/oauth/device", "scope=openid", &[]).await;

        assert_eq!(status, StatusCode::OK);
        let resp: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

        // interval is optional but we include it
        if let Some(interval) = resp.get("interval") {
            assert!(interval.is_number(), "interval must be a number if present");
            assert!(
                interval.as_u64().unwrap_or(0) >= 1,
                "interval should be at least 1 second"
            );
        }
    }

    // ========================================================================
    // RFC 8628 Section 6.1 - User Code Format Tests
    // ========================================================================

    #[tokio::test]
    async fn test_rfc8628_user_code_format() {
        // RFC 8628 Section 6.1: User code format recommendations
        let (app, _state) = test_app().await;

        // RFC 8628 Section 3.1: Request uses application/x-www-form-urlencoded
        let (status, body) = http_post_form(&app, "/oauth/device", "scope=openid", &[]).await;

        assert_eq!(status, StatusCode::OK);
        let resp: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

        let user_code = resp["user_code"].as_str().expect("user_code is a string");

        // RFC 8628 Section 6.1: User code should be in a format like XXXX-XXXX
        // Check format (8 characters with hyphen separator = 9 total)
        assert!(
            user_code.contains('-'),
            "User code should contain a separator for readability"
        );
        assert!(
            user_code.len() >= 8,
            "User code should be at least 8 characters for security"
        );
    }

    #[tokio::test]
    async fn test_rfc8628_user_code_alphabet() {
        // RFC 8628 Section 6.1: User code should avoid ambiguous characters
        // Our implementation uses: BCDFGHJKLMNPQRSTVWXZ (no vowels, no 0/O, 1/l/I confusion)
        let (app, _state) = test_app().await;

        // Generate multiple codes to test the character set
        for _ in 0..5 {
            // RFC 8628 Section 3.1: Request uses application/x-www-form-urlencoded
            let (status, body) = http_post_form(&app, "/oauth/device", "scope=openid", &[]).await;

            assert_eq!(status, StatusCode::OK);
            let resp: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
            let user_code = resp["user_code"].as_str().expect("user_code is a string");

            // Remove separator and check all characters are from our alphabet
            let code_chars: String = user_code.chars().filter(|c| *c != '-').collect();

            // All characters should be uppercase consonants (no vowels, no ambiguous chars)
            let valid_chars = "BCDFGHJKLMNPQRSTVWXZ";
            for c in code_chars.chars() {
                assert!(
                    valid_chars.contains(c),
                    "User code char '{}' should be from the restricted alphabet",
                    c
                );
            }

            // Verify no vowels are used (per RFC 8628 recommendation to avoid words)
            let vowels = "AEIOU";
            for c in code_chars.chars() {
                assert!(
                    !vowels.contains(c),
                    "User code should not contain vowel '{}'",
                    c
                );
            }
        }
    }

    // ========================================================================
    // RFC 8628 Section 3.5 - Device Token Polling Tests
    // ========================================================================

    #[tokio::test]
    async fn test_rfc8628_poll_authorization_pending() {
        // RFC 8628 Section 3.5: Pending authorization returns authorization_pending
        let (app, _state) = test_app().await;

        // Create a device auth request (RFC 8628 Section 3.1: form-urlencoded)
        let (status, body) = http_post_form(&app, "/oauth/device", "scope=openid", &[]).await;
        assert_eq!(status, StatusCode::OK);
        let code_resp: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        let device_code = code_resp["device_code"].as_str().expect("device_code");

        // Poll for token (should return authorization_pending)
        let (status, body) = http_post_form(
            &app,
            "/oauth/token",
            &format!(
                "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code={}",
                device_code
            ),
            &[],
        )
        .await;

        // First poll may return authorization_pending or slow_down (due to timing)
        assert!(
            status == StatusCode::BAD_REQUEST,
            "Pending auth should return 400"
        );
        let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        let error_code = error["error"].as_str().unwrap_or("");
        assert!(
            error_code == "authorization_pending" || error_code == "slow_down",
            "Expected authorization_pending or slow_down, got: {}",
            error_code
        );
    }

    #[tokio::test]
    async fn test_rfc8628_poll_expired_token() {
        // RFC 8628 Section 3.5: Expired device code returns expired_token
        let (app, state) = test_app().await;

        // Create an expired device auth request directly in the database
        let device_code = "test_expired_device_code";
        let device_code_hash = hash_device_code(device_code);
        let user_code = "EXPD-CODE";

        // Set expiration in the past
        let expires_at: Timestamp = "2020-01-01T00:00:00Z".parse().unwrap();
        crate::db::create_device_auth_request(
            &state.store,
            &device_code_hash,
            user_code,
            None,
            expires_at,
            5,
        )
        .await
        .expect("Failed to create device auth request");

        // Poll for token
        let (status, body) = http_post_form(
            &app,
            "/oauth/token",
            &format!(
                "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code={}",
                device_code
            ),
            &[],
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert_eq!(
            error["error"], "expired_token",
            "Expired code should return expired_token"
        );
    }

    #[tokio::test]
    async fn test_rfc8628_poll_access_denied() {
        // RFC 8628 Section 3.5: Denied authorization returns access_denied
        let (app, state) = test_app().await;

        // Create a device auth request and mark it as denied
        let device_code = "test_denied_device_code";
        let device_code_hash = hash_device_code(device_code);
        let user_code = "DENY-CODE";

        let now = Timestamp::now();
        let expires_at = now.checked_add(Span::new().hours(1)).unwrap();

        let id = crate::db::create_device_auth_request(
            &state.store,
            &device_code_hash,
            user_code,
            None,
            expires_at,
            5,
        )
        .await
        .expect("Failed to create device auth request");

        // Mark as denied
        crate::db::deny_device_auth(&state.store, &id)
            .await
            .expect("Failed to update status");

        // Poll for token
        let (status, body) = http_post_form(
            &app,
            "/oauth/token",
            &format!(
                "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code={}",
                device_code
            ),
            &[],
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert_eq!(
            error["error"], "access_denied",
            "Denied auth should return access_denied"
        );
    }

    #[tokio::test]
    async fn test_rfc8628_poll_invalid_device_code() {
        // RFC 8628: Invalid device code returns invalid_grant
        let (app, _state) = test_app().await;

        let (status, body) = http_post_form(
            &app,
            "/oauth/token",
            "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=nonexistent_code",
            &[],
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert_eq!(
            error["error"], "invalid_grant",
            "Invalid device code should return invalid_grant"
        );
    }

    #[tokio::test]
    async fn test_rfc8628_successful_authorization() {
        // RFC 8628: Successful authorization returns access token
        let (app, state) = test_app().await;

        // Create a device auth request
        let device_code = "test_success_device_code";
        let device_code_hash = hash_device_code(device_code);
        let user_code = "SUCC-CODE";

        let now = Timestamp::now();
        let expires_at = now.checked_add(Span::new().hours(1)).unwrap();

        let id = crate::db::create_device_auth_request(
            &state.store,
            &device_code_hash,
            user_code,
            None,
            expires_at,
            5,
        )
        .await
        .expect("Failed to create device auth request");

        // Create a user and authorize the request
        let user = create_test_user(&state.store, "device-success@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;

        crate::db::authorize_device_auth(&state.store, &id, &user.id, &user.email, &auth_id)
            .await
            .expect("Failed to authorize device");

        // Poll for token
        let (status, body) = http_post_form(
            &app,
            "/oauth/token",
            &format!(
                "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code={}",
                device_code
            ),
            &[],
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        let resp: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

        // Verify response contains required fields
        assert!(
            resp.get("access_token").is_some(),
            "Should return access_token"
        );
        assert!(resp.get("token_type").is_some(), "Should return token_type");
        assert_eq!(resp["token_type"], "Bearer");
        assert!(resp.get("expires_in").is_some(), "Should return expires_in");

        // The device-code grant records an oauth_token_issued audit event.
        let events = state
            .audit
            .query_events(&crate::db::AuditEventFilter {
                event_types: Some(vec!["oauth_token_issued".to_string()]),
                ..Default::default()
            })
            .await
            .expect("query audit events");
        assert_eq!(events.len(), 1, "one issuance -> one audit event");
        assert_eq!(events[0].user_id.as_deref(), Some(user.id.as_str()));
        let data: serde_json::Value =
            serde_json::from_str(&events[0].data).expect("event data JSON");
        assert_eq!(data["details"], "grant_type=device_code");
    }

    // ========================================================================
    // RFC 8628 Grant Type Tests
    // ========================================================================

    #[tokio::test]
    async fn test_rfc8628_wrong_grant_type() {
        // RFC 8628: Wrong grant type returns unsupported_grant_type
        let (app, _state) = test_app().await;

        // Using wrong grant type for device_code endpoint
        // Note: This test uses the unified token endpoint which handles multiple grant types
        let (status, body) = http_post_form(
            &app,
            "/oauth/token",
            "grant_type=password&device_code=test",
            &[],
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert_eq!(error["error"], "unsupported_grant_type");
    }

    // ========================================================================
    // RFC 8628 Content-Type Enforcement Tests
    // ========================================================================

    #[tokio::test]
    async fn test_rfc8628_device_code_rejects_json_content_type() {
        // RFC 8628 Section 3.1: Device authorization endpoint MUST use
        // application/x-www-form-urlencoded, not JSON
        let (app, _state) = test_app().await;

        // Attempt to use JSON content-type (should be rejected)
        let (status, _body) =
            http_post_json(&app, "/oauth/device", r#"{"client_id": "test"}"#, &[]).await;

        // Axum's Form extractor returns 415 Unsupported Media Type for JSON
        assert_eq!(
            status,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Device code endpoint should reject JSON content-type per RFC 8628"
        );
    }

    #[tokio::test]
    async fn test_device_code_rejects_unknown_client_id() {
        // Unknown client_id should be rejected as invalid_client.
        let (app, _state) = test_app().await;

        let (status, body) =
            http_post_form(&app, "/oauth/device", "client_id=unknown-client", &[]).await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert_eq!(error["error"], "invalid_client");
    }

    // ========================================================================
    // Device Code Input Validation Tests
    // ========================================================================

    #[tokio::test]
    async fn test_device_code_rejects_empty() {
        // Empty device_code should be rejected before DB lookup
        let (app, _state) = test_app().await;

        let (status, body) = http_post_form(
            &app,
            "/oauth/token",
            "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=",
            &[],
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert_eq!(error["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn test_device_code_rejects_too_long() {
        // Device code > 128 characters should be rejected
        let (app, _state) = test_app().await;

        let long_code = "a".repeat(200);
        let (status, body) = http_post_form(
            &app,
            "/oauth/token",
            &format!(
                "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code={}",
                long_code
            ),
            &[],
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert_eq!(error["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn test_device_code_accepts_valid_length() {
        // A device code within the length limit should pass validation
        // (it won't be found in DB, but it shouldn't be rejected by validation)
        let (app, _state) = test_app().await;

        let valid_code = "a".repeat(128);
        let (status, body) = http_post_form(
            &app,
            "/oauth/token",
            &format!(
                "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code={}",
                valid_code
            ),
            &[],
        )
        .await;

        // Should get invalid_grant (not found) rather than failing validation
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert_eq!(
            error["error"], "invalid_grant",
            "Valid-length code should pass validation and reach DB lookup"
        );
    }

    #[tokio::test]
    async fn test_rfc8628_token_endpoint_rejects_json_content_type() {
        // RFC 8628 Section 3.4 / RFC 6749 Section 4.1.3: Token endpoint MUST use
        // application/x-www-form-urlencoded, not JSON
        let (app, _state) = test_app().await;

        // Attempt to use JSON content-type (should be rejected)
        let (status, _body) = http_post_json(
            &app,
            "/oauth/token",
            r#"{"grant_type": "urn:ietf:params:oauth:grant-type:device_code", "device_code": "test"}"#,
            &[],
        )
        .await;

        // Axum's Form extractor returns 415 Unsupported Media Type for JSON
        assert_eq!(
            status,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Token endpoint should reject JSON content-type per RFC 8628/6749"
        );
    }

    // ========================================================================
    // RFC 8628 Section 3.5 - Device Code Single-Use Tests
    // ========================================================================

    #[tokio::test]
    async fn test_rfc8628_device_code_single_use() {
        // RFC 8628 Section 3.5: Device code is single-use.
        // After a successful token issuance, a second poll must
        // return invalid_grant.
        let (app, state) = test_app().await;

        let device_code = "test_single_use_device_code";
        let device_code_hash = hash_device_code(device_code);
        let user_code = "SNGL-CODE";

        let now = Timestamp::now();
        let expires_at = now.checked_add(Span::new().hours(1)).unwrap();

        let id = crate::db::create_device_auth_request(
            &state.store,
            &device_code_hash,
            user_code,
            None,
            expires_at,
            0, // no rate limit for test
        )
        .await
        .expect("create device auth");

        let user = create_test_user(&state.store, "single-use@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;

        crate::db::authorize_device_auth(&state.store, &id, &user.id, &user.email, &auth_id)
            .await
            .expect("authorize device");

        // First poll — should succeed
        let body = format!(
            "grant_type=urn:ietf:params:oauth:grant-type:\
             device_code&device_code={}",
            device_code
        );
        let (status, _) = http_post_form(&app, "/oauth/token", &body, &[]).await;
        assert_eq!(status, StatusCode::OK, "First poll should succeed");

        // Second poll — must return invalid_grant
        let (status, resp_body) = http_post_form(&app, "/oauth/token", &body, &[]).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "Second poll should fail");
        let error: serde_json::Value = serde_json::from_str(&resp_body).expect("Valid JSON");
        assert_eq!(
            error["error"], "invalid_grant",
            "Replayed device code must return invalid_grant"
        );
    }

    #[tokio::test]
    async fn test_rfc8628_consumed_code_returns_invalid_grant() {
        // Directly set a device code to Consumed, verify polling
        // returns invalid_grant.
        let (app, state) = test_app().await;

        let device_code = "test_consumed_device_code";
        let device_code_hash = hash_device_code(device_code);
        let user_code = "CNSD-CODE";

        let now = Timestamp::now();
        let expires_at = now.checked_add(Span::new().hours(1)).unwrap();

        let id = crate::db::create_device_auth_request(
            &state.store,
            &device_code_hash,
            user_code,
            None,
            expires_at,
            0,
        )
        .await
        .expect("create device auth");

        let user = create_test_user(&state.store, "consumed-test@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;

        // Authorize then consume
        crate::db::authorize_device_auth(&state.store, &id, &user.id, &user.email, &auth_id)
            .await
            .expect("authorize");

        let _claim = crate::db::try_consume_device_auth(&state.store, &device_code_hash)
            .await
            .expect("Consumption should succeed");

        // Poll — must return invalid_grant
        let body = format!(
            "grant_type=urn:ietf:params:oauth:grant-type:\
             device_code&device_code={}",
            device_code
        );
        let (status, resp_body) = http_post_form(&app, "/oauth/token", &body, &[]).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let error: serde_json::Value = serde_json::from_str(&resp_body).expect("Valid JSON");
        assert_eq!(
            error["error"], "invalid_grant",
            "Consumed device code must return invalid_grant"
        );
    }

    #[tokio::test]
    async fn test_rfc8628_consumed_code_with_session_revokes_tokens() {
        // Verify that replay detection actually revokes the user's
        // OAuth sessions, not just returns invalid_grant.
        let (app, state) = test_app().await;

        let device_code = "test_revoke_device_code";
        let device_code_hash = hash_device_code(device_code);
        let user_code = "RVOK-CODE";

        let now = Timestamp::now();
        let expires_at = now.checked_add(Span::new().hours(1)).unwrap();

        let id = crate::db::create_device_auth_request(
            &state.store,
            &device_code_hash,
            user_code,
            None,
            expires_at,
            0,
        )
        .await
        .expect("create device auth");

        let user = create_test_user(&state.store, "revoke@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;

        crate::db::authorize_device_auth(&state.store, &id, &user.id, &user.email, &auth_id)
            .await
            .expect("authorize");

        // First poll — get a real token
        let body = format!(
            "grant_type=urn:ietf:params:oauth:grant-type:\
             device_code&device_code={}",
            device_code
        );
        let (status, resp_body) = http_post_form(&app, "/oauth/token", &body, &[]).await;
        assert_eq!(status, StatusCode::OK, "First poll should succeed");

        // Extract the token and verify the session exists
        let resp: serde_json::Value = serde_json::from_str(&resp_body).expect("Valid JSON");
        let token = resp["access_token"].as_str().expect("token");
        let token_hash = {
            use aws_lc_rs::digest::{self, SHA256};
            URL_SAFE_NO_PAD.encode(digest::digest(&SHA256, token.as_bytes()).as_ref())
        };
        let session =
            crate::db::get_session_by_token_hash(&state.store, &token_hash, Timestamp::now())
                .await
                .expect("session lookup");
        assert!(session.is_some(), "Session should exist before replay");

        // Replay — triggers revocation
        let (status, _) = http_post_form(&app, "/oauth/token", &body, &[]).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // Session should now be revoked
        let session =
            crate::db::get_session_by_token_hash(&state.store, &token_hash, Timestamp::now())
                .await
                .expect("session lookup");
        assert!(session.is_none(), "Session should be revoked after replay");
    }

    #[tokio::test]
    async fn test_rfc8628_consumed_code_without_user_id() {
        // A consumed device code with no user_id should still return
        // invalid_grant without a 500.
        let (app, state) = test_app().await;

        let device_code = "test_no_user_device_code";
        let device_code_hash = hash_device_code(device_code);
        let user_code = "NUID-CODE";

        let now = Timestamp::now();
        let expires_at = now.checked_add(Span::new().hours(1)).unwrap();

        let id = crate::db::create_device_auth_request(
            &state.store,
            &device_code_hash,
            user_code,
            None,
            expires_at,
            0,
        )
        .await
        .expect("create device auth");

        // Directly set status to Consumed without user_id by
        // manipulating the document store.
        use crate::db::documents::device_auth::DeviceAuthRequestDoc;
        let doc = state
            .store
            .get::<DeviceAuthRequestDoc>(&id)
            .await
            .expect("get")
            .expect("doc exists");
        let mut data = doc.data;
        data.status = crate::db::DeviceAuthStatus::Consumed;
        data.consumed_at = Some(now);
        // user_id remains None
        state.store.update(&id, &data).await.expect("update");

        // Poll — should return invalid_grant, not 500
        let body = format!(
            "grant_type=urn:ietf:params:oauth:grant-type:\
             device_code&device_code={}",
            device_code
        );
        let (status, resp_body) = http_post_form(&app, "/oauth/token", &body, &[]).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "Should return 400, not 500"
        );
        let error: serde_json::Value = serde_json::from_str(&resp_body).expect("Valid JSON");
        assert_eq!(
            error["error"], "invalid_grant",
            "Consumed code without user_id should return invalid_grant"
        );
    }

    // ========================================================================
    // Device Code Race-Loser Session Revocation Tests
    // ========================================================================

    /// Helper: set up an authorized device code for a user and create a
    /// pre-existing OAuth session for that user. Returns everything the
    /// race tests need.
    struct RaceSetup {
        device_code_hash: String,
        body: String,
        token_hash: String,
        user_id: String,
    }

    async fn setup_race(setup_label: &str) -> (axum::Router, Arc<AppState>, RaceSetup) {
        let (app, state) = test_app().await;

        let device_code = format!("test_race_{setup_label}");
        let device_code_hash = hash_device_code(&device_code);
        let user_code = "RACE-CODE";

        let now = Timestamp::now();
        let expires_at = now.checked_add(Span::new().hours(1)).unwrap();

        let id = crate::db::create_device_auth_request(
            &state.store,
            &device_code_hash,
            user_code,
            None,
            expires_at,
            0,
        )
        .await
        .expect("create device auth");

        let user = create_test_user(&state.store, &format!("{setup_label}@example.com")).await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;

        crate::db::authorize_device_auth(&state.store, &id, &user.id, &user.email, &auth_id)
            .await
            .expect("authorize device");

        // Create a pre-existing OAuth session for the user. Its survival
        // after a race-loser AlreadyConsumed is the regression we test for.
        let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;
        let token_hash = {
            use aws_lc_rs::digest::{self, SHA256};
            URL_SAFE_NO_PAD.encode(digest::digest(&SHA256, token.as_bytes()).as_ref())
        };
        let session =
            crate::db::get_session_by_token_hash(&state.store, &token_hash, Timestamp::now())
                .await
                .expect("session lookup");
        assert!(session.is_some(), "pre-existing session should exist");

        let body = format!(
            "grant_type=urn:ietf:params:oauth:grant-type:\
             device_code&device_code={}",
            device_code
        );

        (
            app,
            state,
            RaceSetup {
                device_code_hash,
                body,
                token_hash,
                user_id: user.id,
            },
        )
    }

    /// The race-loser `AlreadyConsumed` path must revoke all of the user's
    /// pre-existing OAuth sessions, matching the authorization code flow's
    /// defensive posture.
    #[tokio::test]
    async fn test_device_code_race_loser_revokes_sessions() {
        use crate::db::claim::ClaimError;

        let (_app, state, setup) = setup_race("revoke").await;

        // Two concurrent consumes of the same device code. Exactly one wins;
        // the other gets AlreadyConsumed. This is the same OCC pattern used
        // by the authorization code flow.
        let store_a = state.store.clone();
        let store_b = state.store.clone();
        let hash_a = setup.device_code_hash.clone();
        let hash_b = setup.device_code_hash.clone();
        let (result_a, result_b) = tokio::join!(
            async move { crate::db::try_consume_device_auth(&store_a, &hash_a).await },
            async move { crate::db::try_consume_device_auth(&store_b, &hash_b).await },
        );

        let a_won = result_a.is_ok();
        let b_won = result_b.is_ok();
        assert!(
            a_won ^ b_won,
            "exactly one concurrent device-code consume must win, got a={a_won}, b={b_won}"
        );
        for r in [result_a, result_b] {
            if let Err(e) = r {
                assert!(
                    matches!(e, ClaimError::AlreadyConsumed),
                    "loser should be AlreadyConsumed, got: {e:?}"
                );
            }
        }

        // Simulate what the handler does on the AlreadyConsumed branch:
        // revoke all OAuth sessions for the user that authorized the device
        // code (request.user_id, captured here as setup.user_id).
        let count = crate::db::delete_oauth_sessions_for_user(&state.store, &setup.user_id)
            .await
            .expect("delete sessions");
        assert!(count > 0, "should have revoked at least one session");
        state.session_cache.invalidate_for_user(&setup.user_id);

        // The pre-existing session must now be gone.
        let session =
            crate::db::get_session_by_token_hash(&state.store, &setup.token_hash, Timestamp::now())
                .await
                .expect("session lookup");
        assert!(
            session.is_none(),
            "race-loser AlreadyConsumed must revoke pre-existing sessions"
        );
    }

    /// End-to-end: when two concurrent `/oauth/token` device-code polls
    /// race, the loser's response must trigger revocation of the user's
    /// pre-existing session. Drives the HTTP handler, not just the db layer.
    #[tokio::test]
    async fn test_device_code_race_loser_revokes_sessions_via_handler() {
        let (app, state, setup) = setup_race("handler").await;

        // Issue two concurrent token requests for the same device code.
        // Exactly one wins and gets an access token; the other gets a 400
        // invalid_grant and — via the handler — revokes sessions.
        let app_a = app.clone();
        let app_b = app.clone();
        let body_a = setup.body.clone();
        let body_b = setup.body.clone();
        let (resp_a, resp_b) = tokio::join!(
            async move { http_post_form(&app_a, "/oauth/token", &body_a, &[]).await },
            async move { http_post_form(&app_b, "/oauth/token", &body_b, &[]).await },
        );

        let a_ok = resp_a.0 == StatusCode::OK;
        let b_ok = resp_b.0 == StatusCode::OK;
        assert!(
            a_ok ^ b_ok,
            "exactly one concurrent poll must succeed, got a={} b={}",
            resp_a.0,
            resp_b.0
        );

        // The loser must return invalid_grant (400).
        let (loser_status, loser_body) = if !a_ok { resp_a } else { resp_b };
        assert_eq!(loser_status, StatusCode::BAD_REQUEST);
        let error: serde_json::Value = serde_json::from_str(&loser_body).expect("Valid JSON");
        assert_eq!(
            error["error"], "invalid_grant",
            "race-loser must return invalid_grant"
        );

        // After the race, the user's pre-existing session must be revoked.
        // Note: the winner's freshly-issued session is ALSO revoked under the
        // "replay = full logout" posture — matching the authorization code
        // flow. So we only assert the pre-existing session is gone.
        let session =
            crate::db::get_session_by_token_hash(&state.store, &setup.token_hash, Timestamp::now())
                .await
                .expect("session lookup");
        assert!(
            session.is_none(),
            "race-loser handler path must revoke pre-existing sessions"
        );
    }

    #[tokio::test]
    async fn test_device_token_refused_for_deactivated_user() {
        // A user deactivated between the browser approval and the CLI's
        // token poll must not receive a token (issue #846: the device flow
        // was the one grant path without a `user.active` check).
        let (app, state) = test_app().await;

        let device_code = "test_deactivated_user_code";
        let device_code_hash = hash_device_code(device_code);
        let now = Timestamp::now();
        let expires_at = now.checked_add(Span::new().hours(1)).unwrap();
        let id = crate::db::create_device_auth_request(
            &state.store,
            &device_code_hash,
            "DEAC-CODE",
            None,
            expires_at,
            0,
        )
        .await
        .expect("create device auth");

        let user = create_test_user(&state.store, "device-deactivated@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        crate::db::authorize_device_auth(&state.store, &id, &user.id, &user.email, &auth_id)
            .await
            .expect("authorize device");

        crate::db::update_user_active_status(&state.store, &user.id, false)
            .await
            .expect("deactivate user");

        let body = format!(
            "grant_type=urn:ietf:params:oauth:grant-type:\
             device_code&device_code={device_code}"
        );
        let (status, resp) = http_post_form(&app, "/oauth/token", &body, &[]).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "deactivated user must not mint a device-flow token: {resp}"
        );
        let error: serde_json::Value = serde_json::from_str(&resp).expect("Valid JSON");
        assert_eq!(error["error"], "invalid_grant");
        assert!(
            !resp.contains("access_token"),
            "no token may be issued: {resp}"
        );
    }
}
