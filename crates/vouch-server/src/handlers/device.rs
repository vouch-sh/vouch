// SPDX-License-Identifier: BUSL-1.1
//! Device Authorization Grant handlers (RFC 8628).

use crate::AppState;
use crate::db::{self, DeviceAuthStatus};
use aws_lc_rs::digest::{self, SHA256};
use aws_lc_rs::rand as aws_rand;
use axum::{Json, extract::State, http::StatusCode};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jiff::{Span, Timestamp};
use std::sync::Arc;
use vouch_common::{
    ApiError, DeviceCodeRequest, DeviceCodeResponse, DeviceTokenRequest, DeviceTokenResponse,
    OAuthError,
};

use super::json_error;

/// Characters used for user code generation (no ambiguous characters).
const USER_CODE_ALPHABET: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ";

/// OAuth error response helper.
fn oauth_error(status: StatusCode, error: OAuthError) -> (StatusCode, Json<OAuthError>) {
    (status, Json(error))
}

/// Generate a random device code (32 bytes, base64url encoded).
///
/// # Panics
/// Panics if the system RNG fails.
#[allow(clippy::expect_used)]
fn generate_device_code() -> String {
    let mut bytes = vec![0u8; 32];
    aws_rand::fill(&mut bytes).expect("RNG failure");
    URL_SAFE_NO_PAD.encode(&bytes)
}

/// Generate a user-friendly code in XXXX-XXXX format.
///
/// # Panics
/// Panics if the system RNG fails.
#[allow(clippy::expect_used)]
fn generate_user_code() -> String {
    let mut bytes = vec![0u8; 8];
    aws_rand::fill(&mut bytes).expect("RNG failure");

    let chars: Vec<char> = bytes
        .iter()
        .map(|b| {
            let idx = (*b as usize) % USER_CODE_ALPHABET.len();
            USER_CODE_ALPHABET.get(idx).copied().unwrap_or(b'X') as char
        })
        .collect();

    format!(
        "{}-{}",
        chars.iter().take(4).collect::<String>(),
        chars.iter().skip(4).collect::<String>()
    )
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
#[allow(clippy::unused_async)]
pub async fn device_code(
    State(state): State<Arc<AppState>>,
    axum::Form(_req): axum::Form<DeviceCodeRequest>,
) -> Result<Json<DeviceCodeResponse>, (StatusCode, Json<ApiError>)> {
    tracing::info!("Device authorization request");

    // Generate codes
    let device_code = generate_device_code();
    let user_code = generate_user_code();
    let device_code_hash = hash_device_code(&device_code);

    // Calculate expiration
    let now = Timestamp::now();
    let expires_seconds = i64::try_from(state.config.device_code_expires_seconds).unwrap_or(600);
    let duration = Span::new().seconds(expires_seconds);
    let expires_at = now.checked_add(duration).map_err(|_| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "time_error",
            "Time overflow",
        )
    })?;

    let interval_seconds = i64::try_from(state.config.device_poll_interval_seconds).unwrap_or(5);

    // Store in database
    db::create_device_auth_request(
        &state.db,
        &device_code_hash,
        &user_code,
        &expires_at.to_string(),
        interval_seconds,
    )
    .await
    .map_err(|e| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "db_error",
            &e.to_string(),
        )
    })?;

    // Build verification URL
    let verification_uri = format!("{}/device", state.config.base_url);

    tracing::info!("Created device auth request, user_code: {}", user_code);

    Ok(Json(DeviceCodeResponse {
        device_code,
        user_code,
        verification_uri,
        expires_in: state.config.device_code_expires_seconds,
        interval: state.config.device_poll_interval_seconds,
    }))
}

/// Poll for device token.
/// POST /oauth/token
#[allow(clippy::unused_async)]
pub async fn device_token(
    State(state): State<Arc<AppState>>,
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

    // Hash the device code and look it up
    let device_code_hash = hash_device_code(&req.device_code);
    let request = db::get_device_auth_by_code_hash(&state.db, &device_code_hash)
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
    let expires_at = request.expires_at.to_jiff();

    if now > expires_at {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            OAuthError::expired_token(),
        ));
    }

    // Check polling rate
    let allowed =
        db::update_device_auth_poll_time(&state.db, &request.id, request.interval_seconds)
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

    // Check status
    let status = request.status().ok_or_else(|| {
        oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            OAuthError::invalid_grant(),
        )
    })?;

    match status {
        DeviceAuthStatus::Pending => Err(oauth_error(
            StatusCode::BAD_REQUEST,
            OAuthError::authorization_pending(),
        )),
        DeviceAuthStatus::Denied => Err(oauth_error(
            StatusCode::BAD_REQUEST,
            OAuthError::access_denied(),
        )),
        DeviceAuthStatus::Authorized => {
            // Get user info and create session token
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

            // Generate session token (reuse the auth module's session creation logic)
            let session_hours = i64::try_from(state.config.session_hours).unwrap_or(8);
            let duration = Span::new().hours(session_hours);
            let session_expires = now.checked_add(duration).map_err(|_| {
                oauth_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    OAuthError::invalid_grant(),
                )
            })?;

            // Create JWT claims
            let claims = crate::services::auth::SessionClaims {
                sub: user_id.clone(),
                email: user_email.clone(),
                authenticator_id: Some(authenticator_id.clone()),
                iat: now.as_second(),
                exp: session_expires.as_second(),
            };

            let token = jsonwebtoken::encode(
                &jsonwebtoken::Header::default(),
                &claims,
                &jsonwebtoken::EncodingKey::from_secret(state.config.jwt_secret_bytes()),
            )
            .map_err(|_| {
                oauth_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    OAuthError::invalid_grant(),
                )
            })?;

            // Store session in database
            let token_hash = {
                let hash = digest::digest(&SHA256, token.as_bytes());
                URL_SAFE_NO_PAD.encode(hash.as_ref())
            };

            db::create_session(
                &state.db,
                &user_id,
                &token_hash,
                Some(&authenticator_id),
                &session_expires.to_string(),
            )
            .await
            .map_err(|_| {
                oauth_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    OAuthError::invalid_grant(),
                )
            })?;

            let expires_in = u64::try_from(session_expires.as_second() - now.as_second())
                .unwrap_or(state.config.session_hours * 3600);

            tracing::info!("Device authorization complete for: {}", user_email);

            Ok(Json(DeviceTokenResponse {
                access_token: token,
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
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
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
        let (status, body) = http_post_form(&app, "/oauth/device", "client_id=test", &[]).await;

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
        let (status, body) = http_post_form(&app, "/oauth/device", "client_id=test", &[]).await;

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
        let (status, body) = http_post_form(&app, "/oauth/device", "client_id=test", &[]).await;

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
            let (status, body) = http_post_form(&app, "/oauth/device", "client_id=test", &[]).await;

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
        let (status, body) = http_post_form(&app, "/oauth/device", "client_id=test", &[]).await;
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
        let expires_at = "2020-01-01T00:00:00Z";
        crate::db::create_device_auth_request(
            &state.db,
            &device_code_hash,
            user_code,
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
        let expires_at = now.checked_add(Span::new().hours(1)).unwrap().to_string();

        let id = crate::db::create_device_auth_request(
            &state.db,
            &device_code_hash,
            user_code,
            &expires_at,
            5,
        )
        .await
        .expect("Failed to create device auth request");

        // Mark as denied
        crate::db::deny_device_auth(&state.db, &id)
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
        let expires_at = now.checked_add(Span::new().hours(1)).unwrap().to_string();

        let id = crate::db::create_device_auth_request(
            &state.db,
            &device_code_hash,
            user_code,
            &expires_at,
            5,
        )
        .await
        .expect("Failed to create device auth request");

        // Create a user and authorize the request
        let user = create_test_user(&state.db, "device-success@example.com").await;
        let auth_id = create_test_authenticator(&state.db, &user.id).await;

        crate::db::authorize_device_auth(&state.db, &id, &user.id, &user.email, &auth_id)
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
        assert_eq!(error["code"], "unsupported_grant_type");
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
}
