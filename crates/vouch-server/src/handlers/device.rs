// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Device Authorization Grant handlers (RFC 8628).

use crate::AppState;
use crate::db::{self, DeviceAuthState};
use crate::handlers::extractors::{OAuthForm, OptionalClientCert};
use crate::services::auth::{
    ClientAuthProof, CreateOAuthTokenParams, GrantProof, SenderConstraintProof, TokenBinding,
    TokenIssuanceProof, create_oauth_access_token,
};
use crate::services::oidc::ScopeSet;
use crate::services::oidc::dpop::DpopError;
use crate::services::oidc::token::validate_dpop_if_present;
use aws_lc_rs::digest::{self, SHA256};
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jiff::{Span, Timestamp};
use std::sync::Arc;
use vouch_common::{
    DeviceCodeRequest, DeviceCodeResponse, DeviceTokenResponse, OAuthError, protocol,
};

use crate::error::{OAuthErrorCode, ServiceError};
use crate::handlers::oidc::dpop_use_nonce_response;
use crate::redact_email;

/// Characters used for user code generation (no ambiguous characters).
const USER_CODE_ALPHABET: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ";

/// OAuth error response helper.
fn oauth_error(status: StatusCode, error: OAuthError) -> Response {
    (status, Json(error)).into_response()
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
/// [`protocol::CONTENT_TYPE_FORM_URLENCODED`] format.
pub(crate) async fn device_code(
    State(state): State<Arc<AppState>>,
    OAuthForm(req): OAuthForm<DeviceCodeRequest>,
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

/// Revoke the OAuth sessions issued from a replayed device code, and drop
/// them from the session cache.
///
/// RFC 6749 Section 10.5 asks the server to "revoke all access tokens already
/// granted based on the compromised authorization code", which applies by
/// extension to a device code: revocation is bounded to that code, not
/// widened to every session for the user. `user_id` is used only for the
/// security log; revocation targets sessions whose `source_code_hash` equals
/// `device_code_hash`.
///
/// The caller is already returning `invalid_grant` for the replay; a failed
/// revocation must not mask that response, but it is a security event that
/// must stay visible, so it is logged at error level rather than propagated.
async fn revoke_sessions_for_device_replay(
    state: &AppState,
    device_code_hash: &str,
    user_id: Option<&str>,
) {
    tracing::warn!(
        target: "security",
        user_id = ?user_id,
        "Device code replay detected — revoking tokens issued from that code"
    );
    match db::delete_sessions_for_code_replay(&state.store, device_code_hash).await {
        Ok(token_hashes) => {
            for token_hash in &token_hashes {
                state.session_cache.invalidate(token_hash);
            }
            if !token_hashes.is_empty() {
                tracing::warn!(
                    target: "security",
                    user_id = ?user_id,
                    revoked_count = token_hashes.len(),
                    "Revoked tokens issued from the replayed device code"
                );
            }
        }
        Err(e) => {
            tracing::error!(
                target: "security",
                user_id = ?user_id,
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
#[expect(
    clippy::result_large_err,
    reason = "Err is an HTTP Response; size is acceptable in error path"
)]
pub(crate) async fn device_token(
    State(state): State<Arc<AppState>>,
    client_info: db::ClientInfo,
    client_cert: OptionalClientCert,
    headers: HeaderMap,
    device_code: &str,
) -> Result<Json<DeviceTokenResponse>, Response> {
    // Validate device_code format before hashing and DB lookup.
    // Generated codes are 32 random bytes base64url-encoded (43 chars).
    // Reject obviously invalid inputs to avoid unnecessary work.
    if device_code.is_empty() || device_code.len() > 128 {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            OAuthError::invalid_grant(),
        ));
    }

    // Hash the device code and look it up
    let device_code_hash = hash_device_code(device_code);
    let request = db::get_device_auth_by_code_hash(&state.store, &device_code_hash)
        .await
        .map_err(|e| {
            tracing::error!("Failed to look up device authorization request: {e}");
            oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                OAuthError::server_error(),
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
            .map_err(|e| {
                tracing::error!("Failed to update device authorization poll time: {e}");
                oauth_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    OAuthError::server_error(),
                )
            })?;

    if !allowed {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            OAuthError::slow_down(),
        ));
    }

    match request.state {
        DeviceAuthState::Pending => Err(oauth_error(
            StatusCode::BAD_REQUEST,
            OAuthError::authorization_pending(),
        )),
        DeviceAuthState::Denied => Err(oauth_error(
            StatusCode::BAD_REQUEST,
            OAuthError::access_denied(),
        )),
        DeviceAuthState::Consumed { user_id } => {
            // RFC 8628 Section 3.5: Device code already used.
            // Replay detected — revoke only the tokens issued from this
            // device code (RFC 6749 §10.5), not every session for the user.
            revoke_sessions_for_device_replay(&state, &device_code_hash, user_id.as_deref()).await;
            Err(oauth_error(
                StatusCode::BAD_REQUEST,
                OAuthError::invalid_grant(),
            ))
        }
        DeviceAuthState::Authorized(stale_approval) => {
            // RFC 9449 / FAPI 2.0: Validate the DPoP proof if present.
            // This happens BEFORE consuming the device code so that a
            // `use_dpop_nonce` or `invalid_dpop_proof` response does not
            // burn the single-use code — the client can retry with a
            // corrected proof. Consistent with the authorization code
            // grant, which validates DPoP before exchanging the code.
            let dpop_header = headers
                .get(protocol::HEADER_DPOP)
                .and_then(|v| v.to_str().ok());
            let dpop_proof =
                match validate_dpop_if_present(&state, dpop_header, "POST", "/oauth/token").await {
                    Ok(proof) => proof,
                    Err(DpopError::UseNonce(nonce)) => {
                        return Err(dpop_use_nonce_response(&nonce));
                    }
                    Err(e @ DpopError::Database(_)) => {
                        return Err(oauth_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            OAuthError {
                                error: OAuthErrorCode::ServerError.as_str().to_string(),
                                error_description: Some(e.to_string()),
                            },
                        ));
                    }
                    Err(e) => {
                        return Err(oauth_error(
                            StatusCode::BAD_REQUEST,
                            OAuthError {
                                error: OAuthErrorCode::InvalidDpopProof.as_str().to_string(),
                                error_description: Some(e.to_string()),
                            },
                        ));
                    }
                };
            let has_mtls_cert = client_cert.0.is_some();

            // Look up the registered OAuth client to enforce FAPI 2.0
            // sender-constraint requirements. The built-in CLI flow (no
            // registered client_id) has no FAPI constraints — consistent
            // with how the device auth request is created in `device_code`.
            let oauth_client = match request.client_id.as_deref() {
                Some(cid) => match db::get_oauth_client_by_client_id(&state.store, cid).await {
                    Ok(Some(c)) => Some(c),
                    // A device request carrying a client_id that no longer
                    // resolves (client deleted mid-flow) must not fall
                    // through with FAPI enforcement disabled — that would
                    // issue an unbound token.
                    Ok(None) => {
                        return Err(oauth_error(
                            StatusCode::UNAUTHORIZED,
                            OAuthError {
                                error: OAuthErrorCode::InvalidClient.as_str().to_string(),
                                error_description: Some(
                                    "Unknown client_id for device authorization".to_string(),
                                ),
                            },
                        ));
                    }
                    Err(e) => {
                        tracing::error!("Failed to look up OAuth client for device grant: {e}");
                        return Err(oauth_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            OAuthError::server_error(),
                        ));
                    }
                },
                None => None,
            };

            // Every sender-constraint requirement registered for this
            // client. The built-in CLI flow carries no registered client_id,
            // so there is no registration to enforce against.
            let sender_constraint = match oauth_client {
                Some(ref oc) => match SenderConstraintProof::validate(
                    oc,
                    crate::services::oidc::fapi::SenderConstraints {
                        dpop: dpop_proof.is_some(),
                        mtls_cert: has_mtls_cert,
                    },
                ) {
                    Ok(witness) => witness,
                    Err(e) => return Err(e.into_oauth_response().into_response()),
                },
                None => SenderConstraintProof::no_registered_client(),
            };

            // RFC 8705 Section 3: Bind the access token to the mTLS
            // certificate thumbprint only when the client has opted in.
            // DPoP (jkt) takes priority over mTLS (x5t#S256) in
            // `create_oauth_access_token`.
            let mtls_cert_thumbprint = oauth_client
                .as_ref()
                .filter(|c| c.tls_client_certificate_bound_access_tokens)
                .and(client_cert.0.as_ref())
                .map(|c| c.thumbprint.clone());

            // RFC 8628 Section 3.5: Atomically consume the device
            // code before issuing a token. The returned approval is the
            // attribution read in the same atomic step — issuance never
            // uses the raceable top-of-handler read — and the claim is
            // the structural proof that this caller won the consume,
            // threaded into TokenIssuanceProof below.
            //
            // `AlreadyConsumed` is deliberately indistinguishable between a
            // code that was consumed earlier (replay) and a code that a
            // concurrent caller just consumed (race loser) — see
            // `try_consume_device_auth`. Match the authorization code flow's
            // precise-revocation posture (RFC 6749 §10.5): revoke only the
            // tokens issued from **that** device code in either case,
            // attributed via the approval read at the top of the handler.
            let (approval, device_claim) =
                match db::try_consume_device_auth(&state.store, &device_code_hash).await {
                    Ok(consumed) => consumed,
                    Err(db::claim::ClaimError::AlreadyConsumed) => {
                        revoke_sessions_for_device_replay(
                            &state,
                            &device_code_hash,
                            Some(&stale_approval.user_id),
                        )
                        .await;
                        return Err(oauth_error(
                            StatusCode::BAD_REQUEST,
                            OAuthError::invalid_grant(),
                        ));
                    }
                    Err(db::claim::ClaimError::InvalidInput(msg)) => {
                        tracing::warn!("Rejected device code on consume: {msg}");
                        return Err(oauth_error(
                            StatusCode::BAD_REQUEST,
                            OAuthError::invalid_grant(),
                        ));
                    }
                    Err(db::claim::ClaimError::Database(e)) => {
                        tracing::error!("Failed to consume device code: {e}");
                        return Err(oauth_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            OAuthError::server_error(),
                        ));
                    }
                };
            let db::DeviceAuthApproval {
                user_id,
                user_email,
                authenticator_id,
                verification,
            } = approval;

            // Use the registered client_id from the device auth request.
            let client_id = request
                .client_id
                .unwrap_or_else(|| state.config().base_url.to_string());

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
                    OAuthError::server_error(),
                )
            };
            let hardware_aaguid = db::get_authenticator_by_id(&state.store, &authenticator_id)
                .await
                .map_err(|e| {
                    tracing::error!("Failed to load authenticator for device grant: {e}");
                    db_error()
                })?
                .and_then(|a| a.aaguid);
            // A user deactivated (or deleted) after approving the device
            // authorization must not receive a token — the same `active`
            // guard every other grant path applies. The device code was
            // already consumed above, so the refusal burns it.
            let user = db::get_user_by_id(&state.store, &user_id)
                .await
                .map_err(|e| {
                    tracing::error!("Failed to load user for device grant: {e}");
                    db_error()
                })?
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
                    .map_err(|e| {
                        tracing::error!("Failed to load organization domain for device grant: {e}");
                        db_error()
                    })?,
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
                    binding: TokenBinding::new(dpop_proof.as_ref(), mtls_cert_thumbprint.as_ref()),
                    act: None,
                    audience: None,
                    // Verbatim from the approval, so the claims the credential
                    // endpoints gate on reflect what the browser actually did
                    // — `auth_time` in particular is the ceremony instant
                    // recorded there, not this poll's instant, which can lag
                    // it by up to the device code's lifetime and would
                    // overstate freshness to the key-deletion step-up gate.
                    hardware_verification: verification,
                    session_purpose: crate::db::SessionPurpose::OAuthAccessToken,
                    authorization_details: None,
                    hardware_aaguid: hardware_aaguid.as_deref(),
                    org_domain: org_domain.as_deref(),
                    // Link this session to the consumed device code so replay
                    // detection (revoke_sessions_for_device_replay above) can
                    // revoke only this code's tokens per RFC 6749 §10.5.
                    source_code_hash: Some(&device_code_hash),
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
                    sender_constraint,
                },
            )
            .await
            .map_err(|e| {
                tracing::error!("Failed to create device-flow access token: {e}");
                oauth_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    OAuthError::server_error(),
                )
            })?;

            let token = session_result.token;
            let expires_in = session_result.expires_in;
            let token_type = session_result.token_type;

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
                // Clone the SecretString rather than rebuilding it via
                // expose_secret(): the intermediate String would never be
                // zeroized.
                access_token: token.clone(),
                token_type: token_type.to_string(),
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
    use crate::assurance::HardwareVerification;
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

    /// RFC 8628 §3.5 (https://www.rfc-editor.org/rfc/rfc8628#section-3.5):
    ///
    /// > access_denied
    /// >    The authorization request was denied.
    ///
    /// Deleting the approving authenticator before the device redeems the
    /// code voids the approval: the poll answers `access_denied`, not a 500,
    /// and the device code is not burned on the way to the error.
    #[tokio::test]
    async fn test_rfc8628_poll_after_approving_authenticator_deleted() {
        let (app, state) = test_app().await;

        let device_code = "test_deleted_authenticator_code";
        let expires_at = Timestamp::now()
            .checked_add(Span::new().hours(1))
            .expect("expiry");
        let id = crate::db::create_device_auth_request(
            &state.store,
            &hash_device_code(device_code),
            "GONE-CODE",
            None,
            expires_at,
            0,
        )
        .await
        .expect("create device auth");

        let user = create_test_user(&state.store, "deleted-approver@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        crate::db::authorize_device_auth(
            &state.store,
            crate::db::AuthorizeDeviceAuthParams {
                id: &id,
                user_id: &user.id,
                user_email: &user.email,
                authenticator_id: &auth_id,
                verification: HardwareVerification::Verified {
                    auth_time: Some(Timestamp::now().as_second()),
                },
            },
        )
        .await
        .expect("authorize device");

        crate::test_utils::remove_test_authenticator(&state.store, &auth_id).await;

        let (status, body) = http_post_form(
            &app,
            "/oauth/token",
            &format!(
                "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code={device_code}"
            ),
            &[],
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
        let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert_eq!(
            error["error"], "access_denied",
            "deleted approver must void the approval: {body}"
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

        crate::db::authorize_device_auth(
            &state.store,
            crate::db::AuthorizeDeviceAuthParams {
                id: &id,
                user_id: &user.id,
                user_email: &user.email,
                authenticator_id: &auth_id,
                verification: HardwareVerification::Verified {
                    auth_time: Some(Timestamp::now().as_second()),
                },
            },
        )
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
        // No DPoP proof was presented, so RFC 9449 Section 5 requires "Bearer".
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

    /// RFC 6749 §3.2: "Parameters sent without a value MUST be treated as if
    /// they were omitted from the request." `device_code=` is therefore a
    /// request missing a REQUIRED parameter — `invalid_request` under §5.2 —
    /// and must answer exactly as omitting it does.
    #[tokio::test]
    async fn test_device_code_empty_is_treated_as_omitted() {
        let (app, _state) = test_app().await;

        let (empty_status, empty_body) = http_post_form(
            &app,
            "/oauth/token",
            "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=",
            &[],
        )
        .await;
        let (omitted_status, omitted_body) = http_post_form(
            &app,
            "/oauth/token",
            "grant_type=urn:ietf:params:oauth:grant-type:device_code",
            &[],
        )
        .await;

        assert_eq!(empty_status, StatusCode::BAD_REQUEST);
        assert_eq!(empty_status, omitted_status);
        assert_eq!(
            empty_body, omitted_body,
            "an empty parameter must answer exactly as an omitted one"
        );
        let error: serde_json::Value = serde_json::from_str(&empty_body).expect("Valid JSON");
        assert_eq!(error["error"], "invalid_request");
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

        crate::db::authorize_device_auth(
            &state.store,
            crate::db::AuthorizeDeviceAuthParams {
                id: &id,
                user_id: &user.id,
                user_email: &user.email,
                authenticator_id: &auth_id,
                verification: HardwareVerification::Verified {
                    auth_time: Some(Timestamp::now().as_second()),
                },
            },
        )
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
        crate::db::authorize_device_auth(
            &state.store,
            crate::db::AuthorizeDeviceAuthParams {
                id: &id,
                user_id: &user.id,
                user_email: &user.email,
                authenticator_id: &auth_id,
                verification: HardwareVerification::Verified {
                    auth_time: Some(Timestamp::now().as_second()),
                },
            },
        )
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

        crate::db::authorize_device_auth(
            &state.store,
            crate::db::AuthorizeDeviceAuthParams {
                id: &id,
                user_id: &user.id,
                user_email: &user.email,
                authenticator_id: &auth_id,
                verification: HardwareVerification::Verified {
                    auth_time: Some(Timestamp::now().as_second()),
                },
            },
        )
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

        crate::db::authorize_device_auth(
            &state.store,
            crate::db::AuthorizeDeviceAuthParams {
                id: &id,
                user_id: &user.id,
                user_email: &user.email,
                authenticator_id: &auth_id,
                verification: HardwareVerification::Verified {
                    auth_time: Some(Timestamp::now().as_second()),
                },
            },
        )
        .await
        .expect("authorize device");

        // Create a pre-existing OAuth session for the user. Its survival
        // after a race-loser AlreadyConsumed is the regression we test for.
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
            },
        )
    }

    /// Two concurrent consumes of the same device code: exactly one wins and
    /// the loser sees `AlreadyConsumed` — the signal the handler maps to
    /// session revocation (verified end-to-end by
    /// `test_device_code_race_loser_revokes_sessions_via_handler`).
    #[tokio::test]
    async fn test_device_code_concurrent_consume_single_winner() {
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
    }

    /// End-to-end: when two concurrent `/oauth/token` device-code polls
    /// race, the loser's response must trigger revocation of the sessions
    /// issued from **that** device code (RFC 6749 §10.5), while sessions the
    /// user holds from other grants survive. Drives the HTTP handler, not
    /// just the db layer.
    #[tokio::test]
    async fn test_device_code_race_loser_revokes_sessions_via_handler() {
        let (app, state, setup) = setup_race("handler").await;

        // Seed an extra session issued from the same device code, so the
        // race-loser's revocation has a code-targeted session to revoke.
        // (The pre-existing session from setup_race has no source_code_hash.)
        let code_session_token_hash = {
            use aws_lc_rs::digest::{self, SHA256};
            URL_SAFE_NO_PAD.encode(digest::digest(&SHA256, b"race-code-session-token").as_ref())
        };
        crate::db::create_session(
            &state.store,
            &crate::db::CreateSessionParams {
                user_id: "handler@example.com",
                user_email: "handler@example.com",
                token_hash: &code_session_token_hash,
                authenticator_id: None,
                expires_at: Timestamp::now().checked_add(Span::new().hours(1)).unwrap(),
                session_type: crate::db::SessionPurpose::OAuthAccessToken,
                authorization_details: None,
                hardware_aaguid: None,
                org_domain: None,
                source_code_hash: Some(&setup.device_code_hash),
            },
        )
        .await
        .expect("create code-targeted session");

        // Issue two concurrent token requests for the same device code.
        // Exactly one wins and gets an access token; the other gets a 400
        // invalid_grant and — via the handler — revokes the code's sessions.
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

        // RFC 6749 §10.5: the session issued from the replayed device code
        // must be revoked by the race-loser handler path.
        let code_session = crate::db::get_session_by_token_hash(
            &state.store,
            &code_session_token_hash,
            Timestamp::now(),
        )
        .await
        .expect("code-session lookup");
        assert!(
            code_session.is_none(),
            "race-loser must revoke the session issued from the replayed device code"
        );

        // The user's pre-existing session (from a grant with no single-use
        // code) must survive — a replay of one code must not log the user out
        // of unrelated sessions.
        let pre_existing =
            crate::db::get_session_by_token_hash(&state.store, &setup.token_hash, Timestamp::now())
                .await
                .expect("pre-existing session lookup");
        assert!(
            pre_existing.is_some(),
            "race-loser must NOT revoke sessions unrelated to the replayed device code"
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
        crate::db::authorize_device_auth(
            &state.store,
            crate::db::AuthorizeDeviceAuthParams {
                id: &id,
                user_id: &user.id,
                user_email: &user.email,
                authenticator_id: &auth_id,
                verification: HardwareVerification::Verified {
                    auth_time: Some(Timestamp::now().as_second()),
                },
            },
        )
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

    /// Exchange a device code whose authorization recorded
    /// `hardware_verified`, and return the issued access token.
    async fn device_token_for_approval(
        label: &str,
        hardware_verified: bool,
    ) -> (axum::Router, String) {
        let (app, state) = test_app().await;

        let device_code = format!("test_hwv_{label}");
        let expires_at = Timestamp::now()
            .checked_add(Span::new().hours(1))
            .expect("expiry");
        let id = crate::db::create_device_auth_request(
            &state.store,
            &hash_device_code(&device_code),
            "HWV-CODE",
            None,
            expires_at,
            0,
        )
        .await
        .expect("create device auth");

        let user = create_test_user(&state.store, &format!("{label}@example.com")).await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        crate::db::authorize_device_auth(
            &state.store,
            crate::db::AuthorizeDeviceAuthParams {
                id: &id,
                user_id: &user.id,
                user_email: &user.email,
                authenticator_id: &auth_id,
                verification: if hardware_verified {
                    HardwareVerification::Verified {
                        auth_time: Some(Timestamp::now().as_second()),
                    }
                } else {
                    HardwareVerification::NotVerified
                },
            },
        )
        .await
        .expect("authorize device");

        let body = format!(
            "grant_type=urn:ietf:params:oauth:grant-type:\
             device_code&device_code={device_code}"
        );
        let (status, resp) = http_post_form(&app, "/oauth/token", &body, &[]).await;
        assert_eq!(status, StatusCode::OK, "device grant should issue: {resp}");
        let json: serde_json::Value = serde_json::from_str(&resp).expect("Valid JSON");
        let token = json["access_token"]
            .as_str()
            .expect("access_token")
            .to_string();

        (app, token)
    }

    /// A device authorization approved without a WebAuthn ceremony — what an
    /// upstream-IdP sign-in alone produces — must not mint a token that clears
    /// the credential endpoints' hardware gate.
    #[tokio::test]
    async fn test_device_grant_without_ceremony_cannot_reach_credentials() {
        let (app, token) = device_token_for_approval("unverified", false).await;
        let auth = format!("Bearer {token}");

        // Every credential endpoint, since the requirement rides on
        // `HardwareVerifiedToken` rather than a per-handler check.
        let (status, body) = http_get(
            &app,
            "/v1/credentials/aws/token",
            &[("Authorization", &auth)],
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "aws: {body}");
        let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert_eq!(error["code"], "hardware_required");

        let (status, body) = http_post_json(
            &app,
            "/v1/credentials/ssh",
            r#"{"public_key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA test"}"#,
            &[("Authorization", &auth)],
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "ssh: {body}");
        let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert_eq!(error["code"], "hardware_required");

        let (status, body) = http_post_json(
            &app,
            "/v1/credentials/github/token",
            r#"{"repositories":["owner/repo"]}"#,
            &[("Authorization", &auth)],
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "github: {body}");
        let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert_eq!(error["code"], "hardware_required");
    }

    /// The companion case: an approval that did complete a ceremony still
    /// clears the hardware gate. Reaching the issuer's missing RSA key proves
    /// the request got past it — this app has no signing key configured.
    #[tokio::test]
    async fn test_device_grant_with_ceremony_passes_hardware_gate() {
        let (app, token) = device_token_for_approval("verified", true).await;

        let (status, body) = http_get(
            &app,
            "/v1/credentials/aws/token",
            &[("Authorization", &format!("Bearer {token}"))],
        )
        .await;

        assert_ne!(
            status,
            StatusCode::FORBIDDEN,
            "hardware-verified approval must clear the gate: {body}"
        );
        assert!(
            !body.contains("hardware_required"),
            "gate must not reject a verified approval: {body}"
        );
    }
}
