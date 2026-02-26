// SPDX-License-Identifier: BUSL-1.1
//! FIDO2 challenge endpoint for the FIDO2 assertion grant.
//!
//! `POST /oauth/fido2/challenge` — Issues a short-lived challenge for CTAP2
//! assertion. The CLI calls this before performing a local FIDO2 assertion
//! and exchanging it at the token endpoint.
//!
//! This endpoint is unauthenticated and rate-limited. The returned `state`
//! token is an HS256 JWT (`vouch-fido2-challenge+jwt`) containing the
//! challenge, RP ID, and expiration.

use crate::AppState;
use crate::crypto::jwt::{JwtType, encode_state_token};
use crate::handlers::generate_challenge;
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use jiff::Timestamp;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use vouch_common::encoding::{Base64Url, ConvertEncoding, Raw};
use vouch_common::fido2_types::Challenge;

/// State embedded in the challenge JWT.
#[derive(Debug, Serialize, Deserialize)]
struct Fido2ChallengeState {
    challenge: Challenge<Raw>,
    rp_id: String,
    /// RFC 8725 §3.11: Issued at time.
    iat: i64,
    /// RFC 8725 §3.11: Expiration time (5 minutes).
    exp: i64,
}

/// Response from `POST /oauth/fido2/challenge`.
#[derive(Debug, Serialize)]
pub struct Fido2ChallengeResponse {
    /// Base64url-encoded 32-byte challenge.
    pub challenge: Challenge<Base64Url>,
    /// Relying Party ID.
    pub rp_id: String,
    /// HS256 state JWT to return with the assertion at the token endpoint.
    pub state: String,
}

/// `POST /oauth/fido2/challenge` — Generate a FIDO2 challenge for the
/// assertion grant type.
///
/// Unauthenticated. No `client_id` is needed at this stage; client
/// identification happens at the token endpoint via `client_assertion`.
pub async fn fido2_challenge(State(state): State<Arc<AppState>>) -> Response {
    let challenge = match generate_challenge() {
        Ok(c) => c,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "server_error",
                    "error_description": "Failed to generate challenge"
                })),
            )
                .into_response();
        }
    };

    let challenge: Challenge<Raw> = challenge.into();
    let now = Timestamp::now();
    let exp = now
        .checked_add(jiff::Span::new().minutes(5))
        .map(|t| t.as_second())
        .unwrap_or(now.as_second() + 300);

    let challenge_state = Fido2ChallengeState {
        challenge: challenge.clone(),
        rp_id: state.config().rp_id.clone(),
        iat: now.as_second(),
        exp,
    };

    let state_token = match encode_state_token(
        &challenge_state,
        JwtType::Fido2ChallengeState,
        state.config().jwt_secret.expose_secret().as_bytes(),
    ) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("Failed to encode FIDO2 challenge state: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "server_error",
                    "error_description": "Failed to create challenge state"
                })),
            )
                .into_response();
        }
    };

    (
        StatusCode::OK,
        [("cache-control", "no-store"), ("pragma", "no-cache")],
        Json(Fido2ChallengeResponse {
            challenge: challenge.to_base64url(),
            rp_id: state.config().rp_id.clone(),
            state: state_token,
        }),
    )
        .into_response()
}
