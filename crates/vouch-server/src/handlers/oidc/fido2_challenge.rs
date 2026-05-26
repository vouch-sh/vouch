// SPDX-License-Identifier: Apache-2.0 OR MIT
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
use crate::crypto::jwt::JwtType;
use crate::db;
use crate::handlers::generate_challenge;
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use jiff::Timestamp;
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
pub(super) struct Fido2ChallengeResponse {
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
pub(crate) async fn fido2_challenge(State(state): State<Arc<AppState>>) -> Response {
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
        .map_or(now.as_second().saturating_add(300), |t| t.as_second());

    let challenge_state = Fido2ChallengeState {
        challenge: challenge.clone(),
        rp_id: state.config().rp_id.clone(),
        iat: now.as_second(),
        exp,
    };

    let state_token = match state
        .state_signer
        .encode_state_token(&challenge_state, JwtType::Fido2ChallengeState)
        .await
    {
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

    // RFC 9449 §8.2: Pre-generate a DPoP nonce so the CLI can include it
    // in the token request, avoiding a use_dpop_nonce round-trip in the
    // common case. If the nonce expires before the token request (e.g.
    // very slow touch), the existing use_dpop_nonce retry path handles it.
    let dpop_nonce = db::generate_dpop_nonce(&state.store, 300).await;

    let mut response = (
        StatusCode::OK,
        [
            ("cache-control", "no-cache, no-store, must-revalidate"),
            ("pragma", "no-cache"),
            ("expires", "0"),
        ],
        Json(Fido2ChallengeResponse {
            challenge: challenge.to_base64url(),
            rp_id: state.config().rp_id.clone(),
            state: state_token,
        }),
    )
        .into_response();

    if let Ok(ref nonce) = dpop_nonce
        && let Ok(value) = axum::http::HeaderValue::from_str(nonce)
    {
        response.headers_mut().insert("dpop-nonce", value);
    }

    response
}
