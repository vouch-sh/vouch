// SPDX-License-Identifier: Apache-2.0 OR MIT
//! JARM (JWT Secured Authorization Response Mode) support.
//!
//! Implements the `jwt` and `query.jwt` response modes by wrapping authorization
//! responses in a signed JWT delivered as a single `response` query parameter.
//!
//! References:
//! - <https://openid.net/specs/openid-financial-api-jarm-ID1.html>

use anyhow::Result;
use jiff::Timestamp;
use serde::Serialize;
use std::sync::Arc;
use vouch_common::protocol;

use crate::AppState;
use crate::db::OAuthClient;
use crate::error::OAuthErrorCode;

/// JARM JWT lifetime in seconds (10 minutes per the specification).
const JARM_JWT_LIFETIME_SECONDS: i64 = 600;

/// Claims for a JARM success authorization response.
#[derive(Serialize)]
struct JarmSuccessClaims {
    iss: String,
    aud: String,
    exp: i64,
    code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<String>,
}

/// Claims for a JARM error authorization response.
#[derive(Serialize)]
struct JarmErrorClaims {
    iss: String,
    aud: String,
    exp: i64,
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<String>,
}

/// Select the JARM signing algorithm for a client.
///
/// Uses `client.authorization_signed_response_alg` if explicitly set;
/// defaults to ES256 which is FAPI 2.0 compliant (PS256, ES256, EdDSA
/// per FAPI 2.0 Section 5.4.1). RS256 is only used when a client
/// explicitly registers with `authorization_signed_response_alg=RS256`.
fn select_alg(_state: &AppState, client: &OAuthClient) -> &'static str {
    match client.authorization_signed_response_alg {
        Some(crate::db::JwsAlgorithm::Rs256) => "RS256",
        Some(crate::db::JwsAlgorithm::Es256) | None => protocol::JWS_ALG_ES256,
        // Validated at registration; only RS256 and ES256 are accepted for JARM.
        Some(_) => protocol::JWS_ALG_ES256,
    }
}

/// Build a JARM success JWT wrapping the authorization code.
///
/// # Errors
///
/// Returns an error if the signing key is unavailable or JWT signing fails.
pub async fn build_jarm_success_jwt(
    state: &Arc<AppState>,
    client: &OAuthClient,
    code: &str,
    state_param: Option<&str>,
) -> Result<String> {
    let now = Timestamp::now().as_second();
    let exp = now.saturating_add(JARM_JWT_LIFETIME_SECONDS);
    let issuer = state.config().base_url.to_string();

    let claims = JarmSuccessClaims {
        iss: issuer,
        aud: client.client_id.clone(),
        exp,
        code: code.to_string(),
        state: state_param.map(str::to_string),
    };

    match select_alg(state, client) {
        "RS256" => {
            let rsa_key = state.oidc_rsa_key.as_ref().ok_or_else(|| {
                anyhow::anyhow!("RS256 selected for JARM but no RSA signing key is configured")
            })?;
            rsa_key.sign_jwt(&claims).await
        }
        _ => state.oidc_key.sign_jwt(&claims).await,
    }
}

/// Build a JARM error JWT wrapping an OAuth error response.
///
/// # Errors
///
/// Returns an error if the signing key is unavailable or JWT signing fails.
pub async fn build_jarm_error_jwt(
    state: &Arc<AppState>,
    client: &OAuthClient,
    error: OAuthErrorCode,
    description: Option<&str>,
    state_param: Option<&str>,
) -> Result<String> {
    let now = Timestamp::now().as_second();
    let exp = now.saturating_add(JARM_JWT_LIFETIME_SECONDS);
    let issuer = state.config().base_url.to_string();

    let claims = JarmErrorClaims {
        iss: issuer,
        aud: client.client_id.clone(),
        exp,
        error: error.as_str().to_string(),
        error_description: description.map(str::to_string),
        state: state_param.map(str::to_string),
    };

    match select_alg(state, client) {
        "RS256" => {
            let rsa_key = state.oidc_rsa_key.as_ref().ok_or_else(|| {
                anyhow::anyhow!("RS256 selected for JARM but no RSA signing key is configured")
            })?;
            rsa_key.sign_jwt(&claims).await
        }
        _ => state.oidc_key.sign_jwt(&claims).await,
    }
}
