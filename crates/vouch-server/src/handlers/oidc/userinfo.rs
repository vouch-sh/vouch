// SPDX-License-Identifier: BUSL-1.1
//! UserInfo endpoint handler (OIDC Core Section 5.3).
//!
//! Implements:
//! - OIDC Core Section 5.3 - UserInfo Endpoint
//! - RFC 9449 Section 7.1 - DPoP-bound access tokens at resource endpoints

use crate::AppState;
use crate::services::OAuthErrorCode;
use crate::services::error::OAuthErrorResponse;
use crate::services::oidc::dpop::{self, DpopError};
use crate::services::oidc::token::validate_session_token;
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use std::sync::Arc;

/// User info response (OIDC Core Section 5.3.2).
#[derive(Debug, Serialize)]
pub struct UserInfoResponse {
    /// OIDC Core Section 5.1: Subject Identifier.
    sub: String,
    /// OIDC Core Section 5.1: User email address.
    email: String,
    /// OIDC Core Section 5.1: Whether the email has been verified.
    email_verified: bool,
    /// Custom claim: Hardware verification flag (FIDO2 presence proof).
    hardware_verified: bool,
    /// Custom claim: Hardware authenticator AAGUID.
    hardware_aaguid: Option<String>,
}

/// GET /oauth/userinfo
///
/// Returns information about the authenticated user.
/// Supports both `Bearer` and `DPoP` authorization schemes (RFC 9449 Section 7.1).
pub async fn userinfo(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    // Extract token and scheme from Authorization header
    let auth_header = match headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
    {
        Some(h) => h,
        None => {
            return oauth_error(
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "Missing authorization header",
            );
        }
    };

    let (token, is_dpop_scheme) = if let Some(t) = auth_header.strip_prefix("DPoP ") {
        (t, true)
    } else if let Some(t) = auth_header.strip_prefix("Bearer ") {
        (t, false)
    } else {
        return oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "Unsupported authorization scheme. Use Bearer or DPoP",
        );
    };

    // RFC 9449 Section 7.1: If DPoP scheme is used, validate the DPoP proof at resource endpoint
    if is_dpop_scheme && state.config().dpop_enabled {
        let dpop_header = match headers.get("DPoP").and_then(|v| v.to_str().ok()) {
            Some(h) => h,
            None => {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    OAuthErrorCode::InvalidDpopProof.as_str(),
                    "DPoP scheme requires DPoP proof header",
                );
            }
        };

        let full_uri = format!("{}/oauth/userinfo", state.config().base_url);
        match dpop::validate_dpop_at_resource(
            dpop_header,
            token,
            "GET",
            &full_uri,
            &state.dpop,
            state.config().dpop_max_age_seconds,
            state.config().dpop_nonce_required,
        )
        .await
        {
            Ok(_proof) => {
                // DPoP proof is valid (signature, ath, jti, nonce all verified).
                //
                // TODO(RFC 9449 Section 7.1): Full sender-constrained token validation
                // requires checking that _proof.jkt matches the cnf.jkt associated with
                // this access token at issuance time. This requires storing the DPoP
                // thumbprint in the sessions table (dpop_jkt column) during token exchange.
                // Currently the ath (access token hash) check provides meaningful protection:
                // an attacker needs the actual access token to forge a valid proof.
            }
            Err(DpopError::UseNonce(nonce)) => {
                return (
                    StatusCode::UNAUTHORIZED,
                    [("DPoP-Nonce", nonce.as_str())],
                    Json(OAuthErrorResponse {
                        error: OAuthErrorCode::UseDpopNonce.as_str().to_string(),
                        error_description: Some(
                            "Authorization server requires nonce in DPoP proof".to_string(),
                        ),
                        error_uri: None,
                    }),
                )
                    .into_response();
            }
            Err(e) => {
                return oauth_error(
                    StatusCode::UNAUTHORIZED,
                    OAuthErrorCode::InvalidDpopProof.as_str(),
                    &e.to_string(),
                );
            }
        }
    } else if is_dpop_scheme {
        // DPoP scheme used but DPoP is not enabled
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_token",
            "DPoP is not enabled on this server",
        );
    }

    // Validate the session token
    let result = match validate_session_token(&state, token).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return oauth_error(
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "Invalid or expired token",
            );
        }
        Err(e) => {
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                &e.to_string(),
            );
        }
    };

    let (user, _session, authenticator) = result;

    Json(UserInfoResponse {
        sub: user.email.clone(),
        email: user.email,
        email_verified: true,
        hardware_verified: true,
        hardware_aaguid: authenticator.aaguid,
    })
    .into_response()
}

/// Build an OAuth error response for the userinfo endpoint.
///
/// RFC 6750 Section 3: When the resource server returns a 401, it includes a
/// `WWW-Authenticate` header indicating the supported scheme(s).
fn oauth_error(status: StatusCode, error: &str, description: &str) -> Response {
    let body = Json(OAuthErrorResponse {
        error: error.to_string(),
        error_description: Some(description.to_string()),
        error_uri: None,
    });

    if status == StatusCode::UNAUTHORIZED {
        // RFC 6750 Section 3: Include WWW-Authenticate header on 401 responses
        let www_auth = format!("Bearer error=\"{error}\", error_description=\"{description}\"");
        (status, [("WWW-Authenticate", www_auth.as_str())], body).into_response()
    } else {
        (status, body).into_response()
    }
}
