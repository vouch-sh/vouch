// SPDX-License-Identifier: BUSL-1.1
//! UserInfo endpoint handler (OIDC Core Section 5.3).
//!
//! Implements:
//! - OIDC Core Section 5.3 - UserInfo Endpoint
//! - RFC 9449 Section 7.1 - DPoP-bound access tokens at resource endpoints

use crate::AppState;
use crate::db::SessionPurpose;
use crate::services::OAuthErrorCode;
use crate::services::auth::decode_token;
use crate::services::error::OAuthErrorResponse;
use crate::services::oidc::dpop::{self, DpopError};
use crate::services::oidc::scope::OAuthScope;
use crate::services::oidc::token::validate_session_token;
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use std::sync::Arc;
use subtle::ConstantTimeEq;

/// User info response (OIDC Core Section 5.3.2).
///
/// Per OIDC Core Section 5.4, `email` and `email_verified` claims are only
/// returned when the `email` scope was granted.
#[derive(Debug, Serialize)]
pub struct UserInfoResponse {
    /// OIDC Core Section 5.1: Subject Identifier.
    sub: String,
    /// OIDC Core Section 5.1: User email address.
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    /// OIDC Core Section 5.1: Whether the email has been verified.
    #[serde(skip_serializing_if = "Option::is_none")]
    email_verified: Option<bool>,
    /// Custom claim: Hardware verification flag (FIDO2 presence proof).
    hardware_verified: bool,
    /// Custom claim: Hardware authenticator AAGUID.
    #[serde(skip_serializing_if = "Option::is_none")]
    hardware_aaguid: Option<String>,
}

/// GET /oauth/userinfo
///
/// Returns information about the authenticated user.
/// Supports both `Bearer` and `DPoP` authorization schemes (RFC 9449 Section 7.1).
pub async fn userinfo(
    State(state): State<Arc<AppState>>,
    method: Method,
    headers: HeaderMap,
) -> Response {
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
            method.as_str(),
            &full_uri,
            &state.dpop,
            state.config().dpop_max_age_seconds,
            state.config().dpop_nonce_required,
        )
        .await
        {
            Ok(proof) => {
                // DPoP proof is valid (signature, ath, jti, nonce all verified).
                //
                // RFC 9449 Section 7.1: Verify sender-constrained token binding by
                // comparing the proof's jkt against the access token's cnf.jkt claim.
                // This ensures the DPoP proof was made with the same key that was
                // bound to the token at issuance time.
                //
                // RFC 9449 Section 7.1: If DPoP authorization scheme is used,
                // the token MUST be DPoP-bound (have a cnf.jkt claim). Reject
                // non-DPoP-bound tokens presented with the DPoP scheme.
                // Decode the access token to extract DPoP binding (cnf claim).
                // Note: audience is NOT validated here because the userinfo endpoint
                // receives tokens from any client (aud = client_id per RFC 9068).
                let config = state.config();
                if let Some(decoded) = decode_token(
                    token,
                    config.jwt_secret_bytes(),
                    &state.oidc_key,
                    &config.base_url,
                ) {
                    match decoded.cnf() {
                        Some(cnf) => {
                            let is_valid: bool =
                                proof.jkt.as_bytes().ct_eq(cnf.jkt.as_bytes()).into();
                            if !is_valid {
                                return oauth_error(
                                    StatusCode::UNAUTHORIZED,
                                    OAuthErrorCode::InvalidDpopProof.as_str(),
                                    "DPoP proof key does not match token binding",
                                );
                            }
                        }
                        None => {
                            // Token is not DPoP-bound but DPoP scheme was used
                            return oauth_error(
                                StatusCode::UNAUTHORIZED,
                                OAuthErrorCode::InvalidDpopProof.as_str(),
                                "DPoP scheme used but token is not DPoP-bound",
                            );
                        }
                    }
                }
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

    // Determine whether email claims should be returned based on granted scope.
    // Backward compat: legacy OAuth tokens without a scope field are treated as
    // having full scope if they are OAuthAccessToken purpose.
    let has_email_scope = match &result.scope {
        Some(scope_set) => scope_set.contains(OAuthScope::Email),
        None => result.session.session_type == SessionPurpose::OAuthAccessToken.as_str(),
    };

    Json(UserInfoResponse {
        sub: result.user.id.clone(),
        email: if has_email_scope {
            Some(result.user.email)
        } else {
            None
        },
        email_verified: if has_email_scope { Some(true) } else { None },
        hardware_verified: result.authenticator.is_some(),
        hardware_aaguid: result.authenticator.and_then(|a| a.aaguid),
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
