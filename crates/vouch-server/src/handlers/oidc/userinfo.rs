// SPDX-License-Identifier: Apache-2.0 OR MIT
//! UserInfo endpoint handler (OIDC Core Section 5.3).
//!
//! Implements:
//! - OIDC Core Section 5.3 - UserInfo Endpoint
//! - RFC 9449 Section 7.1 - DPoP-bound access tokens at resource endpoints
//! - RFC 8705 Section 3 - mTLS certificate-bound access tokens at resource endpoints

use crate::AppState;
use crate::crypto::keys::OidcSigningKey;
use crate::db::{self, JwsAlgorithm};
use crate::error::OAuthErrorCode;
use crate::error::OAuthErrorResponse;
use crate::handlers::extractors::OptionalClientCert;
use crate::services::auth::decode_token;
use crate::services::oidc::dpop;
use crate::services::oidc::token::validate_session_token;
use crate::services::oidc::{DpopError, OAuthScope};
use axum::{
    Json,
    body::Bytes,
    extract::State,
    http::{HeaderMap, Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use subtle::ConstantTimeEq;

/// User info response (OIDC Core Section 5.3.2).
///
/// Per OIDC Core Section 5.4, `email` and `email_verified` claims are only
/// returned when the `email` scope was granted.
#[derive(Debug, Serialize)]
pub(super) struct UserInfoResponse {
    /// OIDC Core Section 5.1: Subject Identifier.
    sub: String,
    /// OIDC Core Section 5.1: User email address.
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    /// OIDC Core Section 5.1: Whether the email has been verified.
    #[serde(skip_serializing_if = "Option::is_none")]
    email_verified: Option<bool>,
}

/// Claims for a signed UserInfo JWT response (OIDC Core Section 5.3.4).
#[derive(Debug, Serialize)]
struct SignedUserInfoClaims {
    iss: String,
    sub: String,
    aud: String,
    iat: i64,
    exp: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email_verified: Option<bool>,
}

/// Form body for POST access token delivery (RFC 6750 Section 2.2).
#[derive(Deserialize)]
struct UserInfoForm {
    access_token: Option<String>,
}

/// GET/POST /oauth/userinfo
///
/// Returns information about the authenticated user.
/// Supports `Bearer` and `DPoP` authorization schemes (RFC 9449 Section 7.1),
/// and access token in POST body (RFC 6750 Section 2.2, Bearer only).
/// Enforces mTLS certificate binding per RFC 8705 Section 3.
#[expect(clippy::too_many_lines, reason = "linear OIDC userinfo claim assembly")]
pub(crate) async fn userinfo(
    State(state): State<Arc<AppState>>,
    method: Method,
    headers: HeaderMap,
    client_cert: OptionalClientCert,
    body: Bytes,
) -> Response {
    // Extract token and scheme from Authorization header or POST body
    let auth_header_value = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .map(String::from);

    // Parse form body for POST requests (used as fallback per RFC 6750 Section 2.2)
    let form_token = if method == Method::POST && auth_header_value.is_none() {
        serde_urlencoded::from_bytes::<UserInfoForm>(&body)
            .ok()
            .and_then(|f| f.access_token)
    } else {
        None
    };

    let (token, is_dpop_scheme) = if let Some(ref auth_header) = auth_header_value {
        // RFC 9110 Section 11.1: auth-scheme is case-insensitive.
        // Compare the scheme in lowercase but extract the token from the original
        // header since JWT tokens are case-sensitive (base64url encoding).
        let scheme_and_token = auth_header.split_once(' ');
        match scheme_and_token {
            Some((scheme, tok)) if scheme.eq_ignore_ascii_case("dpop") => (tok.to_string(), true),
            Some((scheme, tok)) if scheme.eq_ignore_ascii_case("bearer") => {
                (tok.to_string(), false)
            }
            _ => {
                return oauth_error(
                    StatusCode::UNAUTHORIZED,
                    "invalid_token",
                    "Unsupported authorization scheme. Use Bearer or DPoP",
                );
            }
        }
    } else if let Some(ref ft) = form_token {
        // RFC 6750 Section 2.2: POST body access_token (Bearer only, no DPoP)
        (ft.clone(), false)
    } else {
        // RFC 6750 Section 3.1: When the request lacks any authentication
        // information, the WWW-Authenticate challenge SHOULD NOT include
        // an error code or other error information.
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
        )
            .into_response();
    };

    // RFC 9449 Section 7.1: If DPoP scheme is used, validate the DPoP proof at resource endpoint
    if is_dpop_scheme {
        // RFC 9449 Section 7.1: There MUST NOT be more than one DPoP header.
        if headers.get_all("DPoP").iter().count() > 1 {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                OAuthErrorCode::InvalidDpopProof.as_str(),
                "Request must contain exactly one DPoP header",
            );
        }
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
            &token,
            dpop_header,
            method.as_str(),
            &full_uri,
            &state.store,
            state.config().dpop_max_age_seconds,
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
                let decoded = match decode_token(&token, &state.oidc_key, &config.base_url) {
                    Some(d) => d,
                    None => {
                        return oauth_error(
                            StatusCode::UNAUTHORIZED,
                            "invalid_token",
                            "Invalid or expired token",
                        );
                    }
                };
                match decoded.cnf() {
                    Some(cnf) if cnf.jkt.is_some() => {
                        let jkt = cnf.jkt.as_deref().unwrap_or("");
                        let is_valid: bool = proof.jkt.as_bytes().ct_eq(jkt.as_bytes()).into();
                        if !is_valid {
                            return oauth_error(
                                StatusCode::UNAUTHORIZED,
                                OAuthErrorCode::InvalidDpopProof.as_str(),
                                "DPoP proof key does not match token binding",
                            );
                        }
                    }
                    Some(_) | None => {
                        // Token is not DPoP-bound (mTLS-only or no cnf)
                        // but DPoP scheme was used
                        return oauth_error(
                            StatusCode::UNAUTHORIZED,
                            OAuthErrorCode::InvalidDpopProof.as_str(),
                            "DPoP scheme used but token is not DPoP-bound",
                        );
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
            Err(e @ DpopError::Database(_)) => {
                return oauth_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    OAuthErrorCode::ServerError.as_str(),
                    &e.to_string(),
                );
            }
            Err(e) => {
                return oauth_error(
                    StatusCode::UNAUTHORIZED,
                    OAuthErrorCode::InvalidDpopProof.as_str(),
                    &e.to_string(),
                );
            }
        }
    }

    // RFC 9449 Section 7.1: If a Bearer scheme is used but the token is
    // DPoP-bound (cnf.jkt claim), reject it — the client MUST use the DPoP scheme.
    if !is_dpop_scheme {
        let config = state.config();
        if let Some(decoded) = decode_token(&token, &state.oidc_key, &config.base_url)
            && decoded.cnf().is_some_and(|cnf| cnf.jkt.is_some())
        {
            return oauth_error(
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "Token is DPoP-bound but was presented with Bearer scheme. Use DPoP scheme instead",
            );
        }
    }

    // RFC 8705 Section 3: Verify mTLS certificate binding.
    if let Err(resp) = verify_mtls_binding(
        &token,
        &state.oidc_key,
        &state.config().base_url,
        &client_cert,
    ) {
        return *resp;
    }

    // Validate the session token
    let result = match validate_session_token(&state, &token).await {
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
    // `scope: None` means no scope was granted — token exchange produces this
    // when the requested scope set has an empty intersection with available
    // scopes. Returning email in that case would be a scope escalation.
    let has_email_scope = match &result.scope {
        Some(scope_set) => scope_set.contains(OAuthScope::Email),
        None => false,
    };

    let response_body = UserInfoResponse {
        sub: result.user.id.clone(),
        email: if has_email_scope {
            Some(result.user.email)
        } else {
            None
        },
        email_verified: if has_email_scope { Some(true) } else { None },
    };

    // OIDC Core Section 5.3.4: Return signed JWT if client registered userinfo_signed_response_alg.
    let signed_alg = if let Some(ref client_id) = result.client_id {
        match db::get_oauth_client_by_client_id(&state.store, client_id).await {
            Ok(Some(client)) => client.userinfo_signed_response_alg,
            _ => None,
        }
    } else {
        None
    };

    if let Some(alg) = signed_alg {
        build_signed_userinfo_response(&state, &result.client_id, &response_body, alg).await
    } else {
        Json(response_body).into_response()
    }
}

/// Build a signed JWT userinfo response (OIDC Core Section 5.3.4).
///
/// Signs the userinfo claims with the algorithm registered by the client.
/// Returns `application/jwt` with the signed JWT, or a 500 error on signing failure.
async fn build_signed_userinfo_response(
    state: &AppState,
    client_id: &Option<String>,
    response_body: &UserInfoResponse,
    alg: JwsAlgorithm,
) -> Response {
    // OIDC Core Section 5.3.4: aud MUST identify the requesting client.
    // client_id is always present in RFC 9068 access tokens, but guard defensively.
    let aud = match client_id.as_deref().filter(|s| !s.is_empty()) {
        Some(id) => id.to_string(),
        None => {
            tracing::error!("Cannot determine client_id for signed userinfo response");
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Cannot determine client identity for signed userinfo",
            );
        }
    };
    let now = Timestamp::now().as_second();
    let signed_claims = SignedUserInfoClaims {
        iss: state.config().base_url.clone(),
        sub: response_body.sub.clone(),
        aud,
        iat: now,
        exp: now.saturating_add(300),
        email: response_body.email.clone(),
        email_verified: response_body.email_verified,
    };
    let jwt_result = match alg {
        JwsAlgorithm::Rs256 => match state.oidc_rsa_key.as_ref() {
            Some(rsa_key) => rsa_key.sign_jwt(&signed_claims).await,
            None => {
                tracing::error!(
                    "Client requested RS256 userinfo signing but RSA key is unavailable"
                );
                return oauth_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "RS256 signing key unavailable",
                );
            }
        },
        JwsAlgorithm::Es256 => state.oidc_key.sign_jwt(&signed_claims).await,
        // Registration rejects non-RS256/ES256 values, but guard against
        // manual client creation or future changes.
        other => {
            tracing::error!("Unsupported userinfo signing algorithm: {other}");
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Unsupported userinfo signing algorithm",
            );
        }
    };
    match jwt_result {
        Ok(token) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/jwt")],
            token,
        )
            .into_response(),
        Err(e) => {
            tracing::error!("Failed to sign userinfo response: {e}");
            oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Failed to generate signed userinfo response",
            )
        }
    }
}

/// Verify mTLS certificate binding per RFC 8705 Section 3.
///
/// If the access token contains a `cnf.x5t#S256` claim, the client MUST
/// present a certificate whose thumbprint matches. Returns `Err(Box<Response>)` on
/// mismatch so the caller can short-circuit with the error response.
///
/// The `Response` is boxed to satisfy `clippy::result_large_err`.
fn verify_mtls_binding(
    token: &str,
    oidc_key: &OidcSigningKey,
    issuer: &str,
    client_cert: &OptionalClientCert,
) -> Result<(), Box<Response>> {
    // Decode the token to check for a cnf claim. If decoding fails here,
    // the token is invalid — validate_session_token will reject it shortly.
    let decoded = match decode_token(token, oidc_key, issuer) {
        Some(d) => d,
        None => return Ok(()),
    };

    // Check if the token carries an x5t#S256 certificate binding.
    let expected = match decoded.cnf() {
        Some(cnf) => match cnf.x5t_s256.as_deref() {
            Some(thumbprint) => thumbprint,
            None => return Ok(()), // No mTLS binding — nothing to verify.
        },
        None => return Ok(()), // No cnf claim at all — nothing to verify.
    };

    // Token is certificate-bound: client MUST present a matching certificate.
    let cert = match &client_cert.0 {
        Some(c) => c,
        None => {
            return Err(Box::new(oauth_error(
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "Token is certificate-bound but no client certificate was presented",
            )));
        }
    };

    // Constant-time comparison prevents timing-based thumbprint enumeration.
    let is_valid: bool = cert.thumbprint.as_bytes().ct_eq(expected.as_bytes()).into();
    if !is_valid {
        return Err(Box::new(oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "Client certificate does not match token certificate binding",
        )));
    }

    Ok(())
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
