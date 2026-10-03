// SPDX-License-Identifier: Apache-2.0 OR MIT
//! UserInfo endpoint handler (OIDC Core Section 5.3).
//!
//! Implements:
//! - OIDC Core Section 5.3 - UserInfo Endpoint
//! - RFC 9449 Section 7.1 - DPoP-bound access tokens at resource endpoints
//! - RFC 8705 Section 3 - mTLS certificate-bound access tokens at resource endpoints

use crate::arrival::ArrivalTime;
use crate::crypto::alg::JwsAlgorithm;
use crate::db::{self};
use crate::error::OAuthErrorCode;
use crate::error::OAuthErrorResponse;
use crate::handlers::extractors::OptionalClientCert;
use crate::services::auth::{DecodedToken, decode_token};
use crate::services::oidc::OAuthScope;
use crate::services::oidc::claims::PossessionError;
use crate::services::oidc::dpop::{self, DpopChallenge};
use crate::services::oidc::token::validate_session_token;
use crate::{AppState, http};
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
use vouch_common::protocol;

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
pub(crate) async fn userinfo(
    arrival: ArrivalTime,
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
        if let Some(tok) = http::strip_auth_scheme(auth_header, protocol::AUTH_SCHEME_DPOP) {
            (tok.to_string(), true)
        } else if let Some(tok) = http::strip_auth_scheme(auth_header, protocol::AUTH_SCHEME_BEARER)
        {
            (tok.to_string(), false)
        } else {
            return oauth_error(
                StatusCode::UNAUTHORIZED,
                OAuthErrorCode::InvalidToken,
                "Unsupported authorization scheme. Use Bearer or DPoP",
            );
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
            [(header::WWW_AUTHENTICATE, http::bearer_challenge(&[]))],
        )
            .into_response();
    };

    // Under the DPoP scheme every refusal answers with a DPoP challenge (RFC
    // 9449 Figure 16). The token is checked before the proof, as on `/v1/*`,
    // so a refused token never records a proof `jti`.
    let refuse_token = |description: &str| -> Response {
        if is_dpop_scheme {
            DpopChallenge::token(description).into_oauth_response()
        } else {
            oauth_error(
                StatusCode::UNAUTHORIZED,
                OAuthErrorCode::InvalidToken,
                description,
            )
        }
    };

    // The audience is not checked: the userinfo endpoint receives tokens from
    // any client (aud = client_id per RFC 9068).
    let config = state.config();
    let Some(decoded) = decode_token(&token, &state.oidc_key, &config.base_url) else {
        return refuse_token("Invalid or expired token");
    };

    let result = match validate_session_token(&state, &token, arrival).await {
        Ok(Some(r)) => r,
        Ok(None) => return refuse_token("Invalid or expired token"),
        Err(e) => {
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                OAuthErrorCode::ServerError,
                &e.to_string(),
            );
        }
    };

    let dpop_cnf = decoded.cnf().filter(|cnf| cnf.jkt.is_some());
    if is_dpop_scheme {
        // RFC 9449 §7.1 covers only DPoP-bound tokens and is silent on an
        // unbound token under the DPoP scheme; it is refused here as on
        // `/v1/*`, so the scheme always means a checked proof.
        let Some(cnf) = dpop_cnf else {
            return DpopChallenge::binding(PossessionError::NotDpopBound).into_oauth_response();
        };
        let full_uri = format!("{}/oauth/userinfo", config.base_url);
        let proof = match dpop::validate_dpop_at_resource(
            &token,
            &headers,
            method.as_str(),
            &full_uri,
            &state.store,
            config.dpop_max_age_seconds,
            arrival,
        )
        .await
        {
            Ok(proof) => proof,
            Err(e) => {
                return match e.resource_challenge() {
                    Some(challenge) => challenge.into_oauth_response(),
                    None => oauth_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        OAuthErrorCode::ServerError,
                        "DPoP validation backend error",
                    ),
                };
            }
        };
        // RFC 9449 Section 7.1: the proof's key must be the key the token is
        // bound to.
        if !cnf.confirms_dpop(&proof) {
            return DpopChallenge::binding(PossessionError::DpopKeyMismatch).into_oauth_response();
        }
    } else if dpop_cnf.is_some() {
        // RFC 9449 Section 7.2: a DPoP-bound token sent as Bearer is refused.
        return oauth_error(
            StatusCode::UNAUTHORIZED,
            OAuthErrorCode::InvalidToken,
            "Token is DPoP-bound but was presented with Bearer scheme. Use DPoP scheme instead",
        );
    }

    // RFC 8705 Section 3: Verify mTLS certificate binding.
    //
    // Reuse the `decoded` claims from the gate decode above (line 144) instead
    // of re-decoding here. A second `decode_token` would read `SystemTime::now()`
    // again — after the `.await`ed DB lookups in `validate_session_token` and
    // the proof validation above — and a divergent integer-second `exp`
    // boundary at the second reading silently skips the binding check (the
    // `Ok(())`-on-decode-failure arm that lived here before). One decode, used
    // everywhere, matches the `/v1/*` path and the `ArrivalTime` design in
    // `arrival.rs` (one wall-clock reading per decision, no TOCTOU window).
    if let Err(resp) = verify_mtls_binding(&decoded, &client_cert) {
        return *resp;
    }

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
#[expect(
    clippy::disallowed_methods,
    reason = "mints the signed userinfo JWT's iat and exp"
)]
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
                OAuthErrorCode::ServerError,
                "Cannot determine client identity for signed userinfo",
            );
        }
    };
    let now = Timestamp::now().as_second();
    let signed_claims = SignedUserInfoClaims {
        iss: state.config().base_url.to_string(),
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
                    OAuthErrorCode::ServerError,
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
                OAuthErrorCode::ServerError,
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
                OAuthErrorCode::ServerError,
                "Failed to generate signed userinfo response",
            )
        }
    }
}

/// Verify mTLS certificate binding per RFC 8705 Section 3.
///
/// `decoded` is the already-validated token from the gate decode at the top
/// of [`userinfo`]. The caller has confirmed it is decodable, so there is no
/// decode-failure path here that could silently skip the binding check — the
/// former redundant `decode_token` would read `SystemTime::now()` a second
/// time after `validate_session_token`'s `.await`ed DB lookups, and mapping
/// that second failure to `Ok(())` opened a TOCTOU window at the integer-
/// second `exp` boundary (reusing the gate decode is the `/v1/*` pattern).
///
/// If the access token contains a `cnf.x5t#S256` claim, the client MUST
/// present a certificate whose thumbprint matches. Returns `Err(Box<Response>)` on
/// mismatch so the caller can short-circuit with the error response.
///
/// The `Response` is boxed to satisfy `clippy::result_large_err`.
fn verify_mtls_binding(
    decoded: &DecodedToken,
    client_cert: &OptionalClientCert,
) -> Result<(), Box<Response>> {
    // Only a token carrying an x5t#S256 certificate binding needs checking.
    let Some(cnf) = decoded.cnf().filter(|cnf| cnf.x5t_s256.is_some()) else {
        return Ok(());
    };

    // Token is certificate-bound: client MUST present a matching certificate.
    let cert = match &client_cert.0 {
        Some(c) => c,
        None => {
            return Err(Box::new(oauth_error(
                StatusCode::UNAUTHORIZED,
                OAuthErrorCode::InvalidToken,
                "Token is certificate-bound but no client certificate was presented",
            )));
        }
    };

    if !cnf.confirms_certificate(&cert.thumbprint) {
        return Err(Box::new(oauth_error(
            StatusCode::UNAUTHORIZED,
            OAuthErrorCode::InvalidToken,
            "Client certificate does not match token certificate binding",
        )));
    }

    Ok(())
}

/// Build an OAuth error response for the userinfo endpoint.
///
/// RFC 6750 Section 3: When the resource server returns a 401, it includes a
/// `WWW-Authenticate` header indicating the supported scheme(s).
fn oauth_error(status: StatusCode, error: OAuthErrorCode, description: &str) -> Response {
    let error = error.as_str();
    let body = Json(OAuthErrorResponse {
        error: error.to_string(),
        error_description: Some(description.to_string()),
        error_uri: None,
    });

    if status == StatusCode::UNAUTHORIZED {
        // RFC 6750 Section 3: Include WWW-Authenticate header on 401 responses
        let www_auth =
            http::bearer_challenge(&[("error", error), ("error_description", description)]);
        (status, [("WWW-Authenticate", www_auth.as_str())], body).into_response()
    } else {
        (status, body).into_response()
    }
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;
    use crate::services::auth::AccessTokenClaims;
    use crate::services::oidc::claims::CnfClaim;
    use crate::services::oidc::mtls::{self, CertThumbprint};
    use crate::test_utils::make_test_cert_der;

    /// Minimal access-token claims carrying `cnf` = `binding`.
    ///
    /// The mTLS check only inspects `cnf`, so every other field is a placeholder.
    fn claims_with_cnf(binding: Option<CnfClaim>) -> DecodedToken {
        DecodedToken::AccessToken(AccessTokenClaims {
            iss: "https://test.example.com".to_string(),
            sub: "user-1".to_string(),
            aud: "client-1".to_string(),
            exp: 9_999_999_999,
            iat: 1_000_000_000,
            nbf: None,
            jti: "jti-1".to_string(),
            client_id: "client-1".to_string(),
            scope: None,
            email: None,
            email_verified: None,
            hardware_verified: false,
            cnf: binding,
            auth_time: None,
            act: None,
            amr: None,
            acr: None,
        })
    }

    /// A `cnf` claiming the SHA-256 thumbprint of a freshly generated cert.
    fn cert_bound_cnf(thumbprint: &CertThumbprint) -> CnfClaim {
        CnfClaim {
            jkt: None,
            x5t_s256: Some(thumbprint.as_str().to_string()),
        }
    }

    /// RFC 8705 §3: a token whose claims carry `cnf.x5t#S256` MUST be refused
    /// when no client certificate is presented.
    ///
    /// This is the regression guard for the TOCTOU fixed here: before the fix,
    /// `verify_mtls_binding` re-decoded the token and returned `Ok(())` on
    /// decode failure, so a cert-bound token whose second decode failed (the
    /// `exp` boundary elapsing after `.await`ed DB lookups) silently skipped
    /// the binding check. The fix takes already-decoded claims, so there is no
    /// decode-failure path and the binding check is always enforced.
    #[test]
    fn verify_mtls_binding_enforces_check_when_claims_carry_x5t_and_no_cert() {
        let der = make_test_cert_der("bound-cert");
        let thumbprint = mtls::compute_cert_thumbprint(&der);
        let decoded = claims_with_cnf(Some(cert_bound_cnf(&thumbprint)));

        let result = verify_mtls_binding(&decoded, &OptionalClientCert(None));

        let err = result.expect_err("cert-bound claim must be refused without a client cert");
        assert_eq!(err.status(), StatusCode::UNAUTHORIZED);
    }

    /// A token bound by DPoP only (`cnf.jkt`, no `cnf.x5t#S256`) is not
    /// certificate-bound at the mTLS layer (DPoP is checked earlier). The mTLS
    /// check must pass so a Bearer-presented DPoP token still reaches the
    /// DPoP-scheme refusal at the binding check, rather than failing here.
    #[test]
    fn verify_mtls_binding_passes_when_cnf_is_dpop_only() {
        let decoded = claims_with_cnf(Some(CnfClaim {
            jkt: Some("dpop-thumbprint".to_string()),
            x5t_s256: None,
        }));
        let result = verify_mtls_binding(&decoded, &OptionalClientCert(None));
        assert!(
            result.is_ok(),
            "DPoP-only cnf is not cert-bound: {result:?}"
        );
    }

    /// A `cnf` that names neither key (`jkt: None`, `x5t_s256: None`) binds the
    /// token to nothing; the mTLS check must not require a certificate.
    #[test]
    fn verify_mtls_binding_passes_when_cnf_names_no_key() {
        let decoded = claims_with_cnf(Some(CnfClaim {
            jkt: None,
            x5t_s256: None,
        }));
        let result = verify_mtls_binding(&decoded, &OptionalClientCert(None));
        assert!(result.is_ok(), "empty cnf binds to nothing: {result:?}");
    }
}
