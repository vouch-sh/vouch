// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Authentication handlers for session management.

use crate::AppState;
use crate::db;
use crate::error::ServiceError;
use crate::services::auth::AccessTokenClaims;
use axum::{
    Json,
    body::Body,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use axum_extra::extract::cookie::CookieJar;
use jiff::Timestamp;
use std::sync::Arc;
use vouch_common::{SessionStatus, protocol};

use super::{clear_session_cookie, hash_token};
use crate::db::ClientInfo;

/// Get current session status.
///
/// Accepts an OAuth access token (Bearer or DPoP scheme) and returns
/// authenticated status, email, expiration, and device name.
pub(crate) async fn status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<SessionStatus>, ServiceError> {
    // Get Authorization header (Bearer or DPoP)
    let auth_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    // RFC 9110 Section 11.1: the auth-scheme token is case-insensitive, so
    // `BEARER`, `bearer`, and `BeArEr` must all match like `Bearer`, and
    // likewise for `DPoP`. Split on the first space and compare the scheme
    // with `eq_ignore_ascii_case` rather than hard-coding casings via
    // `starts_with`. An unrecognized scheme (or no header at all) yields
    // `authenticated: false` — this endpoint never 401s.
    let token = match auth_header.and_then(|h| {
        crate::http::strip_auth_scheme(h, protocol::AUTH_SCHEME_BEARER)
            .or_else(|| crate::http::strip_auth_scheme(h, protocol::AUTH_SCHEME_DPOP))
    }) {
        Some(tok) => tok,
        None => {
            return Ok(Json(SessionStatus {
                authenticated: false,
                email: None,
                expires_in_seconds: None,
                device_name: None,
            }));
        }
    };

    if token.is_empty() {
        return Ok(Json(SessionStatus {
            authenticated: false,
            email: None,
            expires_in_seconds: None,
            device_name: None,
        }));
    }

    // Validate as OAuth access token (ES256, at+jwt)
    let config = state.config();
    let decoded =
        match crate::services::auth::decode_token(token, &state.oidc_key, &config.base_url) {
            Some(d) => d,
            None => {
                return Ok(Json(SessionStatus {
                    authenticated: false,
                    email: None,
                    expires_in_seconds: None,
                    device_name: None,
                }));
            }
        };

    let crate::services::auth::DecodedToken::AccessToken(access_claims) = decoded;

    // Check session exists in database
    let token_hash = hash_token(token);
    let session = state
        .session_cache
        .get_session_by_token_hash(&state.store, &token_hash)
        .await?;

    if session.is_none() {
        return Ok(Json(SessionStatus {
            authenticated: false,
            email: None,
            expires_in_seconds: None,
            device_name: None,
        }));
    }

    // Get authenticator name from server-side session record
    let device_name = match session
        .as_deref()
        .and_then(|s| s.authenticator_id.as_deref())
    {
        Some(auth_id) => db::get_authenticator_by_id(&state.store, auth_id)
            .await
            .ok()
            .flatten()
            .map(|a| a.name),
        None => None,
    };

    Ok(Json(build_status(&access_claims, device_name)))
}

/// Build the [`SessionStatus`] for the success path of [`status`].
///
/// `authenticated` derives from the server's authoritative strict-`>`
/// re-check (`exp > now`), matching the expiry rule in
/// `db::sessions::get_session_by_token_hash`. Per the `SessionStatus::email`
/// contract ("User's email if authenticated"), `email` is gated on that same
/// decision: it is `None` whenever `authenticated == false`. `device_name`
/// carries no "if authenticated" qualifier in the contract and is returned
/// unconditionally.
fn build_status(access_claims: &AccessTokenClaims, device_name: Option<String>) -> SessionStatus {
    let now = Timestamp::now().as_second();
    let expires_in = if access_claims.exp > now {
        u64::try_from(access_claims.exp.saturating_sub(now)).ok()
    } else {
        None
    };

    let authenticated = expires_in.is_some();
    SessionStatus {
        authenticated,
        email: if authenticated {
            access_claims.email.clone()
        } else {
            None
        },
        expires_in_seconds: expires_in,
        device_name,
    }
}

/// Handle sign-out (clears session cookie).
/// POST /logout
pub(crate) async fn logout(
    State(state): State<Arc<AppState>>,
    client_info: ClientInfo,
    jar: CookieJar,
) -> Response {
    // Get session from cookie and delete it from database
    if let Some(token) = jar
        .get(vouch_common::SESSION_COOKIE_NAME)
        .map(|c| c.value())
    {
        let token_hash = hash_token(token);

        // Look up session before deletion to capture user info for audit
        let session_info = match state
            .session_cache
            .get_session_by_token_hash(&state.store, &token_hash)
            .await
        {
            Ok(info) => info,
            Err(e) => {
                // Don't silently drop the error: log it and proceed. The
                // session is still deleted below; only the audit event's user
                // context is lost.
                tracing::warn!(error = %e, "Logout: session lookup for audit failed");
                None
            }
        };

        match db::delete_session_by_token_hash(&state.store, &token_hash).await {
            Ok(deleted) => {
                if deleted {
                    state.session_cache.invalidate(&token_hash);
                    tracing::info!("Session deleted during logout");

                    // Best-effort logout audit event
                    if let Some(session) = session_info {
                        let params = db::AuthEventParams {
                            user_id: session.user_id.clone(),
                            event_type: db::AuthEventType::Logout,
                            success: true,
                            client: client_info,
                            ..Default::default()
                        };
                        db::record_auth_event(
                            &state.audit,
                            params,
                            Some(session.user_email.clone()),
                        )
                        .await;
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Failed to delete session during logout: {}", e);
            }
        }
    }

    // Clear session cookie and redirect to landing page
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(header::LOCATION, "/")
        .header(header::SET_COOKIE, clear_session_cookie().to_string())
        .body(Body::empty())
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use crate::test_utils::*;
    use axum::http::StatusCode;

    #[tokio::test]
    async fn test_auth_status_valid_session() {
        let (app, state) = test_app().await;
        let user = create_test_user(&state.store, "valid@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
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

        let auth_header = format!("Bearer {token}");
        let (status, body) =
            http_get(&app, "/v1/auth/status", &[("Authorization", &auth_header)]).await;

        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(json["authenticated"], true);
        assert!(
            json["expires_in_seconds"].as_u64().unwrap_or(0) > 0,
            "expires_in_seconds should be positive"
        );
    }

    #[tokio::test]
    async fn test_auth_status_includes_email() {
        let (app, state) = test_app().await;
        let user = create_test_user(&state.store, "email-check@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
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

        let auth_header = format!("Bearer {token}");
        let (status, body) =
            http_get(&app, "/v1/auth/status", &[("Authorization", &auth_header)]).await;

        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(json["email"], "email-check@example.com");
    }

    #[tokio::test]
    async fn test_auth_status_no_auth_header() {
        let (app, _state) = test_app().await;

        let (status, body) = http_get(&app, "/v1/auth/status", &[]).await;

        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(json["authenticated"], false);
        assert!(json["email"].is_null());
        assert!(json["expires_in_seconds"].is_null());
        assert!(json["device_name"].is_null());
    }

    #[tokio::test]
    async fn test_auth_status_invalid_token() {
        let (app, _state) = test_app().await;

        let (status, body) = http_get(
            &app,
            "/v1/auth/status",
            &[("Authorization", "Bearer not.a.valid.jwt.token")],
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(json["authenticated"], false);
        assert!(json["email"].is_null());
    }

    #[tokio::test]
    async fn test_auth_status_empty_bearer() {
        let (app, _state) = test_app().await;

        let (status, body) =
            http_get(&app, "/v1/auth/status", &[("Authorization", "Bearer ")]).await;

        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(json["authenticated"], false);
        assert!(json["email"].is_null());
    }

    fn claims_with_exp(exp: i64, email: Option<&str>) -> crate::services::auth::AccessTokenClaims {
        use crate::services::oidc::ScopeSet;
        crate::services::auth::AccessTokenClaims {
            iss: "test-issuer".to_string(),
            sub: "user-123".to_string(),
            aud: "client-abc".to_string(),
            exp,
            iat: exp.saturating_sub(3600),
            nbf: None,
            jti: "jti-1".to_string(),
            client_id: "client-abc".to_string(),
            scope: Some(ScopeSet::parse("openid email")),
            email: email.map(str::to_string),
            email_verified: Some(true),
            hardware_verified: true,
            cnf: None,
            auth_time: None,
            act: None,
            amr: None,
            acr: None,
        }
    }

    #[test]
    fn build_status_email_is_none_at_exp_boundary() {
        let now = jiff::Timestamp::now().as_second();
        let claims = claims_with_exp(now, Some("user@example.com"));
        let status = super::build_status(&claims, None);
        // `exp == now` is the sharp edge of the strict `exp > now` re-check:
        // jsonwebtoken accepts it, but the server's authoritative rule rejects
        // it, so `authenticated == false` and `email` must be `None`.
        assert!(!status.authenticated);
        assert!(
            status.email.is_none(),
            "email must be None when authenticated is false, but got {:?}",
            status.email
        );
        assert_eq!(status.expires_in_seconds, None);
    }

    #[test]
    fn build_status_email_is_some_when_authenticated() {
        let now = jiff::Timestamp::now().as_second();
        let claims = claims_with_exp(now.saturating_add(3600), Some("user@example.com"));
        let status = super::build_status(&claims, None);
        assert!(status.authenticated);
        assert_eq!(status.email.as_deref(), Some("user@example.com"));
        assert!(status.expires_in_seconds.unwrap_or(0) > 0);
    }

    #[test]
    fn build_status_device_name_returned_regardless_of_auth() {
        let now = jiff::Timestamp::now().as_second();

        let live = super::build_status(
            &claims_with_exp(now.saturating_add(3600), Some("user@example.com")),
            Some("YubiKey 5C".to_string()),
        );
        assert!(live.authenticated);
        assert_eq!(live.device_name.as_deref(), Some("YubiKey 5C"));

        let expired = super::build_status(
            &claims_with_exp(now.saturating_sub(3600), Some("user@example.com")),
            Some("YubiKey 5C".to_string()),
        );
        // `device_name` is documented without an "if authenticated" qualifier,
        // so it is returned unconditionally — do not gate it on `authenticated`.
        assert!(!expired.authenticated);
        assert_eq!(expired.device_name.as_deref(), Some("YubiKey 5C"));
    }

    /// End-to-end through the real router: when a token is decoded at its own
    /// expiry second, the handler reaches `build_status` with
    /// `authenticated == false`, and `email` is `null` per the `SessionStatus`
    /// contract ("User's email if authenticated").
    ///
    /// Reachability without a clock seam: forge a JWT with `exp == now`
    /// (jsonwebtoken accepts `exp == now`; only `exp < now` is rejected) and
    /// persist a *valid* session row keyed by the forged token's hash with
    /// `expires_at` one hour in the future, so the cache-miss DB lookup returns
    /// the row and the handler reaches `build_status` rather than bailing at
    /// `session.is_none()`. `build_status`'s strict-`>` re-check then yields
    /// `authenticated == false`.
    #[tokio::test]
    async fn test_auth_status_email_null_at_jwt_exp_boundary_via_router() {
        use crate::db::{CreateSessionParams, SessionPurpose, create_session};
        use crate::services::auth::{DecodedToken, decode_token};
        use jiff::Timestamp;

        let (app, state) = test_app().await;
        let user = create_test_user(&state.store, "boundary@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;

        // Mint a real token to copy valid iss/aud/client_id claims, then
        // re-sign with `exp == now`.
        let real_token = create_test_session_with(
            &state,
            TestSessionSpec {
                user_id: &user.id,
                email: &user.email,
                auth_id: Some(&auth_id),
                ..Default::default()
            },
        )
        .await;
        let DecodedToken::AccessToken(mut claims) =
            decode_token(&real_token, &state.oidc_key, &state.config().base_url)
                .expect("real token must decode");
        let now = Timestamp::now().as_second();
        claims.exp = now;
        claims.jti = uuid::Uuid::now_v7().to_string();
        let forged = state
            .oidc_key
            .sign_access_token_jwt(&claims)
            .await
            .expect("sign forged access token");

        // Persist a *valid* session row (expires_at 1h out) keyed by the forged
        // hash so the cache-miss DB lookup returns the row.
        let forged_hash = crate::crypto::hash_token(&forged);
        let expires_at =
            Timestamp::from_second(now.saturating_add(3600)).expect("valid expires_at");
        create_session(
            &state.store,
            &CreateSessionParams {
                user_id: &user.id,
                user_email: &user.email,
                token_hash: &forged_hash,
                authenticator_id: Some(&auth_id),
                expires_at,
                session_type: SessionPurpose::OAuthAccessToken,
                authorization_details: None,
                hardware_aaguid: None,
                org_domain: None,
                source_code_hash: None,
            },
        )
        .await
        .expect("create session for forged token");

        let auth_header = format!("Bearer {forged}");
        let (status, body) =
            http_get(&app, "/v1/auth/status", &[("Authorization", &auth_header)]).await;

        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(json["authenticated"], false);
        assert!(
            json["email"].is_null(),
            "email must be null when authenticated == false (boundary), got: {json}"
        );
    }
}
