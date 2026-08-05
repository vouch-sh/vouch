// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Authentication handlers for session management.

use crate::AppState;
use crate::db;
use crate::error::ServiceError;
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
use vouch_common::SessionStatus;

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
    let token = match auth_header.and_then(|h| h.split_once(' ')) {
        Some((scheme, tok)) if scheme.eq_ignore_ascii_case("bearer") => tok,
        Some((scheme, tok)) if scheme.eq_ignore_ascii_case("dpop") => tok,
        _ => {
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
    let device_name = match session.and_then(|s| s.authenticator_id) {
        Some(auth_id) => db::get_authenticator_by_id(&state.store, &auth_id)
            .await
            .ok()
            .flatten()
            .map(|a| a.name),
        None => None,
    };

    // Calculate time remaining
    let now = Timestamp::now().as_second();
    let expires_in = if access_claims.exp > now {
        u64::try_from(access_claims.exp.saturating_sub(now)).ok()
    } else {
        None
    };

    Ok(Json(SessionStatus {
        authenticated: expires_in.is_some(),
        email: access_claims.email,
        expires_in_seconds: expires_in,
        device_name,
    }))
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
        let session_info = state
            .session_cache
            .get_session_by_token_hash(&state.store, &token_hash)
            .await
            .ok()
            .flatten();

        match db::delete_session_by_token_hash(&state.store, &token_hash).await {
            Ok(deleted) => {
                if deleted {
                    state.session_cache.invalidate(&token_hash);
                    tracing::info!("Session deleted during logout");

                    // Fire-and-forget logout audit event
                    if let Some(session) = session_info {
                        let params = db::AuthEventParams {
                            user_id: session.user_id.clone(),
                            event_type: db::AuthEventType::Logout,
                            success: true,
                            client: client_info,
                            ..Default::default()
                        };
                        db::spawn_audit_event(&state.audit, params, Some(session.user_email));
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
        let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

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
        let token = create_test_session(&state, &user.id, &user.email, &auth_id).await;

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
}
