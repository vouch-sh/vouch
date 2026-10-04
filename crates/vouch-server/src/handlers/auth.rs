// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Authentication handlers for session management.

use super::enroll::ErrorTemplate;
use crate::AppState;
use crate::arrival::ArrivalTime;
use crate::db;
use crate::error::ServiceError;
use axum::{
    Json,
    body::Body,
    extract::State,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use axum_extra::extract::cookie::CookieJar;
use jiff::Timestamp;
use std::sync::Arc;
use vouch_common::{SessionStatus, protocol};

use super::session::{AuthenticatedToken, OptionalAuthenticatedToken};
use super::{clear_session_cookie, hash_token};
use crate::db::ClientInfo;

/// Get current session status.
///
/// Validates the `Authorization` header token like any resource request,
/// sender constraint included. RFC 9449 §7.2: a protected resource supporting
/// both schemes "MUST reject a DPoP-bound access token received as a bearer
/// token". A missing or rejected token, or one whose account is missing or
/// deactivated, yields `authenticated: false` rather than a 401, except
/// `use_dpop_nonce`, whose fresh `DPoP-Nonce` the client needs to retry
/// (RFC 9449 §8).
pub(crate) async fn status(
    arrival: ArrivalTime,
    State(state): State<Arc<AppState>>,
    token: Result<OptionalAuthenticatedToken, ServiceError>,
) -> Result<Json<SessionStatus>, ServiceError> {
    let token = match token {
        Ok(OptionalAuthenticatedToken(Some(AuthenticatedToken { token, .. }))) => token,
        Err(e @ ServiceError::ApiWithHeaders { .. })
            if matches!(&e, ServiceError::ApiWithHeaders { code, .. }
                if code == protocol::ERROR_USE_DPOP_NONCE) =>
        {
            return Err(e);
        }
        Ok(OptionalAuthenticatedToken(None))
        | Err(
            ServiceError::Api {
                status: StatusCode::UNAUTHORIZED,
                ..
            }
            | ServiceError::ApiWithHeaders {
                status: StatusCode::UNAUTHORIZED,
                ..
            },
        ) => {
            return Ok(Json(SessionStatus {
                authenticated: false,
                email: None,
                expires_in_seconds: None,
                device_name: None,
            }));
        }
        Err(e) => return Err(e),
    };

    let device_name = match token.authenticator_id.as_deref() {
        Some(auth_id) => db::get_authenticator_by_id(&state.store, auth_id)
            .await
            .ok()
            .flatten()
            .map(|a| a.name),
        None => None,
    };

    Ok(Json(build_status(
        token.exp,
        token.email,
        device_name,
        arrival,
    )))
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
fn build_status(
    exp: Timestamp,
    email: Option<String>,
    device_name: Option<String>,
    arrival: ArrivalTime,
) -> SessionStatus {
    let now = arrival.timestamp();
    let expires_in = if exp > now {
        u64::try_from(exp.duration_since(now).as_secs()).ok()
    } else {
        None
    };

    let authenticated = expires_in.is_some();
    SessionStatus {
        authenticated,
        email: email.filter(|_| authenticated),
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

        // The deleted row, expired or not, carries the user for the `Logout`
        // audit event. A failed delete leaves the session live: the user is
        // told sign-out failed and keeps the cookie to retry.
        match state
            .session_cache
            .delete_by_token_hash(&state.store, &token_hash)
            .await
        {
            Ok(Some(session)) => {
                tracing::info!("Session deleted during logout");

                // Best-effort logout audit event
                let params = db::AuthEventParams {
                    user_id: db::Principal::Verified(session.user_id.clone()),
                    event_type: db::AuthEventType::Logout,
                    success: true,
                    client: client_info,
                    authenticator_id: None,
                    failure_reason: None,
                    client_id: None,
                    idp_issuer: None,
                };
                db::record_auth_event(&state.audit, params, Some(session.user_email.clone())).await;
            }
            Ok(None) => {}
            Err(e) => {
                tracing::error!("Failed to delete session during logout: {e}");
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    ErrorTemplate::logout_failed(),
                )
                    .into_response();
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
    use crate::arrival::ArrivalTime;
    use crate::crypto;
    use crate::db::{self, AuditEvent, AuditEventFilter, AuditEventKind, SessionPurpose};
    use crate::services::oidc::mtls::compute_cert_thumbprint;
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

    /// A fixed instant, so a test about the `exp == now` edge compares against
    /// exactly the second it constructed its claims from.
    const FIXED: i64 = 1_800_000_000;

    #[test]
    fn build_status_email_is_none_at_exp_boundary() {
        let status = super::build_status(
            at_second(FIXED),
            Some("user@example.com".to_string()),
            None,
            ArrivalTime::for_test_second(FIXED),
        );
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
        let status = super::build_status(
            at_second(FIXED.saturating_add(3600)),
            Some("user@example.com".to_string()),
            None,
            ArrivalTime::for_test_second(FIXED),
        );
        assert!(status.authenticated);
        assert_eq!(status.email.as_deref(), Some("user@example.com"));
        assert!(status.expires_in_seconds.unwrap_or(0) > 0);
    }

    #[test]
    fn build_status_device_name_returned_regardless_of_auth() {
        let live = super::build_status(
            at_second(FIXED.saturating_add(3600)),
            Some("user@example.com".to_string()),
            Some("YubiKey 5C".to_string()),
            ArrivalTime::for_test_second(FIXED),
        );
        assert!(live.authenticated);
        assert_eq!(live.device_name.as_deref(), Some("YubiKey 5C"));

        let expired = super::build_status(
            at_second(FIXED.saturating_sub(3600)),
            Some("user@example.com".to_string()),
            Some("YubiKey 5C".to_string()),
            ArrivalTime::for_test_second(FIXED),
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
        let DecodedToken::AccessToken(mut claims) = decode_token(
            &real_token,
            &state.oidc_key,
            &state.config().base_url,
            test_arrival(),
        )
        .expect("real token must decode");
        let now = Timestamp::now().as_second();
        claims.exp = at_second(now);
        claims.jti = uuid::Uuid::now_v7().to_string();
        let forged = state
            .oidc_key
            .sign_access_token_jwt(&claims)
            .await
            .expect("sign forged access token");

        // Persist a *valid* session row (expires_at 1h out) keyed by the forged
        // hash so the cache-miss DB lookup returns the row.
        let forged_hash = crypto::hash_token(&forged);
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
                authenticated_at: None,
                client_id: None,
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

    // ====================================================================
    // logout handler — `Logout` audit event coverage
    // ====================================================================

    /// Query the audit store for `Logout` events for `user_id`, the way the
    /// `logout_invalidates_exchange` policy and any audit-analytics consumer
    /// would.
    async fn logout_audit_events(state: &crate::AppState, user_id: &str) -> Vec<AuditEvent> {
        state
            .audit
            .query_events(&AuditEventFilter {
                event_types: Some(vec![AuditEventKind::Logout.as_str().to_string()]),
                user_id: Some(user_id.to_string()),
                ..AuditEventFilter::default()
            })
            .await
            .expect("query audit events")
    }

    /// Regression test for the audit-integrity bug: a `POST /logout` whose
    /// cookie session row is already expired (but still present in the DB)
    /// must still record a `Logout` audit event. Before the fix the handler
    /// fetched the audit context via the expiry-filtering
    /// `get_session_by_token_hash`, which returned `None` for the expired
    /// row, so the audit was silently dropped — even though
    /// `SessionCache::delete_by_token_hash` successfully deleted the row.
    #[tokio::test]
    async fn test_logout_records_audit_event_for_expired_session_row() {
        let (app, state) = test_app().await;
        let user = create_test_user(&state.store, "logout-expired@example.com").await;

        let (token, token_hash) = create_test_expired_session_row(
            &state,
            &user.id,
            &user.email,
            None,
            SessionPurpose::OAuthAccessToken,
        )
        .await;

        // Sanity: the expiry-filtering lookup returns `None` for this row, so
        // a fix that still gated the audit on that lookup would skip the
        // event. This is the precondition the bug report describes.
        let filtered =
            db::get_session_by_token_hash(&state.store, &token_hash, jiff::Timestamp::now())
                .await
                .expect("filtered lookup");
        assert!(filtered.is_none(), "expired row must be filtered out");

        let cookie = format!("{}={token}", vouch_common::SESSION_COOKIE_NAME);
        let (status, _body) = http_post_form(
            &app,
            "/logout",
            "",
            &[
                ("Cookie", cookie.as_str()),
                // `/logout` is mounted under the `same_origin` CSRF layer;
                // it is the route's only CSRF defense. Same-origin passes.
                ("Origin", "https://test.example.com"),
            ],
        )
        .await;
        assert_ne!(
            status,
            StatusCode::FORBIDDEN,
            "same-origin POST must reach the handler"
        );

        // The row must be gone after logout.
        let after = db::find_session_by_token_hash(&state.store, &token_hash)
            .await
            .expect("post-logout lookup");
        assert!(after.is_none(), "session row must be deleted by logout");

        // The `Logout` audit event must exist for this user — the bug dropped it.
        let events = logout_audit_events(&state, &user.id).await;
        assert_eq!(
            events.len(),
            1,
            "a single Logout audit event must be recorded for the expired-but-present row"
        );
    }

    /// A `POST /logout` for a session row that is still live must also record
    /// the `Logout` audit event — guarding against a fix that broke the
    /// happy path while repairing the expired-row case.
    #[tokio::test]
    async fn test_logout_records_audit_event_for_live_session() {
        let (app, state) = test_app().await;
        let user = create_test_user(&state.store, "logout-live@example.com").await;
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
        let token_hash = crypto::hash_token(&token);

        let cookie = format!("{}={token}", vouch_common::SESSION_COOKIE_NAME);
        let (status, _body) = http_post_form(
            &app,
            "/logout",
            "",
            &[
                ("Cookie", cookie.as_str()),
                ("Origin", "https://test.example.com"),
            ],
        )
        .await;
        assert_ne!(
            status,
            StatusCode::FORBIDDEN,
            "same-origin POST must reach the handler"
        );

        let after = db::find_session_by_token_hash(&state.store, &token_hash)
            .await
            .expect("post-logout lookup");
        assert!(
            after.is_none(),
            "live session row must be deleted by logout"
        );

        let events = logout_audit_events(&state, &user.id).await;
        assert_eq!(
            events.len(),
            1,
            "a single Logout audit event must be recorded for a live row"
        );
    }

    /// A `POST /logout` with no cookie / no session row must NOT record a
    /// `Logout` audit event — the audit fires only when a row was actually
    /// deleted. Guards against a fix that records the event unconditionally.
    #[tokio::test]
    async fn test_logout_no_audit_event_when_no_session_row() {
        let (app, state) = test_app().await;
        let user = create_test_user(&state.store, "logout-none@example.com").await;

        let (status, _body) = http_post_form(
            &app,
            "/logout",
            "",
            &[("Origin", "https://test.example.com")],
        )
        .await;
        assert_ne!(status, StatusCode::FORBIDDEN);

        let events = logout_audit_events(&state, &user.id).await;
        assert!(
            events.is_empty(),
            "no Logout audit event when there is no session to delete"
        );
    }

    /// A `POST /logout` whose session delete fails must say so: 503 with no
    /// `Set-Cookie` clearing the session, so the browser keeps a cookie that
    /// still works and can retry. A redirect home would show the user as
    /// signed out while the session stays live.
    #[tokio::test]
    async fn test_logout_reports_failed_session_delete() {
        let (app, state) = test_app().await;
        let user = create_test_user(&state.store, "logout-fault@example.com").await;
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
        let token_hash = crypto::hash_token(&token);
        state.session_cache.inject_fault(token_hash.clone());

        let cookie = format!("{}={token}", vouch_common::SESSION_COOKIE_NAME);
        let response = http_post_form_full(
            &app,
            "/logout",
            "",
            &[
                ("Cookie", cookie.as_str()),
                ("Origin", "https://test.example.com"),
            ],
        )
        .await;

        assert_eq!(response.status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            !response.headers.get_all("set-cookie").iter().any(|v| v
                .to_str()
                .is_ok_and(|v| v.starts_with(vouch_common::SESSION_COOKIE_NAME))),
            "a failed logout must not clear the session cookie"
        );
        let row = db::find_session_by_token_hash(&state.store, &token_hash)
            .await
            .expect("post-logout lookup");
        assert!(row.is_some(), "the session row survives the failed delete");
        assert!(
            logout_audit_events(&state, &user.id).await.is_empty(),
            "no Logout audit event when nothing was deleted"
        );
    }

    /// A DPoP-bound token and the key it is bound to.
    async fn dpop_bound_status_token(
        state: &crate::AppState,
        email: &str,
    ) -> (
        aws_lc_rs::signature::EcdsaKeyPair,
        serde_json::Value,
        String,
    ) {
        let user = create_test_user(&state.store, email).await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let (key, jwk) = generate_dpop_key_pair();
        let jkt = dpop_jkt(&jwk);
        let token = create_test_session_with(
            state,
            TestSessionSpec {
                user_id: &user.id,
                email: &user.email,
                auth_id: Some(&auth_id),
                binding: TestBinding::Dpop(&jkt),
                ..Default::default()
            },
        )
        .await;
        (key, jwk, token)
    }

    fn status_json(status: StatusCode, body: &str) -> serde_json::Value {
        assert_eq!(status, StatusCode::OK, "{body}");
        serde_json::from_str(body).expect("valid JSON")
    }

    // RFC 9449 §7.2: a protected resource supporting both schemes "MUST
    // reject a DPoP-bound access token received as a bearer token".
    #[tokio::test]
    async fn test_auth_status_rejects_dpop_bound_token_as_bearer() {
        let (app, state) = test_app().await;
        let (_key, _jwk, token) =
            dpop_bound_status_token(&state, "status-bound-bearer@example.com").await;

        let (status, body) = http_get(
            &app,
            "/v1/auth/status",
            &[("Authorization", &format!("Bearer {token}"))],
        )
        .await;

        let json = status_json(status, &body);
        assert_eq!(json["authenticated"], false, "{body}");
        assert!(json["email"].is_null(), "{body}");
        assert!(json["device_name"].is_null(), "{body}");
    }

    // RFC 9449 §7.1: a DPoP-bound token is sent with the DPoP scheme and a
    // proof whose key matches the binding.
    #[tokio::test]
    async fn test_auth_status_accepts_dpop_bound_token_with_proof() {
        let (app, state) = test_app().await;
        let (key, jwk, token) =
            dpop_bound_status_token(&state, "status-bound-proof@example.com").await;
        let uri = format!("{}/v1/auth/status", state.config().base_url);
        let proof = create_dpop_proof(&key, &jwk, "GET", &uri, None, Some(&token));

        let (status, body) = http_get(
            &app,
            "/v1/auth/status",
            &[
                ("Authorization", &format!("DPoP {token}")),
                ("DPoP", &proof),
            ],
        )
        .await;

        let json = status_json(status, &body);
        assert_eq!(json["authenticated"], true, "{body}");
        assert_eq!(json["email"], "status-bound-proof@example.com", "{body}");
    }

    #[tokio::test]
    async fn test_auth_status_rejects_dpop_scheme_without_proof() {
        let (app, state) = test_app().await;
        let (_key, _jwk, token) =
            dpop_bound_status_token(&state, "status-bound-no-proof@example.com").await;

        let (status, body) = http_get(
            &app,
            "/v1/auth/status",
            &[("Authorization", &format!("DPoP {token}"))],
        )
        .await;

        assert_eq!(status_json(status, &body)["authenticated"], false, "{body}");
    }

    #[tokio::test]
    async fn test_auth_status_rejects_proof_from_other_key() {
        let (app, state) = test_app().await;
        let (_key, _jwk, token) =
            dpop_bound_status_token(&state, "status-bound-other-key@example.com").await;
        let (other_key, other_jwk) = generate_dpop_key_pair();
        let uri = format!("{}/v1/auth/status", state.config().base_url);
        let proof = create_dpop_proof(&other_key, &other_jwk, "GET", &uri, None, Some(&token));

        let (status, body) = http_get(
            &app,
            "/v1/auth/status",
            &[
                ("Authorization", &format!("DPoP {token}")),
                ("DPoP", &proof),
            ],
        )
        .await;

        assert_eq!(status_json(status, &body)["authenticated"], false, "{body}");
    }

    // RFC 9449 §9: a resource server's nonce demand is "an HTTP 401
    // (Unauthorized) error code with an accompanying WWW-Authenticate: DPoP
    // value and DPoP-Nonce value".
    #[tokio::test]
    async fn test_auth_status_passes_use_dpop_nonce_through() {
        let (app, state) = test_app().await;
        let (key, jwk, token) =
            dpop_bound_status_token(&state, "status-bound-nonce@example.com").await;
        let uri = format!("{}/v1/auth/status", state.config().base_url);
        let proof = create_dpop_proof(&key, &jwk, "GET", &uri, Some("unknown"), Some(&token));

        let response = http_get_full(
            &app,
            "/v1/auth/status",
            &[
                ("Authorization", &format!("DPoP {token}")),
                ("DPoP", &proof),
            ],
        )
        .await;

        assert_eq!(
            response.status,
            StatusCode::UNAUTHORIZED,
            "{}",
            response.body
        );
        assert!(
            response.headers.contains_key("dpop-nonce"),
            "use_dpop_nonce must carry a fresh DPoP-Nonce: {}",
            response.body
        );
        let challenge = response
            .headers
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert!(
            challenge.starts_with(r#"DPoP error="use_dpop_nonce""#),
            "{challenge}"
        );
    }

    // RFC 8705 §3: a certificate-bound token is valid only with the
    // certificate it names.
    #[tokio::test]
    async fn test_auth_status_rejects_certificate_bound_token_without_certificate() {
        let (app, state) = test_app().await;
        let user = create_test_user(&state.store, "status-bound-mtls@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let thumbprint = compute_cert_thumbprint(&test_client_ca().issue("status-bound-mtls"));
        let token = create_test_session_with(
            &state,
            TestSessionSpec {
                user_id: &user.id,
                email: &user.email,
                auth_id: Some(&auth_id),
                binding: TestBinding::Mtls(&thumbprint),
                ..Default::default()
            },
        )
        .await;

        let (status, body) = http_get_with_cert(
            &app,
            "/v1/auth/status",
            &[("Authorization", &format!("Bearer {token}"))],
            None,
        )
        .await;

        assert_eq!(status_json(status, &body)["authenticated"], false, "{body}");
    }
}
