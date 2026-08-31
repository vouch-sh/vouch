// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `GET /api/v1/org/audit-events` — org-scoped audit event export API.
//!
//! Pull API for SIEM pollers (Okta System Log model) and ad hoc scripting:
//! JSON by default, NDJSON via `Accept: application/x-ndjson`, and an OCSF
//! projection via `?format=ocsf`. Auth accepts an org API token with the
//! `audit:read` scope (unattended pollers) or an org-admin user JWT
//! (interactive); cookie auth is rejected outright since this is not a
//! browser-facing endpoint. See `docs/src/admin/audit.md` for the full
//! contract (cursor semantics, delivery guarantee, filters).

use std::sync::Arc;

use aws_lc_rs::digest::{self, SHA256};
use axum::extract::{OriginalUri, Query, State};
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{Json, body::Body};
use axum_extra::extract::cookie::CookieJar;
use jiff::{Span, Timestamp};
use serde::{Deserialize, Serialize};
use vouch_common::protocol;

use super::ocsf::{self, RawOrValue};
use crate::AppState;
use crate::db::audit::{AuditEvent, AuditEventFilter, AuditEventKind};
use crate::db::{self, ScimScope, ScimScopeSet};
use crate::error::ServiceError;
use crate::handlers::session::extract_org_admin;

/// Default and maximum page size. Larger than the admin UI's page (which
/// optimizes for human scanning) since pollers want throughput.
const DEFAULT_PAGE_SIZE: u64 = 500;
const MAX_PAGE_SIZE: u64 = 1000;

/// Events with `created_at` newer than `now - LAG_WINDOW_SECONDS` are never
/// returned. Auth events are written from detached tasks (see
/// `db/config.rs`), so commit order can trail id order by a few seconds
/// under load; a naive high-water-mark poller would otherwise miss events
/// that commit late. This window — documented as the delivery guarantee in
/// `docs/src/admin/audit.md` — is comfortably larger than that lag.
const LAG_WINDOW_SECONDS: i64 = 30;

/// Byte budget for a single NDJSON response body. Keeps responses well
/// under typical reverse-proxy body limits; a caller that hits it gets a
/// cursor for the remainder instead of an unbounded body.
const NDJSON_BYTE_BUDGET: usize = 5 * 1024 * 1024;

/// Query parameters for `GET /api/v1/org/audit-events`.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct AuditEventsQuery {
    /// Comma-separated list of event types (e.g. `login_success,login_failed`).
    pub event_type: Option<String>,
    pub user_id: Option<String>,
    pub email: Option<String>,
    /// RFC 3339 timestamp; only events created strictly after this are returned.
    pub since: Option<String>,
    /// RFC 3339 timestamp; only events created strictly before this are returned.
    pub until: Option<String>,
    /// Forward cursor (ascending order) — the `id` of the last event from a
    /// previous page. Takes precedence over `before` when both are set.
    pub after: Option<String>,
    /// Backward cursor (descending order, matches the `/admin/audit` UI) —
    /// the `id` of the last event from a previous page.
    pub before: Option<String>,
    pub limit: Option<u64>,
    /// `"ocsf"` to project events into OCSF instead of native JSON.
    pub format: Option<String>,
}

/// Native JSON representation of an audit event. `data` is embedded via
/// `serde_json`'s `raw_value` feature when the stored payload parses as
/// JSON (the common case), or as a JSON string otherwise — malformed
/// legacy rows must not 500 the whole page.
#[derive(Serialize)]
pub(crate) struct AuditEventJson {
    pub id: String,
    pub event_type: String,
    pub user_id: Option<String>,
    pub email_domain: Option<String>,
    /// HMAC of the full email, included because it is the documented
    /// correlation key for org-scoped consumers (see `docs/src/admin/audit.md`).
    pub email_hmac: Option<String>,
    pub created_at: Timestamp,
    pub data: RawOrValue,
}

impl From<&AuditEvent> for AuditEventJson {
    fn from(event: &AuditEvent) -> Self {
        Self {
            id: event.id.clone(),
            event_type: event.event_type.clone(),
            user_id: event.user_id.clone(),
            email_domain: event.email_domain.clone(),
            email_hmac: event.email_hmac.clone(),
            created_at: event.created_at,
            data: ocsf::parse_event_data(&event.data),
        }
    }
}

/// `{events, next_cursor}` envelope shared by the JSON and OCSF formats.
#[derive(Serialize)]
struct AuditEventsResponse<T: Serialize> {
    events: Vec<T>,
    next_cursor: Option<String>,
}

/// Who authenticated the request and how.
enum AuditApiAuth {
    /// An org API token (generalized SCIM token) with the `audit:read` scope.
    OrgToken { org_id: String, token_id: String },
    /// An interactive org-admin session (FIDO2-backed user JWT).
    OrgAdmin { org_id: String, user_id: String },
}

impl AuditApiAuth {
    fn org_id(&self) -> &str {
        match self {
            Self::OrgToken { org_id, .. } | Self::OrgAdmin { org_id, .. } => org_id,
        }
    }

    /// `(actor_kind, actor_id)` for the read-access log line.
    fn actor(&self) -> (&'static str, &str) {
        match self {
            Self::OrgToken { token_id, .. } => ("token", token_id.as_str()),
            Self::OrgAdmin { user_id, .. } => ("user", user_id.as_str()),
        }
    }
}

/// Authenticate the request as an org API token with `audit:read`, or an
/// org-admin user JWT. Never falls back to the session cookie: this
/// endpoint is polled by unattended clients, and a request that carries no
/// `Authorization` header is always rejected outright, regardless of
/// whether a browser session cookie happens to be present.
async fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
    jar: &CookieJar,
    method: &str,
    uri: &str,
) -> Result<AuditApiAuth, ServiceError> {
    let Some(auth_header) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    else {
        return Err(ServiceError::api(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "Missing bearer token",
        ));
    };

    if let Some(token) = crate::http::strip_auth_scheme(auth_header, protocol::AUTH_SCHEME_BEARER) {
        let token_hash = hex::encode(digest::digest(&SHA256, token.as_bytes()));
        let token_record = db::get_scim_token_by_hash(&state.store, &token_hash)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "failed to look up org API token");
                ServiceError::api(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "db_error",
                    "Database error",
                )
            })?;

        if let Some(token_record) = token_record {
            let org_id = token_record.org_id.ok_or_else(|| {
                tracing::warn!(token_id = %token_record.id, "org API token has no org_id; rejecting");
                ServiceError::api(StatusCode::UNAUTHORIZED, "unauthorized", "Invalid token")
            })?;
            let scope = ScimScopeSet::parse(&token_record.scope).ok_or_else(|| {
                tracing::error!(token_id = %token_record.id, "invalid org API token scope in database");
                ServiceError::api(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Invalid token scope")
            })?;
            if !scope.contains(ScimScope::AuditRead) {
                return Err(ServiceError::api(
                    StatusCode::FORBIDDEN,
                    "forbidden",
                    "Token lacks the audit:read scope",
                ));
            }
            if let Err(e) = db::update_scim_token_last_used(&state.store, &token_record.id).await {
                tracing::warn!(error = %e, "failed to update org API token last_used_at");
            }
            return Ok(AuditApiAuth::OrgToken {
                org_id,
                token_id: token_record.id,
            });
        }
    }

    // Not a recognized org API token — fall back to an org-admin user JWT
    // (DPoP or Bearer). `extract_org_admin` internally falls back to the
    // session cookie whenever the `Authorization` header doesn't start
    // with `DPoP ` or `Bearer ` (session.rs's `extract_token_from_request`
    // only inspects those two prefixes; anything else, e.g. `Basic ...`,
    // is silently ignored in favor of the cookie). Since this endpoint
    // must reject cookie auth outright, a header that's present but
    // doesn't match a known bearer scheme is a hard 401 here rather than
    // being allowed to fall through to that cookie fallback.
    //
    let scheme_valid = crate::http::strip_auth_scheme(auth_header, protocol::AUTH_SCHEME_DPOP)
        .is_some()
        || crate::http::strip_auth_scheme(auth_header, protocol::AUTH_SCHEME_BEARER).is_some();
    if !scheme_valid {
        return Err(ServiceError::api(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "Unsupported authorization scheme",
        ));
    }

    let (user, org_id) = extract_org_admin(state, headers, jar, method, uri, None).await?;
    Ok(AuditApiAuth::OrgAdmin {
        org_id,
        user_id: user.id,
    })
}

/// Parse and validate the `event_type` query parameter into wire strings.
///
/// Rejects (400) an empty value and any component that isn't a registered
/// [`AuditEventKind`] — silently filtering unknown types would let
/// `sea_query`'s `IN ()` rendering turn a typo into "no events found",
/// which reads as "no security events" to a SIEM instead of a bad filter.
fn parse_event_types(raw: &str) -> Result<Vec<String>, ServiceError> {
    let mut kinds = Vec::new();
    for part in raw.split(',') {
        let part = part.trim();
        if part.is_empty() || AuditEventKind::from_wire(part).is_none() {
            return Err(ServiceError::api(
                StatusCode::BAD_REQUEST,
                "invalid_event_type",
                format!("Unknown event_type: {part:?}"),
            ));
        }
        kinds.push(part.to_string());
    }
    if kinds.is_empty() {
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_event_type",
            "event_type must not be empty",
        ));
    }
    Ok(kinds)
}

fn parse_timestamp_param(name: &str, raw: &str) -> Result<Timestamp, ServiceError> {
    raw.parse::<Timestamp>().map_err(|_| {
        ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_timestamp",
            format!("{name} is not a valid RFC 3339 timestamp"),
        )
    })
}

/// Serialize one event as a single JSON line (native or OCSF, per `format_ocsf`).
fn serialize_line(event: &AuditEvent, format_ocsf: bool) -> Result<String, ServiceError> {
    let result = if format_ocsf {
        serde_json::to_string(&ocsf::to_ocsf(event))
    } else {
        serde_json::to_string(&AuditEventJson::from(event))
    };
    result.map_err(|e| {
        tracing::error!(error = %e, event_id = %event.id, "failed to serialize audit event");
        ServiceError::api(
            StatusCode::INTERNAL_SERVER_ERROR,
            "serialize_error",
            "Failed to serialize audit event",
        )
    })
}

/// Build the `Link` header target for the next NDJSON page: the original
/// request path and query with any existing `after`/`before` replaced by
/// the new cursor. Preserves every other filter (`event_type`, `since`,
/// `until`, `limit`, `format`) — a naive `?after={cursor}` would silently
/// drop them (and `format=ocsf`) on page 2, and would paginate forward
/// even for a request that explicitly paginated backward with `before`.
fn build_link_url(uri: &axum::http::Uri, cursor: &str, cursor_param: &str) -> String {
    let mut pairs: Vec<(String, String)> = uri
        .query()
        .map(|q| {
            url::form_urlencoded::parse(q.as_bytes())
                .into_owned()
                .collect()
        })
        .unwrap_or_default();
    pairs.retain(|(k, _)| k != "after" && k != "before");
    pairs.push((cursor_param.to_string(), cursor.to_string()));
    let query = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(&pairs)
        .finish();
    format!("{}?{}", uri.path(), query)
}

/// Build a buffered NDJSON body, stopping at `budget` bytes (always
/// emitting at least one line, even if it alone exceeds the budget, so a
/// poller always makes forward progress). Returns the body and the cursor
/// for the next page, if any.
///
/// `budget` is [`NDJSON_BYTE_BUDGET`] in production; parameterized so tests
/// can exercise the cap deterministically with a handful of small events
/// instead of generating megabytes of fixture data.
fn build_ndjson_body(
    events: &[AuditEvent],
    format_ocsf: bool,
    has_more: bool,
    budget: usize,
) -> Result<(String, Option<String>), ServiceError> {
    let mut body = String::new();
    let mut last_emitted: Option<&str> = None;
    let mut byte_capped = false;

    for event in events {
        let line = serialize_line(event, format_ocsf)?;
        if !body.is_empty() && body.len().saturating_add(line.len()) > budget {
            byte_capped = true;
            break;
        }
        body.push_str(&line);
        body.push('\n');
        last_emitted = Some(event.id.as_str());
    }

    let next_cursor = if byte_capped {
        last_emitted.map(str::to_string)
    } else if has_more {
        events.last().map(|e| e.id.clone())
    } else {
        None
    };

    Ok((body, next_cursor))
}

/// GET /api/v1/org/audit-events
pub(crate) async fn audit_events(
    method: Method,
    uri: OriginalUri,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
    Query(query): Query<AuditEventsQuery>,
) -> Result<Response, ServiceError> {
    let auth = authenticate(&state, &headers, &jar, method.as_str(), uri.path()).await?;

    let event_types = query
        .event_type
        .as_deref()
        .map(parse_event_types)
        .transpose()?;
    let since = query
        .since
        .as_deref()
        .map(|s| parse_timestamp_param("since", s))
        .transpose()?;
    let until = query
        .until
        .as_deref()
        .map(|s| parse_timestamp_param("until", s))
        .transpose()?;

    let lag_cutoff = Timestamp::now()
        .checked_sub(Span::new().seconds(LAG_WINDOW_SECONDS))
        .map_err(|e| {
            tracing::error!(error = %e, "failed to compute audit API lag window");
            ServiceError::api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Internal error",
            )
        })?;
    let effective_until = match until {
        Some(u) if u < lag_cutoff => u,
        _ => lag_cutoff,
    };

    let org = db::get_organization(&state.store, auth.org_id())
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to load organization for audit events API");
            ServiceError::api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Database error",
            )
        })?
        .ok_or(ServiceError::NotFound("organization"))?;

    // Default to a forward (ascending) walk from the start of retained
    // history when neither cursor is given — this endpoint's primary use
    // case is a poller draining the log forward, not the newest-first
    // browsing the `/admin/audit` UI wants. An empty string sorts before
    // every UUID, so `after_id: Some("")` behaves as "from the beginning"
    // without a special case in the store layer.
    let before_id = query.before.clone().filter(|_| query.after.is_none());
    let after_id = match query.after.clone() {
        Some(cursor) => Some(cursor),
        None if before_id.is_none() => Some(String::new()),
        None => None,
    };
    let page_size = query
        .limit
        .unwrap_or(DEFAULT_PAGE_SIZE)
        .clamp(1, MAX_PAGE_SIZE);

    // Captured before `before_id` is moved into the filter below — decides
    // whether a `Link` header on a byte-capped NDJSON page should carry
    // `after` (forward, the default) or `before` (this request explicitly
    // paginated backward).
    let is_backward = before_id.is_some();

    let filter = AuditEventFilter {
        event_types,
        user_id: query.user_id.clone(),
        email: query.email.clone(),
        email_domains: Some(org.matching_email_domains()),
        since: since.map(|s| s.to_string()),
        until: Some(effective_until.to_string()),
        before_id,
        after_id,
        limit: None,
    };

    let (events, has_more) = state
        .audit
        .query_events_paginated(&filter, page_size)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to query audit events");
            ServiceError::api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Database error",
            )
        })?;

    let format_ocsf = query.format.as_deref() == Some("ocsf");
    let wants_ndjson = headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("application/x-ndjson"));

    let (actor_kind, actor_id) = auth.actor();
    tracing::info!(
        org_id = %auth.org_id(),
        actor_kind = %actor_kind,
        actor_id = %actor_id,
        event_count = events.len(),
        format = %(if format_ocsf { "ocsf" } else { "json" }),
        ndjson = wants_ndjson,
        "audit events API read"
    );

    let mut response = if wants_ndjson {
        let (body, next_cursor) =
            build_ndjson_body(&events, format_ocsf, has_more, NDJSON_BYTE_BUDGET)?;
        let mut response = Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/x-ndjson")
            .body(Body::from(body))
            .map_err(|e| {
                tracing::error!(error = %e, "failed to build NDJSON response");
                ServiceError::api(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "Internal error",
                )
            })?;
        if let Some(cursor) = next_cursor {
            let cursor_param = if is_backward { "before" } else { "after" };
            let link_url = build_link_url(&uri, &cursor, cursor_param);
            let link = format!("<{link_url}>; rel=\"next\"");
            if let Ok(value) = header::HeaderValue::from_str(&link) {
                response.headers_mut().insert(header::LINK, value);
            }
        }
        response
    } else {
        let next_cursor = if has_more {
            events.last().map(|e| e.id.clone())
        } else {
            None
        };
        if format_ocsf {
            let ocsf_events: Vec<ocsf::OcsfEvent> = events.iter().map(ocsf::to_ocsf).collect();
            Json(AuditEventsResponse {
                events: ocsf_events,
                next_cursor,
            })
            .into_response()
        } else {
            let json_events: Vec<AuditEventJson> =
                events.iter().map(AuditEventJson::from).collect();
            Json(AuditEventsResponse {
                events: json_events,
                next_cursor,
            })
            .into_response()
        }
    };

    // The plan requires `Cache-Control: no-store` on every response — the
    // global API layer's `no-cache, no-store, must-revalidate` only applies
    // via `if_not_present`, so set it explicitly here rather than relying
    // on no other layer having claimed the header first.
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );

    Ok(response)
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    #[test]
    fn parse_event_types_rejects_empty() {
        assert!(parse_event_types("").is_err());
        assert!(parse_event_types("  ").is_err());
    }

    #[test]
    fn parse_event_types_rejects_unknown() {
        assert!(parse_event_types("login_success,not_a_real_type").is_err());
    }

    #[test]
    fn parse_event_types_accepts_known_comma_separated() {
        let types =
            parse_event_types("login_success,login_failed").expect("both types are registered");
        assert_eq!(types, vec!["login_success", "login_failed"]);
    }

    #[test]
    fn parse_timestamp_param_rejects_garbage() {
        assert!(parse_timestamp_param("since", "not-a-timestamp").is_err());
    }

    #[test]
    fn parse_timestamp_param_accepts_rfc3339() {
        assert!(parse_timestamp_param("since", "2026-01-01T00:00:00Z").is_ok());
    }

    // ====================================================================
    // HTTP-level tests: auth matrix, filters, cursor, lag window, formats
    // ====================================================================

    use crate::test_utils::*;

    const PATH: &str = "/api/v1/org/audit-events";

    async fn seed_org_admin(state: &AppState) -> (String, String, String) {
        let org = create_test_org(&state.store, "example.com").await;
        let admin = create_test_user_in_org(&state.store, "admin@example.com", &org.id, true).await;
        let auth_id = create_test_authenticator(&state.store, &admin.id).await;
        let token = create_test_session_with(
            state,
            TestSessionSpec {
                user_id: &admin.id,
                email: &admin.email,
                auth_id: Some(&auth_id),
                ..Default::default()
            },
        )
        .await;
        (org.id, admin.id, token)
    }

    #[tokio::test]
    async fn audit_token_with_audit_read_scope_is_accepted() {
        let (app, state) = test_app().await;
        let org = create_test_org(&state.store, "example.com").await;
        let token = create_test_audit_token(&state.store, "poller", &org.id).await;

        let (status, _body) =
            http_get(&app, PATH, &[("Authorization", &format!("Bearer {token}"))]).await;
        assert_eq!(status, StatusCode::OK);
    }

    /// RFC 9110 Section 11.1: the auth-scheme token is case-insensitive, so
    /// `BEARER`, `bearer`, and `BeArEr` must all authenticate the same as
    /// `Bearer`. Regression test for the case-sensitive `strip_prefix`
    /// pattern that incorrectly rejected uppercase/mixed-case schemes.
    #[tokio::test]
    async fn audit_token_accepts_bearer_scheme_case_variants() {
        let (app, state) = test_app().await;
        let org = create_test_org(&state.store, "example.com").await;
        let token = create_test_audit_token(&state.store, "poller", &org.id).await;

        for scheme in ["BEARER", "bearer", "BeArEr", "bEaReR"] {
            let (status, _body) = http_get(
                &app,
                PATH,
                &[("Authorization", &format!("{scheme} {token}"))],
            )
            .await;
            assert_eq!(
                status,
                StatusCode::OK,
                "{scheme} scheme must be accepted (RFC 9110 §11.1 case-insensitivity)"
            );
        }
    }

    /// An unrecognized scheme must still be rejected by the guard clause
    /// even when it's a case variant of a scheme we don't support (e.g.
    /// `Basic`). This confirms the guard didn't become overly permissive.
    #[tokio::test]
    async fn guard_clause_rejects_unrecognized_scheme_case_variants() {
        let (app, _state) = test_app().await;

        for scheme in ["Basic", "basic", "BASIC", "bAsIc"] {
            let (status, body) = http_get(
                &app,
                PATH,
                &[("Authorization", &format!("{scheme} dXNlcjpwYXNz"))],
            )
            .await;
            assert_eq!(
                status,
                StatusCode::UNAUTHORIZED,
                "{scheme} must be rejected by the guard clause"
            );
            assert!(
                body.contains("Unsupported authorization scheme"),
                "{scheme} must be rejected as an unsupported scheme; got: {body}"
            );
        }
    }

    #[tokio::test]
    async fn scim_scope_only_token_is_rejected() {
        // A token minted before this feature (or without the checkbox) has
        // the four SCIM scopes but not audit:read.
        let (app, state) = test_app().await;
        let org = create_test_org(&state.store, "example.com").await;
        let token = create_test_scim_token(&state.store, "scim-only", &org.id).await;

        let (status, _body) =
            http_get(&app, PATH, &[("Authorization", &format!("Bearer {token}"))]).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn org_admin_user_jwt_is_accepted() {
        let (app, state) = test_app().await;
        let (_org_id, _admin_id, token) = seed_org_admin(&state).await;

        let (status, _body) =
            http_get(&app, PATH, &[("Authorization", &format!("Bearer {token}"))]).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn non_admin_user_jwt_is_forbidden() {
        let (app, state) = test_app().await;
        let org = create_test_org(&state.store, "example.com").await;
        let member =
            create_test_user_in_org(&state.store, "member@example.com", &org.id, false).await;
        let auth_id = create_test_authenticator(&state.store, &member.id).await;
        let token = create_test_session_with(
            &state,
            TestSessionSpec {
                user_id: &member.id,
                email: &member.email,
                auth_id: Some(&auth_id),
                ..Default::default()
            },
        )
        .await;

        let (status, _body) =
            http_get(&app, PATH, &[("Authorization", &format!("Bearer {token}"))]).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn cookie_auth_is_rejected() {
        let (app, state) = test_app().await;
        let (_org_id, _admin_id, token) = seed_org_admin(&state).await;
        let cookie = format!("{}={token}", vouch_common::SESSION_COOKIE_NAME);

        let (status, _body) = http_get(&app, PATH, &[("Cookie", &cookie)]).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "cookie-only auth must be rejected even for a valid session"
        );
    }

    #[tokio::test]
    async fn unrecognized_authorization_scheme_with_valid_cookie_is_rejected() {
        // Regression test: `session.rs`'s `extract_token_from_request`
        // only recognizes `DPoP `/`Bearer ` prefixes and silently falls back
        // to the session cookie for anything else (e.g. `Authorization:
        // Basic ...`). Without an explicit scheme check, that fallback would
        // let a request with a nonsense Authorization header plus a valid
        // admin session cookie authenticate anyway — defeating this
        // endpoint's cookie-rejection guarantee. `cookie_auth_is_rejected`
        // above only covers the "no header at all" case.
        let (app, state) = test_app().await;
        let (_org_id, _admin_id, token) = seed_org_admin(&state).await;
        let cookie = format!("{}={token}", vouch_common::SESSION_COOKIE_NAME);

        let (status, _body) = http_get(
            &app,
            PATH,
            &[("Authorization", "Basic dXNlcjpwYXNz"), ("Cookie", &cookie)],
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "an unrecognized Authorization scheme must not fall back to the session cookie"
        );
    }

    #[tokio::test]
    async fn missing_auth_is_unauthorized() {
        let (app, _state) = test_app().await;
        let (status, _body) = http_get(&app, PATH, &[]).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn cross_org_isolation() {
        // Both events are backdated past the lag window with
        // `insert_event_for_test` — using plain `insert_event` here (which
        // always stamps `now`) would make this test pass vacuously: the
        // lag window alone would exclude org B's event regardless of
        // whether domain scoping filtered it out at all.
        let (app, state) = test_app().await;
        let org_a = create_test_org(&state.store, "a.example.com").await;
        let org_b = create_test_org(&state.store, "b.example.com").await;
        let token_a = create_test_audit_token(&state.store, "org-a", &org_a.id).await;

        let old = jiff::Timestamp::now()
            .checked_sub(jiff::Span::new().minutes(5))
            .expect("valid timestamp");
        state
            .audit
            .insert_event_for_test(AuditEventKind::LoginSuccess, Some(&org_a.domain), old, "{}")
            .await
            .expect("insert org a event");
        state
            .audit
            .insert_event_for_test(AuditEventKind::LoginSuccess, Some(&org_b.domain), old, "{}")
            .await
            .expect("insert org b event");

        let (status, body) = http_get(
            &app,
            PATH,
            &[("Authorization", &format!("Bearer {token_a}"))],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let resp: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        let events = resp["events"].as_array().expect("events array");
        assert_eq!(
            events.len(),
            1,
            "org A's token must see exactly its own org's event; got {events:?}"
        );
        assert_eq!(events[0]["email_domain"], "a.example.com");
    }

    #[tokio::test]
    async fn unknown_event_type_returns_400() {
        let (app, state) = test_app().await;
        let org = create_test_org(&state.store, "example.com").await;
        let token = create_test_audit_token(&state.store, "poller", &org.id).await;

        let (status, _body) = http_get(
            &app,
            &format!("{PATH}?event_type=not_a_real_type"),
            &[("Authorization", &format!("Bearer {token}"))],
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn empty_event_type_returns_400() {
        let (app, state) = test_app().await;
        let org = create_test_org(&state.store, "example.com").await;
        let token = create_test_audit_token(&state.store, "poller", &org.id).await;

        let (status, _body) = http_get(
            &app,
            &format!("{PATH}?event_type="),
            &[("Authorization", &format!("Bearer {token}"))],
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn recent_event_is_excluded_by_the_lag_window() {
        // An event written "now" is always within the 30s lag window and
        // must never appear, regardless of any `until` the caller passes.
        let (app, state) = test_app().await;
        let org = create_test_org(&state.store, "example.com").await;
        let token = create_test_audit_token(&state.store, "poller", &org.id).await;

        state
            .audit
            .insert_json_event_for_test(
                AuditEventKind::LoginSuccess,
                None,
                Some("a@example.com"),
                "{}",
            )
            .await
            .expect("insert event");

        let (status, body) =
            http_get(&app, PATH, &[("Authorization", &format!("Bearer {token}"))]).await;
        assert_eq!(status, StatusCode::OK);
        let resp: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        let events = resp["events"].as_array().expect("events array");
        assert!(
            events.is_empty(),
            "an event written moments ago must be held back by the lag window; got {events:?}"
        );
    }

    #[tokio::test]
    async fn ndjson_format_returns_one_json_object_per_line() {
        let (app, state) = test_app().await;
        let org = create_test_org(&state.store, "example.com").await;
        let token = create_test_audit_token(&state.store, "poller", &org.id).await;

        // Backdate the event so it clears the lag window (events inserted
        // via `insert_event`/`insert_event_with_domain` always stamp `now`,
        // which the lag window would hold back).
        let old = jiff::Timestamp::now()
            .checked_sub(jiff::Span::new().minutes(5))
            .expect("valid timestamp");
        state
            .audit
            .insert_event_for_test(AuditEventKind::LoginSuccess, Some("example.com"), old, "{}")
            .await
            .expect("insert event");

        let resp = http_get_full(
            &app,
            PATH,
            &[
                ("Authorization", &format!("Bearer {token}")),
                ("Accept", "application/x-ndjson"),
            ],
        )
        .await;
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(
            resp.headers
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/x-ndjson")
        );
        let lines: Vec<&str> = resp.body.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(lines.len(), 1);
        let parsed: serde_json::Value = serde_json::from_str(lines[0]).expect("line is valid JSON");
        assert_eq!(parsed["event_type"], "login_success");
    }

    #[tokio::test]
    async fn ocsf_format_projects_class_uid() {
        let (app, state) = test_app().await;
        let org = create_test_org(&state.store, "example.com").await;
        let token = create_test_audit_token(&state.store, "poller", &org.id).await;

        let old = jiff::Timestamp::now()
            .checked_sub(jiff::Span::new().minutes(5))
            .expect("valid timestamp");
        state
            .audit
            .insert_event_for_test(AuditEventKind::LoginSuccess, Some("example.com"), old, "{}")
            .await
            .expect("insert event");

        let (status, body) = http_get(
            &app,
            &format!("{PATH}?format=ocsf"),
            &[("Authorization", &format!("Bearer {token}"))],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let resp: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        let events = resp["events"].as_array().expect("events array");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["class_uid"], 3002);
    }

    /// OCSF 1.9.0 MUST: events mapped to `activity_id: 99` (Other) must
    /// emit a source-specific `activity_name` (not the literal "Other")
    /// and preserve `event_type` in `unmapped`. End-to-end check through
    /// the `?format=ocsf` HTTP endpoint, covering all five affected kinds
    /// and confirming `AdminPromote`/`AdminDemote` are distinguishable.
    #[tokio::test]
    async fn ocsf_format_activity_id_99_events_carry_source_specific_name() {
        let (app, state) = test_app().await;
        let org = create_test_org(&state.store, "example.com").await;
        let token = create_test_audit_token(&state.store, "poller", &org.id).await;

        let old = jiff::Timestamp::now()
            .checked_sub(jiff::Span::new().minutes(5))
            .expect("valid timestamp");
        // Seed one event of each activity_id: 99 kind.
        let cases: [(AuditEventKind, u16, &str); 5] = [
            (AuditEventKind::AdminPromote, 3001, "Admin Promote"),
            (AuditEventKind::AdminDemote, 3001, "Admin Demote"),
            (
                AuditEventKind::AdminRevokeCredentials,
                3001,
                "Admin Revoke Credentials",
            ),
            (
                AuditEventKind::OauthTokenRevoked,
                3003,
                "OAuth Token Revoked",
            ),
            (AuditEventKind::ScimOperation, 3004, "SCIM Operation"),
        ];
        for (kind, _, _) in &cases {
            state
                .audit
                .insert_event_for_test(*kind, Some("example.com"), old, "{}")
                .await
                .expect("insert event");
        }

        let (status, body) = http_get(
            &app,
            &format!("{PATH}?format=ocsf&limit=100"),
            &[("Authorization", &format!("Bearer {token}"))],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let resp: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        let events = resp["events"].as_array().expect("events array");
        assert_eq!(events.len(), cases.len());

        // Build a lookup by event_type so order doesn't matter.
        use std::collections::HashMap;
        let mut by_type: HashMap<&str, &serde_json::Value> = HashMap::new();
        for ev in events {
            let et = ev["unmapped"]["event_type"]
                .as_str()
                .expect("event_type in unmapped");
            by_type.insert(et, ev);
        }

        for (kind, expected_class_uid, expected_activity_name) in &cases {
            let ev = by_type
                .get(kind.as_str())
                .expect("event_type must be present in response");
            assert_eq!(
                ev["activity_id"],
                99,
                "{}: activity_id must be 99",
                kind.as_str()
            );
            assert_ne!(
                ev["activity_name"],
                "Other",
                "{}: activity_name must not be the generic \"Other\"",
                kind.as_str()
            );
            assert_eq!(
                ev["activity_name"],
                *expected_activity_name,
                "{}: activity_name mismatch",
                kind.as_str()
            );
            assert_eq!(
                ev["class_uid"],
                *expected_class_uid,
                "{}: class_uid mismatch",
                kind.as_str()
            );
            assert_eq!(
                ev["unmapped"]["event_type"],
                kind.as_str(),
                "{}: unmapped.event_type must preserve source event_type",
                kind.as_str()
            );
            // type_uid = class_uid * 100 + activity_id
            let expected_type_uid = u32::from(*expected_class_uid) * 100 + 99;
            assert_eq!(
                ev["type_uid"],
                expected_type_uid,
                "{}: type_uid mismatch",
                kind.as_str()
            );
        }

        // Explicitly confirm the security-critical distinction: promote
        // vs demote must be distinguishable at the OCSF layer.
        let promote = by_type.get("admin_promote").expect("admin_promote present");
        let demote = by_type.get("admin_demote").expect("admin_demote present");
        assert_ne!(
            promote["activity_name"], demote["activity_name"],
            "admin_promote and admin_demote must be distinguishable by activity_name"
        );
    }

    #[tokio::test]
    async fn forward_cursor_pages_without_gap_or_duplicate() {
        let (app, state) = test_app().await;
        let org = create_test_org(&state.store, "example.com").await;
        let token = create_test_audit_token(&state.store, "poller", &org.id).await;

        let old = jiff::Timestamp::now()
            .checked_sub(jiff::Span::new().minutes(5))
            .expect("valid timestamp");
        for _ in 0..3 {
            state
                .audit
                .insert_event_for_test(AuditEventKind::LoginSuccess, Some("example.com"), old, "{}")
                .await
                .expect("insert event");
        }

        let (status, body) = http_get(
            &app,
            &format!("{PATH}?limit=2"),
            &[("Authorization", &format!("Bearer {token}"))],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let resp: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        let events = resp["events"].as_array().expect("events array");
        assert_eq!(events.len(), 2, "page size must be respected");
        let cursor = resp["next_cursor"].as_str().expect("next_cursor present");

        let (status, body) = http_get(
            &app,
            &format!("{PATH}?limit=2&after={cursor}"),
            &[("Authorization", &format!("Bearer {token}"))],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let resp: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        let events2 = resp["events"].as_array().expect("events array");
        assert_eq!(events2.len(), 1, "the remaining event must be on page two");
        assert_ne!(
            events[0]["id"], events2[0]["id"],
            "no event should repeat across pages"
        );
    }

    #[tokio::test]
    async fn backward_cursor_pages_newest_first_without_gap_or_duplicate() {
        let (app, state) = test_app().await;
        let org = create_test_org(&state.store, "example.com").await;
        let token = create_test_audit_token(&state.store, "poller", &org.id).await;

        let old = jiff::Timestamp::now()
            .checked_sub(jiff::Span::new().minutes(5))
            .expect("valid timestamp");
        for _ in 0..3 {
            state
                .audit
                .insert_event_for_test(AuditEventKind::LoginSuccess, Some("example.com"), old, "{}")
                .await
                .expect("insert event");
        }

        // `before` set to a sentinel that sorts after every real UUID v7 id
        // (its characters are all outside the hex/dash alphabet) so the
        // first page starts from "now" and walks backward — the direction
        // `/admin/audit` uses.
        let sentinel = "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz";
        let (status, body) = http_get(
            &app,
            &format!("{PATH}?limit=2&before={sentinel}"),
            &[("Authorization", &format!("Bearer {token}"))],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let resp: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        let events = resp["events"].as_array().expect("events array");
        assert_eq!(events.len(), 2, "page size must be respected");
        let cursor = resp["next_cursor"].as_str().expect("next_cursor present");

        let (status, body) = http_get(
            &app,
            &format!("{PATH}?limit=2&before={cursor}"),
            &[("Authorization", &format!("Bearer {token}"))],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let resp: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        let events2 = resp["events"].as_array().expect("events array");
        assert_eq!(events2.len(), 1, "the remaining event must be on page two");
        assert_ne!(
            events[0]["id"], events2[0]["id"],
            "no event should repeat across pages"
        );

        let newest_on_page_two = events[1]["id"].as_str().expect("id is a string");
        let only_id_on_page_two = events2[0]["id"].as_str().expect("id is a string");
        assert!(
            only_id_on_page_two < newest_on_page_two,
            "descending order: page two's event must be older than page one's oldest"
        );
    }

    fn sample_audit_event(id: &str, data: &str) -> AuditEvent {
        AuditEvent {
            id: id.to_string(),
            event_type: AuditEventKind::LoginSuccess.as_str().to_string(),
            user_id: None,
            email_domain: Some("example.com".to_string()),
            email_hmac: None,
            data: data.to_string(),
            created_at: Timestamp::now(),
        }
    }

    #[test]
    fn ndjson_body_stops_at_byte_budget_and_always_emits_one_line() {
        let events = vec![
            sample_audit_event("event-1", "{\"padding\":\"aaaaaaaaaa\"}"),
            sample_audit_event("event-2", "{\"padding\":\"bbbbbbbbbb\"}"),
            sample_audit_event("event-3", "{\"padding\":\"cccccccccc\"}"),
        ];
        // Smaller than any two lines combined but larger than one line, so
        // exactly the first event is emitted and the cap kicks in on the
        // second.
        let one_line_len = serialize_line(&events[0], false).expect("serialize").len();
        let budget = one_line_len + 5;

        let (body, next_cursor) =
            build_ndjson_body(&events, false, false, budget).expect("build body");
        let lines: Vec<&str> = body.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(
            lines.len(),
            1,
            "only the first event should fit under budget"
        );
        assert_eq!(
            next_cursor.as_deref(),
            Some("event-1"),
            "cursor must resume at the last emitted event"
        );
    }

    #[test]
    fn ndjson_body_always_emits_at_least_one_line_even_over_budget() {
        let events = vec![sample_audit_event(
            "event-1",
            "{\"padding\":\"aaaaaaaaaaaaaaaaaaaa\"}",
        )];
        let (body, next_cursor) = build_ndjson_body(&events, false, false, 1).expect("build body");
        let lines: Vec<&str> = body.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(
            lines.len(),
            1,
            "a single event that alone exceeds the budget must still be emitted, \
             so a poller always makes forward progress"
        );
        assert_eq!(next_cursor.as_deref(), None, "no more events, so no cursor");
    }
}
