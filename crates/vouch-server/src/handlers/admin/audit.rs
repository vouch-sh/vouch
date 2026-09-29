// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Audit log UI handler.

use crate::AppState;
use crate::db;
use crate::db::audit::AuditEventFilter;
use crate::impl_template_response;
use askama::Template;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use jiff::Timestamp;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::db::audit::AuditEvent;
use crate::handlers::extractors::AdminPage;
use crate::handlers::session::AuthContext;
use crate::infra::i18n::Tr;
use crate::{filters, geo};

/// Page size for the audit log.
const AUDIT_PAGE_SIZE: u64 = 50;

/// Query parameters for audit page (pagination + optional semantic filter).
///
/// The four text inputs come from a GET form, and a browser submits every
/// input of one, so a field the admin left empty arrives as `user_id=`. Each
/// is trimmed and a blank one is read as absent: an empty value filters
/// nothing, rather than matching no row.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct AuditParams {
    pub after: Option<String>,
    pub filter: Option<String>,
    /// Filter to a specific user ID (exact match).
    #[serde(default, deserialize_with = "blank_as_none")]
    pub user_id: Option<String>,
    /// Filter to a specific email address (exact match, case-insensitive).
    #[serde(default, deserialize_with = "blank_as_none")]
    pub email: Option<String>,
    /// Only events created after this RFC 3339 instant.
    #[serde(default, deserialize_with = "blank_as_none")]
    pub since: Option<String>,
    /// Only events created before this RFC 3339 instant.
    #[serde(default, deserialize_with = "blank_as_none")]
    pub until: Option<String>,
}

/// Trim a form value and read a blank one as absent.
fn blank_as_none<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Option::<String>::deserialize(deserializer)?
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty()))
}

/// Parse a date-range bound as an RFC 3339 instant. An offset form such as
/// `2026-01-01T08:00:00-05:00` names the same instant as
/// `2026-01-01T13:00:00Z`; the store compares instants, not the text.
fn parse_bound(raw: Option<&str>, invalid: Tr<'static>) -> Result<Option<Timestamp>, Tr<'static>> {
    raw.map(|s| s.parse::<Timestamp>().map_err(|_| invalid))
        .transpose()
}

impl AuditParams {
    /// Whether any of the date-range/user/email filters are set — used by
    /// the template to decide whether to show a "clear filters" link.
    fn has_advanced_filters(&self) -> bool {
        self.user_id.is_some()
            || self.email.is_some()
            || self.since.is_some()
            || self.until.is_some()
    }
}

/// Map a UI filter name to the corresponding audit event types.
fn audit_filter_event_types(filter: &str) -> Option<Vec<String>> {
    let types: &[&str] = match filter {
        "logins" => &["login_success", "login_failed"],
        "promotions" => &["admin_promote"],
        "demotions" => &["admin_demote"],
        "deactivations" => &["admin_deactivate"],
        "removals" => &["admin_remove_user"],
        "revocations" => &["admin_revoke_credentials", "admin_revoke_scim_token"],
        _ => return None,
    };
    Some(types.iter().map(|s| (*s).to_string()).collect())
}

/// Audit event row for the template.
pub(crate) struct AuditRow {
    pub id: String,
    pub event_type: String,
    pub email_domain: Option<String>,
    pub data: String,
    /// The target member's current email, resolved at display time via
    /// `data.target_user_id` for member-management events (promote,
    /// demote, deactivate, activate, revoke-credentials, remove). `None`
    /// for event types with no target, or when resolution fails and no
    /// fallback is available.
    pub target_email: Option<String>,
    /// Event timestamp, rendered client-side in the viewer's locale and
    /// timezone (`humandatetime` is the no-JS fallback).
    pub created_at: Timestamp,
    /// Pre-formatted IP cell text, e.g. "🇺🇸 8.8.8.8" or "-".
    pub ip_display: String,
    /// Tooltip for the IP cell with country code and ASN.
    pub ip_title: String,
}

/// Audit log page template.
#[derive(Template)]
#[template(path = "admin/audit.html")]
pub(crate) struct AdminAuditTemplate {
    pub auth: AuthContext,
    pub events: Vec<AuditRow>,
    pub has_more: bool,
    pub next_cursor: Option<String>,
    pub filter: Option<String>,
    /// Echoed back into the filter form so a submitted filter stays visible.
    pub user_id: Option<String>,
    pub email: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub has_advanced_filters: bool,
    /// Set when a date-range bound is not a timestamp; no events are listed.
    pub filter_error: Option<Tr<'static>>,
}

impl_template_response!(AdminAuditTemplate);

/// GET /admin/audit — Audit log page.
pub(crate) async fn admin_audit_page(
    State(state): State<Arc<AppState>>,
    _jar: CookieJar,
    admin: AdminPage,
    Query(params): Query<AuditParams>,
) -> Response {
    let AdminPage {
        auth,
        user_id: _,
        org_id,
    } = admin;

    // Get the org's domains (primary + verified additional) to scope
    // audit events to this org.
    let Some(org) = db::get_organization(&state.store, &org_id)
        .await
        .ok()
        .flatten()
    else {
        return Redirect::to("/integrations").into_response();
    };

    let bounds = parse_bound(
        params.since.as_deref(),
        Tr::new("admin-audit-filter-invalid-since"),
    )
    .and_then(|since| {
        parse_bound(
            params.until.as_deref(),
            Tr::new("admin-audit-filter-invalid-until"),
        )
        .map(|until| (since, until))
    });
    let (since, until) = match bounds {
        Ok(bounds) => bounds,
        Err(filter_error) => {
            let has_advanced_filters = params.has_advanced_filters();
            let page = AdminAuditTemplate {
                auth,
                events: Vec::new(),
                has_more: false,
                next_cursor: None,
                filter: params.filter,
                user_id: params.user_id,
                email: params.email,
                since: params.since,
                until: params.until,
                has_advanced_filters,
                filter_error: Some(filter_error),
            };
            return (StatusCode::BAD_REQUEST, page).into_response();
        }
    };

    let event_types = params.filter.as_deref().and_then(audit_filter_event_types);

    let filter = AuditEventFilter {
        email_domains: Some(org.matching_email_domains()),
        event_types,
        user_id: params.user_id.clone(),
        email: params.email.clone(),
        since,
        until,
        before_id: params.after.clone(),
        ..AuditEventFilter::default()
    };

    let (audit_events, has_more): (Vec<AuditEvent>, bool) = match state
        .audit
        .query_events_paginated(&filter, AUDIT_PAGE_SIZE)
        .await
    {
        Ok(result) => result,
        Err(e) => {
            tracing::error!("Failed to load audit events: {e}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    // Batch-resolve every member-management row's target email in a single
    // query instead of one lookup per row (bounded by AUDIT_PAGE_SIZE = 50).
    let target_ids: Vec<String> = audit_events
        .iter()
        .filter(|e| MEMBER_EVENT_TYPES.contains(&e.event_type.as_str()))
        .filter_map(|e| TargetFields::from_json(&e.data).target_user_id)
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();

    let target_users = match db::get_users_by_ids(&state.store, &target_ids).await {
        Ok(map) => map,
        Err(e) => {
            tracing::error!("Failed to batch-resolve audit target users: {e}");
            HashMap::new()
        }
    };

    let mut events: Vec<AuditRow> = Vec::with_capacity(audit_events.len());
    for e in &audit_events {
        let geo = GeoFields::from_json(&e.data);
        let target_email = resolve_target_email(&target_users, e);
        events.push(AuditRow {
            id: e.id.clone(),
            event_type: e.event_type.clone(),
            email_domain: e.email_domain.clone(),
            data: e.data.clone(),
            target_email,
            created_at: e.created_at,
            ip_display: geo.ip_display(),
            ip_title: geo.ip_title(),
        });
    }

    let next_cursor = if has_more {
        events.last().map(|e| e.id.clone())
    } else {
        None
    };

    let has_advanced_filters = params.has_advanced_filters();

    AdminAuditTemplate {
        auth,
        events,
        has_more,
        next_cursor,
        filter: params.filter,
        user_id: params.user_id,
        email: params.email,
        since: params.since,
        until: params.until,
        has_advanced_filters,
        filter_error: None,
    }
    .into_response()
}

/// Member-management event types whose `data` carries a `target_user_id`
/// to resolve into a display email, rather than storing the target's email
/// raw in `data` (which would then be re-exposed verbatim to `audit:read`
/// API consumers — emails are documented as masked to domain-only).
const MEMBER_EVENT_TYPES: &[&str] = &[
    "admin_promote",
    "admin_demote",
    "admin_deactivate",
    "admin_activate",
    "admin_revoke_credentials",
    "admin_remove_user",
];

/// `target_user_id` parsed out of a member-management event's `data`.
#[derive(Default, Deserialize)]
struct TargetFields {
    target_user_id: Option<String>,
}

impl TargetFields {
    fn from_json(data_json: &str) -> Self {
        serde_json::from_str::<Self>(data_json).unwrap_or_else(|e| {
            tracing::trace!("Could not parse target fields from audit data: {e}");
            Self::default()
        })
    }
}

/// Resolve a member-management event's target to a display email via
/// `target_user_id`, looked up in a map pre-fetched once per page load
/// (`admin_audit_page` batches all target IDs into a single
/// `db::get_users_by_ids` call) rather than stored raw in `data`.
///
/// Falls back to the event's own `email_domain`/`email_hmac` columns —
/// stamped from the target's email at write time — when the target no
/// longer exists. This is not a rare case: `admin_remove_user` events are
/// written *after* the target is deleted, so that fallback applies to every
/// removal the floor did not refuse.
fn resolve_target_email(
    target_users: &HashMap<String, db::User>,
    event: &AuditEvent,
) -> Option<String> {
    if !MEMBER_EVENT_TYPES.contains(&event.event_type.as_str()) {
        return None;
    }
    let target_user_id = TargetFields::from_json(&event.data).target_user_id?;

    if let Some(user) = target_users.get(&target_user_id) {
        return Some(user.email.clone());
    }

    match (event.email_domain.as_deref(), event.email_hmac.as_deref()) {
        (Some(domain), Some(hmac)) => {
            let short_hmac = hmac.get(..8).unwrap_or(hmac);
            Some(format!("(removed user, {short_hmac}…@{domain})"))
        }
        (Some(domain), None) => Some(format!("(removed user @{domain})")),
        _ => Some("(removed user)".to_string()),
    }
}

/// Geo fields extracted from audit event JSON data.
#[derive(Default, Deserialize)]
struct GeoFields {
    country_code: Option<String>,
    #[serde(alias = "ip_address")]
    client_ip: Option<String>,
    asn: Option<u32>,
    org_name: Option<String>,
}

impl GeoFields {
    fn from_json(data_json: &str) -> Self {
        serde_json::from_str::<Self>(data_json).unwrap_or_else(|e| {
            tracing::trace!("Could not parse geo fields from audit data: {e}");
            Self::default()
        })
    }

    fn asn_display(&self) -> Option<String> {
        self.asn.map(|n| match self.org_name {
            Some(ref org) => format!("AS{n} ({org})"),
            None => format!("AS{n}"),
        })
    }

    fn ip_display(&self) -> String {
        let flag = self
            .country_code
            .as_deref()
            .and_then(geo::country_flag)
            .unwrap_or_default();
        let ip = self.client_ip.as_deref().unwrap_or("-");

        if flag.is_empty() {
            ip.to_string()
        } else {
            format!("{flag} {ip}")
        }
    }

    fn ip_title(&self) -> String {
        let mut parts = Vec::new();
        if let Some(ref cc) = self.country_code {
            parts.push(cc.clone());
        }
        if let Some(asn) = self.asn_display() {
            parts.push(asn);
        }
        parts.join(" · ")
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;
    use crate::db::audit::{AuditEvent, AuditEventKind};
    use crate::db::documents::audit::AdminMemberActionData;
    use crate::services::oidc::mtls;
    use crate::test_utils::*;
    use axum::http::StatusCode;

    /// Member-event target resolution must parse the typed payload the
    /// admin handlers write.
    #[test]
    fn test_target_fields_parse_the_typed_member_payload() {
        let typed = serde_json::to_string(&AdminMemberActionData {
            action: "promote",
            target_user_id: "u-target",
            admin_user_id: "u-admin",
            keys_revoked: None,
            refusal: None,
        })
        .unwrap();
        let fields = TargetFields::from_json(&typed);
        assert_eq!(fields.target_user_id.as_deref(), Some("u-target"));
    }

    #[test]
    fn test_geo_fields_from_json_full_record() {
        let json = r#"{"country_code":"US","client_ip":"8.8.8.8","asn":15169,"org_name":"GOOGLE"}"#;
        let geo = GeoFields::from_json(json);
        assert_eq!(geo.country_code.as_deref(), Some("US"));
        assert_eq!(geo.client_ip.as_deref(), Some("8.8.8.8"));
        assert_eq!(geo.asn, Some(15169));
        assert_eq!(geo.org_name.as_deref(), Some("GOOGLE"));
    }

    #[test]
    fn test_geo_fields_from_json_backwards_compat_no_asn_fields() {
        let json = r#"{"country_code":"DE","client_ip":"1.2.3.4"}"#;
        let geo = GeoFields::from_json(json);
        assert_eq!(geo.country_code.as_deref(), Some("DE"));
        assert_eq!(geo.client_ip.as_deref(), Some("1.2.3.4"));
        assert!(geo.asn.is_none());
        assert!(geo.org_name.is_none());
    }

    #[test]
    fn test_geo_fields_from_json_invalid_json_returns_default() {
        let geo = GeoFields::from_json("not json");
        assert!(geo.country_code.is_none());
        assert!(geo.client_ip.is_none());
        assert!(geo.asn.is_none());
        assert!(geo.org_name.is_none());
    }

    #[test]
    fn test_geo_fields_from_json_empty_object() {
        let geo = GeoFields::from_json("{}");
        assert!(geo.country_code.is_none());
        assert!(geo.client_ip.is_none());
        assert!(geo.asn.is_none());
        assert!(geo.org_name.is_none());
    }

    #[test]
    fn test_asn_display_with_asn_and_org() {
        let geo = GeoFields {
            asn: Some(15169),
            org_name: Some("GOOGLE".to_string()),
            ..GeoFields::default()
        };
        assert_eq!(geo.asn_display(), Some("AS15169 (GOOGLE)".to_string()));
    }

    #[test]
    fn test_asn_display_with_asn_no_org() {
        let geo = GeoFields {
            asn: Some(15169),
            ..GeoFields::default()
        };
        assert_eq!(geo.asn_display(), Some("AS15169".to_string()));
    }

    #[test]
    fn test_asn_display_no_asn() {
        let geo = GeoFields::default();
        assert!(geo.asn_display().is_none());
    }

    #[test]
    fn test_ip_display_with_country_and_ip() {
        let geo = GeoFields {
            country_code: Some("US".to_string()),
            client_ip: Some("8.8.8.8".to_string()),
            ..GeoFields::default()
        };
        let display = geo.ip_display();
        assert!(display.contains("8.8.8.8"));
        assert!(display.len() > "8.8.8.8".len(), "should include flag");
    }

    #[test]
    fn test_ip_display_no_country_code() {
        let geo = GeoFields {
            client_ip: Some("8.8.8.8".to_string()),
            ..GeoFields::default()
        };
        assert_eq!(geo.ip_display(), "8.8.8.8");
    }

    #[test]
    fn test_ip_display_no_ip_address() {
        let geo = GeoFields::default();
        assert_eq!(geo.ip_display(), "-");
    }

    #[test]
    fn test_ip_title_country_and_asn() {
        let geo = GeoFields {
            country_code: Some("DE".to_string()),
            asn: Some(3320),
            org_name: Some("DTAG".to_string()),
            ..GeoFields::default()
        };
        assert_eq!(geo.ip_title(), "DE · AS3320 (DTAG)");
    }

    #[test]
    fn test_ip_title_country_only() {
        let geo = GeoFields {
            country_code: Some("US".to_string()),
            ..GeoFields::default()
        };
        assert_eq!(geo.ip_title(), "US");
    }

    #[test]
    fn test_ip_title_asn_only() {
        let geo = GeoFields {
            asn: Some(15169),
            ..GeoFields::default()
        };
        assert_eq!(geo.ip_title(), "AS15169");
    }

    #[test]
    fn test_ip_title_all_none() {
        let geo = GeoFields::default();
        assert_eq!(geo.ip_title(), "");
    }

    // ---- Handler tests ----

    #[tokio::test]
    async fn test_audit_page_redirects_unauthenticated() {
        let (app, _state) = test_app().await;
        let (status, _body) = http_get(&app, "/admin/audit", &[]).await;
        assert!(
            status == StatusCode::SEE_OTHER || status == StatusCode::TEMPORARY_REDIRECT,
            "expected redirect, got {status}"
        );
    }

    #[tokio::test]
    async fn test_audit_page_redirects_non_admin() {
        let (app, state) = test_app().await;
        let org = create_test_org(&state.store, "example.com").await;
        let user =
            create_test_user_in_org(&state.store, "regular@example.com", &org.id, false).await;
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
        let cookie = format!("{}={token}", vouch_common::SESSION_COOKIE_NAME);

        let (status, _body) = http_get(&app, "/admin/audit", &[("Cookie", &cookie)]).await;
        assert!(
            status == StatusCode::SEE_OTHER || status == StatusCode::TEMPORARY_REDIRECT,
            "expected redirect for non-admin, got {status}"
        );
    }

    #[tokio::test]
    async fn test_audit_page_redirects_user_without_org() {
        let (app, state) = test_app().await;
        let user = create_test_user(&state.store, "noorg@example.com").await;
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
        let cookie = format!("{}={token}", vouch_common::SESSION_COOKIE_NAME);

        let (status, _body) = http_get(&app, "/admin/audit", &[("Cookie", &cookie)]).await;
        assert!(
            status == StatusCode::SEE_OTHER || status == StatusCode::TEMPORARY_REDIRECT,
            "expected redirect for user without org, got {status}"
        );
    }

    #[tokio::test]
    async fn test_audit_page_returns_html_for_admin() {
        let (app, state) = test_app().await;
        let org = create_test_org(&state.store, "example.com").await;
        let admin = create_test_user_in_org(&state.store, "admin@example.com", &org.id, true).await;
        let auth_id = create_test_authenticator(&state.store, &admin.id).await;
        let token = create_test_session_with(
            &state,
            TestSessionSpec {
                user_id: &admin.id,
                email: &admin.email,
                auth_id: Some(&auth_id),
                ..Default::default()
            },
        )
        .await;
        let cookie = format!("{}={token}", vouch_common::SESSION_COOKIE_NAME);

        let (status, body) = http_get(&app, "/admin/audit", &[("Cookie", &cookie)]).await;
        assert_eq!(status, StatusCode::OK, "admin should get 200");
        assert!(
            body.contains("<!DOCTYPE html") || body.contains("<html"),
            "should return HTML"
        );
    }

    #[tokio::test]
    async fn test_audit_page_with_filter_param() {
        let (app, state) = test_app().await;
        let org = create_test_org(&state.store, "example.com").await;
        let admin = create_test_user_in_org(&state.store, "admin@example.com", &org.id, true).await;
        let auth_id = create_test_authenticator(&state.store, &admin.id).await;
        let token = create_test_session_with(
            &state,
            TestSessionSpec {
                user_id: &admin.id,
                email: &admin.email,
                auth_id: Some(&auth_id),
                ..Default::default()
            },
        )
        .await;
        let cookie = format!("{}={token}", vouch_common::SESSION_COOKIE_NAME);

        let (status, _body) =
            http_get(&app, "/admin/audit?filter=logins", &[("Cookie", &cookie)]).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "admin with filter=logins should get 200"
        );
    }

    #[tokio::test]
    async fn test_audit_page_with_invalid_filter() {
        let (app, state) = test_app().await;
        let org = create_test_org(&state.store, "example.com").await;
        let admin = create_test_user_in_org(&state.store, "admin@example.com", &org.id, true).await;
        let auth_id = create_test_authenticator(&state.store, &admin.id).await;
        let token = create_test_session_with(
            &state,
            TestSessionSpec {
                user_id: &admin.id,
                email: &admin.email,
                auth_id: Some(&auth_id),
                ..Default::default()
            },
        )
        .await;
        let cookie = format!("{}={token}", vouch_common::SESSION_COOKIE_NAME);

        // Unknown filters are treated as no filter — page still loads
        let (status, _body) = http_get(
            &app,
            "/admin/audit?filter=nonexistent",
            &[("Cookie", &cookie)],
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "unknown filter should be ignored, still 200"
        );
    }

    #[tokio::test]
    async fn test_audit_page_shows_event_with_mixed_case_email_domain() {
        // Reproduces the production bug path: an audit event inserted with a
        // mixed-case email domain (as an IdP might return) must still appear
        // on the admin audit page, which filters by the org's stored
        // lowercase domain.
        let (app, state) = test_app().await;
        let org = create_test_org(&state.store, "corp.example.com").await;
        let admin =
            create_test_user_in_org(&state.store, "admin@corp.example.com", &org.id, true).await;
        let auth_id = create_test_authenticator(&state.store, &admin.id).await;
        let token = create_test_session_with(
            &state,
            TestSessionSpec {
                user_id: &admin.id,
                email: &admin.email,
                auth_id: Some(&auth_id),
                ..Default::default()
            },
        )
        .await;
        let cookie = format!("{}={token}", vouch_common::SESSION_COOKIE_NAME);

        // Seed an audit event with a mixed-case email domain, as an IdP might
        // return. The org domain is stored lowercase ("corp.example.com"), so
        // the page's email_domain filter must match via case normalization.
        state
            .audit
            .insert_json_event_for_test(
                AuditEventKind::LoginSuccess,
                Some(&admin.id),
                Some("Alice@CORP.Example.COM"),
                r#"{"success":true}"#,
            )
            .await
            .unwrap();

        let (status, body) = http_get(&app, "/admin/audit", &[("Cookie", &cookie)]).await;
        assert_eq!(status, StatusCode::OK, "admin should get 200");
        assert!(
            body.contains("login_success"),
            "audit page should list the mixed-case-domain event; body did not contain event_type"
        );
    }

    /// An org admin's session cookie for `/admin/audit`.
    async fn admin_cookie(state: &AppState, domain: &str) -> (String, String) {
        let org = create_test_org(&state.store, domain).await;
        let admin =
            create_test_user_in_org(&state.store, &format!("admin@{domain}"), &org.id, true).await;
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
        (
            format!("{}={token}", vouch_common::SESSION_COOKIE_NAME),
            admin.id,
        )
    }

    const MARKER: &str = "auditfiltermarker";

    /// Seed an event for `domain` at `2026-01-01T12:00:00Z` carrying [`MARKER`].
    async fn seed_noon_event(state: &AppState, domain: &str) {
        state
            .audit
            .insert_event_for_test(
                AuditEventKind::OrgDomainAdded,
                Some(domain),
                "2026-01-01T12:00:00Z".parse().unwrap(),
                &format!(r#"{{"marker":"{MARKER}"}}"#),
            )
            .await
            .unwrap();
    }

    /// A browser submits every input of the GET filter form, so filling in
    /// only Email sends the other three empty. Empty and whitespace-only
    /// values filter nothing, and "Clear filters" reflects only real ones.
    #[tokio::test]
    async fn test_audit_page_blank_form_fields_are_not_filters() {
        let (app, state) = test_app().await;
        let (cookie, admin_id) = admin_cookie(&state, "audit-blank.example").await;
        state
            .audit
            .insert_json_event_for_test(
                AuditEventKind::OrgDomainAdded,
                Some(&admin_id),
                Some("admin@audit-blank.example"),
                &format!(r#"{{"marker":"{MARKER}"}}"#),
            )
            .await
            .unwrap();

        let (status, body) = http_get(
            &app,
            "/admin/audit?email=admin%40audit-blank.example&user_id=&since=&until=",
            &[("Cookie", &cookie)],
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(
            body.contains(MARKER),
            "email-only submission must list the event"
        );

        let (status, body) = http_get(
            &app,
            "/admin/audit?email=&user_id=%20%20&since=%20&until=",
            &[("Cookie", &cookie)],
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(
            body.contains(MARKER),
            "a blank submission must list the event"
        );
        assert!(
            !body.contains("Clear filters"),
            "blank fields are not filters to clear"
        );
    }

    /// `2026-01-01T08:00:00-05:00` is `13:00:00Z`: the bounds compare
    /// instants, so an event at `12:00:00Z` is before it whatever the offset.
    #[tokio::test]
    async fn test_audit_page_offset_bounds_compare_as_instants() {
        let (app, state) = test_app().await;
        let (cookie, _) = admin_cookie(&state, "audit-offset.example").await;
        seed_noon_event(&state, "audit-offset.example").await;
        let bound = "2026-01-01T08%3A00%3A00-05%3A00";

        let (status, body) = http_get(
            &app,
            &format!("/admin/audit?until={bound}"),
            &[("Cookie", &cookie)],
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(
            body.contains(MARKER),
            "until 13:00Z must include a 12:00Z event"
        );

        let (status, body) = http_get(
            &app,
            &format!("/admin/audit?since={bound}"),
            &[("Cookie", &cookie)],
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(
            !body.contains(MARKER),
            "since 13:00Z must exclude a 12:00Z event"
        );
    }

    /// A bound that is not a timestamp is reported, not applied as a filter.
    #[tokio::test]
    async fn test_audit_page_rejects_invalid_bound() {
        let (app, state) = test_app().await;
        let (cookie, _) = admin_cookie(&state, "audit-invalid.example").await;
        seed_noon_event(&state, "audit-invalid.example").await;

        let (status, body) =
            http_get(&app, "/admin/audit?since=yesterday", &[("Cookie", &cookie)]).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(
            body.contains("is not a valid timestamp"),
            "the page must say which bound is invalid"
        );
        assert!(
            body.contains("yesterday"),
            "the submitted value stays in the form"
        );
        assert!(
            !body.contains(MARKER),
            "no events are listed for an invalid filter"
        );
    }

    #[tokio::test]
    async fn test_audit_page_resolves_duplicate_targets_consistently() {
        // Two member-management events referencing the same target_user_id
        // must both resolve to that target's email.
        let (app, state) = test_app().await;
        let org = create_test_org(&state.store, "example.com").await;
        let admin = create_test_user_in_org(&state.store, "admin@example.com", &org.id, true).await;
        let target =
            create_test_user_in_org(&state.store, "target@example.com", &org.id, false).await;
        let auth_id = create_test_authenticator(&state.store, &admin.id).await;
        let token = create_test_session_with(
            &state,
            TestSessionSpec {
                user_id: &admin.id,
                email: &admin.email,
                auth_id: Some(&auth_id),
                ..Default::default()
            },
        )
        .await;
        let cookie = format!("{}={token}", vouch_common::SESSION_COOKIE_NAME);

        let data = serde_json::json!({ "target_user_id": target.id }).to_string();
        state
            .audit
            .insert_json_event_for_test(
                AuditEventKind::AdminPromote,
                Some(&admin.id),
                Some(&admin.email),
                &data,
            )
            .await
            .unwrap();
        state
            .audit
            .insert_json_event_for_test(
                AuditEventKind::AdminDemote,
                Some(&admin.id),
                Some(&admin.email),
                &data,
            )
            .await
            .unwrap();

        let (status, body) = http_get(&app, "/admin/audit", &[("Cookie", &cookie)]).await;
        assert_eq!(status, StatusCode::OK, "admin should get 200");
        let occurrences = body.matches("target@example.com").count();
        assert_eq!(
            occurrences, 2,
            "both duplicate-target events should resolve to the shared target's email; body:\n{body}"
        );
    }

    // ---- sender-constrained cookie tokens must be rejected on the admin UI ----
    //
    // `get_resource_auth_context` (used by the `AdminPage` extractor) must
    // enforce the `cnf` sender-constraint the same way the strict API path
    // (`extract_session_from_cookie` → `extract_resource_token`) does. A
    // DPoP- or mTLS-bound access token presented via the `__Host-vouch_session`
    // cookie must NOT authenticate the holder to an admin read page without
    // proving possession of the bound key/cert (RFC 9449 §9 / RFC 8705 §3.6).

    /// A DPoP-bound (`cnf.jkt`) access token placed in the session cookie
    /// must be rejected by the admin UI rather than rendering the page.
    #[tokio::test]
    async fn test_audit_page_rejects_dpop_bound_cookie_token() {
        let (app, state) = test_app().await;
        let org = create_test_org(&state.store, "dpop-ui.example").await;
        let admin =
            create_test_user_in_org(&state.store, "dpop-admin@example.com", &org.id, true).await;
        let auth_id = create_test_authenticator(&state.store, &admin.id).await;
        let token = create_test_session_with(
            &state,
            TestSessionSpec {
                user_id: &admin.id,
                email: &admin.email,
                auth_id: Some(&auth_id),
                binding: TestBinding::Dpop("fake-dpop-jkt-thumbprint"),
                ..Default::default()
            },
        )
        .await;
        let cookie = format!("{}={token}", vouch_common::SESSION_COOKIE_NAME);

        let (status, body) = http_get(&app, "/admin/audit", &[("Cookie", &cookie)]).await;
        assert!(
            status == StatusCode::SEE_OTHER || status == StatusCode::TEMPORARY_REDIRECT,
            "DPoP-bound token via cookie should be REJECTED by the admin UI; got {status} body={body}"
        );
    }

    /// An mTLS-bound (`cnf.x5t#S256`) access token placed in the session
    /// cookie must be rejected by the admin UI rather than rendering the page.
    #[tokio::test]
    async fn test_audit_page_rejects_mtls_bound_cookie_token() {
        let (app, state) = test_app().await;
        let org = create_test_org(&state.store, "mtls-ui.example").await;
        let admin =
            create_test_user_in_org(&state.store, "mtls-admin@example.com", &org.id, true).await;
        let auth_id = create_test_authenticator(&state.store, &admin.id).await;
        let token = create_test_session_with(
            &state,
            TestSessionSpec {
                user_id: &admin.id,
                email: &admin.email,
                auth_id: Some(&auth_id),
                binding: TestBinding::Mtls(&mtls::compute_cert_thumbprint(b"missing-cert-der")),
                ..Default::default()
            },
        )
        .await;
        let cookie = format!("{}={token}", vouch_common::SESSION_COOKIE_NAME);

        let (status, body) = http_get(&app, "/admin/audit", &[("Cookie", &cookie)]).await;
        assert!(
            status == StatusCode::SEE_OTHER || status == StatusCode::TEMPORARY_REDIRECT,
            "mTLS-bound token via cookie should be REJECTED by the admin UI; got {status} body={body}"
        );
    }

    // ---- resolve_target_email ----

    #[test]
    fn resolve_target_email_resolves_live_user() {
        let target = db::User {
            id: "target-id".to_string(),
            email: "target@example.com".to_string(),
            name: None,
            org_id: None,
            org_domain: None,
            is_org_admin: false,
            active: true,
            external_id: None,
            github_id: None,
            github_login: None,
            github_refresh_token: None,
        };

        let data =
            serde_json::json!({ "action": "promote", "target_user_id": target.id }).to_string();
        let event = AuditEvent {
            id: "evt-1".to_string(),
            event_type: "admin_promote".to_string(),
            user_id: None,
            email_domain: None,
            email_hmac: None,
            data,
            created_at: Timestamp::now(),
        };

        let mut target_users = HashMap::new();
        target_users.insert(target.id.clone(), target);

        let resolved = resolve_target_email(&target_users, &event);
        assert_eq!(resolved.as_deref(), Some("target@example.com"));
    }

    #[test]
    fn resolve_target_email_falls_back_when_user_is_gone() {
        let target_users = HashMap::new();

        let data =
            serde_json::json!({ "action": "remove_user", "target_user_id": "nonexistent-id" })
                .to_string();
        let event = AuditEvent {
            id: "evt-2".to_string(),
            event_type: "admin_remove_user".to_string(),
            user_id: None,
            email_domain: Some("example.com".to_string()),
            email_hmac: Some("abcdef0123456789".to_string()),
            data,
            created_at: Timestamp::now(),
        };

        let resolved = resolve_target_email(&target_users, &event);
        let resolved = resolved.expect("fallback must produce a display string");
        assert!(
            resolved.contains("example.com"),
            "fallback must surface the org domain; got {resolved}"
        );
        assert!(
            resolved.to_lowercase().contains("removed"),
            "fallback must signal the user is gone; got {resolved}"
        );
    }

    #[test]
    fn resolve_target_email_is_none_for_non_member_event_types() {
        let target_users = HashMap::new();
        let event = AuditEvent {
            id: "evt-3".to_string(),
            event_type: "login_success".to_string(),
            user_id: None,
            email_domain: Some("example.com".to_string()),
            email_hmac: None,
            data: "{}".to_string(),
            created_at: Timestamp::now(),
        };

        assert_eq!(resolve_target_email(&target_users, &event), None);
    }

    // ---- audit_filter_event_types helper tests ----

    #[test]
    fn test_audit_filter_event_types_logins() {
        let types = audit_filter_event_types("logins").unwrap();
        assert!(types.contains(&"login_success".to_string()));
        assert!(types.contains(&"login_failed".to_string()));
    }

    #[test]
    fn test_audit_filter_event_types_promotions() {
        let types = audit_filter_event_types("promotions").unwrap();
        assert!(types.contains(&"admin_promote".to_string()));
    }

    #[test]
    fn test_audit_filter_event_types_unknown() {
        let result = audit_filter_event_types("nonexistent");
        assert!(result.is_none(), "unknown filter name should return None");
    }

    #[test]
    fn test_audit_filter_event_types_all_known_filters() {
        let known = [
            "logins",
            "promotions",
            "demotions",
            "deactivations",
            "removals",
            "revocations",
        ];
        for filter in &known {
            assert!(
                audit_filter_event_types(filter).is_some(),
                "filter '{filter}' should return Some"
            );
        }
    }
}
