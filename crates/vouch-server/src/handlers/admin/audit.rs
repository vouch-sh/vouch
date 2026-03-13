// SPDX-License-Identifier: BUSL-1.1
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
use std::sync::Arc;

use super::format_timestamp;
use crate::handlers::session::{AuthContext, get_resource_auth_context};

/// Page size for the audit log.
const AUDIT_PAGE_SIZE: u64 = 50;

/// Query parameters for audit page (pagination + optional semantic filter).
#[derive(Debug, Deserialize)]
pub struct AuditParams {
    pub after: Option<String>,
    pub filter: Option<String>,
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
pub struct AuditRow {
    pub id: String,
    pub event_type: String,
    pub email_domain: Option<String>,
    pub data: String,
    pub created_at: String,
    /// Pre-formatted IP cell text, e.g. "🇺🇸 8.8.8.8" or "-".
    pub ip_display: String,
    /// Tooltip for the IP cell with country code and ASN.
    pub ip_title: String,
}

/// Audit log page template.
#[derive(Template)]
#[template(path = "admin/audit.html")]
pub struct AdminAuditTemplate {
    pub auth: AuthContext,
    pub events: Vec<AuditRow>,
    pub has_more: bool,
    pub next_cursor: Option<String>,
    pub filter: Option<String>,
}

impl_template_response!(AdminAuditTemplate);

/// GET /admin/audit — Audit log page.
pub async fn admin_audit_page(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Query(params): Query<AuditParams>,
) -> Response {
    let auth = get_resource_auth_context(&state, &jar).await;

    if !auth.authenticated {
        return Redirect::to("/enroll/start").into_response();
    }
    if !auth.is_org_admin {
        return Redirect::to("/integrations").into_response();
    }

    let user_id = match auth.user_id {
        Some(ref id) => id.clone(),
        None => return Redirect::to("/enroll/start").into_response(),
    };

    // Get the org domain for filtering audit events
    let org_domain = match db::get_user_by_id(&state.store, &user_id).await {
        Ok(Some(user)) => match user.org_id {
            Some(ref org_id) => db::get_organization_domain(&state.store, org_id)
                .await
                .ok()
                .flatten(),
            None => None,
        },
        _ => None,
    };

    let org_domain = match org_domain {
        Some(d) => d,
        None => return Redirect::to("/integrations").into_response(),
    };

    let event_types = params.filter.as_deref().and_then(audit_filter_event_types);

    let filter = AuditEventFilter {
        email_domain: Some(org_domain),
        event_types,
        before_id: params.after.clone(),
        ..AuditEventFilter::default()
    };

    let (audit_events, has_more): (Vec<crate::db::audit::AuditEvent>, bool) = match state
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

    let events: Vec<AuditRow> = audit_events
        .iter()
        .map(|e| {
            let geo = GeoFields::from_json(&e.data);
            let created_at = e
                .created_at
                .parse::<Timestamp>()
                .map(|ts| format_timestamp(&ts))
                .unwrap_or_else(|_| e.created_at.clone());
            AuditRow {
                id: e.id.clone(),
                event_type: e.event_type.clone(),
                email_domain: e.email_domain.clone(),
                data: e.data.clone(),
                created_at,
                ip_display: geo.ip_display(),
                ip_title: geo.ip_title(),
            }
        })
        .collect();

    let next_cursor = if has_more {
        events.last().map(|e| e.id.clone())
    } else {
        None
    };

    AdminAuditTemplate {
        auth,
        events,
        has_more,
        next_cursor,
        filter: params.filter,
    }
    .into_response()
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
            .and_then(crate::geo::country_flag)
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
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

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
}
