// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Additional email domain management — admin UI handlers.
//!
//! Lets an org admin claim secondary email domains for their organization.
//! Each new domain enters a pending state until DNS TXT ownership is
//! verified. Only verified domains participate in login matching.

use crate::AppState;
use crate::db;
use crate::handlers::HasVersion;
use crate::handlers::browser_login::validate_origin;
use crate::handlers::session::{AuthContext, extract_org_admin, get_resource_auth_context};
use crate::impl_template_response;
use crate::infra::dns;
use crate::services::error::ServiceError;
use askama::Template;
use axum::extract::{OriginalUri, Path, Query, State};
use axum::http::{HeaderMap, Method};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use std::sync::Arc;

/// Visual status of a domain row in the admin UI.
///
/// Typed so template comparisons can't drift from the handler's spelling
/// of the status string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainRowStatus {
    /// The organization's primary domain (configured at org creation).
    Primary,
    /// Added but never verified — TXT record has not yet been observed.
    Pending,
    /// DNS TXT ownership confirmed.
    Verified,
    /// Was verified at some point but flipped back to unverified after
    /// consecutive re-verification failures.
    Unverified,
}

/// Display row for an organization's email domains in the template.
pub struct DomainRow {
    pub domain: String,
    /// Unicode rendering of a punycode domain, if applicable. `None` for
    /// pure-ASCII domains. Surfacing both forms makes IDN spoofing visible.
    pub unicode: Option<String>,
    pub status: DomainRowStatus,
    pub verification_token: Option<String>,
    pub added_at: Option<String>,
}

/// Email domains page template.
#[derive(Template)]
#[template(path = "admin/domains.html")]
pub struct AdminDomainsTemplate {
    pub auth: AuthContext,
    pub domains: Vec<DomainRow>,
    pub max_additional: usize,
    pub additional_count: usize,
    pub flash_message: Option<String>,
    pub flash_success: Option<String>,
}

impl_template_response!(AdminDomainsTemplate);

#[derive(Debug, Deserialize)]
pub struct DomainsParams {
    pub error: Option<String>,
    pub ok: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AddDomainForm {
    pub domain: String,
}

const REDIRECT_BASE: &str = "/admin/domains";

fn redirect_error(msg: &str) -> Response {
    let encoded = urlencoding::encode(msg);
    Redirect::to(&format!("{REDIRECT_BASE}?error={encoded}")).into_response()
}

fn redirect_ok(msg: &str) -> Response {
    let encoded = urlencoding::encode(msg);
    Redirect::to(&format!("{REDIRECT_BASE}?ok={encoded}")).into_response()
}

/// Build the rows shown on the admin domains page.
///
/// `row.domain` is interpolated directly into `/admin/domains/{domain}/...`
/// action URLs in the template. That is safe without URL-encoding because
/// every domain on the org has been through `normalize_domain`, which rejects
/// anything outside `[a-z0-9.-]` — no `/`, `?`, `#`, `%`, or whitespace can
/// reach the template.
fn build_rows(org: &db::Organization) -> Vec<DomainRow> {
    let cap = org.additional_domains.len().saturating_add(1);
    let mut rows = Vec::with_capacity(cap);
    rows.push(DomainRow {
        domain: org.domain.clone(),
        unicode: db::unicode_form(&org.domain),
        status: DomainRowStatus::Primary,
        verification_token: None,
        added_at: None,
    });
    for ad in &org.additional_domains {
        use crate::db::documents::organization::AdditionalDomainState;
        let (status, verification_token) = match &ad.state {
            AdditionalDomainState::Verified { .. } => (DomainRowStatus::Verified, None),
            AdditionalDomainState::Unverified { .. } => (
                DomainRowStatus::Unverified,
                Some(ad.verification_token.clone()),
            ),
            AdditionalDomainState::Pending => (
                DomainRowStatus::Pending,
                Some(ad.verification_token.clone()),
            ),
        };
        rows.push(DomainRow {
            domain: ad.domain.clone(),
            unicode: db::unicode_form(&ad.domain),
            status,
            verification_token,
            added_at: Some(ad.added_at.strftime("%Y-%m-%d %H:%M UTC").to_string()),
        });
    }
    rows
}

/// GET /admin/domains — list primary and additional domains.
pub async fn admin_domains_page(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Query(params): Query<DomainsParams>,
) -> Response {
    let auth = get_resource_auth_context(&state, &jar).await;
    if !auth.authenticated {
        return Redirect::to("/enroll/start").into_response();
    }
    if !auth.is_org_admin {
        return Redirect::to("/integrations").into_response();
    }

    let Some(user_id) = auth.user_id.clone() else {
        return Redirect::to("/enroll/start").into_response();
    };

    let org_id = match db::get_user_by_id(&state.store, &user_id).await {
        Ok(Some(user)) => match user.org_id {
            Some(id) => id,
            None => return Redirect::to("/integrations").into_response(),
        },
        _ => return Redirect::to("/integrations").into_response(),
    };

    let org = match db::get_organization(&state.store, &org_id).await {
        Ok(Some(o)) => o,
        Ok(None) => return Redirect::to("/integrations").into_response(),
        Err(e) => {
            tracing::error!(error = %e, org_id, "failed to load organization");
            return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let additional_count = org.additional_domains.len();
    let domains = build_rows(&org);

    AdminDomainsTemplate {
        auth,
        domains,
        max_additional: db::MAX_ADDITIONAL_DOMAINS,
        additional_count,
        flash_message: params.error,
        flash_success: params.ok,
    }
    .into_response()
}

/// POST /admin/domains — add a pending additional domain.
pub async fn admin_add_domain(
    method: Method,
    uri: OriginalUri,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
    axum::Form(form): axum::Form<AddDomainForm>,
) -> Result<Response, ServiceError> {
    validate_origin(&headers, &state.config().base_url)?;
    let (admin, org_id) =
        extract_org_admin(&state, &headers, &jar, method.as_str(), uri.path(), None).await?;

    let result = db::add_additional_domain(&state.store, &org_id, &form.domain, &admin.id).await;
    match result {
        Ok(added) => {
            let data = serde_json::json!({
                "action": "add_org_domain",
                "domain": added.domain,
                "admin_user_id": admin.id,
            });
            if let Err(e) = state
                .audit
                .insert_event(
                    "org_domain_added",
                    Some(&admin.id),
                    Some(&admin.email),
                    &data.to_string(),
                )
                .await
            {
                tracing::warn!(error = %e, "failed to write org_domain_added audit event");
            }
            tracing::info!(
                admin_email = %admin.email,
                org_id = %org_id,
                domain = %added.domain,
                "Added pending additional domain"
            );
            Ok(redirect_ok(&format!(
                "Added {} as pending. Publish the TXT record shown below, then click Verify.",
                added.domain
            )))
        }
        Err(e) => {
            let msg = e.to_string();
            tracing::info!(error = %msg, org_id = %org_id, "Add additional domain rejected");
            Ok(redirect_error(&msg))
        }
    }
}

/// POST /admin/domains/{domain}/verify — fetch DNS TXT and mark verified.
pub async fn admin_verify_domain(
    method: Method,
    uri: OriginalUri,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
    Path(domain): Path<String>,
) -> Result<Response, ServiceError> {
    validate_origin(&headers, &state.config().base_url)?;
    let (admin, org_id) =
        extract_org_admin(&state, &headers, &jar, method.as_str(), uri.path(), None).await?;

    let normalized = match db::normalize_domain(&domain) {
        Ok(d) => d,
        Err(e) => return Ok(redirect_error(&e.to_string())),
    };

    let token = match db::get_verification_token(&state.store, &org_id, &normalized).await? {
        Some(t) => t,
        None => {
            return Ok(redirect_error(
                "Domain is not pending verification on this org.",
            ));
        }
    };

    let txt_ok = match dns::verify_txt_record(&normalized, &token).await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(
                error = %e,
                domain = %normalized,
                "DNS TXT lookup failed during verify"
            );
            return Ok(redirect_error(
                "DNS lookup failed. Check that the TXT record is published and try again.",
            ));
        }
    };

    if !txt_ok {
        return Ok(redirect_error(
            "TXT record not found or token does not match. DNS changes may take a few minutes to propagate.",
        ));
    }

    match db::mark_additional_domain_verified(&state.store, &org_id, &normalized).await {
        Ok(()) => {
            let data = serde_json::json!({
                "action": "verify_org_domain",
                "domain": normalized,
                "admin_user_id": admin.id,
                "method": "dns_txt",
            });
            if let Err(e) = state
                .audit
                .insert_event(
                    "org_domain_verified",
                    Some(&admin.id),
                    Some(&admin.email),
                    &data.to_string(),
                )
                .await
            {
                tracing::warn!(error = %e, "failed to write org_domain_verified audit event");
            }
            tracing::info!(
                admin_email = %admin.email,
                org_id = %org_id,
                domain = %normalized,
                "Verified additional domain"
            );
            Ok(redirect_ok(&format!("Verified {normalized}.")))
        }
        Err(e) => Ok(redirect_error(&e.to_string())),
    }
}

/// POST /admin/domains/{domain}/remove — remove an additional domain.
pub async fn admin_remove_domain(
    method: Method,
    uri: OriginalUri,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
    Path(domain): Path<String>,
) -> Result<Response, ServiceError> {
    validate_origin(&headers, &state.config().base_url)?;
    let (admin, org_id) =
        extract_org_admin(&state, &headers, &jar, method.as_str(), uri.path(), None).await?;

    let normalized = match db::normalize_domain(&domain) {
        Ok(d) => d,
        Err(e) => return Ok(redirect_error(&e.to_string())),
    };

    match db::remove_additional_domain(&state.store, &org_id, &normalized).await {
        Ok(Some(summary)) => {
            let revoked = summary.revoked_user_count;
            let errored = summary.revocation_errored;
            let data = serde_json::json!({
                "action": "remove_org_domain",
                "domain": normalized,
                "admin_user_id": admin.id,
                "revoked_user_session_count": revoked,
                "revocation_errored": errored,
            });
            if let Err(e) = state
                .audit
                .insert_event(
                    "org_domain_removed",
                    Some(&admin.id),
                    Some(&admin.email),
                    &data.to_string(),
                )
                .await
            {
                tracing::warn!(error = %e, "failed to write org_domain_removed audit event");
            }
            tracing::info!(
                admin_email = %admin.email,
                org_id = %org_id,
                domain = %normalized,
                revoked_user_count = revoked,
                revocation_errored = errored,
                "Removed additional domain"
            );
            let msg = if errored {
                format!(
                    "Removed {normalized}, but session revocation for matching users failed; check server logs and revoke manually."
                )
            } else if revoked == 0 {
                format!("Removed {normalized}. No matching users had active sessions to revoke.")
            } else if revoked == 1 {
                format!(
                    "Removed {normalized}. Revoked sessions for 1 user; their org membership is unchanged."
                )
            } else {
                format!(
                    "Removed {normalized}. Revoked sessions for {revoked} users; org membership is unchanged."
                )
            };
            Ok(redirect_ok(&msg))
        }
        Ok(None) => Ok(redirect_error("Domain not found on this organization.")),
        Err(e) => Ok(redirect_error(&e.to_string())),
    }
}
