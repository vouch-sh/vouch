// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Additional email domain management — admin UI handlers.
//!
//! Lets an org admin claim secondary email domains for their organization.
//! Each new domain enters a pending state until DNS TXT ownership is
//! verified. Only verified domains participate in login matching.

use crate::AppState;
use crate::db;
use crate::error::ServiceError;
use crate::filters;
use crate::handlers::admin::flash;
use crate::handlers::browser_login::validate_origin;
use crate::handlers::session::{AuthContext, extract_org_admin, get_resource_auth_context};
use crate::impl_template_response;
use crate::infra::dns;
use crate::infra::i18n::Tr;
use askama::Template;
use axum::extract::{OriginalUri, Path, State};
use axum::http::{HeaderMap, Method};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use jiff::Timestamp;
use serde::Deserialize;
use std::sync::Arc;

/// Visual status of a domain row in the admin UI.
///
/// Typed so template comparisons can't drift from the handler's spelling
/// of the status string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DomainRowStatus {
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
pub(crate) struct DomainRow {
    pub domain: String,
    /// Unicode rendering of a punycode domain, if applicable. `None` for
    /// pure-ASCII domains. Surfacing both forms makes IDN spoofing visible.
    pub unicode: Option<String>,
    pub status: DomainRowStatus,
    pub verification_token: Option<String>,
    /// When the domain was added — `org.created_at` for the primary domain,
    /// `ad.added_at` for additional domains. Rendered client-side in the
    /// viewer's locale and timezone (`humandatetime` is the no-JS fallback).
    pub added_at: Timestamp,
    /// Email of the admin who added this domain. `None` for the primary
    /// (provisioned at org creation).
    pub added_by: Option<String>,
}

/// Email domains page template.
#[derive(Template)]
#[template(path = "admin/domains.html")]
pub(crate) struct AdminDomainsTemplate {
    pub auth: AuthContext,
    pub domains: Vec<DomainRow>,
    pub max_additional: usize,
    pub additional_count: usize,
    pub flash_message: Option<String>,
    pub flash_success: Option<String>,
}

impl_template_response!(AdminDomainsTemplate);

#[derive(Debug, Deserialize)]
pub(crate) struct AddDomainForm {
    pub domain: String,
}

const REDIRECT_BASE: &str = "/admin/domains";

fn redirect_error(jar: CookieJar, msg: impl Into<String>) -> Response {
    (flash::set_err(jar, msg), Redirect::to(REDIRECT_BASE)).into_response()
}

fn redirect_ok(jar: CookieJar, msg: impl Into<String>) -> Response {
    (flash::set_ok(jar, msg), Redirect::to(REDIRECT_BASE)).into_response()
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
        added_at: org.created_at,
        added_by: None,
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
            added_at: ad.added_at,
            added_by: Some(ad.added_by_email.clone()),
        });
    }
    rows
}

/// GET /admin/domains — list primary and additional domains.
pub(crate) async fn admin_domains_page(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
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

    // Consume any flash messages set by a prior POST → redirect, then expire
    // the cookies in the response so a refresh doesn't re-show them.
    let messages = flash::read(&jar);
    let jar = flash::clear(jar);

    let body = AdminDomainsTemplate {
        auth,
        domains,
        max_additional: db::MAX_ADDITIONAL_DOMAINS,
        additional_count,
        flash_message: messages.err,
        flash_success: messages.ok,
    };
    (jar, body).into_response()
}

/// POST /admin/domains — add a pending additional domain.
pub(crate) async fn admin_add_domain(
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

    let result =
        db::add_additional_domain(&state.store, &org_id, &form.domain, &admin.id, &admin.email)
            .await;
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
                    db::AuditEventKind::OrgDomainAdded,
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
            Ok(redirect_ok(
                jar,
                Tr::new("admin-domains-flash-add-pending")
                    .arg("domain", added.domain.as_str())
                    .to_string(),
            ))
        }
        Err(e) => {
            let flash = match &e {
                db::AddDomainError::MaxDomains => {
                    Tr::new("admin-domains-error-max-domains").to_string()
                }
                db::AddDomainError::PrimaryDomain => {
                    Tr::new("admin-domains-error-primary-domain").to_string()
                }
                db::AddDomainError::AlreadyAttached => {
                    Tr::new("admin-domains-error-already-attached").to_string()
                }
                db::AddDomainError::ClaimedByOtherOrg => {
                    Tr::new("admin-domains-error-claimed-by-other-org").to_string()
                }
                db::AddDomainError::PendingOtherOrg => {
                    Tr::new("admin-domains-error-pending-other-org").to_string()
                }
                db::AddDomainError::HeldByOtherOrg => {
                    Tr::new("admin-domains-error-held-other-org").to_string()
                }
                db::AddDomainError::InvalidDomain(v) => match v {
                    db::DomainValidationError::Empty => {
                        Tr::new("admin-domains-invalid-empty").to_string()
                    }
                    db::DomainValidationError::NotAscii => {
                        Tr::new("admin-domains-invalid-ascii").to_string()
                    }
                    db::DomainValidationError::IpAddress => {
                        Tr::new("admin-domains-invalid-ip").to_string()
                    }
                    db::DomainValidationError::TooLong => {
                        Tr::new("admin-domains-invalid-too-long").to_string()
                    }
                    db::DomainValidationError::NoDot => {
                        Tr::new("admin-domains-invalid-no-dot").to_string()
                    }
                    db::DomainValidationError::LeadingOrTrailingDot => {
                        Tr::new("admin-domains-invalid-dot-edge").to_string()
                    }
                    db::DomainValidationError::EmptyLabel => {
                        Tr::new("admin-domains-invalid-empty-label").to_string()
                    }
                    db::DomainValidationError::LabelTooLong => {
                        Tr::new("admin-domains-invalid-label-too-long").to_string()
                    }
                    db::DomainValidationError::LabelHyphenEdge => {
                        Tr::new("admin-domains-invalid-label-hyphen-edge").to_string()
                    }
                    db::DomainValidationError::LabelInvalidChar => {
                        Tr::new("admin-domains-invalid-label-chars").to_string()
                    }
                    db::DomainValidationError::ReservedTld(tld) => {
                        Tr::new("admin-domains-invalid-reserved-tld")
                            .arg("tld", tld.as_str())
                            .to_string()
                    }
                },
                db::AddDomainError::OccConflict | db::AddDomainError::Other(_) => {
                    tracing::error!(
                        error = %e,
                        org_id = %org_id,
                        domain = %form.domain,
                        "add_additional_domain failed"
                    );
                    return Ok(redirect_error(
                        jar,
                        Tr::new("admin-domains-error-internal").to_string(),
                    ));
                }
            };
            tracing::info!(error = %e, org_id = %org_id, "Add additional domain rejected");
            Ok(redirect_error(jar, flash))
        }
    }
}

/// POST /admin/domains/{domain}/verify — fetch DNS TXT and mark verified.
pub(crate) async fn admin_verify_domain(
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
        Err(e) => {
            tracing::error!(error = %e, domain = %domain, "domain normalization failed in verify");
            return Ok(redirect_error(
                jar,
                Tr::new("admin-domains-error-internal").to_string(),
            ));
        }
    };

    let token = match db::get_verification_token(&state.store, &org_id, &normalized).await? {
        Some(t) => t,
        None => {
            return Ok(redirect_error(
                jar,
                Tr::new("admin-domains-error-not-pending").to_string(),
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
                jar,
                Tr::new("admin-domains-error-dns-lookup").to_string(),
            ));
        }
    };

    if !txt_ok {
        return Ok(redirect_error(
            jar,
            Tr::new("admin-domains-error-txt-not-found").to_string(),
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
                    db::AuditEventKind::OrgDomainVerified,
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
            Ok(redirect_ok(
                jar,
                Tr::new("admin-domains-flash-verified")
                    .arg("domain", normalized.as_str())
                    .to_string(),
            ))
        }
        Err(db::MarkVerifiedError::ClaimedByOtherOrg) => Ok(redirect_error(
            jar,
            Tr::new("admin-domains-error-verified-by-other-org").to_string(),
        )),
        Err(e) => {
            tracing::error!(
                error = %e,
                org_id = %org_id,
                domain = %normalized,
                "mark_additional_domain_verified failed"
            );
            Ok(redirect_error(
                jar,
                Tr::new("admin-domains-error-internal").to_string(),
            ))
        }
    }
}

/// POST /admin/domains/{domain}/remove — remove an additional domain.
pub(crate) async fn admin_remove_domain(
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
        Err(e) => {
            tracing::error!(error = %e, domain = %domain, "domain normalization failed in remove");
            return Ok(redirect_error(
                jar,
                Tr::new("admin-domains-error-internal").to_string(),
            ));
        }
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
                "released_subdomain": summary.released_subdomain,
            });
            if let Err(e) = state
                .audit
                .insert_event(
                    db::AuditEventKind::OrgDomainRemoved,
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
            let base = if errored {
                Tr::new("admin-domains-flash-removed-revoke-error")
                    .arg("domain", normalized.as_str())
                    .to_string()
            } else {
                Tr::new("admin-domains-flash-removed")
                    .arg("domain", normalized.as_str())
                    .arg("revoked", i64::try_from(revoked).unwrap_or(i64::MAX))
                    .to_string()
            };
            let msg = if let Some(label) = &summary.released_subdomain {
                format!(
                    "{base} {}",
                    Tr::new("admin-domains-subdomain-auto-released").arg("label", label.as_str())
                )
            } else {
                base
            };
            Ok(redirect_ok(jar, msg))
        }
        Ok(None) => Ok(redirect_error(
            jar,
            Tr::new("admin-domains-error-not-found").to_string(),
        )),
        Err(e) => {
            tracing::error!(
                error = %e,
                org_id = %org_id,
                domain = %normalized,
                "remove_additional_domain failed"
            );
            Ok(redirect_error(
                jar,
                Tr::new("admin-domains-error-internal").to_string(),
            ))
        }
    }
}
