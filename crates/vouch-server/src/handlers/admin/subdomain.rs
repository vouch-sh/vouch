// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Org issuer-subdomain management — admin UI handlers.
//!
//! Lets an org admin claim a subdomain of the primary host as the org's
//! OIDC issuer for AWS workload identity federation
//! (`acme` → `https://acme.us.vouch.sh`). The label must match the first
//! label of one of the org's verified domains; see
//! [`crate::db::claim_subdomain`] for the invariants.

use crate::AppState;
use crate::db;
use crate::db::{SubdomainClaimError, SubdomainLabelError};
use crate::handlers::admin::flash;
use crate::handlers::browser_login::validate_origin;
use crate::handlers::session::{AuthContext, extract_org_admin, get_resource_auth_context};
use crate::impl_template_response;
use crate::infra::i18n::Tr;
use crate::services::error::ServiceError;
use askama::Template;
use axum::extract::{OriginalUri, State};
use axum::http::{HeaderMap, Method};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use std::sync::Arc;

/// Issuer subdomain page template.
#[derive(Template)]
#[template(path = "admin/subdomain.html")]
pub(crate) struct AdminSubdomainTemplate {
    pub auth: AuthContext,
    /// The claimed label, if any (e.g. `acme`).
    pub subdomain: Option<String>,
    /// The issuer URL for the claimed label (e.g. `https://acme.us.vouch.sh`).
    pub issuer: Option<String>,
    /// The discovery URL AWS IAM consumes for the claimed label.
    pub discovery_url: Option<String>,
    /// Labels this org may claim, derived from its verified domains.
    pub eligible_labels: Vec<String>,
    /// First labels of verified domains that are reserved or invalid and
    /// therefore not claimable — shown so an empty eligible list doesn't
    /// read as "no verified domains".
    pub ineligible_candidates: Vec<String>,
    pub flash_message: Option<String>,
    pub flash_success: Option<String>,
}

impl_template_response!(AdminSubdomainTemplate);

#[derive(Debug, Deserialize)]
pub(crate) struct ClaimSubdomainForm {
    pub label: String,
}

const REDIRECT_BASE: &str = "/admin/subdomain";

fn redirect_error(jar: CookieJar, msg: impl Into<String>) -> Response {
    (flash::set_err(jar, msg), Redirect::to(REDIRECT_BASE)).into_response()
}

fn redirect_ok(jar: CookieJar, msg: impl Into<String>) -> Response {
    (flash::set_ok(jar, msg), Redirect::to(REDIRECT_BASE)).into_response()
}

/// Render a claim failure as a localized flash message.
fn claim_error_message(e: &SubdomainClaimError) -> String {
    match e {
        SubdomainClaimError::InvalidLabel(reason) => match reason {
            SubdomainLabelError::Empty => {
                Tr::new("admin-subdomain-error-invalid-empty").to_string()
            }
            SubdomainLabelError::NotAscii => {
                Tr::new("admin-subdomain-error-invalid-ascii").to_string()
            }
            SubdomainLabelError::TooLong => {
                Tr::new("admin-subdomain-error-invalid-length").to_string()
            }
            SubdomainLabelError::ContainsDot => {
                Tr::new("admin-subdomain-error-invalid-dot").to_string()
            }
            SubdomainLabelError::HyphenEdge => {
                Tr::new("admin-subdomain-error-invalid-hyphen").to_string()
            }
            SubdomainLabelError::InvalidChar => {
                Tr::new("admin-subdomain-error-invalid-charset").to_string()
            }
            SubdomainLabelError::NoLetter => {
                Tr::new("admin-subdomain-error-invalid-letter").to_string()
            }
            SubdomainLabelError::Reserved(label) => {
                Tr::new("admin-subdomain-error-invalid-reserved")
                    .arg("label", label.as_str())
                    .to_string()
            }
        },
        SubdomainClaimError::NotEligible => {
            Tr::new("admin-subdomain-error-not-eligible").to_string()
        }
        SubdomainClaimError::AlreadyClaimed(existing) => {
            Tr::new("admin-subdomain-error-already-claimed")
                .arg("existing", existing.as_str())
                .to_string()
        }
        SubdomainClaimError::Conflict => Tr::new("admin-subdomain-error-conflict").to_string(),
        SubdomainClaimError::RecentlyReleased => {
            Tr::new("admin-subdomain-error-recently-released").to_string()
        }
        SubdomainClaimError::OccConflict => {
            tracing::error!("subdomain claim retry budget exhausted");
            Tr::new("admin-subdomain-error-internal").to_string()
        }
        SubdomainClaimError::Other(e) => {
            tracing::error!("subdomain claim failed: {e}");
            Tr::new("admin-subdomain-error-internal").to_string()
        }
    }
}

/// GET /admin/subdomain — show the org's issuer-subdomain state.
pub(crate) async fn admin_subdomain_page(
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

    let config = state.config();
    let issuer = org
        .subdomain
        .as_deref()
        .and_then(|label| config.org_issuer(label));
    let discovery_url = issuer
        .as_deref()
        .map(|iss| format!("{iss}/.well-known/openid-configuration"));

    let messages = flash::read(&jar);
    let jar = flash::clear(jar);

    let body = AdminSubdomainTemplate {
        auth,
        eligible_labels: db::eligible_subdomain_labels(&org.domain, &org.additional_domains),
        ineligible_candidates: db::ineligible_subdomain_candidates(
            &org.domain,
            &org.additional_domains,
        ),
        subdomain: org.subdomain,
        issuer,
        discovery_url,
        flash_message: messages.err,
        flash_success: messages.ok,
    };
    (jar, body).into_response()
}

/// POST /admin/subdomain — claim an issuer subdomain for the org.
pub(crate) async fn admin_claim_subdomain(
    method: Method,
    uri: OriginalUri,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
    axum::Form(form): axum::Form<ClaimSubdomainForm>,
) -> Result<Response, ServiceError> {
    validate_origin(&headers, &state.config().base_url)?;
    let (admin, org_id) =
        extract_org_admin(&state, &headers, &jar, method.as_str(), uri.path(), None).await?;

    let label = match db::claim_subdomain(&state.store, &org_id, &form.label).await {
        Ok(label) => label,
        Err(e) => {
            let msg = claim_error_message(&e);
            tracing::info!(error = %e, org_id = %org_id, "Subdomain claim rejected");
            return Ok(redirect_error(jar, msg));
        }
    };

    let issuer = state.config().org_issuer(&label);

    let data = serde_json::json!({
        "action": "claim_subdomain",
        "label": label,
        "issuer": issuer,
        "admin_user_id": admin.id,
    });
    if let Err(e) = state
        .audit
        .insert_event(
            "org_subdomain_claimed",
            Some(&admin.id),
            Some(&admin.email),
            &data.to_string(),
        )
        .await
    {
        tracing::warn!(error = %e, "failed to write org_subdomain_claimed audit event");
    }

    tracing::info!(
        admin_email = %admin.email,
        org_id = %org_id,
        label = %label,
        "Claimed issuer subdomain"
    );

    Ok(redirect_ok(
        jar,
        match issuer {
            Some(iss) => Tr::new("admin-subdomain-flash-claimed")
                .arg("label", label.as_str())
                .arg("issuer", iss.as_str())
                .to_string(),
            None => Tr::new("admin-subdomain-flash-claimed-plain")
                .arg("label", label.as_str())
                .to_string(),
        },
    ))
}

/// POST /admin/subdomain/release — release the org's issuer subdomain.
pub(crate) async fn admin_release_subdomain(
    method: Method,
    uri: OriginalUri,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
) -> Result<Response, ServiceError> {
    validate_origin(&headers, &state.config().base_url)?;
    let (admin, org_id) =
        extract_org_admin(&state, &headers, &jar, method.as_str(), uri.path(), None).await?;

    let released = match db::release_subdomain(&state.store, &org_id).await {
        Ok(Some(label)) => label,
        Ok(None) => {
            return Ok(redirect_error(
                jar,
                Tr::new("admin-subdomain-error-nothing-to-release").to_string(),
            ));
        }
        Err(e) => {
            tracing::error!(error = %e, org_id = %org_id, "Subdomain release failed");
            return Ok(redirect_error(
                jar,
                Tr::new("admin-subdomain-error-internal").to_string(),
            ));
        }
    };

    let data = serde_json::json!({
        "action": "release_subdomain",
        "label": released,
        "admin_user_id": admin.id,
    });
    if let Err(e) = state
        .audit
        .insert_event(
            "org_subdomain_released",
            Some(&admin.id),
            Some(&admin.email),
            &data.to_string(),
        )
        .await
    {
        tracing::warn!(error = %e, "failed to write org_subdomain_released audit event");
    }

    tracing::info!(
        admin_email = %admin.email,
        org_id = %org_id,
        label = %released,
        "Released issuer subdomain"
    );

    Ok(redirect_ok(
        jar,
        Tr::new("admin-subdomain-flash-released")
            .arg("label", released.as_str())
            .to_string(),
    ))
}
