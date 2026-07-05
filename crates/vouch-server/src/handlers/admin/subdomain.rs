// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Org issuer-subdomain management — JSON API.
//!
//! Lets an org admin claim a subdomain of the primary host as the org's
//! OIDC issuer for AWS workload identity federation
//! (`acme` → `https://acme.us.vouch.sh`). The label must match the first
//! label of one of the org's verified domains; see
//! [`crate::db::claim_subdomain`] for the invariants.

use crate::AppState;
use crate::db;
use crate::db::SubdomainClaimError;
use crate::services::error::ServiceError;
use axum::Json;
use axum::extract::{OriginalUri, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use std::sync::Arc;

use crate::handlers::session::extract_org_admin;

/// Response describing the org's issuer-subdomain state.
#[derive(Debug, serde::Serialize)]
pub(crate) struct OrgSubdomainResponse {
    /// The claimed label, if any (e.g. `acme`).
    pub subdomain: Option<String>,
    /// The resulting issuer URL, if a label is claimed
    /// (e.g. `https://acme.us.vouch.sh`).
    pub issuer: Option<String>,
    /// Labels this org is currently eligible to claim, derived from its
    /// verified domains.
    pub eligible_labels: Vec<String>,
}

/// Request to claim an issuer subdomain.
#[derive(Debug, Deserialize)]
pub(crate) struct ClaimSubdomainRequest {
    pub label: String,
}

/// Response after releasing an issuer subdomain.
#[derive(Debug, serde::Serialize)]
pub(crate) struct ReleaseSubdomainResponse {
    pub released: String,
    /// Operator follow-up: IAM OIDC providers for the released issuer host
    /// should be deleted, since the label may eventually be claimed by
    /// another organization.
    pub warning: String,
}

fn map_claim_error(e: SubdomainClaimError) -> ServiceError {
    match e {
        SubdomainClaimError::InvalidLabel(msg) => {
            ServiceError::api(StatusCode::BAD_REQUEST, "invalid_label", msg)
        }
        SubdomainClaimError::NotEligible => ServiceError::api(
            StatusCode::BAD_REQUEST,
            "label_not_eligible",
            "Label must match the first label of one of the organization's verified domains",
        ),
        SubdomainClaimError::AlreadyClaimed(existing) => ServiceError::api(
            StatusCode::CONFLICT,
            "subdomain_already_claimed",
            format!("Organization already has subdomain '{existing}'; release it first"),
        ),
        SubdomainClaimError::Conflict => ServiceError::api(
            StatusCode::CONFLICT,
            "subdomain_conflict",
            "Subdomain is already claimed by another organization",
        ),
        SubdomainClaimError::RecentlyReleased => ServiceError::api(
            StatusCode::CONFLICT,
            "subdomain_recently_released",
            "Subdomain was recently released by another organization and cannot be claimed yet",
        ),
        SubdomainClaimError::Other(e) => {
            tracing::error!("subdomain claim failed: {e}");
            ServiceError::api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Internal database error",
            )
        }
    }
}

/// Get the org's issuer-subdomain state.
/// GET /api/v1/org/subdomain
pub(crate) async fn get_org_subdomain(
    method: Method,
    uri: OriginalUri,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
) -> Result<Json<OrgSubdomainResponse>, ServiceError> {
    let (_user, org_id) =
        extract_org_admin(&state, &headers, &jar, method.as_str(), uri.path(), None).await?;

    let org = db::get_organization(&state.store, &org_id)
        .await?
        .ok_or_else(|| {
            ServiceError::api(StatusCode::NOT_FOUND, "not_found", "Organization not found")
        })?;

    let config = state.config();
    let issuer = org
        .subdomain
        .as_deref()
        .and_then(|label| config.org_issuer(label));

    Ok(Json(OrgSubdomainResponse {
        eligible_labels: db::eligible_subdomain_labels(&org.domain, &org.additional_domains),
        subdomain: org.subdomain,
        issuer,
    }))
}

/// Claim an issuer subdomain for the org.
/// PUT /api/v1/org/subdomain
pub(crate) async fn claim_org_subdomain(
    method: Method,
    uri: OriginalUri,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(req): Json<ClaimSubdomainRequest>,
) -> Result<Json<OrgSubdomainResponse>, ServiceError> {
    // Validate the label shape before auth to fail fast on bad requests.
    if let Err(e) = db::validate_subdomain_label(&req.label) {
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_label",
            e.to_string(),
        ));
    }

    let (user, org_id) =
        extract_org_admin(&state, &headers, &jar, method.as_str(), uri.path(), None).await?;

    let label = db::claim_subdomain(&state.store, &org_id, &req.label)
        .await
        .map_err(map_claim_error)?;

    let config = state.config();
    let issuer = config.org_issuer(&label);

    let data = serde_json::json!({
        "action": "claim_subdomain",
        "label": label,
        "issuer": issuer,
        "admin_user_id": user.id,
    });
    if let Err(e) = state
        .audit
        .insert_event(
            "org_subdomain_claimed",
            Some(&user.id),
            Some(&user.email),
            &data.to_string(),
        )
        .await
    {
        tracing::warn!(error = %e, "failed to write org_subdomain_claimed audit event");
    }

    tracing::info!("Org {org_id} claimed issuer subdomain '{label}'");

    let org = db::get_organization(&state.store, &org_id).await?;
    let eligible_labels = org
        .map(|o| db::eligible_subdomain_labels(&o.domain, &o.additional_domains))
        .unwrap_or_default();

    Ok(Json(OrgSubdomainResponse {
        subdomain: Some(label),
        issuer,
        eligible_labels,
    }))
}

/// Release the org's issuer subdomain.
/// DELETE /api/v1/org/subdomain
pub(crate) async fn release_org_subdomain(
    method: Method,
    uri: OriginalUri,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
) -> Result<Json<ReleaseSubdomainResponse>, ServiceError> {
    let (user, org_id) =
        extract_org_admin(&state, &headers, &jar, method.as_str(), uri.path(), None).await?;

    let released = db::release_subdomain(&state.store, &org_id)
        .await?
        .ok_or_else(|| {
            ServiceError::api(
                StatusCode::NOT_FOUND,
                "not_found",
                "Organization has no issuer subdomain",
            )
        })?;

    let data = serde_json::json!({
        "action": "release_subdomain",
        "label": released,
        "admin_user_id": user.id,
    });
    if let Err(e) = state
        .audit
        .insert_event(
            "org_subdomain_released",
            Some(&user.id),
            Some(&user.email),
            &data.to_string(),
        )
        .await
    {
        tracing::warn!(error = %e, "failed to write org_subdomain_released audit event");
    }

    tracing::info!("Org {org_id} released issuer subdomain '{released}'");

    Ok(Json(ReleaseSubdomainResponse {
        warning: format!(
            "Delete any AWS IAM OIDC identity providers for the released issuer host \
             '{released}'; the label may eventually be claimed by another organization."
        ),
        released,
    }))
}
