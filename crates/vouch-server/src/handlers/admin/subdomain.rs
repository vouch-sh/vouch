// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Org issuer-subdomain management — admin UI handlers.
//!
//! Lets an org admin claim a subdomain of the primary host as the org's
//! OIDC issuer for AWS workload identity federation
//! (`acme-com` → `https://acme-com.us.vouch.sh`). The label is derived from
//! the registrable apex of one of the org's verified domains; see
//! [`crate::db::claim_subdomain`] for the invariants. Claiming requires a
//! document store that encrypts at rest (per-org signing keys are never
//! persisted in plaintext).

use crate::AppState;
use crate::db;
use crate::db::{SubdomainClaimError, SubdomainLabelError};
use crate::handlers::admin::flash;
use crate::handlers::browser_login::validate_origin;
use crate::handlers::session::{AuthContext, extract_org_admin, get_resource_auth_context};
use crate::impl_template_response;
use crate::infra::i18n::Tr;
use crate::services::error::ServiceError;
use crate::services::oidc::{emergency_rotate_org_keys, stage_org_key_rotation};
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
    /// The claimed label, if any (e.g. `acme-com`).
    pub subdomain: Option<String>,
    /// The issuer URL for the claimed label (e.g. `https://acme-com.us.vouch.sh`).
    pub issuer: Option<String>,
    /// The discovery URL AWS IAM consumes for the claimed label.
    pub discovery_url: Option<String>,
    /// Labels this org may claim, derived from its verified domains.
    pub eligible_labels: Vec<String>,
    /// Apex-derived labels of verified domains that are not claimable (e.g.
    /// longer than a DNS label allows) — shown so an empty eligible list
    /// doesn't read as "no verified domains".
    pub ineligible_candidates: Vec<String>,
    /// Whether the document store encrypts at rest. When it doesn't, the
    /// claim form is replaced by an explanation — per-org signing keys are
    /// never persisted in plaintext, so subdomains can't be claimed.
    pub store_encrypted: bool,
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
        store_encrypted: state.store.is_encrypted(),
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

    // Per-org signing keys are never persisted in plaintext, and the startup
    // guard refuses to boot an unencrypted server with claims — reject here
    // so a claim can't create that state at runtime.
    if !state.store.is_encrypted() {
        return Ok(redirect_error(
            jar,
            Tr::new("admin-subdomain-error-requires-encryption").to_string(),
        ));
    }

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

/// POST /admin/subdomain/rotate — stage a graceful signing-key rotation.
///
/// Generates ES256 and RS256 successors with
/// `activate_at = now + PUBLISH_AHEAD_HOURS (24h)`, writes them to the
/// next-slot, and publishes them in the org JWKS immediately. The cleanup loop
/// activates the new keys after 24h and retires the old keys after
/// `max(session_hours, 8h) + 2h`.
pub(crate) async fn admin_rotate_keys(
    method: Method,
    uri: OriginalUri,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
) -> Result<Response, ServiceError> {
    validate_origin(&headers, &state.config().base_url)?;
    let (admin, org_id) =
        extract_org_admin(&state, &headers, &jar, method.as_str(), uri.path(), None).await?;

    if org_id.is_empty() {
        // Empty org_id means the session has no org association — an auth/session
        // issue, not a subdomain-state issue. Use the generic internal-error key so
        // the message isn't misleading (L3 i18n refinement).
        return Ok(redirect_error(
            jar,
            Tr::new("admin-subdomain-error-internal").to_string(),
        ));
    }

    // Guard: rotating keys for an org with no claimed subdomain would write
    // orphan Pending docs that can never activate (I4 / L3).
    let org = match db::get_organization(&state.store, &org_id).await {
        Ok(Some(o)) => o,
        Ok(None) | Err(_) => {
            return Ok(redirect_error(
                jar,
                Tr::new("admin-subdomain-error-internal").to_string(),
            ));
        }
    };
    if org.subdomain.is_none() {
        return Ok(redirect_error(
            jar,
            Tr::new("admin-subdomain-error-no-subdomain").to_string(),
        ));
    }

    let newly_staged =
        match stage_org_key_rotation(&state.store, &org_id, &state.org_keys_cache).await {
            Ok(staged) => staged,
            Err(e) => {
                tracing::error!(error = %e, org_id, "Org issuer key rotation staging failed");
                return Ok(redirect_error(
                    jar,
                    Tr::new("admin-subdomain-error-internal").to_string(),
                ));
            }
        };

    if newly_staged {
        // Only emit the audit event when keys were actually staged (C6).
        let data = serde_json::json!({
            "action": "stage_org_key_rotation",
            "org_id": org_id,
            "admin_user_id": admin.id,
        });
        if let Err(e) = state
            .audit
            .insert_event(
                "org_issuer_key_rotation_staged",
                Some(&admin.id),
                Some(&admin.email),
                &data.to_string(),
            )
            .await
        {
            tracing::warn!(error = %e, "failed to write org_issuer_key_rotation_staged audit event");
        }
        tracing::info!(
            admin_email = %admin.email,
            org_id = %org_id,
            "Staged org issuer key rotation"
        );
        Ok(redirect_ok(
            jar,
            Tr::new("admin-subdomain-flash-rotation-staged").to_string(),
        ))
    } else {
        // Both next-slots were already occupied — rotation was already in progress.
        tracing::info!(
            admin_email = %admin.email,
            org_id = %org_id,
            "Org issuer key rotation already in progress; no-op"
        );
        Ok(redirect_ok(
            jar,
            Tr::new("admin-subdomain-flash-rotation-already-staged").to_string(),
        ))
    }
}

/// POST /admin/subdomain/emergency-rotate — emergency signing-key rotation.
///
/// Immediately replaces both ES256 and RS256 keys. Outstanding tokens signed by
/// the old keys will fail verification until relying parties refetch the JWKS
/// (cross-instance ≤ 60s, downstream ≤ 1h). Use only when a key compromise is
/// suspected. Intended for compromised key material — outstanding token breakage
/// is accepted.
pub(crate) async fn admin_emergency_rotate_keys(
    method: Method,
    uri: OriginalUri,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
) -> Result<Response, ServiceError> {
    validate_origin(&headers, &state.config().base_url)?;
    let (admin, org_id) =
        extract_org_admin(&state, &headers, &jar, method.as_str(), uri.path(), None).await?;

    if org_id.is_empty() {
        // Empty org_id is an auth/session issue — use the generic internal-error
        // key rather than the misleading no-subdomain message (L3 i18n refinement).
        return Ok(redirect_error(
            jar,
            Tr::new("admin-subdomain-error-internal").to_string(),
        ));
    }

    // Guard: emergency rotation for an org with no claimed subdomain has no
    // Active key to replace; fail early with a clear message (I4 / L3).
    let org = match db::get_organization(&state.store, &org_id).await {
        Ok(Some(o)) => o,
        Ok(None) | Err(_) => {
            return Ok(redirect_error(
                jar,
                Tr::new("admin-subdomain-error-internal").to_string(),
            ));
        }
    };
    if org.subdomain.is_none() {
        return Ok(redirect_error(
            jar,
            Tr::new("admin-subdomain-error-no-subdomain").to_string(),
        ));
    }

    if let Err(e) = emergency_rotate_org_keys(
        &state.store,
        &org_id,
        &state.audit,
        &state.org_keys_cache,
        Some(&admin.id),
        Some(&admin.email),
    )
    .await
    {
        tracing::error!(error = %e, org_id, "Emergency org issuer key rotation failed");
        return Ok(redirect_error(
            jar,
            Tr::new("admin-subdomain-error-internal").to_string(),
        ));
    }

    // Per-alg audit events with operator identity are emitted by
    // emergency_rotate_org_keys; no separate handler-level event needed (C1).

    tracing::warn!(
        admin_email = %admin.email,
        org_id = %org_id,
        "Emergency org issuer key rotation completed"
    );

    Ok(redirect_ok(
        jar,
        Tr::new("admin-subdomain-flash-emergency-rotation-done").to_string(),
    ))
}
