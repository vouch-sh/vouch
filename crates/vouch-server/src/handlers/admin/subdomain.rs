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
use crate::db::SigningKeyState;
use crate::db::{SubdomainClaimError, SubdomainLabelError};
use crate::handlers::admin::flash;
use crate::handlers::browser_login::validate_origin;
use crate::handlers::session::{AuthContext, extract_org_admin, get_resource_auth_context};
use crate::impl_template_response;
use crate::infra::i18n::Tr;
use crate::services::error::ServiceError;
use crate::services::oidc::{
    Operator, OrgKeyPanel, RevokeOutcome, RotateOutcome, emergency_rotate_org_keys, org_key_panel,
    revoke_org_previous_keys, rotate_org_keys,
};
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
    /// Signing-key rows for the key panel (empty when no subdomain is claimed
    /// or the keys have not been created yet).
    pub signing_keys: Vec<SigningKeyRow>,
    /// Localized reason the Rotate button is disabled; `None` = enabled.
    pub rotate_blocked: Option<String>,
    /// Localized reason the Revoke button is disabled; `None` = enabled.
    pub revoke_blocked: Option<String>,
    /// Whether any Previous key exists (controls the Revoke button's presence).
    pub has_previous: bool,
    pub flash_message: Option<String>,
    pub flash_success: Option<String>,
}

/// One row of the signing-key panel.
pub(crate) struct SigningKeyRow {
    pub alg: String,
    /// Localized display label for the key's state.
    pub state_label: String,
    pub kid: String,
    /// When the key entered its state (staged/demoted); `None` for Current.
    pub since: Option<String>,
}

/// Localized display label for a key state.
fn state_label(state: SigningKeyState) -> String {
    match state {
        SigningKeyState::Current => Tr::new("admin-subdomain-key-state-current").to_string(),
        SigningKeyState::Next => Tr::new("admin-subdomain-key-state-next").to_string(),
        SigningKeyState::Previous => Tr::new("admin-subdomain-key-state-previous").to_string(),
    }
}

/// Localized reason a rotate is (or would be) rejected; `None` when allowed.
fn rotate_blocked_message(outcome: &RotateOutcome) -> Option<String> {
    match outcome {
        RotateOutcome::Rotated { .. } => None,
        RotateOutcome::NextNotReady { ready_at } => Some(
            Tr::new("admin-subdomain-flash-rotate-not-ready")
                .arg("ready", ready_at.to_string().as_str())
                .to_string(),
        ),
        RotateOutcome::PreviousUnrevoked => {
            Some(Tr::new("admin-subdomain-flash-rotate-previous-unrevoked").to_string())
        }
        RotateOutcome::NotBootstrapped => {
            Some(Tr::new("admin-subdomain-flash-rotate-not-bootstrapped").to_string())
        }
    }
}

/// Localized reason a revoke is (or would be) rejected; `None` when allowed.
fn revoke_blocked_message(outcome: &RevokeOutcome) -> Option<String> {
    match outcome {
        RevokeOutcome::Revoked { .. } => None,
        RevokeOutcome::NotReady { ready_at } => Some(
            Tr::new("admin-subdomain-flash-revoke-not-ready")
                .arg("ready", ready_at.to_string().as_str())
                .to_string(),
        ),
        RevokeOutcome::NothingToRevoke => {
            Some(Tr::new("admin-subdomain-flash-nothing-to-revoke").to_string())
        }
    }
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

    // The signing-key panel only applies to a claimed subdomain on an
    // encrypted store (per-org keys are never created otherwise).
    let panel = if org.subdomain.is_some() && state.store.is_encrypted() {
        match org_key_panel(&state, &org_id).await {
            Ok(panel) => Some(panel),
            Err(e) => {
                tracing::error!(error = %e, org_id, "failed to build signing-key panel");
                None
            }
        }
    } else {
        None
    };
    let (signing_keys, rotate_blocked, revoke_blocked, has_previous) = match panel {
        Some(OrgKeyPanel {
            rows,
            rotate_blocked,
            revoke_blocked,
        }) => (
            rows.into_iter()
                .map(|row| SigningKeyRow {
                    alg: row.alg.as_str().to_string(),
                    state_label: state_label(row.state),
                    kid: row.kid,
                    since: row.since.map(|ts| ts.to_string()),
                })
                .collect(),
            rotate_blocked.as_ref().and_then(rotate_blocked_message),
            revoke_blocked.as_ref().and_then(revoke_blocked_message),
            rotate_blocked == Some(RotateOutcome::PreviousUnrevoked),
        ),
        None => (Vec::new(), None, None, false),
    };

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
        signing_keys,
        rotate_blocked,
        revoke_blocked,
        has_previous,
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

/// Request context shared by the key-management POST handlers.
struct ActionParts<'a> {
    method: &'a Method,
    uri: &'a OriginalUri,
    headers: &'a HeaderMap,
}

/// Shared guard for the key-management POST handlers: valid origin, an
/// org-admin session with an org, and a claimed subdomain. On a guard failure
/// the caller returns the ready-made redirect.
async fn subdomain_action_guard(
    state: &Arc<AppState>,
    parts: &ActionParts<'_>,
    jar: &CookieJar,
) -> Result<Result<(db::User, String), Response>, ServiceError> {
    validate_origin(parts.headers, &state.config().base_url)?;
    let (admin, org_id) = extract_org_admin(
        state,
        parts.headers,
        jar,
        parts.method.as_str(),
        parts.uri.path(),
        None,
    )
    .await?;

    if org_id.is_empty() {
        // No org association is an auth/session problem, not a subdomain one.
        return Ok(Err(redirect_error(
            jar.clone(),
            Tr::new("admin-subdomain-error-internal").to_string(),
        )));
    }
    let org = match db::get_organization(&state.store, &org_id).await {
        Ok(Some(o)) => o,
        Ok(None) | Err(_) => {
            return Ok(Err(redirect_error(
                jar.clone(),
                Tr::new("admin-subdomain-error-internal").to_string(),
            )));
        }
    };
    if org.subdomain.is_none() {
        return Ok(Err(redirect_error(
            jar.clone(),
            Tr::new("admin-subdomain-error-no-subdomain").to_string(),
        )));
    }
    Ok(Ok((admin, org_id)))
}

/// POST /admin/subdomain/rotate — switch signing to the pre-staged Next keys.
///
/// Promotes Next to Current for both algorithms, demotes the old signers to
/// Previous (published, verify-only, awaiting an explicit revoke), and stages
/// fresh Next keys. Rejected while the Next keys' publish window is still
/// warming relying-party caches, and while Previous keys remain unrevoked.
pub(crate) async fn admin_rotate_keys(
    method: Method,
    uri: OriginalUri,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
) -> Result<Response, ServiceError> {
    let parts = ActionParts {
        method: &method,
        uri: &uri,
        headers: &headers,
    };
    let (admin, org_id) = match subdomain_action_guard(&state, &parts, &jar).await? {
        Ok(v) => v,
        Err(response) => return Ok(response),
    };

    let operator = Operator {
        user_id: Some(&admin.id),
        email: Some(&admin.email),
    };
    match rotate_org_keys(&state, &org_id, operator).await {
        Ok(RotateOutcome::Rotated { .. }) => {
            tracing::info!(
                admin_email = %admin.email,
                org_id = %org_id,
                "Rotated org issuer keys"
            );
            Ok(redirect_ok(
                jar,
                Tr::new("admin-subdomain-flash-rotated").to_string(),
            ))
        }
        Ok(blocked) => {
            // The service emits no audit event for a rejected rotate.
            let message = rotate_blocked_message(&blocked)
                .unwrap_or_else(|| Tr::new("admin-subdomain-error-internal").to_string());
            Ok(redirect_error(jar, message))
        }
        Err(e) => {
            tracing::error!(error = %e, org_id, "Org issuer key rotation failed");
            Ok(redirect_error(
                jar,
                Tr::new("admin-subdomain-error-internal").to_string(),
            ))
        }
    }
}

/// POST /admin/subdomain/revoke — delete the Previous signing keys.
///
/// Allowed once the token-drain window since the demoting rotate has elapsed,
/// so no outstanding token loses its verification key.
pub(crate) async fn admin_revoke_keys(
    method: Method,
    uri: OriginalUri,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
) -> Result<Response, ServiceError> {
    let parts = ActionParts {
        method: &method,
        uri: &uri,
        headers: &headers,
    };
    let (admin, org_id) = match subdomain_action_guard(&state, &parts, &jar).await? {
        Ok(v) => v,
        Err(response) => return Ok(response),
    };

    let operator = Operator {
        user_id: Some(&admin.id),
        email: Some(&admin.email),
    };
    match revoke_org_previous_keys(&state, &org_id, operator).await {
        Ok(RevokeOutcome::Revoked { .. }) => {
            tracing::info!(
                admin_email = %admin.email,
                org_id = %org_id,
                "Revoked previous org issuer keys"
            );
            Ok(redirect_ok(
                jar,
                Tr::new("admin-subdomain-flash-revoked").to_string(),
            ))
        }
        Ok(blocked) => {
            let message = revoke_blocked_message(&blocked)
                .unwrap_or_else(|| Tr::new("admin-subdomain-error-internal").to_string());
            Ok(redirect_error(jar, message))
        }
        Err(e) => {
            tracing::error!(error = %e, org_id, "Org issuer key revoke failed");
            Ok(redirect_error(
                jar,
                Tr::new("admin-subdomain-error-internal").to_string(),
            ))
        }
    }
}

/// POST /admin/subdomain/emergency-rotate — replace the whole key set now.
///
/// Compromise recovery: fresh Current and Next keys for both algorithms, the
/// Previous keys deleted. Outstanding tokens signed by the old keys stop
/// verifying — deliberate, since keeping a compromised key verifiable would
/// keep attacker-forged tokens verifiable too.
pub(crate) async fn admin_emergency_rotate_keys(
    method: Method,
    uri: OriginalUri,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
) -> Result<Response, ServiceError> {
    let parts = ActionParts {
        method: &method,
        uri: &uri,
        headers: &headers,
    };
    let (admin, org_id) = match subdomain_action_guard(&state, &parts, &jar).await? {
        Ok(v) => v,
        Err(response) => return Ok(response),
    };

    let operator = Operator {
        user_id: Some(&admin.id),
        email: Some(&admin.email),
    };
    // A claimed subdomain whose keys were never created has nothing to
    // replace; say so instead of reporting an internal error.
    match db::get_org_signing_key(
        &state.store,
        &org_id,
        db::JwsAlgorithm::Es256,
        SigningKeyState::Current,
    )
    .await
    {
        Ok(Some(_)) => {}
        Ok(None) => {
            return Ok(redirect_error(
                jar,
                Tr::new("admin-subdomain-flash-rotate-not-bootstrapped").to_string(),
            ));
        }
        Err(e) => {
            tracing::error!(error = %e, org_id, "failed to load current signing key");
            return Ok(redirect_error(
                jar,
                Tr::new("admin-subdomain-error-internal").to_string(),
            ));
        }
    }
    if let Err(e) = emergency_rotate_org_keys(&state, &org_id, operator).await {
        tracing::error!(error = %e, org_id, "Emergency org issuer key rotation failed");
        return Ok(redirect_error(
            jar,
            Tr::new("admin-subdomain-error-internal").to_string(),
        ));
    }

    // Per-alg audit events with operator identity are emitted by the service.
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
