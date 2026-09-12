// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Web UI handlers for OAuth Application Registration.
//!
//! These handlers return HTML responses via Askama templates for the
//! self-service application management portal.

use crate::AppState;
use crate::arrival::ArrivalTime;
use crate::db::{self, AccessScope, UpdateOAuthClientParams};
use axum::{
    Form,
    extract::{Path, State},
    response::{IntoResponse, Redirect, Response},
};
use std::sync::Arc;

use super::types::{
    ApplicationCreateTemplate, ApplicationCreatedTemplate, ApplicationDetailTemplate,
    ApplicationErrorTemplate, ApplicationInfo, ApplicationsListTemplate, CreateApplicationForm,
    SecretAddedTemplate, SecretInfo, UpdateApplicationForm, UsageStat,
};
use super::validate::{
    AppValidationError, CreateAppContext, CreateAppInput, UpdateAppInput, build_create_params,
    compute_fapi_update_fields, validate_create_application, validate_update_fapi,
    validate_update_format,
};
use super::{generate_client_secret, parse_redirect_uris, parse_resource_uris};
use crate::handlers::extractors::SignedInSession;
use crate::handlers::hash_token;
use crate::infra::i18n::Tr;

/// Render the standard application error page from translation keys, resolving
/// them against the request locale.
fn error_page(title: Tr<'static>, message: Tr<'static>, back_url: impl Into<String>) -> Response {
    ApplicationErrorTemplate {
        title,
        message,
        back_url: back_url.into(),
    }
    .into_response()
}

/// Render a shared validation failure as the standard error page.
///
/// Uses `err.localized()`, not `err.message()`. The two say the same thing to
/// different readers: `message()` is the OAuth `error_description` the JSON
/// API returns to a client developer, which RFC 6749 §5.2 keeps ASCII and
/// English, while this page is read by whoever submitted the form.
fn validation_error_response(err: &AppValidationError, back_url: String) -> Response {
    error_page(
        Tr::new("apps-error-title-invalid-input"),
        err.localized(),
        back_url,
    )
}

/// List user's applications.
/// GET /applications
pub(crate) async fn list_applications_page(
    State(state): State<Arc<AppState>>,
    session: SignedInSession,
) -> Response {
    let SignedInSession { auth } = session;

    let user_id = auth.user_id.as_deref().unwrap_or_default();
    let applications = match db::get_oauth_clients_for_user(&state.store, user_id).await {
        Ok(apps) => apps.into_iter().map(ApplicationInfo::from).collect(),
        Err(e) => {
            tracing::error!("Failed to list applications: {}", e);
            return error_page(
                Tr::new("apps-error-title-error"),
                Tr::new("apps-error-load-applications"),
                "/",
            );
        }
    };

    ApplicationsListTemplate { applications, auth }.into_response()
}

/// Show create application form.
/// GET /applications/new
pub(crate) async fn create_application_page(session: SignedInSession) -> Response {
    let SignedInSession { auth } = session;

    let user_has_org = auth.has_org;
    ApplicationCreateTemplate { auth, user_has_org }.into_response()
}

/// Create a new application.
/// POST /applications/new
pub(crate) async fn create_application_form(
    State(state): State<Arc<AppState>>,
    session: SignedInSession,
    Form(form): Form<CreateApplicationForm>,
) -> Response {
    let SignedInSession { auth } = session;

    let user_id = auth.user_id.as_deref().unwrap_or_default();

    // Parse textarea inputs, then run the shared format validation
    let redirect_uris = parse_redirect_uris(&form.redirect_uris);
    let resource_uris = parse_resource_uris(form.resource_uris.as_deref());
    let post_logout_redirect_uris_raw = parse_redirect_uris(
        form.post_logout_redirect_uris
            .as_deref()
            .unwrap_or_default(),
    );
    // Pass None when the textarea was empty (no post-logout URIs wanted); validation
    // happens inside validate_create_application via the AppValidationError enum.
    let post_logout_redirect_uris_input: Option<&[String]> =
        if post_logout_redirect_uris_raw.is_empty() {
            None
        } else {
            Some(&post_logout_redirect_uris_raw)
        };

    let validated = match validate_create_application(CreateAppInput {
        name: &form.name,
        application_type: &form.application_type,
        redirect_uris: &redirect_uris,
        resource_uris: &resource_uris,
        post_logout_redirect_uris: post_logout_redirect_uris_input,
        access_scope: Some(&form.access_scope),
        fapi_profile: form.fapi_profile.as_deref(),
        jwks: form.jwks.as_deref(),
        jwks_uri: form.jwks_uri.as_deref(),
    }) {
        Ok(v) => v,
        Err(e) => return validation_error_response(&e, "/applications/new".to_string()),
    };
    let name = validated.name;

    // Validated access scope (format checked in validate_create_application;
    // org-membership check stays here because it depends on the auth context).
    let access_scope = validated.access_scope;

    // Validate: Organization scope requires user to have an org
    if access_scope == AccessScope::Organization && !auth.has_org {
        return error_page(
            Tr::new("apps-error-title-invalid-input"),
            Tr::new("apps-error-org-scope-required"),
            "/applications/new",
        );
    }

    // All input validated — now fetch org_id from DB. Only organization-scoped
    // apps need it, and a missing user or missing `org_id` must reject rather
    // than fall through to `None`: an organization-scoped application
    // persisted with a NULL `org_id` is detached from its owning org and
    // unmanageable (every management endpoint gates on `client.user_id ==
    // caller`, and a concurrent `delete_user` between the extractor's
    // `load_active_user` read and this second `get_user_by_id` read is the one
    // path that returns `Ok(None)` here). Mirrors `load_active_user_for_scope`
    // in the JSON API path, which makes the existence and org-membership
    // decisions on the same load the `org_id` comes from.
    let user_org_id = if access_scope == AccessScope::Organization {
        match db::get_user_by_id(&state.store, user_id).await {
            Ok(Some(user)) if user.org_id.is_some() => user.org_id,
            Ok(Some(_)) | Ok(None) => {
                tracing::error!(
                    "User {user_id} missing or has no org_id for org-scoped app creation"
                );
                return error_page(
                    Tr::new("apps-error-title-error"),
                    Tr::new("apps-error-create-failed"),
                    "/applications/new",
                );
            }
            Err(e) => {
                tracing::error!("Failed to load user {user_id} for app org scoping: {e}");
                return error_page(
                    Tr::new("apps-error-title-error"),
                    Tr::new("apps-error-create-failed"),
                    "/applications/new",
                );
            }
        }
    } else {
        None
    };

    // `user_org_id` is `Some` only for organization-scoped apps (and is
    // guaranteed non-`None` there by the rejection above), so `as_deref()`
    // yields the org for org-scoped apps and `None` otherwise.
    let org_id = user_org_id.as_deref();

    // Create the application with FAPI settings included at creation time
    let (client, client_id) = match db::create_oauth_client(
        &state.store,
        &build_create_params(
            &validated,
            CreateAppContext {
                user_id,
                description: form.description.as_deref(),
                redirect_uris: &redirect_uris,
                resource_uris: &resource_uris,
                post_logout_redirect_uris: post_logout_redirect_uris_input,
                access_scope,
                org_id,
            },
        ),
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to create application: {}", e);
            return error_page(
                Tr::new("apps-error-title-error"),
                Tr::new("apps-error-create-failed"),
                "/applications/new",
            );
        }
    };

    let client_secret = if client.token_endpoint_auth_method
        == db::TokenEndpointAuthMethod::ClientSecretBasic
    {
        let secret = generate_client_secret();
        let secret_hash = hash_token(&secret);

        if let Err(e) = db::create_oauth_client_secret(
            &state.store,
            &client.id,
            &secret_hash,
            Some("Initial secret"),
            None,
        )
        .await
        {
            // ServiceError does not implement std::error::Error but does impl Display.
            tracing::error!("Failed to create client secret: {}", e);
            // Clean up the client
            if let Err(cleanup_err) = db::delete_oauth_client(&state.store, &client.id).await {
                tracing::warn!(
                    "Failed to clean up OAuth client after secret creation failure: {cleanup_err}"
                );
            }
            return error_page(
                Tr::new("apps-error-title-error"),
                Tr::new("apps-error-create-failed"),
                "/applications/new",
            );
        }

        Some(secret)
    } else {
        None
    };

    tracing::info!("Created OAuth application: {} ({})", name, client_id);

    ApplicationCreatedTemplate {
        name: name.to_string(),
        client_id,
        requires_secret: client_secret.is_some(),
        client_secret,
        application_type: form.application_type,
        auth,
    }
    .into_response()
}

/// Show application details.
/// GET /applications/:id
pub(crate) async fn detail_application_page(
    arrival: ArrivalTime,
    State(state): State<Arc<AppState>>,
    session: SignedInSession,
    Path(app_id): Path<String>,
) -> Response {
    let SignedInSession { auth } = session;

    let user_id = auth.user_id.as_deref().unwrap_or_default();

    // Get the application
    let client = match db::get_oauth_client_by_id(&state.store, &app_id).await {
        Ok(Some(c)) if c.user_id.as_deref() == Some(user_id) => c,
        Ok(Some(_)) => {
            return error_page(
                Tr::new("apps-error-title-not-found"),
                Tr::new("apps-error-app-not-found"),
                "/applications",
            );
        }
        Ok(None) => {
            return error_page(
                Tr::new("apps-error-title-not-found"),
                Tr::new("apps-error-app-not-found"),
                "/applications",
            );
        }
        Err(e) => {
            tracing::error!("Failed to get application: {}", e);
            return error_page(
                Tr::new("apps-error-title-error"),
                Tr::new("apps-error-load-application"),
                "/applications",
            );
        }
    };

    // Get secrets metadata
    let now = arrival.timestamp();
    let all_secrets = db::get_oauth_client_secrets(&state.store, &app_id)
        .await
        .unwrap_or_default();
    let secrets: Vec<SecretInfo> = all_secrets
        .iter()
        .map(|s| SecretInfo {
            id: s.id.clone(),
            description: s.description.clone(),
            created_at: s.created_at,
            expires_at: s.expires_at,
            active: s.is_valid(&now),
        })
        .collect();
    let secrets_count = secrets.iter().filter(|s| s.active).count();

    // Get usage stats. A failure renders the page without them rather than
    // failing the whole detail view, but "no usage" and "stats unavailable"
    // look identical to the reader, so log the cause.
    let usage_stats = match db::get_oauth_usage_stats(&state.audit, &app_id, None).await {
        Ok(stats) => stats
            .into_iter()
            .map(|s| UsageStat {
                event_type: s.event_type,
                count: s.count,
            })
            .collect(),
        Err(e) => {
            tracing::warn!(error = %e, app_id, "Usage stats lookup failed; rendering page without them");
            vec![]
        }
    };

    ApplicationDetailTemplate {
        app: ApplicationInfo::from(client),
        secrets_count,
        secrets,
        usage_stats,
        auth,
    }
    .into_response()
}

/// Update an application.
/// POST /applications/:id
pub(crate) async fn update_application_form(
    State(state): State<Arc<AppState>>,
    session: SignedInSession,
    Path(app_id): Path<String>,
    Form(form): Form<UpdateApplicationForm>,
) -> Response {
    let SignedInSession { auth } = session;

    let user_id = auth.user_id.as_deref().unwrap_or_default();

    // Verify ownership
    let client = match db::get_oauth_client_by_id(&state.store, &app_id).await {
        Ok(Some(c)) if c.user_id.as_deref() == Some(user_id) => c,
        _ => {
            return error_page(
                Tr::new("apps-error-title-not-found"),
                Tr::new("apps-error-app-not-found"),
                "/applications",
            );
        }
    };

    // Validate inputs
    let name = form.name.trim();
    if name.is_empty() {
        return validation_error_response(
            &AppValidationError::EmptyName,
            format!("/applications/{}", app_id),
        );
    }

    // Parse textarea inputs, then run the shared format validation.
    // The web form always submits the post_logout_redirect_uris field, so
    // empty textarea = explicitly clear (Some(&[])), not absent (None).
    let redirect_uris = parse_redirect_uris(&form.redirect_uris);
    let resource_uris = parse_resource_uris(form.resource_uris.as_deref());
    let post_logout_redirect_uris_raw = parse_redirect_uris(
        form.post_logout_redirect_uris
            .as_deref()
            .unwrap_or_default(),
    );

    let validated = match validate_update_format(UpdateAppInput {
        redirect_uris: Some(&redirect_uris),
        resource_uris: Some(&resource_uris),
        // Always Some: empty vec = explicitly clear; validation rejects invalid URIs.
        post_logout_redirect_uris: Some(&post_logout_redirect_uris_raw),
        access_scope: form.access_scope.as_deref(),
        fapi_profile: form.fapi_profile.as_deref(),
        jwks: form.jwks.as_deref(),
        jwks_uri: form.jwks_uri.as_deref(),
    }) {
        Ok(v) => v,
        Err(e) => return validation_error_response(&e, format!("/applications/{}", app_id)),
    };

    // Validated access scope (format checked in validate_update_format;
    // org-membership check stays here because it depends on the auth context).
    let access_scope = validated.access_scope;

    // Validate: Organization scope requires user to have an org
    if access_scope == Some(AccessScope::Organization) && !auth.has_org {
        return error_page(
            Tr::new("apps-error-title-invalid-input"),
            Tr::new("apps-error-org-scope-required"),
            format!("/applications/{}", app_id),
        );
    }

    // Get the user's org_id for org-scoped apps. Only organization-scoped
    // updates need it, and a missing user or missing `org_id` must reject
    // rather than fall through to `None`: a NULL `org_id` would silently
    // detach an existing org-scoped app from its owning org — and for a
    // concurrent `delete_user` between the extractor's `load_active_user` read
    // and this second `get_user_by_id` read, that is the only path that
    // returns `Ok(None)` here. Mirrors the create path and
    // `load_active_user_for_scope` in the JSON API path, which makes the
    // existence and org-membership decisions on the same load the `org_id`
    // comes from.
    let user_org_id = if access_scope == Some(AccessScope::Organization) {
        match db::get_user_by_id(&state.store, user_id).await {
            Ok(Some(user)) if user.org_id.is_some() => user.org_id,
            Ok(Some(_)) | Ok(None) => {
                tracing::error!(
                    "User {user_id} missing or has no org_id for org-scoped app update"
                );
                return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
            Err(e) => {
                tracing::error!("Failed to load user {user_id} for app org scoping: {e}");
                return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
    } else {
        None
    };

    // `user_org_id` is `Some` only for organization-scoped updates (and is
    // guaranteed non-`None` there by the rejection above), so `as_deref()`
    // yields the org for org-scoped updates and `None` otherwise.
    let org_id = user_org_id.as_deref();

    // FAPI rules that depend on the existing client record
    if let Err(e) = validate_update_fapi(&validated, &client) {
        return validation_error_response(&e, format!("/applications/{}", app_id));
    }

    // Merge FAPI-related fields against the existing client record. The form's
    // security-profile radio group always submits fapi_profile; selecting
    // Standard for a client that is already FAPI is rejected above, so what
    // reaches here either enables FAPI or leaves a non-FAPI client standard.
    let fapi = match compute_fapi_update_fields(&validated, &client) {
        Ok(fapi) => fapi,
        Err(e) => {
            return validation_error_response(&e, format!("/applications/{}", app_id));
        }
    };

    // Update the application
    if let Err(e) = db::update_oauth_client(
        &state.store,
        &UpdateOAuthClientParams {
            id: &app_id,
            name,
            // Fall back to the stored value, matching the API path: a request
            // that omits the field is not asking to erase it.
            description: form
                .description
                .as_deref()
                .or(client.description.as_deref()),
            redirect_uris: &redirect_uris,
            access_scope,
            org_id,
            resource_uris: &resource_uris,
            token_endpoint_auth_method: fapi.token_endpoint_auth_method,
            keys: fapi.keys,
            fapi_profile: fapi.fapi_profile,
            dpop_bound_access_tokens: fapi.dpop_bound_access_tokens,
            post_logout_redirect_uris: validated.post_logout_redirect_uris.map(<[String]>::to_vec),
        },
    )
    .await
    {
        tracing::error!("Failed to update application: {}", e);
        return error_page(
            Tr::new("apps-error-title-error"),
            Tr::new("apps-error-update-failed"),
            format!("/applications/{}", app_id),
        );
    }

    tracing::info!("Updated OAuth application: {} ({})", name, client.client_id);

    Redirect::to(&format!("/applications/{}", app_id)).into_response()
}

/// Delete an application.
/// POST /applications/:id/delete
pub(crate) async fn delete_application_form(
    State(state): State<Arc<AppState>>,
    session: SignedInSession,
    Path(app_id): Path<String>,
) -> Response {
    let SignedInSession { auth } = session;

    let user_id = auth.user_id.as_deref().unwrap_or_default();

    // Verify ownership
    let client = match db::get_oauth_client_by_id(&state.store, &app_id).await {
        Ok(Some(c)) if c.user_id.as_deref() == Some(user_id) => c,
        _ => {
            return error_page(
                Tr::new("apps-error-title-not-found"),
                Tr::new("apps-error-app-not-found"),
                "/applications",
            );
        }
    };

    // Delete the application and revoke every session it minted (M2M and
    // user-issued). Web-UI twin of `delete_application_api`: without the
    // session delete, access tokens minted for the deleted application keep
    // validating at resource endpoints until `exp`.
    if let Err(e) = db::delete_oauth_client_and_revoke_sessions(
        &state.store,
        &state.session_cache,
        &app_id,
        &client.client_id,
    )
    .await
    {
        tracing::error!("Failed to delete application: {}", e);
        return error_page(
            Tr::new("apps-error-title-error"),
            Tr::new("apps-error-delete-failed"),
            format!("/applications/{}", app_id),
        );
    }

    // Record the `ClientDeleted` audit event, mirroring the RFC 7592 delete
    // path and `delete_application_api`. The secret/token handlers on this
    // same surface already record `SecretAdded`/`SecretRevoked`; the delete
    // cascade is a strictly stronger revocation and must not be the one
    // lifecycle event that leaves no durable record.
    //
    // The client document is already deleted above, so the `Unresolved`
    // client-org fallback inside `record_oauth_event` (a lookup by
    // `client.id`) would always miss. Pre-resolve org-domain attribution
    // from the already-in-scope `client.user_id`/`client.org_id` instead,
    // exactly as the RFC 7592 path does, then stamp it via `Known`.
    let user_org_domain = if let Some(owner_id) = client.user_id.as_deref()
        && let Ok(Some(user)) = db::get_user_by_id(&state.store, owner_id).await
        && let Some(org_id) = user.org_id.as_deref()
    {
        match user.org_domain.clone() {
            Some(domain) => Some(domain),
            None => db::get_organization_domain(&state.store, org_id)
                .await
                .ok()
                .flatten(),
        }
    } else {
        None
    };
    let audit_org_domain = db::resolve_event_org_domain(
        &state.store,
        user_org_domain.as_deref(),
        client.org_id.as_deref(),
    )
    .await;
    db::record_oauth_event(
        &state.audit,
        &state.store,
        &db::RecordOAuthEventParams {
            oauth_client_id: &app_id,
            event_type: db::OAuthEventType::ClientDeleted,
            user_id: Some(user_id),
            ip_address: None,
            user_agent: None,
            details: Some("Application deleted via web UI"),
            org_domain: db::RecordedOrgDomain::Known(audit_org_domain.as_deref()),
        },
    )
    .await;

    tracing::info!("Deleted OAuth application: {}", client.client_id);

    Redirect::to("/applications").into_response()
}

/// Add a new client secret.
/// POST /applications/:id/secrets
pub(crate) async fn add_secret_form(
    State(state): State<Arc<AppState>>,
    session: SignedInSession,
    Path(app_id): Path<String>,
) -> Response {
    let SignedInSession { auth } = session;

    let user_id = auth.user_id.as_deref().unwrap_or_default();

    let client = match db::get_oauth_client_by_id(&state.store, &app_id).await {
        Ok(Some(c)) if c.user_id.as_deref() == Some(user_id) => c,
        _ => {
            return error_page(
                Tr::new("apps-error-title-not-found"),
                Tr::new("apps-error-app-not-found"),
                "/applications",
            );
        }
    };

    if !client.application_type.requires_secret() {
        return error_page(
            Tr::new("apps-error-title-error"),
            Tr::new("apps-error-no-client-secrets"),
            format!("/applications/{app_id}"),
        );
    }

    // FAPI 2.0 clients authenticate via `private_key_jwt` or mTLS
    // (`tls_client_auth` / `self_signed_tls_client_auth`) and never use a
    // shared client secret, regardless of auth method. Block every FAPI
    // client — narrowing this to `PrivateKeyJwt` lets mTLS-FAPI clients
    // (reachable since #214) mint dead secrets the token endpoint refuses.
    if client.is_fapi() {
        return error_page(
            Tr::new("apps-error-title-error"),
            Tr::new("apps-error-fapi-no-secrets"),
            format!("/applications/{app_id}"),
        );
    }

    let secret = generate_client_secret();
    let secret_hash = hash_token(&secret);

    // Cap guard (≤ MAX_ACTIVE_SECRETS) is enforced atomically inside
    // create_oauth_client_secret — the pre-flight count has been dropped because
    // the in-tx OCC guard is authoritative on all backends.
    let record =
        match db::create_oauth_client_secret(&state.store, &app_id, &secret_hash, None, None).await
        {
            Ok(r) => r,
            Err(crate::error::ServiceError::Api { ref code, .. })
                if code == "max_secrets_reached" =>
            {
                return error_page(
                    Tr::new("apps-error-title-error"),
                    Tr::new("apps-error-secret-max"),
                    format!("/applications/{app_id}"),
                );
            }
            Err(e) => {
                tracing::error!("Failed to create secret: {e}");
                return error_page(
                    Tr::new("apps-error-title-error"),
                    Tr::new("apps-error-secret-add-failed"),
                    format!("/applications/{app_id}"),
                );
            }
        };

    db::record_oauth_event(
        &state.audit,
        &state.store,
        &db::RecordOAuthEventParams {
            oauth_client_id: &app_id,
            event_type: db::OAuthEventType::SecretAdded,
            user_id: auth.user_id.as_deref(),
            ip_address: None,
            user_agent: None,
            details: Some("Secret added"),
            org_domain: db::RecordedOrgDomain::Unresolved,
        },
    )
    .await;

    tracing::info!("Added secret for OAuth application: {}", client.client_id);

    SecretAddedTemplate {
        app_id: app_id.to_string(),
        name: client.name,
        client_id: client.client_id,
        client_secret: secret,
        secret_id: record.id,
        auth,
    }
    .into_response()
}

/// Delete (revoke) a secret.
/// POST /applications/:id/secrets/:secret_id/delete
pub(crate) async fn delete_secret_form(
    arrival: ArrivalTime,
    State(state): State<Arc<AppState>>,
    session: SignedInSession,
    Path((app_id, secret_id)): Path<(String, String)>,
) -> Response {
    let SignedInSession { auth } = session;

    let user_id = auth.user_id.as_deref().unwrap_or_default();

    let client = match db::get_oauth_client_by_id(&state.store, &app_id).await {
        Ok(Some(c)) if c.user_id.as_deref() == Some(user_id) => c,
        _ => {
            return error_page(
                Tr::new("apps-error-title-not-found"),
                Tr::new("apps-error-app-not-found"),
                "/applications",
            );
        }
    };

    let secret = match db::get_oauth_client_secret_by_id(&state.store, &secret_id).await {
        Ok(Some(s)) if s.oauth_client_id == app_id => s,
        _ => {
            return error_page(
                Tr::new("apps-error-title-not-found"),
                Tr::new("apps-error-secret-not-found"),
                format!("/applications/{app_id}"),
            );
        }
    };

    if secret.revoked_at.is_some() {
        return error_page(
            Tr::new("apps-error-title-not-found"),
            Tr::new("apps-error-secret-not-found"),
            format!("/applications/{app_id}"),
        );
    }

    let now = arrival.timestamp();
    let all_secrets = db::get_oauth_client_secrets(&state.store, &app_id)
        .await
        .unwrap_or_default();
    let other_active = all_secrets
        .iter()
        .filter(|s| s.id != secret_id && s.is_valid(&now))
        .count();

    // FAPI clients cannot authenticate with a secret (minting is blocked for
    // every FAPI profile, and `authenticate_client` refuses a secret from a
    // FAPI client at every secret-verifying endpoint), so the last-secret
    // floor does not apply: pre-guard secret rows must remain deletable.
    // The authoritative check is the same exemption inside
    // `revoke_oauth_client_secret`'s transaction.
    if other_active == 0 && !client.is_fapi() {
        return error_page(
            Tr::new("apps-error-title-error"),
            Tr::new("apps-error-secret-last-active"),
            format!("/applications/{app_id}"),
        );
    }

    // Floor guard (≥1 active) is enforced atomically inside
    // revoke_oauth_client_secret — the pre-flight count above remains as a
    // fast-path for the common non-concurrent case.  A concurrent revoke may
    // still race us to the last secret and return last_secret 409; show the
    // specific message rather than the generic delete-failed page.
    if let Err(e) = db::revoke_oauth_client_secret(&state.store, &secret_id, &app_id).await {
        let msg = match &e {
            crate::error::ServiceError::Api { code, .. } if code == "last_secret" => {
                Tr::new("apps-error-secret-last-active")
            }
            _ => {
                tracing::error!("Failed to revoke secret: {e}");
                Tr::new("apps-error-secret-delete-failed")
            }
        };
        return error_page(
            Tr::new("apps-error-title-error"),
            msg,
            format!("/applications/{app_id}"),
        );
    }

    db::record_oauth_event(
        &state.audit,
        &state.store,
        &db::RecordOAuthEventParams {
            oauth_client_id: &app_id,
            event_type: db::OAuthEventType::SecretRevoked,
            user_id: Some(user_id),
            ip_address: None,
            user_agent: None,
            details: Some("Secret revoked"),
            org_domain: db::RecordedOrgDomain::Unresolved,
        },
    )
    .await;

    tracing::info!(
        "Revoked secret {} for OAuth application: {}",
        secret_id,
        client.client_id
    );

    Redirect::to(&format!("/applications/{app_id}")).into_response()
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};

    use axum::http::StatusCode;

    use crate::db::store::GetUserByIdTestHook;
    use crate::test_utils::*;

    // Web handlers use Path<String> (not ValidPath<ValidUuid>) so that invalid
    // UUIDs flow through to the db lookup and produce HTML error pages, not
    // JSON 400s. These tests guard against accidentally switching to ValidPath.

    #[tokio::test]
    async fn test_detail_page_invalid_uuid_returns_html_not_json() {
        let (app, state) = test_app().await;
        let user = create_test_user(&state.store, "uuid-detail@example.com").await;
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
        let cookie = format!("__Host-vouch_session={token}");

        let resp = http_get_full(&app, "/applications/not-a-uuid", &[("Cookie", &cookie)]).await;

        // A person mistyping a URL reads a page, not a JSON error envelope —
        // the browser routes answer in HTML where the API routes answer 400.
        assert_ne!(resp.status, StatusCode::BAD_REQUEST);
        let ct = resp
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert!(
            ct.contains("text/html"),
            "expected HTML content-type, got: {ct}"
        );
    }

    #[tokio::test]
    async fn test_delete_page_invalid_uuid_returns_html_not_json() {
        let (app, state) = test_app().await;
        let user = create_test_user(&state.store, "uuid-delete@example.com").await;
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
        let cookie = format!("__Host-vouch_session={token}");

        let (status, body) = http_post_form(
            &app,
            "/applications/not-a-uuid/delete",
            "",
            &[("Origin", "https://test.example.com"), ("Cookie", &cookie)],
        )
        .await;

        assert_ne!(status, StatusCode::BAD_REQUEST);
        assert!(
            body.contains("</html>") || body.contains("<!DOCTYPE"),
            "expected HTML response, got: {body}"
        );
    }

    #[tokio::test]
    async fn test_add_secret_page_invalid_uuid_returns_html_not_json() {
        let (app, state) = test_app().await;
        let user = create_test_user(&state.store, "uuid-secret@example.com").await;
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
        let cookie = format!("__Host-vouch_session={token}");

        let (status, body) = http_post_form(
            &app,
            "/applications/not-a-uuid/secrets",
            "",
            &[("Origin", "https://test.example.com"), ("Cookie", &cookie)],
        )
        .await;

        assert_ne!(status, StatusCode::BAD_REQUEST);
        assert!(
            body.contains("</html>") || body.contains("<!DOCTYPE"),
            "expected HTML response, got: {body}"
        );
    }

    #[tokio::test]
    async fn test_delete_secret_page_invalid_uuids_returns_html_not_json() {
        let (app, state) = test_app().await;
        let user = create_test_user(&state.store, "uuid-secret-del@example.com").await;
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
        let cookie = format!("__Host-vouch_session={token}");

        let (status, body) = http_post_form(
            &app,
            "/applications/not-a-uuid/secrets/also-bad/delete",
            "",
            &[("Origin", "https://test.example.com"), ("Cookie", &cookie)],
        )
        .await;

        assert_ne!(status, StatusCode::BAD_REQUEST);
        assert!(
            body.contains("</html>") || body.contains("<!DOCTYPE"),
            "expected HTML response, got: {body}"
        );
    }

    // ========================================================================
    // #546 — Web form update validation: empty name + empty redirect_uris
    // ========================================================================

    /// Deleting an application from the web UI must revoke every access token
    /// it minted, exactly like `delete_application_api`. Regression for the
    /// web-UI sibling of the `revoke_tokens_api` bug: `delete_application_form`
    /// used to call the bare `delete_oauth_client`, so user-issued sessions
    /// (keyed by the resource owner's `user_id`, tagged with the issuing
    /// `client_id`) and M2M sessions (`user_id == client_id`, RFC 9068 §2.2)
    /// kept validating until `exp`. Without the fix the session rows survive
    /// the delete and this test fails.
    #[tokio::test]
    async fn test_web_delete_application_revokes_minted_sessions() {
        let (app, state) = test_app().await;
        let user = create_test_user(&state.store, "web-delete-revokes@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let session_token = create_test_session_with(
            &state,
            TestSessionSpec {
                user_id: &user.id,
                email: &user.email,
                auth_id: Some(&auth_id),
                ..Default::default()
            },
        )
        .await;
        let cookie = format!("__Host-vouch_session={session_token}");
        let client = create_test_oauth_client(&state.store, &user.id).await;

        // A user-issued access token for this client and an M2M session.
        create_test_session_with(
            &state,
            TestSessionSpec {
                user_id: &user.id,
                email: &user.email,
                auth_id: Some(&auth_id),
                client_id: Some(&client.client_id),
                ..Default::default()
            },
        )
        .await;
        create_test_session_with(
            &state,
            TestSessionSpec {
                user_id: &client.client_id,
                email: &format!("{}@clients", client.client_id),
                auth_id: Some(&auth_id),
                client_id: Some(&client.client_id),
                ..Default::default()
            },
        )
        .await;

        // A sibling client's token must survive (no over-revocation).
        let other_client = create_test_oauth_client(&state.store, &user.id).await;
        create_test_session_with(
            &state,
            TestSessionSpec {
                user_id: &user.id,
                email: &user.email,
                auth_id: Some(&auth_id),
                client_id: Some(&other_client.client_id),
                ..Default::default()
            },
        )
        .await;

        let sessions_for = |client_id: String| {
            let store = state.store.clone();
            async move {
                store
                    .count::<crate::db::documents::session::SessionDoc>("client_id", &client_id)
                    .await
                    .expect("count must not error")
            }
        };
        assert!(
            sessions_for(client.client_id.clone()).await >= 1,
            "client must have minted sessions before the delete"
        );

        // Delete via the browser form.
        let (status, _body) = http_post_form(
            &app,
            &format!("/applications/{}/delete", client.app_id),
            "",
            &[("Origin", "https://test.example.com"), ("Cookie", &cookie)],
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER, "delete should redirect");

        // Every session minted by the deleted client is gone — both the
        // user-issued one (client_id index) and the M2M one (user_id index).
        assert_eq!(
            sessions_for(client.client_id.clone()).await,
            0,
            "sessions tagged with the deleted client must be gone"
        );
        assert_eq!(
            state
                .store
                .count::<crate::db::documents::session::SessionDoc>("user_id", &client.client_id)
                .await
                .expect("count must not error"),
            0,
            "M2M sessions for the deleted client must be gone"
        );

        // The sibling client's session survives.
        assert!(
            sessions_for(other_client.client_id.clone()).await >= 1,
            "deleting one application must not revoke another client's sessions"
        );
    }

    #[tokio::test]
    async fn test_web_update_form_rejects_empty_name() {
        // Guard: submitting the web form with an empty name must be rejected
        // with a validation error page and must NOT persist the empty value.
        let (app, state) = test_app().await;
        let user = create_test_user(&state.store, "web-update-empty-name@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let session_token = create_test_session_with(
            &state,
            TestSessionSpec {
                user_id: &user.id,
                email: &user.email,
                auth_id: Some(&auth_id),
                ..Default::default()
            },
        )
        .await;
        let client = create_test_oauth_client(&state.store, &user.id).await;

        // Submit the web update form with an empty name.
        let form_body = "name=&redirect_uris=https%3A%2F%2Fexample.com%2Fcallback";
        let (status, body) = http_post_form(
            &app,
            &format!("/applications/{}", client.app_id),
            form_body,
            &[
                ("Cookie", &format!("__Host-vouch_session={session_token}")),
                ("Origin", "https://test.example.com"),
            ],
        )
        .await;

        // Must be a non-redirect (error page), not a success redirect.
        assert_ne!(
            status,
            StatusCode::FOUND,
            "Empty name must not be accepted: {body}"
        );
        assert_ne!(
            status,
            StatusCode::SEE_OTHER,
            "Empty name must not be accepted: {body}"
        );
        // Response must be HTML (the validation error template).
        assert!(
            body.contains("</html>") || body.contains("<!DOCTYPE"),
            "Validation error must return HTML: {body}"
        );

        // Verify the DB record was not mutated: name must still be "Test App".
        let record = crate::db::get_oauth_client_by_id(&state.store, &client.app_id)
            .await
            .expect("db query ok")
            .expect("client must still exist");
        assert_eq!(
            record.name, "Test App",
            "Empty name must not overwrite existing name in the database"
        );
    }

    #[tokio::test]
    async fn test_web_update_form_rejects_empty_redirect_uris() {
        // Guard: submitting the web form with blank redirect_uris must be rejected
        // with a validation error and must NOT persist the empty list.
        let (app, state) = test_app().await;
        let user = create_test_user(&state.store, "web-update-empty-uris@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let session_token = create_test_session_with(
            &state,
            TestSessionSpec {
                user_id: &user.id,
                email: &user.email,
                auth_id: Some(&auth_id),
                ..Default::default()
            },
        )
        .await;
        let client = create_test_oauth_client(&state.store, &user.id).await;

        // Submit with a valid name but blank redirect_uris textarea.
        let form_body = "name=Test+App&redirect_uris=";
        let (status, body) = http_post_form(
            &app,
            &format!("/applications/{}", client.app_id),
            form_body,
            &[
                ("Cookie", &format!("__Host-vouch_session={session_token}")),
                ("Origin", "https://test.example.com"),
            ],
        )
        .await;

        // Must be a non-redirect (error page), not a success redirect.
        assert_ne!(
            status,
            StatusCode::FOUND,
            "Empty redirect_uris must not be accepted: {body}"
        );
        assert_ne!(
            status,
            StatusCode::SEE_OTHER,
            "Empty redirect_uris must not be accepted: {body}"
        );
        assert!(
            body.contains("</html>") || body.contains("<!DOCTYPE"),
            "Validation error must return HTML: {body}"
        );

        // Verify the DB record was not mutated: redirect_uris must be unchanged.
        let record = crate::db::get_oauth_client_by_id(&state.store, &client.app_id)
            .await
            .expect("db query ok")
            .expect("client must still exist");
        assert_eq!(
            record.redirect_uris,
            vec!["https://example.com/callback".to_string()],
            "Empty redirect_uris must not overwrite existing uris in the database"
        );
    }

    #[tokio::test]
    async fn test_web_update_form_rejects_fapi_exit() {
        // Regression for #743: selecting Standard for a FAPI client used to
        // move it to client_secret_basic without minting a secret, leaving it
        // unable to authenticate. The web form must refuse the transition and
        // leave the client untouched, matching the JSON API.
        let (app, state) = test_app().await;
        let user = create_test_user(&state.store, "web-update-fapi-exit@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let session_token = create_test_session_with(
            &state,
            TestSessionSpec {
                user_id: &user.id,
                email: &user.email,
                auth_id: Some(&auth_id),
                ..Default::default()
            },
        )
        .await;
        let client = create_test_client(
            &state.store,
            &user.id,
            TestClientSpec {
                token_endpoint_auth_method: Some(crate::db::TokenEndpointAuthMethod::PrivateKeyJwt),
                jwks: TestJwks::Shared,
                dpop_bound_access_tokens: true,
                fapi_profile: Some(crate::db::FapiProfile::Fapi2Security),
                with_secret: false,
                ..Default::default()
            },
        )
        .await;

        // The security-profile radio group always submits; "" selects Standard.
        let form_body =
            "name=Test%20App&redirect_uris=https%3A%2F%2Fexample.com%2Fcallback&fapi_profile=";
        let (status, body) = http_post_form(
            &app,
            &format!("/applications/{}", client.app_id),
            form_body,
            &[
                ("Cookie", &format!("__Host-vouch_session={session_token}")),
                ("Origin", "https://test.example.com"),
            ],
        )
        .await;
        assert!(
            !status.is_redirection(),
            "FAPI exit must not be applied, got {status}: {body}"
        );
        assert!(
            body.contains("cannot be changed to a standard profile"),
            "the error page must explain the refusal: {body}"
        );

        // Every FAPI-sensitive field must survive the rejected update.
        let record = crate::db::get_oauth_client_by_id(&state.store, &client.app_id)
            .await
            .expect("db query ok")
            .expect("client must still exist");
        assert_eq!(record.fapi_profile, crate::db::FapiProfile::Fapi2Security);
        assert_eq!(
            record.token_endpoint_auth_method,
            crate::db::TokenEndpointAuthMethod::PrivateKeyJwt
        );
        assert!(
            record.dpop_bound_access_tokens,
            "a rejected update must not clear the DPoP binding"
        );
        assert!(
            record.keys.as_ref().is_some_and(|k| k.inline().is_some()),
            "a rejected update must not drop the JWKS"
        );
    }

    // ========================================================================
    // #214 / FAPI-over-mTLS: the secret-minting guard must block *every* FAPI
    // client, not just `private_key_jwt`. An mTLS-FAPI client previously
    // slipped past the narrow `== PrivateKeyJwt` guard and minted a dead
    // `vouch_...` secret the token endpoint can never accept.
    // ========================================================================

    // Regression for #214: an mTLS-FAPI (`tls_client_auth`) client must NOT
    // be able to mint a client secret via direct POST. Previously the narrow
    // `== PrivateKeyJwt` guard let it through and rendered a plaintext
    // `SecretAddedTemplate` while persisting a dead secret row.
    //
    // `error_page` and `SecretAddedTemplate` both render as HTTP 200 HTML
    // (the `impl_template_into_response!` macro sets no status), so the
    // guard is verified by response content + persisted rows, not by status.
    #[tokio::test]
    async fn test_web_add_secret_mints_unusable_secret_for_mtls_fapi_client() {
        let (app, state) = test_app().await;
        let user = create_test_user(&state.store, "mtls-fapi-secret@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let session_token = create_test_session_with(
            &state,
            TestSessionSpec {
                user_id: &user.id,
                email: &user.email,
                auth_id: Some(&auth_id),
                ..Default::default()
            },
        )
        .await;
        let client = create_test_client(
            &state.store,
            &user.id,
            TestClientSpec {
                token_endpoint_auth_method: Some(crate::db::TokenEndpointAuthMethod::TlsClientAuth),
                tls_client_auth_subject_dn: Some("CN=test.example.com".to_string()),
                jwks: TestJwks::Shared,
                dpop_bound_access_tokens: true,
                fapi_profile: Some(crate::db::FapiProfile::Fapi2Security),
                with_secret: false,
                ..Default::default()
            },
        )
        .await;

        let cookie = format!("__Host-vouch_session={session_token}");
        let (_status, body) = http_post_form(
            &app,
            &format!("/applications/{}/secrets", client.app_id),
            "",
            &[("Origin", "https://test.example.com"), ("Cookie", &cookie)],
        )
        .await;

        assert!(
            !body.contains("vouch_"),
            "mTLS FAPI client must NOT receive a minted secret: {body}"
        );
        assert!(
            body.contains("FAPI clients do not use client secrets"),
            "the error page must explain that FAPI clients do not use secrets: {body}"
        );

        let secrets = crate::db::get_oauth_client_secrets(&state.store, &client.app_id)
            .await
            .expect("db query ok");
        assert!(
            secrets.is_empty(),
            "no secret rows should exist for an mTLS FAPI client, got {secrets:?}"
        );
    }

    // The self-signed mTLS variant (`self_signed_tls_client_auth`) is the
    // other FAPI auth method #214 made reachable; it must be blocked too.
    #[tokio::test]
    async fn test_web_add_secret_rejects_self_signed_mtls_fapi_client() {
        let (app, state) = test_app().await;
        let user = create_test_user(&state.store, "self-signed-mtls-fapi-secret@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let session_token = create_test_session_with(
            &state,
            TestSessionSpec {
                user_id: &user.id,
                email: &user.email,
                auth_id: Some(&auth_id),
                ..Default::default()
            },
        )
        .await;
        let client = create_test_client(
            &state.store,
            &user.id,
            TestClientSpec {
                token_endpoint_auth_method: Some(
                    crate::db::TokenEndpointAuthMethod::SelfSignedTlsClientAuth,
                ),
                tls_client_auth_subject_dn: Some("CN=test.example.com".to_string()),
                jwks: TestJwks::Shared,
                dpop_bound_access_tokens: true,
                fapi_profile: Some(crate::db::FapiProfile::Fapi2Security),
                with_secret: false,
                ..Default::default()
            },
        )
        .await;

        let cookie = format!("__Host-vouch_session={session_token}");
        let (_status, body) = http_post_form(
            &app,
            &format!("/applications/{}/secrets", client.app_id),
            "",
            &[("Origin", "https://test.example.com"), ("Cookie", &cookie)],
        )
        .await;

        assert!(
            !body.contains("vouch_"),
            "self-signed mTLS FAPI client must NOT receive a minted secret: {body}"
        );
        assert!(
            body.contains("FAPI clients do not use client secrets"),
            "the error page must explain that FAPI clients do not use secrets: {body}"
        );

        let secrets = crate::db::get_oauth_client_secrets(&state.store, &client.app_id)
            .await
            .expect("db query ok");
        assert!(
            secrets.is_empty(),
            "no secret rows should exist for a self-signed mTLS FAPI client, got {secrets:?}"
        );
    }

    // The originally-blocked `private_key_jwt` FAPI case must remain blocked
    // after widening the guard from `is_fapi() && == PrivateKeyJwt` to
    // `is_fapi()` — the wider net must not re-open the case it used to catch.
    #[tokio::test]
    async fn test_web_add_secret_rejects_private_key_jwt_fapi_client() {
        let (app, state) = test_app().await;
        let user = create_test_user(&state.store, "privkeyjwt-fapi-secret@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let session_token = create_test_session_with(
            &state,
            TestSessionSpec {
                user_id: &user.id,
                email: &user.email,
                auth_id: Some(&auth_id),
                ..Default::default()
            },
        )
        .await;
        let client = create_test_client(
            &state.store,
            &user.id,
            TestClientSpec {
                token_endpoint_auth_method: Some(crate::db::TokenEndpointAuthMethod::PrivateKeyJwt),
                jwks: TestJwks::Shared,
                dpop_bound_access_tokens: true,
                fapi_profile: Some(crate::db::FapiProfile::Fapi2Security),
                with_secret: false,
                ..Default::default()
            },
        )
        .await;

        let cookie = format!("__Host-vouch_session={session_token}");
        let (_status, body) = http_post_form(
            &app,
            &format!("/applications/{}/secrets", client.app_id),
            "",
            &[("Origin", "https://test.example.com"), ("Cookie", &cookie)],
        )
        .await;

        assert!(
            !body.contains("vouch_"),
            "private_key_jwt FAPI client must NOT receive a minted secret: {body}"
        );
        assert!(
            body.contains("FAPI clients do not use client secrets"),
            "the error page must explain that FAPI clients do not use secrets: {body}"
        );

        let secrets = crate::db::get_oauth_client_secrets(&state.store, &client.app_id)
            .await
            .expect("db query ok");
        assert!(
            secrets.is_empty(),
            "no secret rows should exist for a private_key_jwt FAPI client, got {secrets:?}"
        );
    }

    // No regression on the happy path: a non-FAPI Web client (the only kind
    // the "Add Secret" UI surfaces) must still be able to mint a second
    // secret and see the plaintext value rendered exactly once.
    #[tokio::test]
    async fn test_web_add_secret_succeeds_for_non_fapi_web_client() {
        let (app, state) = test_app().await;
        let user = create_test_user(&state.store, "non-fapi-web-secret@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let session_token = create_test_session_with(
            &state,
            TestSessionSpec {
                user_id: &user.id,
                email: &user.email,
                auth_id: Some(&auth_id),
                ..Default::default()
            },
        )
        .await;
        let client = create_test_oauth_client(&state.store, &user.id).await;

        let cookie = format!("__Host-vouch_session={session_token}");
        let (status, body) = http_post_form(
            &app,
            &format!("/applications/{}/secrets", client.app_id),
            "",
            &[("Origin", "https://test.example.com"), ("Cookie", &cookie)],
        )
        .await;

        assert!(
            status.is_success(),
            "non-FAPI Web client must be able to mint a secret, got {status}: {body}"
        );
        assert!(
            body.contains("vouch_"),
            "the response must render the freshly minted plaintext secret: {body}"
        );

        let secrets = crate::db::get_oauth_client_secrets(&state.store, &client.app_id)
            .await
            .expect("db query ok");
        assert_eq!(
            secrets.len(),
            2,
            "the new secret row must be persisted alongside the seeded one: {secrets:?}"
        );
    }

    // ========================================================================
    // Org-scoped app creation: the owner's `org_id` must come from the same
    // `get_user_by_id` load the existence decision is made on. A concurrent
    // `delete_user` between the extractor's `load_active_user` read and the
    // handler's second `get_user_by_id` read used to let `Ok(None)` fall
    // through to `None`, persisting an organization-scoped client with a NULL
    // `org_id` — detached from its owning org and permanently unmanageable
    // (every management endpoint gates on `client.user_id == caller`, and the
    // owner is gone). For a confidential client the secret kept minting
    // `client_credentials` tokens that introspection reported `active: true`.
    // ========================================================================

    /// The `get_user_by_id_test_hook` is inactive while the target user id is
    /// unset, so the `get_user_by_id` calls made by `create_test_user_in_org`
    /// and `create_test_session_with`'s `resolve_session_snapshot` during
    /// setup run for real and never short-circuit. Once the test sets the
    /// target, the hook forces `Ok(None)` on every subsequent read for that
    /// user after the first — the first being the `SignedInSession`
    /// extractor's `load_active_user`, which must still find the user and
    /// let the request through to the handler.
    fn install_user_vanish_hook(
        target: Arc<Mutex<Option<String>>>,
    ) -> (Arc<AtomicU32>, GetUserByIdTestHook) {
        let calls = Arc::new(AtomicU32::new(0));
        let calls_for_hook = calls.clone();
        let hook: GetUserByIdTestHook = Arc::new(move |uid: &str| {
            let guard = target.lock().expect("hook target lock poisoned");
            if guard.as_deref() != Some(uid) {
                return false;
            }
            drop(guard);
            // 0 = extractor's `load_active_user` (must read the real user);
            // >=1 = the handler's second read and any later read — force the
            // "user vanished mid-request" outcome (`Ok(None)`) there.
            let n = calls_for_hook.fetch_add(1, Ordering::SeqCst);
            n >= 1
        });
        (calls, hook)
    }

    /// Regression: creating an organization-scoped OAuth application while the
    /// owning user is deleted mid-request must be rejected — not persisted
    /// with a NULL `org_id`. The forced `Ok(None)` lands on the handler's
    /// read (the 2nd `get_user_by_id` for the user; the 1st is the
    /// extractor's `load_active_user`), and the post-request call count must
    /// be exactly 2 to prove the rejection came from the handler, not a
    /// too-early fire that the extractor caught.
    #[tokio::test]
    async fn test_web_create_org_scoped_rejects_when_user_vanishes_mid_request() {
        let target: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let target_for_hook = target.clone();
        let (calls, hook) = install_user_vanish_hook(target_for_hook);
        let (app, state) = test_app_with_modify_hook(|store| {
            store.set_get_user_by_id_test_hook(hook);
        })
        .await;

        let org = create_test_org(&state.store, "race-create.example.com").await;
        let user =
            create_test_user_in_org(&state.store, "race-create@example.com", &org.id, false).await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let session_token = create_test_session_with(
            &state,
            TestSessionSpec {
                user_id: &user.id,
                email: &user.email,
                auth_id: Some(&auth_id),
                ..Default::default()
            },
        )
        .await;
        let cookie = format!("__Host-vouch_session={session_token}");

        // Activate the hook only now — every `get_user_by_id` during setup
        // ran with the target unset and so was a no-op.
        *target.lock().expect("activate hook") = Some(user.id.clone());

        // Submit a confidential, organization-scoped application. The bug
        // minted and rendered a `vouch_` secret here and persisted a client
        // with `org_id = NULL`.
        let form_body = "name=Zombie+Guard&application_type=web&redirect_uris=https%3A%2F%2Fexample.com%2Fcallback&access_scope=organization";
        let (status, body) = http_post_form(
            &app,
            "/applications/new",
            form_body,
            &[("Cookie", &cookie), ("Origin", "https://test.example.com")],
        )
        .await;

        assert!(
            !body.contains("vouch_"),
            "no client secret should be minted when the owner vanishes mid-request: {status} {body}"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "expected exactly two get_user_by_id calls (extractor + handler); \
             the forced Ok(None) must land on the handler's read, got {status} {body}"
        );
        let clients = crate::db::get_oauth_clients_for_user(&state.store, &user.id)
            .await
            .expect("db query ok");
        assert!(
            clients.is_empty(),
            "no org-scoped client must be persisted when the owner vanishes mid-request, got {clients:?}"
        );
    }

    /// No regression: an organization-scoped create whose owner is present
    /// must still succeed and persist the client attached to the owner's org
    /// (a non-NULL `org_id`).
    #[tokio::test]
    async fn test_web_create_org_scoped_succeeds_and_persists_org_id() {
        let (app, state) = test_app().await;
        let org = create_test_org(&state.store, "org-create-happy.example.com").await;
        let user =
            create_test_user_in_org(&state.store, "org-create@example.com", &org.id, false).await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let session_token = create_test_session_with(
            &state,
            TestSessionSpec {
                user_id: &user.id,
                email: &user.email,
                auth_id: Some(&auth_id),
                ..Default::default()
            },
        )
        .await;
        let cookie = format!("__Host-vouch_session={session_token}");

        let form_body = "name=Tethered+App&application_type=web&redirect_uris=https%3A%2F%2Fexample.com%2Fcallback&access_scope=organization";
        let (status, body) = http_post_form(
            &app,
            "/applications/new",
            form_body,
            &[("Cookie", &cookie), ("Origin", "https://test.example.com")],
        )
        .await;

        assert!(
            status.is_success(),
            "happy-path org create should succeed: {status}: {body}"
        );
        assert!(
            body.contains("vouch_"),
            "the freshly minted secret should render on success: {body}"
        );

        let clients = crate::db::get_oauth_clients_for_user(&state.store, &user.id)
            .await
            .expect("db query ok");
        assert_eq!(
            clients.len(),
            1,
            "exactly one client should be persisted: {clients:?}"
        );
        let client = clients.first().expect("exactly one client asserted above");
        assert_eq!(client.access_scope, crate::db::AccessScope::Organization);
        assert_eq!(
            client.org_id.as_deref(),
            Some(org.id.as_str()),
            "the client must be attached to the owner's org, not NULL: {client:?}"
        );
    }

    /// Regression: updating an existing organization-scoped application while
    /// the owner is deleted mid-request must reject (500) and leave the
    /// client's `org_id` attached to its org. The bug wiped a non-NULL
    /// `org_id` to NULL on this path.
    #[tokio::test]
    async fn test_web_update_org_scoped_rejects_when_user_vanishes_mid_request() {
        let target: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let target_for_hook = target.clone();
        let (calls, hook) = install_user_vanish_hook(target_for_hook);
        let (app, state) = test_app_with_modify_hook(|store| {
            store.set_get_user_by_id_test_hook(hook);
        })
        .await;

        let org = create_test_org(&state.store, "race-update.example.com").await;
        let user =
            create_test_user_in_org(&state.store, "race-update@example.com", &org.id, false).await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let session_token = create_test_session_with(
            &state,
            TestSessionSpec {
                user_id: &user.id,
                email: &user.email,
                auth_id: Some(&auth_id),
                ..Default::default()
            },
        )
        .await;
        let cookie = format!("__Host-vouch_session={session_token}");

        // Seed an existing org-scoped client owned by the user, attached to
        // the org — the record the buggy update wiped to `org_id = NULL`.
        let client = create_test_client(
            &state.store,
            &user.id,
            crate::test_utils::TestClientSpec {
                name: "Tethered".to_string(),
                access_scope: crate::db::AccessScope::Organization,
                org_id: Some(org.id.clone()),
                ..Default::default()
            },
        )
        .await;

        *target.lock().expect("activate hook") = Some(user.id.clone());

        let form_body = "name=Tethered+Renamed&redirect_uris=https%3A%2F%2Fexample.com%2Fcallback&access_scope=organization";
        let (status, _body) = http_post_form(
            &app,
            &format!("/applications/{}", client.app_id),
            form_body,
            &[("Cookie", &cookie), ("Origin", "https://test.example.com")],
        )
        .await;

        assert_eq!(
            status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "org-scoped update with a vanished owner must reject with 500, got {status}"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "the forced Ok(None) must land on the handler's read (extractor + handler = 2 calls)"
        );

        // The client must be untouched: name unchanged and still attached
        // to the org (the bug wiped `org_id` to NULL here).
        let record = crate::db::get_oauth_client_by_id(&state.store, &client.app_id)
            .await
            .expect("db query ok")
            .expect("client must still exist");
        assert_eq!(
            record.name, "Tethered",
            "a rejected update must not rename the client"
        );
        assert_eq!(record.access_scope, crate::db::AccessScope::Organization);
        assert_eq!(
            record.org_id.as_deref(),
            Some(org.id.as_str()),
            "a rejected update must not wipe the client's org_id to NULL: {record:?}"
        );
    }

    /// No regression: an organization-scoped update whose owner is present
    /// must still apply (rename) and keep the client attached to its org.
    #[tokio::test]
    async fn test_web_update_org_scoped_succeeds_and_preserves_org_id() {
        let (app, state) = test_app().await;
        let org = create_test_org(&state.store, "org-update-happy.example.com").await;
        let user =
            create_test_user_in_org(&state.store, "org-update@example.com", &org.id, false).await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let session_token = create_test_session_with(
            &state,
            TestSessionSpec {
                user_id: &user.id,
                email: &user.email,
                auth_id: Some(&auth_id),
                ..Default::default()
            },
        )
        .await;
        let cookie = format!("__Host-vouch_session={session_token}");

        let client = create_test_client(
            &state.store,
            &user.id,
            crate::test_utils::TestClientSpec {
                name: "Tethered".to_string(),
                access_scope: crate::db::AccessScope::Organization,
                org_id: Some(org.id.clone()),
                ..Default::default()
            },
        )
        .await;

        let form_body = "name=Tethered+Renamed&redirect_uris=https%3A%2F%2Fexample.com%2Fcallback&access_scope=organization";
        let (status, _body) = http_post_form(
            &app,
            &format!("/applications/{}", client.app_id),
            form_body,
            &[("Cookie", &cookie), ("Origin", "https://test.example.com")],
        )
        .await;
        assert_eq!(
            status,
            StatusCode::SEE_OTHER,
            "happy-path org update should redirect: {status}"
        );

        let record = crate::db::get_oauth_client_by_id(&state.store, &client.app_id)
            .await
            .expect("db query ok")
            .expect("client must still exist");
        assert_eq!(record.name, "Tethered Renamed", "the rename must apply");
        assert_eq!(record.access_scope, crate::db::AccessScope::Organization);
        assert_eq!(
            record.org_id.as_deref(),
            Some(org.id.as_str()),
            "the update must keep the client attached to its org: {record:?}"
        );
    }

    /// Negative control: with the vanish hook installed, a *personal*-scoped
    /// create must still succeed — the fix only reads the user for
    /// organization-scoped apps (`if access_scope == AccessScope::Organization`),
    /// so the handler never issues the second `get_user_by_id` for a personal
    /// app, the hook never fires past the extractor, and the create proceeds
    /// normally. Pins that the gating is correct and the hook does not
    /// over-fire on the personal path.
    #[tokio::test]
    async fn test_web_create_personal_scoped_unaffected_by_vanish_hook() {
        let target: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let target_for_hook = target.clone();
        let (calls, hook) = install_user_vanish_hook(target_for_hook);
        let (app, state) = test_app_with_modify_hook(|store| {
            store.set_get_user_by_id_test_hook(hook);
        })
        .await;

        // A user with no org: personal scope is the only valid choice.
        let user = create_test_user(&state.store, "personal-hook@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let session_token = create_test_session_with(
            &state,
            TestSessionSpec {
                user_id: &user.id,
                email: &user.email,
                auth_id: Some(&auth_id),
                ..Default::default()
            },
        )
        .await;
        let cookie = format!("__Host-vouch_session={session_token}");

        *target.lock().expect("activate hook") = Some(user.id.clone());

        let form_body = "name=Lone+App&application_type=web&redirect_uris=https%3A%2F%2Fexample.com%2Fcallback&access_scope=personal";
        let (status, body) = http_post_form(
            &app,
            "/applications/new",
            form_body,
            &[("Cookie", &cookie), ("Origin", "https://test.example.com")],
        )
        .await;

        assert!(
            status.is_success(),
            "personal create must succeed with the vanish hook installed: {status}: {body}"
        );
        assert!(
            body.contains("vouch_"),
            "the personal create must mint and render a secret: {body}"
        );
        // Only the extractor's `load_active_user` calls `get_user_by_id` for
        // a personal create — the handler does not. The hook's counter must
        // show exactly one call, so the hook never forced `Ok(None)`.
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "personal create must not trigger the handler's second get_user_by_id: {body}"
        );

        let clients = crate::db::get_oauth_clients_for_user(&state.store, &user.id)
            .await
            .expect("db query ok");
        assert_eq!(
            clients.len(),
            1,
            "the personal client must be persisted: {clients:?}"
        );
        let client = clients.first().expect("one personal client asserted above");
        assert_eq!(client.access_scope, crate::db::AccessScope::Personal);
        assert!(
            client.org_id.is_none(),
            "a personal client has no org_id, not a NULL-by-race org_id: {client:?}"
        );
    }

    // ========================================================================
    // POST /applications/:id/delete — ClientDeleted audit event
    // ========================================================================

    /// `delete_application_form` must record a `ClientDeleted`
    /// (`oauth_client_deleted`) audit event after the delete commits, mirroring
    /// `delete_application_api` and the RFC 7592 delete path. Regression for the
    /// audit-parity gap on the web-form surface.
    #[tokio::test]
    async fn test_web_delete_application_records_client_deleted_audit_event() {
        let (app, state) = test_app().await;

        let user = create_test_user(&state.store, "web-audit-delete@example.com").await;
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
        let cookie = format!("__Host-vouch_session={token}");
        let client = create_test_oauth_client(&state.store, &user.id).await;

        let (status, _body) = http_post_form(
            &app,
            &format!("/applications/{}/delete", client.app_id),
            "",
            &[("Origin", "https://test.example.com"), ("Cookie", &cookie)],
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER, "delete should redirect");

        let events = state
            .audit
            .query_events(&crate::db::AuditEventFilter {
                event_types: Some(vec!["oauth_client_deleted".to_string()]),
                user_id: Some(user.id.clone()),
                ..Default::default()
            })
            .await
            .expect("query audit events");
        assert_eq!(
            events.len(),
            1,
            "web delete must write exactly one audit event; got {}",
            events.len()
        );
    }

    /// The web-form `ClientDeleted` event's org-domain attribution must fall
    /// through to the client's own org when the owning user has no org.
    /// Regression for the pre-resolution step (duplicated in the web handler):
    /// the client doc is already deleted when the event is recorded, so a naive
    /// client-org lookup would miss. Mirrors the RFC 7592 regression test.
    #[tokio::test]
    async fn test_web_delete_application_attributes_org_domain_for_org_owned_client() {
        let (app, state) = test_app().await;

        let org = create_test_org(&state.store, "web-org-owned-deleted.example").await;
        let owner = create_test_user(&state.store, "solo-owner-web@personal.example").await;
        let auth_id = create_test_authenticator(&state.store, &owner.id).await;
        let token = create_test_session_with(
            &state,
            TestSessionSpec {
                user_id: &owner.id,
                email: &owner.email,
                auth_id: Some(&auth_id),
                ..Default::default()
            },
        )
        .await;
        let cookie = format!("__Host-vouch_session={token}");
        let client = create_test_client(
            &state.store,
            &owner.id,
            TestClientSpec {
                org_id: Some(org.id.clone()),
                ..Default::default()
            },
        )
        .await;

        let (status, _body) = http_post_form(
            &app,
            &format!("/applications/{}/delete", client.app_id),
            "",
            &[("Origin", "https://test.example.com"), ("Cookie", &cookie)],
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER, "delete should redirect");

        let events = state
            .audit
            .query_events(&crate::db::AuditEventFilter {
                event_types: Some(vec!["oauth_client_deleted".to_string()]),
                user_id: Some(owner.id.clone()),
                ..Default::default()
            })
            .await
            .expect("query audit events");
        assert_eq!(events.len(), 1, "delete must write exactly one audit event");
        let event = events.first().expect("delete must write one audit event");
        assert_eq!(
            event.email_domain.as_deref(),
            Some("web-org-owned-deleted.example"),
            "the client's own org must be attributed even though the owning user \
             has no org and the client doc is already deleted by the time the \
             event is recorded"
        );
    }
}
