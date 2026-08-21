// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Web UI handlers for OAuth Application Registration.
//!
//! These handlers return HTML responses via Askama templates for the
//! self-service application management portal.

use crate::AppState;
use crate::db::{self, AccessScope, UpdateOAuthClientParams};
use axum::{
    Form,
    extract::{Path, State},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::cookie::CookieJar;
use std::sync::Arc;

use super::types::{
    ApplicationCreateTemplate, ApplicationCreatedTemplate, ApplicationDetailTemplate,
    ApplicationErrorTemplate, ApplicationInfo, ApplicationUnauthorizedTemplate,
    ApplicationsListTemplate, CreateApplicationForm, SecretAddedTemplate, SecretInfo,
    UpdateApplicationForm, UsageStat,
};
use super::validate::{
    AppValidationError, CreateAppContext, CreateAppInput, UpdateAppInput, build_create_params,
    compute_fapi_update_fields, validate_create_application, validate_update_fapi,
    validate_update_format,
};
use super::{
    extract_auth_from_cookie, generate_client_secret, parse_redirect_uris, parse_resource_uris,
};
use crate::handlers::hash_token;
use crate::infra::i18n::Tr;

/// Render the standard application error page from translation keys, resolving
/// them against the request locale.
fn error_page(title: Tr<'_>, message: Tr<'_>, back_url: impl Into<String>) -> Response {
    ApplicationErrorTemplate {
        title: title.to_string(),
        message: message.to_string(),
        back_url: back_url.into(),
    }
    .into_response()
}

/// Render a shared validation failure as the standard error page. The title is
/// localized; `err.message()` stays English — it is shared with the JSON API
/// path (`ServiceError`), which is English by spec (RFC 6749 §5.2).
fn validation_error_response(err: &AppValidationError, back_url: String) -> Response {
    ApplicationErrorTemplate {
        title: Tr::new("apps-error-title-invalid-input").to_string(),
        message: err.message(),
        back_url,
    }
    .into_response()
}

/// List user's applications.
/// GET /applications
pub(crate) async fn list_applications_page(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Response {
    let Some(auth) = extract_auth_from_cookie(&state, &jar).await else {
        return ApplicationUnauthorizedTemplate.into_response();
    };

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
pub(crate) async fn create_application_page(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Response {
    let Some(auth) = extract_auth_from_cookie(&state, &jar).await else {
        return ApplicationUnauthorizedTemplate.into_response();
    };

    let user_has_org = auth.has_org;
    ApplicationCreateTemplate { auth, user_has_org }.into_response()
}

/// Create a new application.
/// POST /applications/new
pub(crate) async fn create_application_form(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Form(form): Form<CreateApplicationForm>,
) -> Response {
    let Some(auth) = extract_auth_from_cookie(&state, &jar).await else {
        return ApplicationUnauthorizedTemplate.into_response();
    };

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

    // All input validated — now fetch org_id from DB (only needed for org-scoped apps).
    // A lookup failure must not fall through to `None`: for an
    // organization-scoped application that persists a NULL org_id, creating an
    // app detached from the org that should own it.
    let user_org_id = if auth.has_org {
        match db::get_user_by_id(&state.store, user_id).await {
            Ok(Some(user)) => user.org_id,
            Ok(None) => None,
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

    let org_id = if access_scope == AccessScope::Organization {
        user_org_id.as_deref()
    } else {
        None
    };

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
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path(app_id): Path<String>,
) -> Response {
    let Some(auth) = extract_auth_from_cookie(&state, &jar).await else {
        return ApplicationUnauthorizedTemplate.into_response();
    };

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
    let now = jiff::Timestamp::now();
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

    // Get usage stats
    let usage_stats = match db::get_oauth_usage_stats(&state.audit, &app_id, None).await {
        Ok(stats) => stats
            .into_iter()
            .map(|s| UsageStat {
                event_type: s.event_type,
                count: s.count,
            })
            .collect(),
        Err(_) => vec![],
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
    jar: CookieJar,
    Path(app_id): Path<String>,
    Form(form): Form<UpdateApplicationForm>,
) -> Response {
    let Some(auth) = extract_auth_from_cookie(&state, &jar).await else {
        return ApplicationUnauthorizedTemplate.into_response();
    };

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

    // Get user's org_id for org-scoped apps. A lookup failure must not fall
    // through to `None`: for an organization-scoped application that persists
    // a NULL org_id, silently detaching it from the org that owns it.
    let user_org_id = if auth.has_org {
        match db::get_user_by_id(&state.store, user_id).await {
            Ok(Some(user)) => user.org_id,
            Ok(None) => None,
            Err(e) => {
                tracing::error!("Failed to load user {user_id} for app org scoping: {e}");
                return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
    } else {
        None
    };

    // Set org_id only for organization-scoped apps
    let org_id = if access_scope == Some(AccessScope::Organization) {
        user_org_id.as_deref()
    } else {
        None
    };

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
            jwks: fapi.jwks,
            jwks_uri: fapi.jwks_uri,
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
    jar: CookieJar,
    Path(app_id): Path<String>,
) -> Response {
    let Some(auth) = extract_auth_from_cookie(&state, &jar).await else {
        return ApplicationUnauthorizedTemplate.into_response();
    };

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

    // Delete the application
    if let Err(e) = db::delete_oauth_client(&state.store, &app_id).await {
        tracing::error!("Failed to delete application: {}", e);
        return error_page(
            Tr::new("apps-error-title-error"),
            Tr::new("apps-error-delete-failed"),
            format!("/applications/{}", app_id),
        );
    }

    tracing::info!("Deleted OAuth application: {}", client.client_id);

    Redirect::to("/applications").into_response()
}

/// Add a new client secret.
/// POST /applications/:id/secrets
pub(crate) async fn add_secret_form(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path(app_id): Path<String>,
) -> Response {
    let Some(auth) = extract_auth_from_cookie(&state, &jar).await else {
        return ApplicationUnauthorizedTemplate.into_response();
    };

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

    if client.is_fapi()
        && client.token_endpoint_auth_method == db::TokenEndpointAuthMethod::PrivateKeyJwt
    {
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
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path((app_id, secret_id)): Path<(String, String)>,
) -> Response {
    let Some(auth) = extract_auth_from_cookie(&state, &jar).await else {
        return ApplicationUnauthorizedTemplate.into_response();
    };

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

    let now = jiff::Timestamp::now();
    let all_secrets = db::get_oauth_client_secrets(&state.store, &app_id)
        .await
        .unwrap_or_default();
    let other_active = all_secrets
        .iter()
        .filter(|s| s.id != secret_id && s.is_valid(&now))
        .count();

    if other_active == 0 {
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
    use axum::http::StatusCode;

    use crate::test_utils::*;

    // Web handlers use Path<String> (not ValidPath<ValidUuid>) so that invalid
    // UUIDs flow through to the db lookup and produce HTML error pages, not
    // JSON 400s. These tests guard against accidentally switching to ValidPath.

    #[tokio::test]
    async fn test_detail_page_invalid_uuid_returns_html_not_json() {
        let (app, _state) = test_app().await;

        let resp = http_get_full(&app, "/applications/not-a-uuid", &[]).await;

        // Should NOT be 400 (which ValidPath would produce).
        // Without a session cookie the handler returns the unauthorized template (200).
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
        let (app, _state) = test_app().await;

        let (status, body) = http_post_form(&app, "/applications/not-a-uuid/delete", "", &[]).await;

        assert_ne!(status, StatusCode::BAD_REQUEST);
        assert!(
            body.contains("</html>") || body.contains("<!DOCTYPE"),
            "expected HTML response, got: {body}"
        );
    }

    #[tokio::test]
    async fn test_add_secret_page_invalid_uuid_returns_html_not_json() {
        let (app, _state) = test_app().await;

        let (status, body) =
            http_post_form(&app, "/applications/not-a-uuid/secrets", "", &[]).await;

        assert_ne!(status, StatusCode::BAD_REQUEST);
        assert!(
            body.contains("</html>") || body.contains("<!DOCTYPE"),
            "expected HTML response, got: {body}"
        );
    }

    #[tokio::test]
    async fn test_delete_secret_page_invalid_uuids_returns_html_not_json() {
        let (app, _state) = test_app().await;

        let (status, body) = http_post_form(
            &app,
            "/applications/not-a-uuid/secrets/also-bad/delete",
            "",
            &[],
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

    #[tokio::test]
    async fn test_web_update_form_rejects_empty_name() {
        // Guard: submitting the web form with an empty name must be rejected
        // with a validation error page and must NOT persist the empty value.
        let (app, state) = test_app().await;
        let user = create_test_user(&state.store, "web-update-empty-name@example.com").await;
        let auth_id = create_test_authenticator(&state.store, &user.id).await;
        let session_token = create_test_session(&state, &user.id, &user.email, &auth_id).await;
        let client = create_test_oauth_client(&state.store, &user.id).await;

        // Submit the web update form with an empty name.
        let form_body = "name=&redirect_uris=https%3A%2F%2Fexample.com%2Fcallback";
        let (status, body) = http_post_form(
            &app,
            &format!("/applications/{}", client.app_id),
            form_body,
            &[("Cookie", &format!("__Host-vouch_session={session_token}"))],
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
        let session_token = create_test_session(&state, &user.id, &user.email, &auth_id).await;
        let client = create_test_oauth_client(&state.store, &user.id).await;

        // Submit with a valid name but blank redirect_uris textarea.
        let form_body = "name=Test+App&redirect_uris=";
        let (status, body) = http_post_form(
            &app,
            &format!("/applications/{}", client.app_id),
            form_body,
            &[("Cookie", &format!("__Host-vouch_session={session_token}"))],
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
        let session_token = create_test_session(&state, &user.id, &user.email, &auth_id).await;
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
            &[("Cookie", &format!("__Host-vouch_session={session_token}"))],
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
            record.jwks.is_some(),
            "a rejected update must not drop the JWKS"
        );
    }
}
