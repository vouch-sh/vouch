// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Web UI handlers for OAuth Application Registration.
//!
//! These handlers return HTML responses via Askama templates for the
//! self-service application management portal.

use crate::AppState;
use crate::db::{
    self, AccessScope, CreateOAuthClientParams, FapiProfile, JwsAlgorithm, RegistrationSource,
    TokenEndpointAuthMethod, UpdateOAuthClientParams,
};
use crate::infra::i18n::PageContext;
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
    AppValidationError, CreateAppInput, UpdateAppInput, validate_create_application,
    validate_update_fapi, validate_update_format,
};
use super::{
    MAX_ACTIVE_SECRETS, extract_auth_from_cookie, generate_client_secret, parse_redirect_uris,
    parse_resource_uris,
};
use crate::handlers::hash_token;

/// Render a shared validation failure as the standard error page.
fn validation_error_response(err: &AppValidationError, back_url: String) -> Response {
    ApplicationErrorTemplate {
        page: PageContext::current(),
        title: "Invalid Input".to_string(),
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
        return ApplicationUnauthorizedTemplate {
            page: PageContext::current(),
        }
        .into_response();
    };

    let user_id = auth.user_id.as_deref().unwrap_or_default();
    let applications = match db::get_oauth_clients_for_user(&state.store, user_id).await {
        Ok(apps) => apps.into_iter().map(ApplicationInfo::from).collect(),
        Err(e) => {
            tracing::error!("Failed to list applications: {}", e);
            return ApplicationErrorTemplate {
                page: PageContext::current(),
                title: "Error".to_string(),
                message: "Failed to load applications.".to_string(),
                back_url: "/".to_string(),
            }
            .into_response();
        }
    };

    ApplicationsListTemplate {
        page: PageContext::current(),
        applications,
        auth,
    }
    .into_response()
}

/// Show create application form.
/// GET /applications/new
pub(crate) async fn create_application_page(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Response {
    let Some(auth) = extract_auth_from_cookie(&state, &jar).await else {
        return ApplicationUnauthorizedTemplate {
            page: PageContext::current(),
        }
        .into_response();
    };

    let user_has_org = auth.has_org;
    ApplicationCreateTemplate {
        page: PageContext::current(),
        auth,
        user_has_org,
    }
    .into_response()
}

/// Create a new application.
/// POST /applications/new
#[expect(
    clippy::too_many_lines,
    reason = "axum handler; linear application-creation flow with inline error templates"
)]
pub(crate) async fn create_application_form(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Form(form): Form<CreateApplicationForm>,
) -> Response {
    let Some(auth) = extract_auth_from_cookie(&state, &jar).await else {
        return ApplicationUnauthorizedTemplate {
            page: PageContext::current(),
        }
        .into_response();
    };

    let user_id = auth.user_id.as_deref().unwrap_or_default();

    // Parse textarea inputs, then run the shared format validation
    let redirect_uris = parse_redirect_uris(&form.redirect_uris);
    let resource_uris = parse_resource_uris(form.resource_uris.as_deref());

    let validated = match validate_create_application(CreateAppInput {
        name: &form.name,
        application_type: &form.application_type,
        redirect_uris: &redirect_uris,
        resource_uris: &resource_uris,
        fapi_profile: form.fapi_profile.as_deref(),
        jwks: form.jwks.as_deref(),
        jwks_uri: form.jwks_uri.as_deref(),
    }) {
        Ok(v) => v,
        Err(e) => return validation_error_response(&e, "/applications/new".to_string()),
    };
    let name = validated.name;
    let app_type = validated.app_type;
    let is_fapi = validated.is_fapi;
    let jwks_value = validated.jwks;
    let jwks_uri_trimmed = validated.jwks_uri;

    // Parse and validate access scope
    let access_scope = form.access_scope.parse::<AccessScope>().unwrap_or_default();

    // Validate: Organization scope requires user to have an org
    if access_scope == AccessScope::Organization && !auth.has_org {
        return ApplicationErrorTemplate {
            page: PageContext::current(),
            title: "Invalid Input".to_string(),
            message: "Organization scope requires organization membership.".to_string(),
            back_url: "/applications/new".to_string(),
        }
        .into_response();
    }

    // All input validated — now fetch org_id from DB (only needed for org-scoped apps)
    let user_org_id = if auth.has_org {
        match db::get_user_by_id(&state.store, user_id).await {
            Ok(Some(user)) => user.org_id,
            _ => None,
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
        &CreateOAuthClientParams {
            user_id: Some(user_id),
            name,
            description: form.description.as_deref(),
            application_type: app_type,
            redirect_uris: &redirect_uris,
            access_scope,
            org_id,
            resource_uris: &resource_uris,
            token_endpoint_auth_method: if is_fapi {
                Some(TokenEndpointAuthMethod::PrivateKeyJwt)
            } else {
                None
            },
            jwks: if is_fapi { jwks_value.as_ref() } else { None },
            jwks_uri: if is_fapi { jwks_uri_trimmed } else { None },
            fapi_profile: if is_fapi {
                Some(FapiProfile::Fapi2Security)
            } else {
                None
            },
            dpop_bound_access_tokens: if is_fapi { Some(true) } else { None },
            grant_types: None,
            response_types: None,
            software_id: None,
            software_version: None,
            registration_source: RegistrationSource::Manual,
            registration_access_token_hash: None,
            registration_metadata: None,
            id_token_signed_response_alg: JwsAlgorithm::Rs256,
            tls_client_auth_subject_dn: None,
            tls_client_auth_san_dns: None,
            tls_client_auth_san_uri: None,
            tls_client_auth_san_ip: None,
            tls_client_auth_san_email: None,
            tls_client_certificate_bound_access_tokens: None,
            authorization_signed_response_alg: None,
            introspection_signed_response_alg: None,
            request_object_signing_alg: None,
            require_signed_request_object: None,
            userinfo_signed_response_alg: None,
            request_uris: None,
        },
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to create application: {}", e);
            return ApplicationErrorTemplate {
                page: PageContext::current(),
                title: "Error".to_string(),
                message: "Failed to create application.".to_string(),
                back_url: "/applications/new".to_string(),
            }
            .into_response();
        }
    };

    // Generate client secret for confidential clients (skip for FAPI — they use private_key_jwt)
    let client_secret = if app_type.requires_secret() && !is_fapi {
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
            tracing::error!("Failed to create client secret: {}", e);
            // Clean up the client
            if let Err(cleanup_err) = db::delete_oauth_client(&state.store, &client.id).await {
                tracing::warn!(
                    "Failed to clean up OAuth client after secret creation failure: {cleanup_err}"
                );
            }
            return ApplicationErrorTemplate {
                page: PageContext::current(),
                title: "Error".to_string(),
                message: "Failed to create application.".to_string(),
                back_url: "/applications/new".to_string(),
            }
            .into_response();
        }

        Some(secret)
    } else {
        None
    };

    tracing::info!("Created OAuth application: {} ({})", name, client_id);

    ApplicationCreatedTemplate {
        page: PageContext::current(),
        name: name.to_string(),
        client_id,
        client_secret,
        application_type: form.application_type,
        requires_secret: app_type.requires_secret() && !is_fapi,
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
        return ApplicationUnauthorizedTemplate {
            page: PageContext::current(),
        }
        .into_response();
    };

    let user_id = auth.user_id.as_deref().unwrap_or_default();

    // Get the application
    let client = match db::get_oauth_client_by_id(&state.store, &app_id).await {
        Ok(Some(c)) if c.user_id.as_deref() == Some(user_id) => c,
        Ok(Some(_)) => {
            return ApplicationErrorTemplate {
                page: PageContext::current(),
                title: "Not Found".to_string(),
                message: "Application not found.".to_string(),
                back_url: "/applications".to_string(),
            }
            .into_response();
        }
        Ok(None) => {
            return ApplicationErrorTemplate {
                page: PageContext::current(),
                title: "Not Found".to_string(),
                message: "Application not found.".to_string(),
                back_url: "/applications".to_string(),
            }
            .into_response();
        }
        Err(e) => {
            tracing::error!("Failed to get application: {}", e);
            return ApplicationErrorTemplate {
                page: PageContext::current(),
                title: "Error".to_string(),
                message: "Failed to load application.".to_string(),
                back_url: "/applications".to_string(),
            }
            .into_response();
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
        page: PageContext::current(),
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
        return ApplicationUnauthorizedTemplate {
            page: PageContext::current(),
        }
        .into_response();
    };

    let user_id = auth.user_id.as_deref().unwrap_or_default();

    // Verify ownership
    let client = match db::get_oauth_client_by_id(&state.store, &app_id).await {
        Ok(Some(c)) if c.user_id.as_deref() == Some(user_id) => c,
        _ => {
            return ApplicationErrorTemplate {
                page: PageContext::current(),
                title: "Not Found".to_string(),
                message: "Application not found.".to_string(),
                back_url: "/applications".to_string(),
            }
            .into_response();
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

    // Parse access scope if provided
    let access_scope = form
        .access_scope
        .as_ref()
        .and_then(|s| s.parse::<AccessScope>().ok());

    // Validate: Organization scope requires user to have an org
    if access_scope == Some(AccessScope::Organization) && !auth.has_org {
        return ApplicationErrorTemplate {
            page: PageContext::current(),
            title: "Invalid Input".to_string(),
            message: "Organization scope requires organization membership.".to_string(),
            back_url: format!("/applications/{}", app_id),
        }
        .into_response();
    }

    // Get user's org_id for org-scoped apps
    let user_org_id = if auth.has_org {
        match db::get_user_by_id(&state.store, user_id).await {
            Ok(Some(user)) => user.org_id,
            _ => None,
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

    // Parse textarea inputs, then run the shared format validation
    let redirect_uris = parse_redirect_uris(&form.redirect_uris);
    let resource_uris = parse_resource_uris(form.resource_uris.as_deref());

    let validated = match validate_update_format(UpdateAppInput {
        redirect_uris: Some(&redirect_uris),
        resource_uris: Some(&resource_uris),
        fapi_profile: form.fapi_profile.as_deref(),
        jwks: form.jwks.as_deref(),
        jwks_uri: form.jwks_uri.as_deref(),
    }) {
        Ok(v) => v,
        Err(e) => return validation_error_response(&e, format!("/applications/{}", app_id)),
    };

    // FAPI rules that depend on the existing client record
    if let Err(e) = validate_update_fapi(&validated, &client) {
        return validation_error_response(&e, format!("/applications/{}", app_id));
    }
    let is_fapi = validated.is_fapi;
    let jwks_value = validated.jwks;
    let jwks_uri_trimmed = validated.jwks_uri;

    // Compute FAPI-related values: merge form values with existing client values
    let fapi_profile = if is_fapi {
        FapiProfile::Fapi2Security
    } else {
        FapiProfile::None
    };

    let token_endpoint_auth_method = if is_fapi {
        TokenEndpointAuthMethod::PrivateKeyJwt
    } else if !is_fapi && client.is_fapi() {
        // Transitioning from FAPI to Standard: reset to default
        TokenEndpointAuthMethod::ClientSecretBasic
    } else {
        client.token_endpoint_auth_method
    };

    // Resolve final JWKS values: use form values if provided, otherwise keep existing
    let effective_jwks = if jwks_value.is_some() {
        jwks_value.as_ref()
    } else if is_fapi {
        client.jwks.as_ref()
    } else {
        None
    };

    let effective_jwks_uri = if jwks_uri_trimmed.is_some() {
        jwks_uri_trimmed
    } else if is_fapi {
        client.jwks_uri.as_deref()
    } else {
        None
    };

    let dpop_bound = if is_fapi {
        true
    } else {
        client.dpop_bound_access_tokens
    };

    // Update the application
    if let Err(e) = db::update_oauth_client(
        &state.store,
        &UpdateOAuthClientParams {
            id: &app_id,
            name,
            description: form.description.as_deref(),
            redirect_uris: &redirect_uris,
            access_scope,
            org_id,
            resource_uris: &resource_uris,
            token_endpoint_auth_method,
            jwks: effective_jwks,
            jwks_uri: effective_jwks_uri,
            fapi_profile,
            dpop_bound_access_tokens: dpop_bound,
        },
    )
    .await
    {
        tracing::error!("Failed to update application: {}", e);
        return ApplicationErrorTemplate {
            page: PageContext::current(),
            title: "Error".to_string(),
            message: "Failed to update application.".to_string(),
            back_url: format!("/applications/{}", app_id),
        }
        .into_response();
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
        return ApplicationUnauthorizedTemplate {
            page: PageContext::current(),
        }
        .into_response();
    };

    let user_id = auth.user_id.as_deref().unwrap_or_default();

    // Verify ownership
    let client = match db::get_oauth_client_by_id(&state.store, &app_id).await {
        Ok(Some(c)) if c.user_id.as_deref() == Some(user_id) => c,
        _ => {
            return ApplicationErrorTemplate {
                page: PageContext::current(),
                title: "Not Found".to_string(),
                message: "Application not found.".to_string(),
                back_url: "/applications".to_string(),
            }
            .into_response();
        }
    };

    // Delete the application
    if let Err(e) = db::delete_oauth_client(&state.store, &app_id).await {
        tracing::error!("Failed to delete application: {}", e);
        return ApplicationErrorTemplate {
            page: PageContext::current(),
            title: "Error".to_string(),
            message: "Failed to delete application.".to_string(),
            back_url: format!("/applications/{}", app_id),
        }
        .into_response();
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
        return ApplicationUnauthorizedTemplate {
            page: PageContext::current(),
        }
        .into_response();
    };

    let user_id = auth.user_id.as_deref().unwrap_or_default();

    let client = match db::get_oauth_client_by_id(&state.store, &app_id).await {
        Ok(Some(c)) if c.user_id.as_deref() == Some(user_id) => c,
        _ => {
            return ApplicationErrorTemplate {
                page: PageContext::current(),
                title: "Not Found".to_string(),
                message: "Application not found.".to_string(),
                back_url: "/applications".to_string(),
            }
            .into_response();
        }
    };

    if !client.application_type.requires_secret() {
        return ApplicationErrorTemplate {
            page: PageContext::current(),
            title: "Error".to_string(),
            message: "This application type does not use client secrets.".to_string(),
            back_url: format!("/applications/{app_id}"),
        }
        .into_response();
    }

    if client.is_fapi()
        && client.token_endpoint_auth_method == db::TokenEndpointAuthMethod::PrivateKeyJwt
    {
        return ApplicationErrorTemplate {
            page: PageContext::current(),
            title: "Error".to_string(),
            message: "FAPI clients using private_key_jwt do not use client secrets.".to_string(),
            back_url: format!("/applications/{app_id}"),
        }
        .into_response();
    }

    let now = jiff::Timestamp::now();
    let secrets = match db::get_oauth_client_secrets(&state.store, &app_id).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to get secrets: {e}");
            return ApplicationErrorTemplate {
                page: PageContext::current(),
                title: "Error".to_string(),
                message: "Failed to add secret.".to_string(),
                back_url: format!("/applications/{app_id}"),
            }
            .into_response();
        }
    };

    let active_count = secrets.iter().filter(|s| s.is_valid(&now)).count();
    if active_count >= MAX_ACTIVE_SECRETS {
        return ApplicationErrorTemplate {
            page: PageContext::current(),
            title: "Error".to_string(),
            message: "Maximum of 2 active secrets allowed.".to_string(),
            back_url: format!("/applications/{app_id}"),
        }
        .into_response();
    }

    let secret = generate_client_secret();
    let secret_hash = hash_token(&secret);

    let record =
        match db::create_oauth_client_secret(&state.store, &app_id, &secret_hash, None, None).await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("Failed to create secret: {e}");
                return ApplicationErrorTemplate {
                    page: PageContext::current(),
                    title: "Error".to_string(),
                    message: "Failed to add secret.".to_string(),
                    back_url: format!("/applications/{app_id}"),
                }
                .into_response();
            }
        };

    tracing::info!("Added secret for OAuth application: {}", client.client_id);

    SecretAddedTemplate {
        page: PageContext::current(),
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
        return ApplicationUnauthorizedTemplate {
            page: PageContext::current(),
        }
        .into_response();
    };

    let user_id = auth.user_id.as_deref().unwrap_or_default();

    let client = match db::get_oauth_client_by_id(&state.store, &app_id).await {
        Ok(Some(c)) if c.user_id.as_deref() == Some(user_id) => c,
        _ => {
            return ApplicationErrorTemplate {
                page: PageContext::current(),
                title: "Not Found".to_string(),
                message: "Application not found.".to_string(),
                back_url: "/applications".to_string(),
            }
            .into_response();
        }
    };

    let secret = match db::get_oauth_client_secret_by_id(&state.store, &secret_id).await {
        Ok(Some(s)) if s.oauth_client_id == app_id => s,
        _ => {
            return ApplicationErrorTemplate {
                page: PageContext::current(),
                title: "Not Found".to_string(),
                message: "Secret not found.".to_string(),
                back_url: format!("/applications/{app_id}"),
            }
            .into_response();
        }
    };

    if secret.revoked_at.is_some() {
        return ApplicationErrorTemplate {
            page: PageContext::current(),
            title: "Not Found".to_string(),
            message: "Secret not found.".to_string(),
            back_url: format!("/applications/{app_id}"),
        }
        .into_response();
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
        return ApplicationErrorTemplate {
            page: PageContext::current(),
            title: "Error".to_string(),
            message: "Cannot delete the last active secret.".to_string(),
            back_url: format!("/applications/{app_id}"),
        }
        .into_response();
    }

    if let Err(e) = db::revoke_oauth_client_secret(&state.store, &secret_id).await {
        tracing::error!("Failed to revoke secret: {e}");
        return ApplicationErrorTemplate {
            page: PageContext::current(),
            title: "Error".to_string(),
            message: "Failed to delete secret.".to_string(),
            back_url: format!("/applications/{app_id}"),
        }
        .into_response();
    }

    tracing::info!(
        "Revoked secret {} for OAuth application: {}",
        secret_id,
        client.client_id
    );

    Redirect::to(&format!("/applications/{app_id}")).into_response()
}

#[cfg(test)]
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
}
