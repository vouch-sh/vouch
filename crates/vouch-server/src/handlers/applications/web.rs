// SPDX-License-Identifier: BUSL-1.1
//! Web UI handlers for OAuth Application Registration.
//!
//! These handlers return HTML responses via Askama templates for the
//! self-service application management portal.

use crate::AppState;
use crate::db::{
    self, AccessScope, CreateOAuthClientParams, FapiProfile, OAuthClientType, RegistrationSource,
    UpdateOAuthClientParams,
};
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
    ApplicationsListTemplate, CreateApplicationForm, SecretRotatedTemplate, UpdateApplicationForm,
    UsageStat,
};
use super::{
    extract_auth_from_cookie, generate_client_secret, parse_redirect_uris, parse_resource_uris,
    validate_redirect_uris,
};
use crate::handlers::hash_token;
use crate::services::oidc::ResourceUri;

/// List user's applications.
/// GET /applications
pub async fn list_applications_page(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Response {
    let Some(auth) = extract_auth_from_cookie(&state, &jar).await else {
        return ApplicationUnauthorizedTemplate.into_response();
    };

    let user_id = auth.user_id.as_deref().unwrap_or_default();
    let applications = match db::get_oauth_clients_for_user(&state.db, user_id).await {
        Ok(apps) => apps.into_iter().map(ApplicationInfo::from).collect(),
        Err(e) => {
            tracing::error!("Failed to list applications: {}", e);
            return ApplicationErrorTemplate {
                title: "Error".to_string(),
                message: "Failed to load applications.".to_string(),
                back_url: "/".to_string(),
            }
            .into_response();
        }
    };

    ApplicationsListTemplate { applications, auth }.into_response()
}

/// Show create application form.
/// GET /applications/new
pub async fn create_application_page(
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
pub async fn create_application_form(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Form(form): Form<CreateApplicationForm>,
) -> Response {
    let Some(auth) = extract_auth_from_cookie(&state, &jar).await else {
        return ApplicationUnauthorizedTemplate.into_response();
    };

    let user_id = auth.user_id.as_deref().unwrap_or_default();

    // Validate inputs
    let name = form.name.trim();
    if name.is_empty() {
        return ApplicationErrorTemplate {
            title: "Invalid Input".to_string(),
            message: "Application name is required.".to_string(),
            back_url: "/applications/new".to_string(),
        }
        .into_response();
    }

    let Some(app_type) = OAuthClientType::from_str(&form.application_type) else {
        return ApplicationErrorTemplate {
            title: "Invalid Input".to_string(),
            message: "Invalid application type.".to_string(),
            back_url: "/applications/new".to_string(),
        }
        .into_response();
    };

    // Parse and validate access scope
    let access_scope = AccessScope::from_str(&form.access_scope).unwrap_or_default();

    // Validate: Organization scope requires user to have an org
    if access_scope == AccessScope::Organization && !auth.has_org {
        return ApplicationErrorTemplate {
            title: "Invalid Input".to_string(),
            message: "Organization scope requires organization membership.".to_string(),
            back_url: "/applications/new".to_string(),
        }
        .into_response();
    }

    // Get user's org_id for org-scoped apps
    let user_org_id = if auth.has_org {
        // Fetch user to get org_id
        match db::get_user_by_id(&state.db, user_id).await {
            Ok(Some(user)) => user.org_id,
            _ => None,
        }
    } else {
        None
    };

    // Set org_id only for organization-scoped apps
    let org_id = if access_scope == AccessScope::Organization {
        user_org_id.as_deref()
    } else {
        None
    };

    let redirect_uris = parse_redirect_uris(&form.redirect_uris);

    // For non-service apps, at least one redirect URI is required
    if !matches!(app_type, OAuthClientType::Service) && redirect_uris.is_empty() {
        return ApplicationErrorTemplate {
            title: "Invalid Input".to_string(),
            message: "At least one redirect URI is required.".to_string(),
            back_url: "/applications/new".to_string(),
        }
        .into_response();
    }

    // Validate redirect URIs are valid URLs
    if let Err(invalid) = validate_redirect_uris(&redirect_uris) {
        return ApplicationErrorTemplate {
            title: "Invalid Input".to_string(),
            message: format!(
                "Invalid redirect URI(s): {}. Each URI must be a valid http:// or https:// URL.",
                invalid.join(", ")
            ),
            back_url: "/applications/new".to_string(),
        }
        .into_response();
    }

    // RFC 8707: Parse and validate resource URIs from form (if provided).
    let resource_uris = parse_resource_uris(form.resource_uris.as_deref());

    for uri in &resource_uris {
        if let Err(e) = ResourceUri::parse(uri) {
            return ApplicationErrorTemplate {
                title: "Invalid Input".to_string(),
                message: format!(
                    "Invalid resource URI '{uri}': {e}. \
                     Resource URIs must be absolute URIs without fragment components."
                ),
                back_url: "/applications/new".to_string(),
            }
            .into_response();
        }
    }

    // Determine FAPI profile
    let is_fapi = form
        .fapi_profile
        .as_deref()
        .is_some_and(|p| p == "fapi2_security");

    // FAPI validation: must be a confidential client type
    if is_fapi && !matches!(app_type, OAuthClientType::Web | OAuthClientType::Service) {
        return ApplicationErrorTemplate {
            title: "Invalid Input".to_string(),
            message: "FAPI 2.0 Security Profile requires a confidential client type \
                      (Web Application or Service)."
                .to_string(),
            back_url: "/applications/new".to_string(),
        }
        .into_response();
    }

    // FAPI validation: require JWKS or JWKS URI
    let jwks_trimmed = form
        .jwks
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let jwks_uri_trimmed = form
        .jwks_uri
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    if is_fapi && jwks_trimmed.is_none() && jwks_uri_trimmed.is_none() {
        return ApplicationErrorTemplate {
            title: "Invalid Input".to_string(),
            message: "FAPI 2.0 requires a JWKS (inline JSON) or JWKS URI for \
                      private_key_jwt authentication."
                .to_string(),
            back_url: "/applications/new".to_string(),
        }
        .into_response();
    }

    // Validate JWKS JSON if provided
    if let Some(jwks_json) = jwks_trimmed {
        match serde_json::from_str::<serde_json::Value>(jwks_json) {
            Ok(val) => {
                if !val
                    .get("keys")
                    .is_some_and(|k| k.is_array() && !k.as_array().is_some_and(|a| a.is_empty()))
                {
                    return ApplicationErrorTemplate {
                        title: "Invalid Input".to_string(),
                        message: "JWKS must be a JSON object with a non-empty \"keys\" array."
                            .to_string(),
                        back_url: "/applications/new".to_string(),
                    }
                    .into_response();
                }
            }
            Err(_) => {
                return ApplicationErrorTemplate {
                    title: "Invalid Input".to_string(),
                    message: "JWKS must be valid JSON.".to_string(),
                    back_url: "/applications/new".to_string(),
                }
                .into_response();
            }
        }
    }

    // Validate JWKS URI if provided
    if let Some(uri) = jwks_uri_trimmed {
        match url::Url::parse(uri) {
            Ok(parsed) if parsed.scheme() == "https" => {}
            _ => {
                return ApplicationErrorTemplate {
                    title: "Invalid Input".to_string(),
                    message: "JWKS URI must be a valid https:// URL.".to_string(),
                    back_url: "/applications/new".to_string(),
                }
                .into_response();
            }
        }
    }

    // Create the application
    let (client, client_id) = match db::create_oauth_client(
        &state.db,
        &CreateOAuthClientParams {
            user_id,
            name,
            description: form.description.as_deref(),
            application_type: app_type,
            redirect_uris: &redirect_uris,
            access_scope,
            org_id,
            resource_uris: &resource_uris,
            token_endpoint_auth_method: None,
            jwks: None,
            jwks_uri: None,
            fapi_profile: None,
            dpop_bound_access_tokens: None,
            grant_types: None,
            response_types: None,
            software_id: None,
            software_version: None,
            registration_source: RegistrationSource::Manual,
            registration_access_token_hash: None,
            registration_metadata: None,
        },
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to create application: {}", e);
            return ApplicationErrorTemplate {
                title: "Error".to_string(),
                message: "Failed to create application.".to_string(),
                back_url: "/applications/new".to_string(),
            }
            .into_response();
        }
    };

    // If FAPI is enabled, update the client with FAPI settings
    if is_fapi
        && let Err(e) = db::update_oauth_client(
            &state.db,
            &UpdateOAuthClientParams {
                id: &client.id,
                name,
                description: form.description.as_deref(),
                redirect_uris: &redirect_uris,
                access_scope: Some(access_scope),
                org_id,
                resource_uris: &resource_uris,
                token_endpoint_auth_method: "private_key_jwt",
                jwks: jwks_trimmed,
                jwks_uri: jwks_uri_trimmed,
                fapi_profile: FapiProfile::Fapi2Security,
                dpop_bound_access_tokens: true,
            },
        )
        .await
    {
        tracing::error!("Failed to apply FAPI settings: {}", e);
        if let Err(cleanup_err) = db::delete_oauth_client(&state.db, &client.id).await {
            tracing::warn!(
                "Failed to clean up OAuth client after FAPI settings failure: {cleanup_err}"
            );
        }
        return ApplicationErrorTemplate {
            title: "Error".to_string(),
            message: "Failed to create application.".to_string(),
            back_url: "/applications/new".to_string(),
        }
        .into_response();
    }

    // Generate client secret for confidential clients (skip for FAPI — they use private_key_jwt)
    let client_secret = if app_type.requires_secret() && !is_fapi {
        let secret = generate_client_secret();
        let secret_hash = hash_token(&secret);

        if let Err(e) = db::create_oauth_client_secret(
            &state.db,
            &client.id,
            &secret_hash,
            Some("Initial secret"),
            None,
        )
        .await
        {
            tracing::error!("Failed to create client secret: {}", e);
            // Clean up the client
            if let Err(cleanup_err) = db::delete_oauth_client(&state.db, &client.id).await {
                tracing::warn!(
                    "Failed to clean up OAuth client after secret creation failure: {cleanup_err}"
                );
            }
            return ApplicationErrorTemplate {
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
pub async fn detail_application_page(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path(app_id): Path<String>,
) -> Response {
    let Some(auth) = extract_auth_from_cookie(&state, &jar).await else {
        return ApplicationUnauthorizedTemplate.into_response();
    };

    let user_id = auth.user_id.as_deref().unwrap_or_default();

    // Get the application
    let client = match db::get_oauth_client_by_id(&state.db, &app_id).await {
        Ok(Some(c)) if c.user_id == user_id => c,
        Ok(Some(_)) => {
            return ApplicationErrorTemplate {
                title: "Not Found".to_string(),
                message: "Application not found.".to_string(),
                back_url: "/applications".to_string(),
            }
            .into_response();
        }
        Ok(None) => {
            return ApplicationErrorTemplate {
                title: "Not Found".to_string(),
                message: "Application not found.".to_string(),
                back_url: "/applications".to_string(),
            }
            .into_response();
        }
        Err(e) => {
            tracing::error!("Failed to get application: {}", e);
            return ApplicationErrorTemplate {
                title: "Error".to_string(),
                message: "Failed to load application.".to_string(),
                back_url: "/applications".to_string(),
            }
            .into_response();
        }
    };

    // Get secrets count
    let secrets_count = match db::get_oauth_client_secrets(&state.db, &app_id).await {
        Ok(s) => s.iter().filter(|s| s.revoked_at.is_none()).count(),
        Err(_) => 0,
    };

    // Get usage stats
    let usage_stats = match db::get_oauth_usage_stats(&state.db, &app_id, None).await {
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
        usage_stats,
        auth,
    }
    .into_response()
}

/// Update an application.
/// POST /applications/:id
pub async fn update_application_form(
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
    let client = match db::get_oauth_client_by_id(&state.db, &app_id).await {
        Ok(Some(c)) if c.user_id == user_id => c,
        _ => {
            return ApplicationErrorTemplate {
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
        return ApplicationErrorTemplate {
            title: "Invalid Input".to_string(),
            message: "Application name is required.".to_string(),
            back_url: format!("/applications/{}", app_id),
        }
        .into_response();
    }

    // Parse access scope if provided
    let access_scope = form
        .access_scope
        .as_ref()
        .and_then(|s| AccessScope::from_str(s));

    // Validate: Organization scope requires user to have an org
    if access_scope == Some(AccessScope::Organization) && !auth.has_org {
        return ApplicationErrorTemplate {
            title: "Invalid Input".to_string(),
            message: "Organization scope requires organization membership.".to_string(),
            back_url: format!("/applications/{}", app_id),
        }
        .into_response();
    }

    // Get user's org_id for org-scoped apps
    let user_org_id = if auth.has_org {
        match db::get_user_by_id(&state.db, user_id).await {
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

    let redirect_uris = parse_redirect_uris(&form.redirect_uris);

    // Validate redirect URIs are valid URLs
    if let Err(invalid) = validate_redirect_uris(&redirect_uris) {
        return ApplicationErrorTemplate {
            title: "Invalid Input".to_string(),
            message: format!(
                "Invalid redirect URI(s): {}. Each URI must be a valid http:// or https:// URL.",
                invalid.join(", ")
            ),
            back_url: format!("/applications/{}", app_id),
        }
        .into_response();
    }

    // RFC 8707: Parse and validate resource URIs from form (if provided).
    let resource_uris = parse_resource_uris(form.resource_uris.as_deref());

    for uri in &resource_uris {
        if let Err(e) = ResourceUri::parse(uri) {
            return ApplicationErrorTemplate {
                title: "Invalid Input".to_string(),
                message: format!(
                    "Invalid resource URI '{uri}': {e}. \
                     Resource URIs must be absolute URIs without fragment components."
                ),
                back_url: format!("/applications/{}", app_id),
            }
            .into_response();
        }
    }

    // Determine FAPI profile
    let is_fapi = form
        .fapi_profile
        .as_deref()
        .is_some_and(|p| p == "fapi2_security");

    // FAPI validation: must be a confidential client type
    if is_fapi
        && !matches!(
            client.application_type,
            OAuthClientType::Web | OAuthClientType::Service
        )
    {
        return ApplicationErrorTemplate {
            title: "Invalid Input".to_string(),
            message: "FAPI 2.0 Security Profile requires a confidential client type \
                      (Web Application or Service)."
                .to_string(),
            back_url: format!("/applications/{}", app_id),
        }
        .into_response();
    }

    // FAPI validation: require JWKS or JWKS URI
    let jwks_trimmed = form
        .jwks
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let jwks_uri_trimmed = form
        .jwks_uri
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    if is_fapi && jwks_trimmed.is_none() && jwks_uri_trimmed.is_none() {
        // If transitioning to FAPI, check if client already has JWKS configured
        if client.jwks.is_none() && client.jwks_uri.is_none() {
            return ApplicationErrorTemplate {
                title: "Invalid Input".to_string(),
                message: "FAPI 2.0 requires a JWKS (inline JSON) or JWKS URI for \
                          private_key_jwt authentication."
                    .to_string(),
                back_url: format!("/applications/{}", app_id),
            }
            .into_response();
        }
    }

    // Validate JWKS JSON if provided
    if let Some(jwks_json) = jwks_trimmed {
        match serde_json::from_str::<serde_json::Value>(jwks_json) {
            Ok(val) => {
                if !val
                    .get("keys")
                    .is_some_and(|k| k.is_array() && !k.as_array().is_some_and(|a| a.is_empty()))
                {
                    return ApplicationErrorTemplate {
                        title: "Invalid Input".to_string(),
                        message: "JWKS must be a JSON object with a non-empty \"keys\" array."
                            .to_string(),
                        back_url: format!("/applications/{}", app_id),
                    }
                    .into_response();
                }
            }
            Err(_) => {
                return ApplicationErrorTemplate {
                    title: "Invalid Input".to_string(),
                    message: "JWKS must be valid JSON.".to_string(),
                    back_url: format!("/applications/{}", app_id),
                }
                .into_response();
            }
        }
    }

    // Validate JWKS URI if provided
    if let Some(uri) = jwks_uri_trimmed {
        match url::Url::parse(uri) {
            Ok(parsed) if parsed.scheme() == "https" => {}
            _ => {
                return ApplicationErrorTemplate {
                    title: "Invalid Input".to_string(),
                    message: "JWKS URI must be a valid https:// URL.".to_string(),
                    back_url: format!("/applications/{}", app_id),
                }
                .into_response();
            }
        }
    }

    // Compute FAPI-related values: merge form values with existing client values
    let fapi_profile = if is_fapi {
        FapiProfile::Fapi2Security
    } else {
        FapiProfile::None
    };

    let token_endpoint_auth_method = if is_fapi {
        "private_key_jwt"
    } else if !is_fapi && client.is_fapi() {
        // Transitioning from FAPI to Standard: reset to default
        "client_secret_basic"
    } else {
        client.token_endpoint_auth_method.as_str()
    };

    // Resolve final JWKS values: use form values if provided, otherwise keep existing
    let effective_jwks = if jwks_trimmed.is_some() {
        jwks_trimmed
    } else if is_fapi {
        client.jwks.as_deref()
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
        &state.db,
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
pub async fn delete_application_form(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path(app_id): Path<String>,
) -> Response {
    let Some(auth) = extract_auth_from_cookie(&state, &jar).await else {
        return ApplicationUnauthorizedTemplate.into_response();
    };

    let user_id = auth.user_id.as_deref().unwrap_or_default();

    // Verify ownership
    let client = match db::get_oauth_client_by_id(&state.db, &app_id).await {
        Ok(Some(c)) if c.user_id == user_id => c,
        _ => {
            return ApplicationErrorTemplate {
                title: "Not Found".to_string(),
                message: "Application not found.".to_string(),
                back_url: "/applications".to_string(),
            }
            .into_response();
        }
    };

    // Delete the application
    if let Err(e) = db::delete_oauth_client(&state.db, &app_id).await {
        tracing::error!("Failed to delete application: {}", e);
        return ApplicationErrorTemplate {
            title: "Error".to_string(),
            message: "Failed to delete application.".to_string(),
            back_url: format!("/applications/{}", app_id),
        }
        .into_response();
    }

    tracing::info!("Deleted OAuth application: {}", client.client_id);

    Redirect::to("/applications").into_response()
}

/// Rotate client secret.
/// POST /applications/:id/rotate
pub async fn rotate_secret_form(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path(app_id): Path<String>,
) -> Response {
    let Some(auth) = extract_auth_from_cookie(&state, &jar).await else {
        return ApplicationUnauthorizedTemplate.into_response();
    };

    let user_id = auth.user_id.as_deref().unwrap_or_default();

    // Verify ownership
    let client = match db::get_oauth_client_by_id(&state.db, &app_id).await {
        Ok(Some(c)) if c.user_id == user_id => c,
        _ => {
            return ApplicationErrorTemplate {
                title: "Not Found".to_string(),
                message: "Application not found.".to_string(),
                back_url: "/applications".to_string(),
            }
            .into_response();
        }
    };

    // Check if this client type supports secrets
    if !client.application_type.requires_secret() {
        return ApplicationErrorTemplate {
            title: "Error".to_string(),
            message: "This application type does not use client secrets.".to_string(),
            back_url: format!("/applications/{}", app_id),
        }
        .into_response();
    }

    // Generate new secret
    let secret = generate_client_secret();
    let secret_hash = hash_token(&secret);

    // Revoke old secrets
    if let Err(e) = db::revoke_all_oauth_client_secrets(&state.db, &app_id).await {
        tracing::error!("Failed to revoke old secrets: {}", e);
    }

    // Create new secret
    if let Err(e) = db::create_oauth_client_secret(
        &state.db,
        &app_id,
        &secret_hash,
        Some("Rotated secret"),
        None,
    )
    .await
    {
        tracing::error!("Failed to create new secret: {}", e);
        return ApplicationErrorTemplate {
            title: "Error".to_string(),
            message: "Failed to rotate secret.".to_string(),
            back_url: format!("/applications/{}", app_id),
        }
        .into_response();
    }

    tracing::info!("Rotated secret for OAuth application: {}", client.client_id);

    SecretRotatedTemplate {
        name: client.name,
        client_id: client.client_id,
        client_secret: secret,
        auth,
    }
    .into_response()
}
