// SPDX-License-Identifier: BUSL-1.1
//! Types for OAuth Application Registration handlers.
//!
//! Contains all structs, enums, templates, and their implementations used by
//! both the web UI and API handlers.

use crate::db::{AccessScope, OAuthClient};
use crate::impl_template_response;
use askama::Template;
use axum::{
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use super::super::session::AuthContext;

// ============================================================================
// Templates
// ============================================================================

/// Applications list page template.
#[derive(Template)]
#[template(path = "applications/list.html")]
pub struct ApplicationsListTemplate {
    pub applications: Vec<ApplicationInfo>,
    /// Authentication context for header display.
    pub auth: AuthContext,
}

/// Application info for display.
pub struct ApplicationInfo {
    pub id: String,
    pub client_id: String,
    pub name: String,
    pub description: Option<String>,
    pub application_type: String,
    pub redirect_uris: Vec<String>,
    pub active: bool,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub access_scope: AccessScope,
    pub org_id: Option<String>,
    /// RFC 8707: Registered resource URIs.
    pub resource_uris: Vec<String>,
}

impl From<OAuthClient> for ApplicationInfo {
    fn from(client: OAuthClient) -> Self {
        let redirect_uris = client.get_redirect_uris();
        let resource_uris = client.get_resource_uris();
        Self {
            id: client.id,
            client_id: client.client_id,
            name: client.name,
            description: client.description,
            application_type: client.application_type.as_str().to_string(),
            redirect_uris,
            active: client.active,
            created_at: client.created_at.to_jiff().to_string(),
            last_used_at: client.last_used_at.map(|ts| ts.to_jiff().to_string()),
            access_scope: client.access_scope,
            org_id: client.org_id,
            resource_uris,
        }
    }
}

/// Application create page template.
#[derive(Template)]
#[template(path = "applications/create.html")]
#[allow(dead_code)]
pub struct ApplicationCreateTemplate {
    /// Authentication context for header display.
    pub auth: AuthContext,
    /// Whether the user has an organization (affects available access scopes).
    pub user_has_org: bool,
}

/// Application created success page (shows credentials once).
#[derive(Template)]
#[template(path = "applications/created.html")]
#[allow(dead_code)]
pub struct ApplicationCreatedTemplate {
    pub name: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub application_type: String,
    pub requires_secret: bool,
    /// Authentication context for header display.
    pub auth: AuthContext,
}

/// Application detail page template.
#[derive(Template)]
#[template(path = "applications/detail.html")]
#[allow(dead_code)]
pub struct ApplicationDetailTemplate {
    pub app: ApplicationInfo,
    pub secrets_count: usize,
    pub usage_stats: Vec<UsageStat>,
    /// Authentication context for header display.
    pub auth: AuthContext,
}

/// Usage stat for display.
pub struct UsageStat {
    pub event_type: String,
    pub count: i64,
}

/// Secret rotated success page (shows new secret once).
#[derive(Template)]
#[template(path = "applications/rotated.html")]
#[allow(dead_code)]
pub struct SecretRotatedTemplate {
    pub name: String,
    pub client_id: String,
    pub client_secret: String,
    /// Authentication context for header display.
    pub auth: AuthContext,
}

/// Error page template.
#[derive(Template)]
#[template(path = "applications/error.html")]
pub struct ApplicationErrorTemplate {
    pub title: String,
    pub message: String,
    pub back_url: String,
}

/// Unauthorized template.
#[derive(Template)]
#[template(path = "applications/unauthorized.html")]
pub struct ApplicationUnauthorizedTemplate;

impl_template_response!(
    ApplicationsListTemplate,
    ApplicationCreateTemplate,
    ApplicationCreatedTemplate,
    ApplicationDetailTemplate,
    SecretRotatedTemplate,
    ApplicationErrorTemplate,
);

// Note: ApplicationUnauthorizedTemplate needs a custom implementation
// because it returns a different status code
impl IntoResponse for ApplicationUnauthorizedTemplate {
    fn into_response(self) -> Response {
        match self.render() {
            Ok(html) => (StatusCode::UNAUTHORIZED, Html(html)).into_response(),
            Err(e) => {
                tracing::error!("Template render error: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    }
}

// ============================================================================
// Request/Response Types
// ============================================================================

/// Form data for creating an application.
#[derive(Debug, Deserialize)]
pub struct CreateApplicationForm {
    pub name: String,
    pub description: Option<String>,
    pub application_type: String,
    pub redirect_uris: String,
    pub access_scope: String,
    /// RFC 8707: Resource URIs (newline or comma separated, optional).
    #[serde(default)]
    pub resource_uris: Option<String>,
}

/// Form data for updating an application.
#[derive(Debug, Deserialize)]
pub struct UpdateApplicationForm {
    pub name: String,
    pub description: Option<String>,
    pub redirect_uris: String,
    pub access_scope: Option<String>,
    /// RFC 8707: Resource URIs (newline or comma separated, optional).
    #[serde(default)]
    pub resource_uris: Option<String>,
}

/// API request for creating an application.
#[derive(Debug, Deserialize)]
pub struct CreateApplicationRequest {
    pub name: String,
    pub description: Option<String>,
    pub application_type: String,
    pub redirect_uris: Vec<String>,
    pub access_scope: Option<String>,
    /// RFC 8707: Resource URIs for audience-restricted tokens.
    #[serde(default)]
    pub resource_uris: Option<Vec<String>>,
}

/// API request for updating an application.
#[derive(Debug, Deserialize)]
pub struct UpdateApplicationRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub redirect_uris: Option<Vec<String>>,
    pub access_scope: Option<String>,
    /// RFC 8707: Resource URIs for audience-restricted tokens.
    #[serde(default)]
    pub resource_uris: Option<Vec<String>>,
}

/// API response for a created application.
#[derive(Debug, Serialize)]
pub struct CreateApplicationResponse {
    pub id: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub name: String,
    pub application_type: String,
    pub access_scope: String,
    /// RFC 8707: Registered resource URIs.
    pub resource_uris: Vec<String>,
}

/// API response for application details.
#[derive(Debug, Serialize)]
pub struct ApplicationResponse {
    pub id: String,
    pub client_id: String,
    pub name: String,
    pub description: Option<String>,
    pub application_type: String,
    pub redirect_uris: Vec<String>,
    pub active: bool,
    pub created_at: String,
    pub updated_at: String,
    pub last_used_at: Option<String>,
    pub access_scope: String,
    pub org_id: Option<String>,
    /// RFC 8707: Registered resource URIs.
    pub resource_uris: Vec<String>,
}

impl From<OAuthClient> for ApplicationResponse {
    fn from(client: OAuthClient) -> Self {
        let redirect_uris = client.get_redirect_uris();
        let resource_uris = client.get_resource_uris();
        Self {
            id: client.id,
            client_id: client.client_id,
            name: client.name,
            description: client.description,
            application_type: client.application_type.as_str().to_string(),
            redirect_uris,
            active: client.active,
            created_at: client.created_at.to_jiff().to_string(),
            updated_at: client.updated_at.to_jiff().to_string(),
            last_used_at: client.last_used_at.map(|ts| ts.to_jiff().to_string()),
            access_scope: client.access_scope.as_str().to_string(),
            org_id: client.org_id,
            resource_uris,
        }
    }
}

/// API response for listing applications.
#[derive(Debug, Serialize)]
pub struct ListApplicationsResponse {
    pub applications: Vec<ApplicationResponse>,
}

/// API response for secret rotation.
#[derive(Debug, Serialize)]
pub struct RotateSecretResponse {
    pub client_secret: String,
    pub created_at: String,
    pub expires_at: Option<String>,
}
