// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Types for OAuth Application Registration handlers.
//!
//! Contains all structs, enums, templates, and their implementations used by
//! both the web UI and API handlers.

use crate::db::{AccessScope, OAuthClient};
use crate::impl_template_response;
use crate::infra::i18n::PageContext;
use askama::Template;
use axum::{
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use super::super::session::AuthContext;
use crate::filters;

// ============================================================================
// Templates
// ============================================================================

/// Applications list page template.
#[derive(Template)]
#[template(path = "applications/list.html")]
pub(crate) struct ApplicationsListTemplate {
    /// Page-level template context: i18n + version.
    pub page: PageContext,
    pub applications: Vec<ApplicationInfo>,
    /// Authentication context for header display.
    pub auth: AuthContext,
}

/// Application info for display.
#[allow(dead_code, reason = "fields rendered via Askama template macros")]
pub(crate) struct ApplicationInfo {
    pub id: String,
    pub client_id: String,
    pub name: String,
    pub description: Option<String>,
    pub application_type: String,
    pub redirect_uris: Vec<String>,
    pub active: bool,
    pub created_at: Timestamp,
    pub last_used_at: Option<Timestamp>,
    pub access_scope: AccessScope,
    pub org_id: Option<String>,
    /// RFC 8707: Registered resource URIs.
    pub resource_uris: Vec<String>,
    /// Token endpoint authentication method.
    pub token_endpoint_auth_method: String,
    /// FAPI 2.0 Security Profile designation ("none" or "fapi2_security").
    pub fapi_profile: String,
    /// Inline JWKS JSON (RFC 7523).
    pub jwks: Option<String>,
    /// Remote JWKS URI (RFC 7523).
    pub jwks_uri: Option<String>,
}

impl From<OAuthClient> for ApplicationInfo {
    fn from(client: OAuthClient) -> Self {
        let token_endpoint_auth_method = client.token_endpoint_auth_method.as_str().to_string();
        let fapi_profile = client.fapi_profile.as_str().to_string();
        let jwks = client.jwks.map(|v| v.to_string());
        let jwks_uri = client.jwks_uri.clone();
        Self {
            id: client.id,
            client_id: client.client_id,
            name: client.name,
            description: client.description,
            application_type: client.application_type.as_str().to_string(),
            redirect_uris: client.redirect_uris,
            active: client.active,
            created_at: client.created_at,
            last_used_at: client.last_used_at,
            access_scope: client.access_scope,
            org_id: client.org_id,
            resource_uris: client.resource_uris,
            token_endpoint_auth_method,
            fapi_profile,
            jwks,
            jwks_uri,
        }
    }
}

/// Application create page template.
#[derive(Template)]
#[template(path = "applications/create.html")]
pub(crate) struct ApplicationCreateTemplate {
    /// Authentication context for header display.
    /// Page-level template context: i18n + version.
    pub page: PageContext,
    pub auth: AuthContext,
    /// Whether the user has an organization (affects available access scopes).
    pub user_has_org: bool,
}

/// Application created success page (shows credentials once).
#[derive(Template)]
#[template(path = "applications/created.html")]
pub(crate) struct ApplicationCreatedTemplate {
    /// Page-level template context: i18n + version.
    pub page: PageContext,
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
pub(crate) struct ApplicationDetailTemplate {
    /// Page-level template context: i18n + version.
    pub page: PageContext,
    pub app: ApplicationInfo,
    pub secrets_count: usize,
    pub secrets: Vec<SecretInfo>,
    pub usage_stats: Vec<UsageStat>,
    /// Authentication context for header display.
    pub auth: AuthContext,
}

/// Usage stat for display.
pub(crate) struct UsageStat {
    pub event_type: String,
    pub count: i64,
}

/// Secret added success page (shows new secret once).
#[derive(Template)]
#[template(path = "applications/secret_added.html")]
#[allow(dead_code, reason = "fields rendered via Askama template macros")]
pub(crate) struct SecretAddedTemplate {
    /// Page-level template context: i18n + version.
    pub page: PageContext,
    pub app_id: String,
    pub name: String,
    pub client_id: String,
    pub client_secret: String,
    pub secret_id: String,
    /// Authentication context for header display.
    pub auth: AuthContext,
}

/// Error page template.
#[derive(Template)]
#[template(path = "applications/error.html")]
pub(crate) struct ApplicationErrorTemplate {
    /// Page-level template context: i18n + version.
    pub page: PageContext,
    pub title: String,
    pub message: String,
    pub back_url: String,
}

/// Unauthorized template.
#[derive(Template)]
#[template(path = "applications/unauthorized.html")]
pub(crate) struct ApplicationUnauthorizedTemplate {
    /// Page-level template context: i18n + version.
    pub page: PageContext,
}

impl_template_response!(
    ApplicationsListTemplate,
    ApplicationCreateTemplate,
    ApplicationCreatedTemplate,
    ApplicationDetailTemplate,
    SecretAddedTemplate,
    ApplicationErrorTemplate,
);

// `ApplicationUnauthorizedTemplate` needs a custom `IntoResponse` because it
// returns 401 rather than 200, so it can't use the macro that wires the
// `IntoResponse + page` shims together. The page-context delegators are
// generated manually here to keep templates rendering `{{ self.tr(...) }}`.
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

#[allow(
    dead_code,
    reason = "page-context shims used by the Askama template renderer"
)]
impl ApplicationUnauthorizedTemplate {
    fn version(&self) -> &'static str {
        self.page.version()
    }
    fn lang(&self) -> &str {
        self.page.lang()
    }
    fn dir(&self) -> &'static str {
        self.page.dir()
    }
    fn tr(&self, id: &str) -> String {
        self.page.tr(id)
    }
    fn tr1(&self, id: &str, name: &str, value: &str) -> String {
        self.page.tr1(id, name, value)
    }
}

// ============================================================================
// Request/Response Types
// ============================================================================

/// Form data for creating an application.
#[derive(Debug, Deserialize)]
pub(crate) struct CreateApplicationForm {
    pub name: String,
    pub description: Option<String>,
    pub application_type: String,
    pub redirect_uris: String,
    pub access_scope: String,
    /// RFC 8707: Resource URIs (newline or comma separated, optional).
    #[serde(default)]
    pub resource_uris: Option<String>,
    /// FAPI 2.0: Security profile ("fapi2_security" or absent/empty for standard).
    #[serde(default)]
    pub fapi_profile: Option<String>,
    /// RFC 7523: Inline JWKS JSON for private_key_jwt authentication.
    #[serde(default)]
    pub jwks: Option<String>,
    /// RFC 7523: Remote JWKS endpoint URL for private_key_jwt authentication.
    #[serde(default)]
    pub jwks_uri: Option<String>,
}

/// Form data for updating an application.
#[derive(Debug, Deserialize)]
pub(crate) struct UpdateApplicationForm {
    pub name: String,
    pub description: Option<String>,
    pub redirect_uris: String,
    pub access_scope: Option<String>,
    /// RFC 8707: Resource URIs (newline or comma separated, optional).
    #[serde(default)]
    pub resource_uris: Option<String>,
    /// FAPI 2.0: Security profile ("fapi2_security" or absent/empty for standard).
    #[serde(default)]
    pub fapi_profile: Option<String>,
    /// RFC 7523: Inline JWKS JSON for private_key_jwt authentication.
    #[serde(default)]
    pub jwks: Option<String>,
    /// RFC 7523: Remote JWKS endpoint URL for private_key_jwt authentication.
    #[serde(default)]
    pub jwks_uri: Option<String>,
}

/// API request for creating an application.
#[derive(Debug, Deserialize)]
pub(crate) struct CreateApplicationRequest {
    pub name: String,
    pub description: Option<String>,
    pub application_type: String,
    pub redirect_uris: Vec<String>,
    pub access_scope: Option<String>,
    /// RFC 8707: Resource URIs for audience-restricted tokens.
    #[serde(default)]
    pub resource_uris: Option<Vec<String>>,
    /// FAPI 2.0: Security profile ("fapi2_security" or absent/empty for standard).
    #[serde(default)]
    pub fapi_profile: Option<String>,
    /// RFC 7523: Inline JWKS JSON for private_key_jwt authentication.
    #[serde(default)]
    pub jwks: Option<String>,
    /// RFC 7523: Remote JWKS endpoint URL for private_key_jwt authentication.
    #[serde(default)]
    pub jwks_uri: Option<String>,
}

/// API request for updating an application.
#[derive(Debug, Deserialize)]
pub(crate) struct UpdateApplicationRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub redirect_uris: Option<Vec<String>>,
    pub access_scope: Option<String>,
    /// RFC 8707: Resource URIs for audience-restricted tokens.
    #[serde(default)]
    pub resource_uris: Option<Vec<String>>,
    /// FAPI 2.0: Security profile ("fapi2_security" or absent/empty for standard).
    #[serde(default)]
    pub fapi_profile: Option<String>,
    /// RFC 7523: Inline JWKS JSON for private_key_jwt authentication.
    #[serde(default)]
    pub jwks: Option<String>,
    /// RFC 7523: Remote JWKS endpoint URL for private_key_jwt authentication.
    #[serde(default)]
    pub jwks_uri: Option<String>,
}

/// API response for a created application.
#[derive(Debug, Serialize)]
pub(crate) struct CreateApplicationResponse {
    pub id: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub name: String,
    pub application_type: String,
    pub access_scope: String,
    /// RFC 8707: Registered resource URIs.
    pub resource_uris: Vec<String>,
    /// Token endpoint authentication method.
    pub token_endpoint_auth_method: String,
    /// FAPI 2.0 Security Profile designation.
    pub fapi_profile: String,
    /// Whether JWKS is configured (inline or via URI).
    pub jwks_configured: bool,
    /// Remote JWKS URI if configured.
    pub jwks_uri: Option<String>,
}

/// API response for application details.
#[derive(Debug, Serialize)]
pub(crate) struct ApplicationResponse {
    pub id: String,
    pub client_id: String,
    pub name: String,
    pub description: Option<String>,
    pub application_type: String,
    pub redirect_uris: Vec<String>,
    pub active: bool,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    pub last_used_at: Option<Timestamp>,
    pub access_scope: String,
    pub org_id: Option<String>,
    /// RFC 8707: Registered resource URIs.
    pub resource_uris: Vec<String>,
    /// Token endpoint authentication method.
    pub token_endpoint_auth_method: String,
    /// FAPI 2.0 Security Profile designation.
    pub fapi_profile: String,
    /// Whether JWKS is configured (inline or via URI).
    pub jwks_configured: bool,
    /// Remote JWKS URI if configured.
    pub jwks_uri: Option<String>,
}

impl From<OAuthClient> for ApplicationResponse {
    fn from(client: OAuthClient) -> Self {
        let jwks_configured = client.jwks.is_some() || client.jwks_uri.is_some();
        let jwks_uri = client.jwks_uri.clone();
        Self {
            id: client.id,
            client_id: client.client_id,
            name: client.name,
            description: client.description,
            application_type: client.application_type.as_str().to_string(),
            redirect_uris: client.redirect_uris,
            active: client.active,
            created_at: client.created_at,
            updated_at: client.updated_at,
            last_used_at: client.last_used_at,
            access_scope: client.access_scope.as_str().to_string(),
            org_id: client.org_id,
            resource_uris: client.resource_uris,
            token_endpoint_auth_method: client.token_endpoint_auth_method.as_str().to_string(),
            fapi_profile: client.fapi_profile.as_str().to_string(),
            jwks_configured,
            jwks_uri,
        }
    }
}

/// API response for listing applications.
#[derive(Debug, Serialize)]
pub(crate) struct ListApplicationsResponse {
    pub applications: Vec<ApplicationResponse>,
}

/// API request for adding a secret.
#[derive(Debug, Deserialize)]
pub(crate) struct AddSecretRequest {
    pub description: Option<String>,
}

/// API response for adding a secret (plaintext shown once).
#[derive(Debug, Serialize)]
pub(crate) struct AddSecretResponse {
    pub secret_id: String,
    pub client_secret: String,
    pub created_at: Timestamp,
    pub expires_at: Option<Timestamp>,
}

/// Secret metadata for listing (never exposes hash).
#[derive(Debug, Serialize)]
pub(crate) struct SecretInfo {
    pub id: String,
    pub description: Option<String>,
    pub created_at: Timestamp,
    pub expires_at: Option<Timestamp>,
    pub active: bool,
}

/// API response for listing secrets.
#[derive(Debug, Serialize)]
pub(crate) struct ListSecretsResponse {
    pub secrets: Vec<SecretInfo>,
}
