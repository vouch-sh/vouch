// SPDX-License-Identifier: Apache-2.0 OR MIT
//! SCIM token management API — `POST/GET /api/v1/org/scim-tokens`,
//! `DELETE /api/v1/org/scim-tokens/{id}`.

use crate::AppState;
use crate::db;
use crate::db::CreateScimTokenParams;
use crate::db::documents::audit::ScimTokenAdminData;
use crate::error::ServiceError;
use crate::handlers::admin::{
    MAX_SCIM_TOKEN_DESCRIPTION_CHARS, compute_token_expiry, generate_scim_token, has_audit_read,
    requested_scope,
};
use crate::handlers::extractors::{OptionalClientCert, OrgAdmin};
use crate::handlers::session::extract_org_admin;
use crate::handlers::{ValidPath, ValidUuid};
use axum::Json;
use axum::extract::{OriginalUri, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum_extra::extract::cookie::CookieJar;
use jiff::Timestamp;
use secrecy::SecretString;
use serde::Deserialize;
use std::sync::Arc;

/// Request to create an organization API token.
#[derive(Debug, Deserialize)]
pub(crate) struct CreateScimTokenRequest {
    pub description: Option<String>,
    /// Token expiration in days (required, 1-365 days).
    pub expires_in_days: i64,
    /// Grant the `audit:read` scope (`GET /api/v1/org/audit-events`).
    #[serde(default)]
    pub audit_read: bool,
}

/// Response for created SCIM token.
///
/// `Debug` is hand-implemented to redact the bearer token; do not derive.
#[derive(serde::Serialize)]
pub(crate) struct CreateScimTokenResponse {
    pub id: String,
    #[serde(serialize_with = "vouch_common::serialize_secret_string")]
    pub token: SecretString,
    pub description: Option<String>,
    pub expires_at: Option<Timestamp>,
    pub audit_read: bool,
}

impl std::fmt::Debug for CreateScimTokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateScimTokenResponse")
            .field("id", &self.id)
            .field("token", &"[REDACTED]")
            .field("description", &self.description)
            .field("expires_at", &self.expires_at)
            .field("audit_read", &self.audit_read)
            .finish()
    }
}

/// SCIM token info for listing.
#[derive(Debug, serde::Serialize)]
pub(crate) struct ScimTokenInfo {
    pub id: String,
    pub description: Option<String>,
    pub created_at: Timestamp,
    pub last_used_at: Option<Timestamp>,
    pub expires_at: Option<Timestamp>,
    pub audit_read: bool,
}

/// Response for listing SCIM tokens.
#[derive(Debug, serde::Serialize)]
pub(crate) struct ListScimTokensResponse {
    pub tokens: Vec<ScimTokenInfo>,
}

/// Create a new SCIM token.
/// POST /api/v1/org/scim-tokens
pub(crate) async fn create_scim_token(
    method: Method,
    uri: OriginalUri,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
    client_cert: OptionalClientCert,
    Json(req): Json<CreateScimTokenRequest>,
) -> Result<Json<CreateScimTokenResponse>, ServiceError> {
    // Validate inputs before auth to fail fast on obviously bad requests
    if let Some(ref desc) = req.description
        && desc.chars().count() > MAX_SCIM_TOKEN_DESCRIPTION_CHARS
    {
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Description must be 256 characters or less",
        ));
    }

    if req.expires_in_days < 1 || req.expires_in_days > 365 {
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_expiration",
            "expires_in_days must be between 1 and 365",
        ));
    }

    let (user, org_id) = extract_org_admin(
        &state,
        &headers,
        &jar,
        method.as_str(),
        uri.path(),
        client_cert.0.as_ref(),
    )
    .await?;

    let generated = generate_scim_token()?;
    let expires_at = Some(compute_token_expiry(req.expires_in_days)?);
    let scope = requested_scope(req.audit_read);

    // The 2-token limit is enforced inside the transaction: counting here and
    // inserting afterwards lets two concurrent requests both pass the check.
    let token_id = db::create_scim_token(
        &state.store,
        &CreateScimTokenParams {
            org_id: &org_id,
            token_hash: &generated.hash,
            description: req.description.as_deref(),
            expires_at,
            scope,
        },
    )
    .await?;

    let data = ScimTokenAdminData {
        action: "create_scim_token",
        token_id: &token_id,
        admin_user_id: &user.id,
    };
    state
        .audit
        .record_event(
            db::AuditEventKind::AdminCreateScimToken,
            Some(&user.id),
            Some(&user.email),
            &data,
        )
        .await;

    tracing::info!("Created SCIM token: {} for org: {}", token_id, org_id);

    Ok(Json(CreateScimTokenResponse {
        id: token_id,
        token: generated.plaintext.clone(),
        description: req.description,
        expires_at,
        audit_read: req.audit_read,
    }))
}

/// List SCIM tokens for the organization.
/// GET /api/v1/org/scim-tokens
pub(crate) async fn list_scim_tokens(
    State(state): State<Arc<AppState>>,
    admin: OrgAdmin,
) -> Result<Json<ListScimTokensResponse>, ServiceError> {
    let OrgAdmin {
        user: _user,
        org_id,
    } = admin;

    let tokens = db::list_scim_tokens(&state.store, Some(&org_id)).await?;

    let tokens: Vec<ScimTokenInfo> = tokens
        .into_iter()
        .map(|t| ScimTokenInfo {
            id: t.id,
            description: t.description,
            created_at: t.created_at,
            last_used_at: t.last_used_at,
            expires_at: t.expires_at,
            audit_read: has_audit_read(&t.scope),
        })
        .collect();

    Ok(Json(ListScimTokensResponse { tokens }))
}

/// Delete a SCIM token.
/// DELETE /api/v1/org/scim-tokens/:id
pub(crate) async fn delete_scim_token(
    State(state): State<Arc<AppState>>,
    ValidPath(token_id): ValidPath<ValidUuid>,
    admin: OrgAdmin,
) -> Result<StatusCode, ServiceError> {
    let OrgAdmin { user, org_id } = admin;

    let deleted = db::delete_scim_token(&state.store, &token_id, &org_id).await?;

    if !deleted {
        return Err(ServiceError::api(
            StatusCode::NOT_FOUND,
            "not_found",
            "SCIM token not found",
        ));
    }

    let data = ScimTokenAdminData {
        action: "delete_scim_token",
        token_id: &token_id,
        admin_user_id: &user.id,
    };
    state
        .audit
        .record_event(
            db::AuditEventKind::AdminDeleteScimToken,
            Some(&user.id),
            Some(&user.email),
            &data,
        )
        .await;

    tracing::info!("Deleted SCIM token: {}", token_id);

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests;
