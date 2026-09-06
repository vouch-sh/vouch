// SPDX-License-Identifier: Apache-2.0 OR MIT
//! JSON handlers for `/api/v1/applications/*` — programmatic OAuth
//! application management. Every handler takes the `AuthenticatedToken`
//! extractor and answers with a JSON error envelope; the browser portal for
//! the same data lives in [`crate::handlers::applications`], which also owns
//! the request/response types and validation rules both surfaces share.

use crate::AppState;
use crate::db::{self, AccessScope, OAuthEventType, UpdateOAuthClientParams};
use axum::{Json, extract::State, http::StatusCode};
use std::sync::Arc;

use crate::error::ServiceError;
use crate::handlers::applications::generate_client_secret;
use crate::handlers::applications::types::{
    AddSecretRequest, AddSecretResponse, ApplicationResponse, CreateApplicationRequest,
    CreateApplicationResponse, ListApplicationsResponse, ListSecretsResponse, SecretInfo,
    UpdateApplicationRequest,
};
use crate::handlers::applications::validate::{
    CreateAppContext, CreateAppInput, UpdateAppInput, build_create_params,
    compute_fapi_update_fields, validate_create_application, validate_update_fapi,
    validate_update_format,
};
use crate::handlers::hash_token;
use crate::handlers::session::AuthenticatedToken;
use crate::handlers::{ValidPath, ValidUuid};

/// List user's applications (API).
/// GET /api/v1/applications
pub(crate) async fn list_applications_api(
    State(state): State<Arc<AppState>>,
    AuthenticatedToken(token): AuthenticatedToken,
) -> Result<Json<ListApplicationsResponse>, ServiceError> {
    let applications = db::get_oauth_clients_for_user(&state.store, &token.sub)
        .await
        .map_err(|e| {
            tracing::error!("Failed to list applications: {e}");
            ServiceError::api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Internal database error",
            )
        })?
        .into_iter()
        .map(ApplicationResponse::from)
        .collect();

    Ok(Json(ListApplicationsResponse { applications }))
}

/// Load the requesting user and enforce account-status and access-scope rules.
///
/// The account must be active, and organization scope requires organization
/// membership. Shared by the create and update handlers.
async fn load_active_user_for_scope(
    state: &AppState,
    user_id: &str,
    wants_org_scope: bool,
) -> Result<db::User, ServiceError> {
    let user = crate::handlers::session::load_active_user(state, user_id).await?;

    // Validate: Organization scope requires user to have an org
    if wants_org_scope && user.org_id.is_none() {
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_access_scope",
            "Organization scope requires organization membership",
        ));
    }

    Ok(user)
}

/// Create a new application (API).
/// POST /api/v1/applications
pub(crate) async fn create_application_api(
    State(state): State<Arc<AppState>>,
    token: Result<AuthenticatedToken, ServiceError>,
    Json(req): Json<CreateApplicationRequest>,
) -> Result<Json<CreateApplicationResponse>, ServiceError> {
    // ── Pure format validation first — no DB cost for malformed requests ──
    // RFC 8707: Resource URIs default to empty if not provided.
    let resource_uris = req.resource_uris.as_deref().unwrap_or(&[]);
    let post_logout_redirect_uris_raw = req.post_logout_redirect_uris.as_deref();

    let validated = validate_create_application(CreateAppInput {
        name: &req.name,
        application_type: &req.application_type,
        redirect_uris: &req.redirect_uris,
        resource_uris,
        post_logout_redirect_uris: post_logout_redirect_uris_raw,
        access_scope: req.access_scope.as_deref(),
        fapi_profile: req.fapi_profile.as_deref(),
        jwks: req.jwks.as_deref(),
        jwks_uri: req.jwks_uri.as_deref(),
    })?;
    let name = validated.name;

    // ── Authentication — validated input is good, now check credentials ──
    // Deferred so a malformed body still answers 400 rather than 401; an
    // unauthenticated request costs no DB lookup either way, because token
    // extraction fails before touching the store when no credential is sent.
    let AuthenticatedToken(token) = token?;

    let access_scope = validated.access_scope;

    let user = load_active_user_for_scope(
        &state,
        &token.sub,
        access_scope == AccessScope::Organization,
    )
    .await?;

    // Set org_id only for organization-scoped apps
    let org_id = if access_scope == AccessScope::Organization {
        user.org_id.as_deref()
    } else {
        None
    };

    // Create the application with FAPI settings included at creation time
    let (client, client_id) = db::create_oauth_client(
        &state.store,
        &build_create_params(
            &validated,
            CreateAppContext {
                user_id: &token.sub,
                description: req.description.as_deref(),
                redirect_uris: &req.redirect_uris,
                resource_uris,
                post_logout_redirect_uris: post_logout_redirect_uris_raw,
                access_scope,
                org_id,
            },
        ),
    )
    .await
    .map_err(|e| {
        tracing::error!("Failed to create OAuth client: {e}");
        ServiceError::api(
            StatusCode::INTERNAL_SERVER_ERROR,
            "db_error",
            "Internal database error",
        )
    })?;

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
            tracing::error!("Failed to create client secret: {e}");
            // Remove the just-created client so a failed registration does
            // not leave a secretless confidential client behind (matches
            // the web form path).
            if let Err(cleanup_err) = db::delete_oauth_client(&state.store, &client.id).await {
                tracing::warn!(
                    "Failed to clean up OAuth client after secret creation failure: {cleanup_err}"
                );
            }
            return Err(e);
        }

        Some(secrecy::SecretString::from(secret))
    } else {
        None
    };

    tracing::info!("Created OAuth application: {} ({})", name, client_id);

    let jwks_configured = client.keys.is_some();
    let response_jwks_uri = client
        .keys
        .as_ref()
        .and_then(db::ClientKeys::uri)
        .map(String::from);

    Ok(Json(CreateApplicationResponse {
        id: client.id,
        client_id,
        client_secret,
        name: name.to_string(),
        application_type: req.application_type,
        access_scope: access_scope.as_str().to_string(),
        resource_uris: resource_uris.to_vec(),
        token_endpoint_auth_method: client.token_endpoint_auth_method.as_str().to_string(),
        fapi_profile: client.fapi_profile.as_str().to_string(),
        jwks_configured,
        jwks_uri: response_jwks_uri,
        post_logout_redirect_uris: client.post_logout_redirect_uris,
    }))
}

/// Get application details (API).
/// GET /api/v1/applications/:id
pub(crate) async fn get_application_api(
    State(state): State<Arc<AppState>>,
    AuthenticatedToken(token): AuthenticatedToken,
    ValidPath(app_id): ValidPath<ValidUuid>,
) -> Result<Json<ApplicationResponse>, ServiceError> {
    let client = db::get_oauth_client_by_id(&state.store, &app_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get application: {e}");
            ServiceError::api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Internal database error",
            )
        })?
        .ok_or_else(|| {
            ServiceError::api(StatusCode::NOT_FOUND, "not_found", "Application not found")
        })?;

    // Verify ownership
    if client.user_id.as_deref() != Some(token.sub.as_str()) {
        return Err(ServiceError::api(
            StatusCode::NOT_FOUND,
            "not_found",
            "Application not found",
        ));
    }

    Ok(Json(ApplicationResponse::from(client)))
}

/// Update an application (API).
/// PATCH /api/v1/applications/:id
pub(crate) async fn update_application_api(
    State(state): State<Arc<AppState>>,
    token: Result<AuthenticatedToken, ServiceError>,
    ValidPath(app_id): ValidPath<ValidUuid>,
    Json(req): Json<UpdateApplicationRequest>,
) -> Result<Json<ApplicationResponse>, ServiceError> {
    // ── Pure format validation first — no DB cost for malformed requests ──

    let validated = validate_update_format(UpdateAppInput {
        redirect_uris: req.redirect_uris.as_deref(),
        resource_uris: req.resource_uris.as_deref(),
        post_logout_redirect_uris: req.post_logout_redirect_uris.as_deref(),
        access_scope: req.access_scope.as_deref(),
        fapi_profile: req.fapi_profile.as_deref(),
        jwks: req.jwks.as_deref(),
        jwks_uri: req.jwks_uri.as_deref(),
    })?;

    // ── Authentication — validated input is good, now check credentials ──
    // Deferred so a malformed body still answers 400 rather than 401; an
    // unauthenticated request costs no DB lookup either way, because token
    // extraction fails before touching the store when no credential is sent.
    let AuthenticatedToken(token) = token?;

    // Get existing application
    let client = db::get_oauth_client_by_id(&state.store, &app_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get application for update: {e}");
            ServiceError::api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Internal database error",
            )
        })?
        .ok_or_else(|| {
            ServiceError::api(StatusCode::NOT_FOUND, "not_found", "Application not found")
        })?;

    // Verify ownership
    if client.user_id.as_deref() != Some(token.sub.as_str()) {
        return Err(ServiceError::api(
            StatusCode::NOT_FOUND,
            "not_found",
            "Application not found",
        ));
    }

    let access_scope = validated.access_scope;

    let user = load_active_user_for_scope(
        &state,
        &token.sub,
        access_scope == Some(AccessScope::Organization),
    )
    .await?;

    // Set org_id only for organization-scoped apps
    let org_id = if access_scope == Some(AccessScope::Organization) {
        user.org_id.as_deref()
    } else {
        None
    };

    // Apply updates (merge request values with existing client record).
    // Reject an explicitly provided empty/whitespace name; absent (None)
    // means "keep the existing name" and is always accepted.
    if let Some(new_name) = req.name.as_deref()
        && new_name.trim().is_empty()
    {
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "invalid_name",
            "Application name is required",
        ));
    }
    let name = req.name.as_deref().map_or(client.name.as_str(), str::trim);
    let description = req.description.as_deref().or(client.description.as_deref());
    let redirect_uris = req
        .redirect_uris
        .clone()
        .unwrap_or_else(|| client.redirect_uris.clone());

    // RFC 8707: Resource URIs default to existing if not provided.
    let resource_uris = req
        .resource_uris
        .as_deref()
        .map_or_else(|| client.resource_uris.clone(), <[String]>::to_vec);

    // FAPI rules that depend on the existing client record
    validate_update_fapi(&validated, &client)?;
    let fapi = compute_fapi_update_fields(&validated, &client)?;

    db::update_oauth_client(
        &state.store,
        &UpdateOAuthClientParams {
            id: &app_id,
            name,
            description,
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
    .map_err(|e| {
        tracing::error!("Failed to update OAuth client: {e}");
        ServiceError::api(
            StatusCode::INTERNAL_SERVER_ERROR,
            "db_error",
            "Internal database error",
        )
    })?;

    // Fetch updated client
    let updated = db::get_oauth_client_by_id(&state.store, &app_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to fetch updated application: {e}");
            ServiceError::api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Internal database error",
            )
        })?
        .ok_or_else(|| {
            ServiceError::api(StatusCode::NOT_FOUND, "not_found", "Application not found")
        })?;

    tracing::info!("Updated OAuth application: {} ({})", name, client.client_id);

    Ok(Json(ApplicationResponse::from(updated)))
}

/// Delete an application (API).
/// DELETE /api/v1/applications/:id
pub(crate) async fn delete_application_api(
    State(state): State<Arc<AppState>>,
    AuthenticatedToken(token): AuthenticatedToken,
    ValidPath(app_id): ValidPath<ValidUuid>,
) -> Result<StatusCode, ServiceError> {
    // Verify ownership
    let client = db::get_oauth_client_by_id(&state.store, &app_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get application for deletion: {e}");
            ServiceError::api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Internal database error",
            )
        })?
        .ok_or_else(|| {
            ServiceError::api(StatusCode::NOT_FOUND, "not_found", "Application not found")
        })?;

    if client.user_id.as_deref() != Some(token.sub.as_str()) {
        return Err(ServiceError::api(
            StatusCode::NOT_FOUND,
            "not_found",
            "Application not found",
        ));
    }

    db::delete_oauth_client(&state.store, &app_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to delete OAuth client: {e}");
            ServiceError::api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Internal database error",
            )
        })?;

    tracing::info!("Deleted OAuth application: {}", client.client_id);

    Ok(StatusCode::NO_CONTENT)
}

/// Add a new client secret (API).
/// POST /api/v1/applications/:id/secrets
pub(crate) async fn add_secret_api(
    State(state): State<Arc<AppState>>,
    AuthenticatedToken(token): AuthenticatedToken,
    ValidPath(app_id): ValidPath<ValidUuid>,
    Json(req): Json<AddSecretRequest>,
) -> Result<(StatusCode, Json<AddSecretResponse>), ServiceError> {
    let client = db::get_oauth_client_by_id(&state.store, &app_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get application: {e}");
            ServiceError::api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Internal database error",
            )
        })?
        .ok_or_else(|| {
            ServiceError::api(StatusCode::NOT_FOUND, "not_found", "Application not found")
        })?;

    if client.user_id.as_deref() != Some(token.sub.as_str()) {
        return Err(ServiceError::api(
            StatusCode::NOT_FOUND,
            "not_found",
            "Application not found",
        ));
    }

    if !client.application_type.requires_secret() {
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "no_secret",
            "This application type does not use client secrets",
        ));
    }

    if client.is_fapi()
        && client.token_endpoint_auth_method == db::TokenEndpointAuthMethod::PrivateKeyJwt
    {
        return Err(ServiceError::api(
            StatusCode::BAD_REQUEST,
            "no_secret",
            "FAPI clients using private_key_jwt do not use client secrets",
        ));
    }

    let secret = generate_client_secret();
    let secret_hash = hash_token(&secret);

    // The cap guard (≤ MAX_ACTIVE_SECRETS) is enforced inside
    // create_oauth_client_secret via an OCC-guarded transaction — the
    // pre-flight count that was here has been dropped because the in-tx guard
    // is authoritative and works correctly under concurrent adds on all backends.
    let record = db::create_oauth_client_secret(
        &state.store,
        &app_id,
        &secret_hash,
        req.description.as_deref(),
        None,
    )
    .await?;

    db::record_oauth_event(
        &state.audit,
        &state.store,
        &db::RecordOAuthEventParams {
            oauth_client_id: &app_id,
            event_type: OAuthEventType::SecretAdded,
            user_id: Some(&token.sub),
            ip_address: None,
            user_agent: None,
            details: Some("Secret added"),
            org_domain: db::RecordedOrgDomain::Unresolved,
        },
    )
    .await;

    tracing::info!("Added secret for OAuth application: {}", client.client_id);

    Ok((
        StatusCode::CREATED,
        Json(AddSecretResponse {
            secret_id: record.id,
            client_secret: secret.into(),
            created_at: record.created_at,
            expires_at: record.expires_at,
        }),
    ))
}

/// List secrets for an application (API).
/// GET /api/v1/applications/:id/secrets
pub(crate) async fn list_secrets_api(
    State(state): State<Arc<AppState>>,
    AuthenticatedToken(token): AuthenticatedToken,
    ValidPath(app_id): ValidPath<ValidUuid>,
) -> Result<Json<ListSecretsResponse>, ServiceError> {
    let client = db::get_oauth_client_by_id(&state.store, &app_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get application: {e}");
            ServiceError::api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Internal database error",
            )
        })?
        .ok_or_else(|| {
            ServiceError::api(StatusCode::NOT_FOUND, "not_found", "Application not found")
        })?;

    if client.user_id.as_deref() != Some(token.sub.as_str()) {
        return Err(ServiceError::api(
            StatusCode::NOT_FOUND,
            "not_found",
            "Application not found",
        ));
    }

    let now = jiff::Timestamp::now();
    let secrets = db::get_oauth_client_secrets(&state.store, &app_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get secrets: {e}");
            ServiceError::api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Internal database error",
            )
        })?;

    let secret_infos = secrets
        .into_iter()
        .map(|s| SecretInfo {
            active: s.is_valid(&now),
            id: s.id,
            description: s.description,
            created_at: s.created_at,
            expires_at: s.expires_at,
        })
        .collect();

    Ok(Json(ListSecretsResponse {
        secrets: secret_infos,
    }))
}

/// Delete (revoke) a secret (API).
/// DELETE /api/v1/applications/:id/secrets/:secret_id
pub(crate) async fn delete_secret_api(
    State(state): State<Arc<AppState>>,
    AuthenticatedToken(token): AuthenticatedToken,
    ValidPath((app_id, secret_id)): ValidPath<(ValidUuid, ValidUuid)>,
) -> Result<StatusCode, ServiceError> {
    let client = db::get_oauth_client_by_id(&state.store, &app_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get application: {e}");
            ServiceError::api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Internal database error",
            )
        })?
        .ok_or_else(|| {
            ServiceError::api(StatusCode::NOT_FOUND, "not_found", "Application not found")
        })?;

    if client.user_id.as_deref() != Some(token.sub.as_str()) {
        return Err(ServiceError::api(
            StatusCode::NOT_FOUND,
            "not_found",
            "Application not found",
        ));
    }

    let secret = db::get_oauth_client_secret_by_id(&state.store, &secret_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get secret: {e}");
            ServiceError::api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Internal database error",
            )
        })?
        .ok_or_else(|| ServiceError::api(StatusCode::NOT_FOUND, "not_found", "Secret not found"))?;

    if secret.oauth_client_id != *app_id {
        return Err(ServiceError::api(
            StatusCode::NOT_FOUND,
            "not_found",
            "Secret not found",
        ));
    }

    if secret.revoked_at.is_some() {
        return Err(ServiceError::api(
            StatusCode::NOT_FOUND,
            "not_found",
            "Secret not found",
        ));
    }

    let now = jiff::Timestamp::now();
    let all_secrets = db::get_oauth_client_secrets(&state.store, &app_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get secrets: {e}");
            ServiceError::api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Internal database error",
            )
        })?;

    let other_active = all_secrets
        .iter()
        .filter(|s| s.id != *secret_id && s.is_valid(&now))
        .count();

    if other_active == 0 {
        return Err(ServiceError::api(
            StatusCode::CONFLICT,
            "last_secret",
            "Cannot delete the last active secret",
        ));
    }

    // The floor guard (≥1 active) is enforced atomically inside
    // revoke_oauth_client_secret via an OCC-guarded transaction.  The pre-flight
    // count above remains as a fast-path for the common non-concurrent case.
    db::revoke_oauth_client_secret(&state.store, &secret_id, &app_id).await?;

    db::record_oauth_event(
        &state.audit,
        &state.store,
        &db::RecordOAuthEventParams {
            oauth_client_id: &app_id,
            event_type: OAuthEventType::SecretRevoked,
            user_id: Some(&token.sub),
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

    Ok(StatusCode::NO_CONTENT)
}

/// Revoke all tokens for an application (API).
/// `POST /api/v1/applications/:id/revoke`
pub(crate) async fn revoke_tokens_api(
    State(state): State<Arc<AppState>>,
    AuthenticatedToken(token): AuthenticatedToken,
    ValidPath(app_id): ValidPath<ValidUuid>,
) -> Result<StatusCode, ServiceError> {
    // Verify ownership
    let client = db::get_oauth_client_by_id(&state.store, &app_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get application for token revocation: {e}");
            ServiceError::api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Internal database error",
            )
        })?
        .ok_or_else(|| {
            ServiceError::api(StatusCode::NOT_FOUND, "not_found", "Application not found")
        })?;

    if client.user_id.as_deref() != Some(token.sub.as_str()) {
        return Err(ServiceError::api(
            StatusCode::NOT_FOUND,
            "not_found",
            "Application not found",
        ));
    }

    // Revoke all secrets. This blocks new issuance only —
    // `db::revoke_all_oauth_client_secrets` sets `revoked_at` on
    // `OAuthClientSecretDoc` rows, which the token-endpoint client-auth path
    // consults; the resource-protection and introspection paths never read
    // `revoked_at`. Already-minted access tokens are invalidated by the
    // session deletes below.
    db::revoke_all_oauth_client_secrets(&state.store, &app_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to revoke all secrets: {e}");
            ServiceError::api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Internal database error",
            )
        })?;

    // Terminate live M2M (client_credentials) sessions.
    //
    // Per RFC 9068 §2.2, client_credentials access tokens are persisted as
    // sessions whose `user_id` equals the OAuth client's `client_id`, so this
    // delete reaches exactly the M2M sessions for this client. Revoking
    // secrets is not enough on its own: the session cache may still serve
    // unexpired tokens until their TTL elapses. Deleting those sessions and
    // invalidating the cache is what closes the M2M half of revocation.
    //
    // Fail closed: if session deletion fails, do not report revocation
    // success. Secrets are already revoked, but unexpired M2M access tokens
    // could still validate via DB-backed session lookup, so the caller must
    // be told the revocation was incomplete (and retry) rather than see a
    // 204 + TokenRevoked.
    db::delete_sessions_for_user(&state.store, &client.client_id)
        .await
        .map_err(|e| {
            tracing::error!(
                "Failed to delete M2M sessions for {}: {e}",
                client.client_id
            );
            ServiceError::api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Internal database error",
            )
        })?;
    state.session_cache.invalidate_for_user(&client.client_id);

    // Terminate user-issued access-token sessions minted for this client.
    //
    // `authorization_code`, `device_code`, RFC 8693 `token_exchange`, and
    // FIDO2-assertion grants all persist sessions under the *real resource
    // owner's* `user_id` (not the client's), so the M2M delete above — which
    // filters by `user_id == client_id` — cannot reach them. Those sessions
    // carry the issuing client's id on the `client_id` index (stamped by
    // `create_oauth_access_token` from the RFC 9068 `client_id` claim), so a
    // client-scoped delete is what "revoke all tokens for an application"
    // must cover. Without it the tokens keep validating at resource
    // endpoints until their `exp`.
    //
    // Pre-migration sessions issued before the `client_id` index existed
    // deserialize `client_id` to `None` and so are not matched; they remain
    // valid until their `exp` (bounded by `session_hours`). New tokens minted
    // after this change are revocable on demand.
    //
    // Fail closed, as above: a failure here means some user-issued tokens for
    // this client may still validate, so do not report revocation success.
    db::delete_sessions_for_oauth_client(&state.store, &client.client_id)
        .await
        .map_err(|e| {
            tracing::error!(
                "Failed to delete user-issued sessions for client {}: {e}",
                client.client_id
            );
            ServiceError::api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db_error",
                "Internal database error",
            )
        })?;
    state.session_cache.invalidate_for_client(&client.client_id);

    // Log the event
    db::record_oauth_event(
        &state.audit,
        &state.store,
        &db::RecordOAuthEventParams {
            oauth_client_id: &app_id,
            event_type: OAuthEventType::TokenRevoked,
            user_id: Some(&token.sub),
            ip_address: None,
            user_agent: None,
            details: Some("All tokens revoked"),
            org_domain: db::RecordedOrgDomain::Unresolved,
        },
    )
    .await;

    tracing::info!(
        "Revoked all tokens for OAuth application: {}",
        client.client_id
    );

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests;
