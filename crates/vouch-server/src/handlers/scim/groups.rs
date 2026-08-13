// SPDX-License-Identifier: Apache-2.0 OR MIT
//! SCIM 2.0 Group operations (RFC 7644).

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use std::sync::Arc;

use super::authenticate_scim;
use super::types::{
    ScimError, ScimGroup, ScimGroupMember, ScimListQuery, ScimListResponse, ScimMeta,
    ScimPatchOpType, ScimPatchRequest,
};
use crate::AppState;
use crate::db;
use crate::db::{ScimFilterError, ScimScope};

/// GET /scim/v2/Groups (RFC 7644 Section 3.4.2).
///
/// Returns a paginated list of Group resources, with optional filtering.
pub(crate) async fn list_groups(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<ScimListQuery>,
) -> Response {
    // Pure validation first — no DB cost for malformed requests
    let start_index = query.start_index.unwrap_or(1);
    let count = query.count.unwrap_or(100).min(100);

    if let Err((status, json)) = super::validate_list_params(query.filter.as_deref(), start_index) {
        return (status, json).into_response();
    }

    // Authenticate and check scope
    let auth = match authenticate_scim(&state, &headers).await {
        Ok(auth) => auth,
        Err((status, json)) => return (status, json).into_response(),
    };
    if let Err((status, json)) = auth.require_scope(ScimScope::GroupsRead) {
        return (status, json).into_response();
    }

    // Get groups from database (returns page + total count in one call)
    let (groups, total) = match db::list_scim_groups(
        &state.store,
        &auth.org_id,
        query.filter.as_deref(),
        start_index,
        count,
    )
    .await
    {
        Ok(result) => result,
        Err(e) => {
            if let Some(filter_err) = e.downcast_ref::<ScimFilterError>() {
                let (detail, error_type) = match filter_err {
                    ScimFilterError::UnsupportedOperator(_) => {
                        tracing::debug!("SCIM filter parse error: {e}");
                        ("Invalid filter expression", "invalidFilter")
                    }
                    ScimFilterError::FilterTooBroad => (
                        "Filter is too broad; add a more specific filter",
                        "invalidFilter",
                    ),
                    ScimFilterError::OffsetTooLarge => (
                        "startIndex is too large; maximum supported offset is 10000",
                        "invalidValue",
                    ),
                };
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ScimError::new(400, detail).with_type(error_type)),
                )
                    .into_response();
            }
            tracing::error!("Failed to list groups: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ScimError::new(500, "Failed to list groups")),
            )
                .into_response();
        }
    };

    let base_url = &state.config().base_url;
    let mut resources = Vec::new();
    for g in groups {
        let members = get_group_members_scim(&state.store, base_url, &g.id, &auth.org_id).await;
        resources.push(db_group_to_scim(base_url, g, members));
    }

    // Audit log
    if let Err(e) = db::insert_scim_audit(
        &state.audit,
        "list",
        "Group",
        "*",
        Some(&auth.token_id),
        Some(&format!("{{\"count\": {}}}", resources.len())),
        auth.org_domain.as_deref(),
    )
    .await
    {
        tracing::warn!("Failed to record SCIM audit: {e}");
    }

    Json(ScimListResponse {
        schemas: vec!["urn:ietf:params:scim:api:messages:2.0:ListResponse".to_string()],
        total_results: total,
        items_per_page: resources.len(),
        start_index,
        resources,
    })
    .into_response()
}

/// Map a `create_scim_group` error onto its SCIM wire response.
///
/// Split from the create handler so every error arm — the 400
/// `invalidValue` path (NUL in an index field) and the 500 infrastructure
/// path — has a test that triggers it directly, mirroring the user
/// handler's `create_scim_user_error_response`.
///
/// Infrastructure failures (serialization, encryption, database connection
/// or timeout errors, exhausted OCC retries) return `500 INTERNAL SERVER
/// ERROR`, matching `list_groups`, `get_group`, `patch_group`, and
/// `delete_group`. A previous version returned `409 CONFLICT` with a
/// `uniqueness` SCIM type for all errors, which mislabelled transient
/// infrastructure faults as duplicate-group conflicts.
pub(super) fn create_scim_group_error_response(err: anyhow::Error) -> Response {
    if let Some(resp) = super::invalid_index_value_response(&err) {
        return resp.into_response();
    }
    tracing::error!("Failed to create group: {err}");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ScimError::new(500, "Failed to create group")),
    )
        .into_response()
}

/// POST /scim/v2/Groups (RFC 7644 Section 3.3).
///
/// Creates a new Group resource. Returns 201 Created on success.
pub(crate) async fn create_group(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(group): Json<ScimGroup>,
) -> Response {
    // Pure validation first — no DB cost for malformed requests
    if group.display_name.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ScimError::new(
                400,
                "displayName is required and must not be empty",
            )),
        )
            .into_response();
    }

    // Authenticate and check scope
    let auth = match authenticate_scim(&state, &headers).await {
        Ok(auth) => auth,
        Err((status, json)) => return (status, json).into_response(),
    };
    if let Err((status, json)) = auth.require_scope(ScimScope::GroupsWrite) {
        return (status, json).into_response();
    }

    // Create group
    let db_group = match db::create_scim_group(
        &state.store,
        &auth.org_id,
        &group.display_name,
        group.external_id.as_deref(),
    )
    .await
    {
        Ok(g) => g,
        Err(e) => return create_scim_group_error_response(e),
    };

    // Add members if provided
    if let Some(members) = &group.members {
        for member in members {
            if let Err(e) =
                db::add_scim_group_member(&state.store, &db_group.id, &auth.org_id, &member.value)
                    .await
            {
                if let Some(resp) = super::invalid_index_value_response(&e) {
                    return resp.into_response();
                }
                tracing::warn!("Failed to add member {} to group: {e}", member.value);
            }
        }
    }

    // Audit log
    if let Err(e) = db::insert_scim_audit(
        &state.audit,
        "create",
        "Group",
        &db_group.id,
        Some(&auth.token_id),
        Some(&serde_json::json!({"displayName": &db_group.display_name}).to_string()),
        auth.org_domain.as_deref(),
    )
    .await
    {
        tracing::warn!("Failed to record SCIM audit: {e}");
    }

    let base_url = &state.config().base_url;
    let members = get_group_members_scim(&state.store, base_url, &db_group.id, &auth.org_id).await;
    let scim_group = db_group_to_scim(base_url, db_group, members);

    (StatusCode::CREATED, Json(scim_group)).into_response()
}

/// GET /scim/v2/Groups/:id (RFC 7644 Section 3.4.1).
///
/// Retrieves a single Group resource by ID, including its members.
pub(crate) async fn get_group(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    // Validate resource ID before any processing
    if let Err((status, json)) = super::validate_resource_id(&id) {
        return (status, json).into_response();
    }

    // Authenticate
    let auth = match authenticate_scim(&state, &headers).await {
        Ok(auth) => auth,
        Err((status, json)) => return (status, json).into_response(),
    };
    if let Err((status, json)) = auth.require_scope(ScimScope::GroupsRead) {
        return (status, json).into_response();
    }

    let group = match db::get_scim_group(&state.store, &id, &auth.org_id).await {
        Ok(Some(g)) => g,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ScimError::new(404, "Group not found")),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("Failed to get group: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ScimError::new(500, "Failed to get group")),
            )
                .into_response();
        }
    };

    let base_url = &state.config().base_url;
    let members = get_group_members_scim(&state.store, base_url, &group.id, &auth.org_id).await;
    Json(db_group_to_scim(base_url, group, members)).into_response()
}

/// PATCH /scim/v2/Groups/:id (RFC 7644 Section 3.5.2).
///
/// Modifies a Group resource using SCIM PATCH operations (add, replace, remove).
/// Supports member management via the `members` path.
#[expect(
    clippy::too_many_lines,
    reason = "SCIM PATCH operation handles add/remove/replace across all group fields"
)]
pub(crate) async fn patch_group(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(patch): Json<ScimPatchRequest>,
) -> Response {
    // Validate resource ID before any processing
    if let Err((status, json)) = super::validate_resource_id(&id) {
        return (status, json).into_response();
    }

    // Authenticate and check scope
    let auth = match authenticate_scim(&state, &headers).await {
        Ok(auth) => auth,
        Err((status, json)) => return (status, json).into_response(),
    };
    if let Err((status, json)) = auth.require_scope(ScimScope::GroupsWrite) {
        return (status, json).into_response();
    }

    // Get existing group
    let group = match db::get_scim_group(&state.store, &id, &auth.org_id).await {
        Ok(Some(g)) => g,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ScimError::new(404, "Group not found")),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("Failed to get group: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ScimError::new(500, "Failed to get group")),
            )
                .into_response();
        }
    };

    // Apply patch operations
    let mut display_name = group.display_name.clone();
    let mut external_id = group.external_id.clone();

    for op in &patch.operations {
        match op.op {
            ScimPatchOpType::Replace => {
                if let Some(path) = &op.path {
                    match path.as_str() {
                        "displayName" => {
                            if let Some(val) = &op.value
                                && let Some(s) = val.as_str()
                            {
                                display_name = s.to_string();
                            }
                        }
                        "externalId" => {
                            if let Some(val) = &op.value {
                                external_id = val.as_str().map(String::from);
                            }
                        }
                        "members" => {
                            // Replace all members
                            if let Some(val) = &op.value
                                && let Some(arr) = val.as_array()
                            {
                                let user_ids: Vec<String> = arr
                                    .iter()
                                    .filter_map(|v| {
                                        v.get("value").and_then(|v| v.as_str()).map(String::from)
                                    })
                                    .collect();
                                if let Err(e) = db::replace_scim_group_members(
                                    &state.store,
                                    &id,
                                    &auth.org_id,
                                    &user_ids,
                                )
                                .await
                                {
                                    if let Some(resp) = super::invalid_index_value_response(&e) {
                                        return resp.into_response();
                                    }
                                    tracing::error!("Failed to replace group members: {e}");
                                }
                            }
                        }
                        _ => {}
                    }
                } else if let Some(val) = &op.value {
                    // Replace entire resource
                    if let Some(n) = val.get("displayName").and_then(|v| v.as_str()) {
                        display_name = n.to_string();
                    }
                    if let Some(e) = val.get("externalId").and_then(|v| v.as_str()) {
                        external_id = Some(e.to_string());
                    }
                }
            }
            ScimPatchOpType::Add => {
                if let Some(path) = &op.path
                    && path == "members"
                    && let Some(val) = &op.value
                {
                    // Add members
                    if let Some(arr) = val.as_array() {
                        for member in arr {
                            if let Some(user_id) = member.get("value").and_then(|v| v.as_str())
                                && let Err(e) = db::add_scim_group_member(
                                    &state.store,
                                    &id,
                                    &auth.org_id,
                                    user_id,
                                )
                                .await
                            {
                                if let Some(resp) = super::invalid_index_value_response(&e) {
                                    return resp.into_response();
                                }
                                tracing::warn!("Failed to add member: {e}");
                            }
                        }
                    }
                }
            }
            ScimPatchOpType::Remove => {
                if let Some(path) = &op.path {
                    if path == "externalId" {
                        external_id = None;
                    } else if path.starts_with("members")
                        && let Some(user_id) = parse_member_filter(path)
                        && let Err(e) =
                            db::remove_scim_group_member(&state.store, &id, &auth.org_id, &user_id)
                                .await
                    {
                        tracing::warn!("Failed to remove member: {e}");
                    }
                }
            }
        }
    }

    // Update group in database
    if display_name != group.display_name || external_id != group.external_id {
        match db::update_scim_group(
            &state.store,
            &id,
            &auth.org_id,
            Some(&display_name),
            external_id.as_deref(),
        )
        .await
        {
            Ok(true) => {}
            Ok(false) => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(ScimError::new(404, "Group not found")),
                )
                    .into_response();
            }
            Err(e) => {
                if let Some(resp) = super::invalid_index_value_response(&e) {
                    return resp.into_response();
                }
                tracing::error!("Failed to update group: {e}");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ScimError::new(500, "Failed to update group")),
                )
                    .into_response();
            }
        }
    }

    // Audit log
    if let Err(e) = db::insert_scim_audit(
        &state.audit,
        "update",
        "Group",
        &id,
        Some(&auth.token_id),
        None,
        auth.org_domain.as_deref(),
    )
    .await
    {
        tracing::warn!("Failed to record SCIM audit: {e}");
    }

    // Return updated group
    let updated = match db::get_scim_group(&state.store, &id, &auth.org_id).await {
        Ok(Some(g)) => g,
        Ok(None) | Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ScimError::new(500, "Failed to get updated group")),
            )
                .into_response();
        }
    };

    let base_url = &state.config().base_url;
    let members = get_group_members_scim(&state.store, base_url, &updated.id, &auth.org_id).await;
    Json(db_group_to_scim(base_url, updated, members)).into_response()
}

/// DELETE /scim/v2/Groups/:id (RFC 7644 Section 3.6).
///
/// Permanently deletes a Group resource. Returns 204 No Content on success.
/// Group membership records are cascade-deleted.
pub(crate) async fn delete_group(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    // Validate resource ID before any processing
    if let Err((status, json)) = super::validate_resource_id(&id) {
        return (status, json).into_response();
    }

    // Authenticate and check scope
    let auth = match authenticate_scim(&state, &headers).await {
        Ok(auth) => auth,
        Err((status, json)) => return (status, json).into_response(),
    };
    if let Err((status, json)) = auth.require_scope(ScimScope::GroupsWrite) {
        return (status, json).into_response();
    }

    // Check group exists
    let group = match db::get_scim_group(&state.store, &id, &auth.org_id).await {
        Ok(Some(g)) => g,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ScimError::new(404, "Group not found")),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("Failed to get group: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ScimError::new(500, "Failed to get group")),
            )
                .into_response();
        }
    };

    // Delete group (cascades to memberships)
    if let Err(e) = db::delete_scim_group(&state.store, &id, &auth.org_id).await {
        tracing::error!("Failed to delete group: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ScimError::new(500, "Failed to delete group")),
        )
            .into_response();
    }

    // Audit log
    if let Err(e) = db::insert_scim_audit(
        &state.audit,
        "delete",
        "Group",
        &id,
        Some(&auth.token_id),
        Some(&serde_json::json!({"displayName": &group.display_name}).to_string()),
        auth.org_domain.as_deref(),
    )
    .await
    {
        tracing::warn!("Failed to record SCIM audit: {e}");
    }

    StatusCode::NO_CONTENT.into_response()
}

/// Helper to get group members in SCIM format, scoped to the
/// caller's org. Cross-org user_ids in the membership table are
/// silently filtered out at read time by `db::get_scim_group_members`.
pub(crate) async fn get_group_members_scim(
    db: &crate::db::store::DocumentStore,
    base_url: &str,
    group_id: &str,
    org_id: &str,
) -> Vec<ScimGroupMember> {
    match db::get_scim_group_members(db, group_id, org_id).await {
        Ok(Some(users)) => users
            .into_iter()
            .map(|u| ScimGroupMember {
                value: u.id.clone(),
                ref_url: Some(format!("{base_url}/scim/v2/Users/{}", u.id)),
                display: Some(u.email),
            })
            .collect(),
        Ok(None) | Err(_) => Vec::new(),
    }
}

/// Convert database group to SCIM group.
pub(crate) fn db_group_to_scim(
    base_url: &str,
    group: db::ScimGroupRecord,
    members: Vec<ScimGroupMember>,
) -> ScimGroup {
    ScimGroup {
        schemas: vec!["urn:ietf:params:scim:schemas:core:2.0:Group".to_string()],
        id: Some(group.id.clone()),
        external_id: group.external_id,
        display_name: group.display_name,
        members: if members.is_empty() {
            None
        } else {
            Some(members)
        },
        meta: Some(ScimMeta {
            resource_type: "Group".to_string(),
            created: group.created_at,
            last_modified: Some(group.updated_at),
            location: format!("{base_url}/scim/v2/Groups/{}", group.id),
        }),
    }
}

/// Parse members filter path like "members[value eq \"user-id\"]".
fn parse_member_filter(path: &str) -> Option<String> {
    // Simple parser for members[value eq "user-id"]
    if let Some(start) = path.find("value eq \"") {
        let start_idx = start.saturating_add(10);
        if let Some(rest) = path.get(start_idx..)
            && let Some(end) = rest.find('"')
        {
            return rest.get(..end).map(String::from);
        }
    }
    None
}
