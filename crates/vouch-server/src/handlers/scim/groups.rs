// SPDX-License-Identifier: Apache-2.0 OR MIT
//! SCIM 2.0 Group operations (RFC 7644).

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use std::collections::BTreeSet;
use std::sync::Arc;

use super::extract::{ScimJson, ScimQuery};
use super::patch::{
    Attribute, AttributeError, PatchOp, PatchOperation, apply_patch_op, get_attribute,
    optional_string, required_attribute, strip_prefix_ignore_ascii_case, unqualified,
};
use super::types::{
    ScimError, ScimGroup, ScimGroupMember, ScimListQuery, ScimListResponse, ScimMeta, ScimPatchOp,
    ScimPatchRequest,
};
use super::{ScimAuth, authenticate_scim, urn};
use crate::AppState;
use crate::arrival::ArrivalTime;
use crate::db;
use crate::db::{ScimFilterError, ScimScope};
use crate::error::ServiceError;

/// GET /scim/v2/Groups (RFC 7644 Section 3.4.2).
///
/// Returns a paginated list of Group resources, with optional filtering.
pub(crate) async fn list_groups(
    arrival: ArrivalTime,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ScimQuery(query): ScimQuery<ScimListQuery>,
) -> Response {
    // Pure validation first — no DB cost for malformed requests
    let start_index = query.start_index.unwrap_or(1);
    let count = query.count.unwrap_or(100).min(100);

    if let Err((status, json)) = super::validate_list_params(query.filter.as_deref(), start_index) {
        return (status, json).into_response();
    }

    // Authenticate and check scope
    let auth = match authenticate_scim(&state, &headers, arrival).await {
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
        // RFC 7644 §3.10: the attribute may carry its core schema URN prefix.
        query
            .filter
            .as_deref()
            .map(|filter| unqualified(filter.trim_start(), urn::GROUP)),
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
        let Ok(members) = get_group_members_scim(&state.store, base_url, &g.id, &auth.org_id).await
        else {
            return members_read_error_response();
        };
        resources.push(db_group_to_scim(base_url, g, members));
    }

    // Audit log
    db::record_scim_audit(
        &state.audit,
        &db::ScimAuditData {
            operation: "list",
            resource_type: "Group",
            resource_id: "*",
            actor_token_id: Some(&auth.token_id),
            details: Some(&format!("{{\"count\": {}}}", resources.len())),
            refusal: None,
        },
        auth.org_domain.as_deref(),
    )
    .await;

    Json(ScimListResponse {
        schemas: vec![urn::LIST_RESPONSE.to_string()],
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

/// Response for a failed group-membership read.
///
/// The read itself logs the cause; this only shapes the SCIM error body.
fn members_read_error_response() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ScimError::new(500, "Failed to read group members")),
    )
        .into_response()
}

/// POST /scim/v2/Groups (RFC 7644 Section 3.3).
///
/// Creates a new Group resource. Returns 201 Created on success.
pub(crate) async fn create_group(
    arrival: ArrivalTime,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ScimJson(group): ScimJson<ScimGroup>,
) -> Response {
    // Pure validation first — no DB cost for malformed requests
    let display_name = match check_display_name(group.display_name.as_deref()) {
        Ok(display_name) => display_name,
        Err(invalid) => return invalid.into_response(),
    };

    // Authenticate and check scope
    let auth = match authenticate_scim(&state, &headers, arrival).await {
        Ok(auth) => auth,
        Err((status, json)) => return (status, json).into_response(),
    };
    if let Err((status, json)) = auth.require_scope(ScimScope::GroupsWrite) {
        return (status, json).into_response();
    }

    // Create the group and its members in one transaction
    let member_ids: Vec<String> = group
        .members
        .unwrap_or_default()
        .into_iter()
        .map(|member| member.value)
        .collect();
    let db_group = match db::create_scim_group(
        &state.store,
        &auth.org_id,
        display_name,
        group.external_id.as_deref(),
        &member_ids,
    )
    .await
    {
        Ok(g) => g,
        Err(e) => return create_scim_group_error_response(e),
    };

    db::record_scim_audit(
        &state.audit,
        &db::ScimAuditData {
            operation: "create",
            resource_type: "Group",
            resource_id: &db_group.id,
            actor_token_id: Some(&auth.token_id),
            details: Some(&serde_json::json!({"displayName": &db_group.display_name}).to_string()),
            refusal: None,
        },
        auth.org_domain.as_deref(),
    )
    .await;

    let base_url = &state.config().base_url;
    let Ok(members) =
        get_group_members_scim(&state.store, base_url, &db_group.id, &auth.org_id).await
    else {
        return members_read_error_response();
    };
    let scim_group = db_group_to_scim(base_url, db_group, members);

    (StatusCode::CREATED, Json(scim_group)).into_response()
}

/// GET /scim/v2/Groups/:id (RFC 7644 Section 3.4.1).
///
/// Retrieves a single Group resource by ID, including its members.
pub(crate) async fn get_group(
    arrival: ArrivalTime,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    // Authenticate
    let auth = match authenticate_scim(&state, &headers, arrival).await {
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
    let Ok(members) = get_group_members_scim(&state.store, base_url, &group.id, &auth.org_id).await
    else {
        return members_read_error_response();
    };
    Json(db_group_to_scim(base_url, group, members)).into_response()
}

/// The single-valued Group attributes Vouch stores (RFC 7643 §4.2).
const GROUP_ATTRIBUTES: &[Attribute<db::ScimGroupState>] = &[
    Attribute {
        paths: &["displayName"],
        set: |group, path, value| {
            let Some(display_name) = value.as_str() else {
                return Err(AttributeError::invalid_value(format!(
                    "{path} must be a string"
                )));
            };
            check_display_name(Some(display_name))?;
            group.display_name = display_name.to_string();
            Ok(())
        },
        // RFC 7644 §3.5.2.2: "If an attribute is removed or becomes
        // unassigned and is defined as a required attribute ..., the server
        // SHALL return ... a "scimType" error code of "mutability"", and
        // RFC 7643 §4.2 makes displayName required.
        remove: |_, path| {
            Err(AttributeError::mutability(format!(
                "{path} is required and cannot be removed"
            )))
        },
    },
    Attribute {
        paths: &["externalId"],
        set: |group, path, value| {
            group.external_id = optional_string(path, value)?;
            Ok(())
        },
        remove: |group, _| {
            group.external_id = None;
            Ok(())
        },
    },
];

/// A PATCH `path` addressing the Group `members` attribute: `members`, a
/// value filter `members[value eq "…"]`, and an optional sub-attribute
/// (RFC 7644 §3.5.2, `PATH = attrPath / valuePath [subAttr]`).
#[derive(Debug, PartialEq, Eq)]
struct MembersPath<'p> {
    /// The member user id a `value eq` filter selects.
    filter: Option<&'p str>,
    sub_attribute: Option<&'p str>,
}

/// Parses `path` as a [`MembersPath`], or `None` when it addresses another
/// attribute.
///
/// Attribute names and the `eq` operator are case insensitive (RFC 7643
/// §2.1, RFC 7644 §3.4.2.2); the quoted id is returned verbatim. `value eq`
/// is the only filter members support, so any other filter is 400
/// `invalidFilter` (RFC 7644 §3.12 Table 9: "the specified attribute and
/// filter comparison combination is not supported").
fn parse_members_path(path: &str) -> Result<Option<MembersPath<'_>>, AttributeError> {
    let root_end = path.find(['[', '.']).unwrap_or(path.len());
    let (root, rest) = path.split_at(root_end);
    if !root.eq_ignore_ascii_case("members") {
        return Ok(None);
    }

    let (filter, rest) = match rest.strip_prefix('[') {
        Some(inner) => {
            let unsupported = || {
                AttributeError::invalid_filter(format!(
                    "{path}: members supports only a [value eq \"<id>\"] filter"
                ))
            };
            let inner = inner.trim_start();
            let inner = strip_prefix_ignore_ascii_case(inner, "value")
                .ok_or_else(unsupported)?
                .trim_start();
            let inner = strip_prefix_ignore_ascii_case(inner, "eq")
                .ok_or_else(unsupported)?
                .trim_start();
            let inner = inner.strip_prefix('"').ok_or_else(unsupported)?;
            let (id, after) = inner.split_once('"').ok_or_else(unsupported)?;
            let after = after
                .trim_start()
                .strip_prefix(']')
                .ok_or_else(unsupported)?;
            (Some(id), after)
        }
        None => (None, rest),
    };

    let sub_attribute = match rest {
        "" => None,
        rest => match rest.strip_prefix('.') {
            Some(sub_attribute) if !sub_attribute.is_empty() => Some(sub_attribute),
            Some(_) | None => {
                return Err(AttributeError::invalid_path(format!(
                    "{path} is not a valid members path"
                )));
            }
        },
    };

    Ok(Some(MembersPath {
        filter,
        sub_attribute,
    }))
}

/// The member user ids in a `members` value: an array of member objects or a
/// single one, each carrying a string `value`.
fn member_ids(path: &str, value: &serde_json::Value) -> Result<Vec<String>, AttributeError> {
    let entries = match value {
        serde_json::Value::Array(entries) => entries.as_slice(),
        serde_json::Value::Object(_) => std::slice::from_ref(value),
        serde_json::Value::Null
        | serde_json::Value::Bool(_)
        | serde_json::Value::Number(_)
        | serde_json::Value::String(_) => {
            return Err(AttributeError::invalid_value(format!(
                "{path} must be an array of member objects"
            )));
        }
    };
    let mut ids = Vec::with_capacity(entries.len());
    for entry in entries {
        let Some(id) = get_attribute(entry, "value").and_then(serde_json::Value::as_str) else {
            return Err(AttributeError::invalid_value(format!(
                "{path} entries must carry a string value"
            )));
        };
        ids.push(id.to_string());
    }
    Ok(ids)
}

/// Applies one operation addressing `members` to the member set
/// (RFC 7644 §3.5.2.1–§3.5.2.3).
///
/// - `add` adds the presented members; one already present changes nothing.
/// - `replace` without a filter replaces the whole set. With a filter it
///   replaces the matched member, and "If the target location is a
///   multi-valued attribute for which a value selection filter ("valuePath")
///   has been supplied and no record match was made, the service provider
///   SHALL indicate failure by returning HTTP status code 400 and a
///   "scimType" error code of "noTarget"."
/// - `remove` with a filter removes the matched member, and with a `value`
///   list (Entra's form) the members it names; one that is not a member
///   changes nothing. With neither, "the attribute and all values are
///   removed".
/// - `value` is the one member sub-attribute Vouch stores. `display` and
///   `$ref` are derived on output, so operations on them change nothing;
///   removing `value` is removing a required sub-attribute, 400 `mutability`.
fn apply_members_op(
    members: &mut BTreeSet<String>,
    path: &str,
    target: &MembersPath<'_>,
    op: PatchOp<'_>,
) -> Result<(), AttributeError> {
    let targets_value = target
        .sub_attribute
        .map(|sub_attribute| sub_attribute.eq_ignore_ascii_case("value"));
    match (op, target.filter, targets_value) {
        (PatchOp::Add(value), None, None) => {
            members.extend(member_ids(path, value)?);
            Ok(())
        }
        (PatchOp::Add(_), Some(_), _) | (PatchOp::Add(_), None, Some(_)) => {
            Err(AttributeError::invalid_path(format!(
                "add cannot target {path}; add to members instead"
            )))
        }
        (PatchOp::Replace(value), None, None) => {
            *members = member_ids(path, value)?.into_iter().collect();
            Ok(())
        }
        (PatchOp::Replace(_), None, Some(_)) => Err(AttributeError::invalid_path(format!(
            "replace cannot target {path} without a member filter"
        ))),
        (PatchOp::Replace(value), Some(id), targets_value) => {
            if !members.contains(id) {
                return Err(AttributeError::no_target(format!(
                    "no member matches {path}"
                )));
            }
            let replacements = match targets_value {
                None => member_ids(path, value)?,
                Some(true) => {
                    let Some(replacement) = value.as_str() else {
                        return Err(AttributeError::invalid_value(format!(
                            "{path} must be a string"
                        )));
                    };
                    vec![replacement.to_string()]
                }
                Some(false) => return Ok(()),
            };
            members.remove(id);
            members.extend(replacements);
            Ok(())
        }
        (PatchOp::Remove(_), _, Some(true)) => Err(AttributeError::mutability(format!(
            "{path} is required and cannot be removed"
        ))),
        (PatchOp::Remove(_), _, Some(false)) => Ok(()),
        (PatchOp::Remove(_), Some(id), None) => {
            members.remove(id);
            Ok(())
        }
        (PatchOp::Remove(value), None, None) => {
            match value {
                Some(value) => {
                    for id in member_ids(path, value)? {
                        members.remove(&id);
                    }
                }
                None => members.clear(),
            }
            Ok(())
        }
    }
}

/// Applies one PATCH operation to a Group: `members` paths to the member
/// set, every other path through [`GROUP_ATTRIBUTES`]. A pathless `add` or
/// `replace` may carry `members` among the attributes in its value.
fn apply_group_op(group: &mut db::ScimGroupState, op: &ScimPatchOp) -> Result<(), AttributeError> {
    let operation = PatchOperation::parse(op, urn::GROUP)?;
    let Some(path) = operation.path.map(|path| unqualified(path, urn::GROUP)) else {
        apply_patch_op(GROUP_ATTRIBUTES, urn::GROUP, group, &operation)?;
        if let Some(members) = operation.attribute("members") {
            let target = MembersPath {
                filter: None,
                sub_attribute: None,
            };
            apply_members_op(&mut group.members, "members", &target, members)?;
        }
        return Ok(());
    };
    match parse_members_path(path)? {
        Some(target) => apply_members_op(&mut group.members, path, &target, operation.op),
        None => apply_patch_op(GROUP_ATTRIBUTES, urn::GROUP, group, &operation),
    }
}

/// The `displayName` a Group body presents. RFC 7643 §4.2 makes it required:
/// omitted, the body does not conform to the schema (`invalidSyntax`); empty
/// or whitespace, the value is unusable (`invalidValue`).
fn check_display_name(display_name: Option<&str>) -> Result<&str, AttributeError> {
    let display_name = required_attribute("displayName", display_name)?;
    if display_name.trim().is_empty() {
        return Err(AttributeError::invalid_value(
            "displayName must not be empty",
        ));
    }
    Ok(display_name)
}

/// PATCH /scim/v2/Groups/:id (RFC 7644 Section 3.5.2).
///
/// Applies the operations in order to the stored group and commits the
/// result in one transaction: an operation that fails leaves the group, its
/// attributes and its members, exactly as it was.
pub(crate) async fn patch_group(
    arrival: ArrivalTime,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    ScimJson(patch): ScimJson<ScimPatchRequest>,
) -> Response {
    // Authenticate and check scope
    let auth = match authenticate_scim(&state, &headers, arrival).await {
        Ok(auth) => auth,
        Err((status, json)) => return (status, json).into_response(),
    };
    if let Err((status, json)) = auth.require_scope(ScimScope::GroupsWrite) {
        return (status, json).into_response();
    }

    let result = db::update_scim_group(&state.store, &id, &auth.org_id, |group| {
        patch
            .operations
            .iter()
            .try_for_each(|op| apply_group_op(group, op))
    })
    .await;
    group_write_response(&state, &auth, &id, result, "update").await
}

/// PUT /scim/v2/Groups/:id (RFC 7644 Section 3.5.1).
///
/// Replaces a Group's attributes in one transaction. PUT never creates: an
/// unknown id is 404. `displayName` is required. `externalId` and `members`
/// are `readWrite`, so each takes the presented value and an omitted one is
/// cleared — §3.5.1 lets the service provider "assume that any existing
/// values are to be cleared" — which for `members` removes every member.
/// `id`, `meta`, and `schemas` are ignored.
pub(crate) async fn put_group(
    arrival: ArrivalTime,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    ScimJson(group): ScimJson<ScimGroup>,
) -> Response {
    // Pure validation first — no DB cost for malformed requests
    let display_name = match check_display_name(group.display_name.as_deref()) {
        Ok(display_name) => display_name.to_string(),
        Err(invalid) => return invalid.into_response(),
    };

    let auth = match authenticate_scim(&state, &headers, arrival).await {
        Ok(auth) => auth,
        Err((status, json)) => return (status, json).into_response(),
    };
    if let Err((status, json)) = auth.require_scope(ScimScope::GroupsWrite) {
        return (status, json).into_response();
    }

    let replacement = db::ScimGroupState {
        display_name,
        external_id: group.external_id,
        members: group
            .members
            .unwrap_or_default()
            .into_iter()
            .map(|member| member.value)
            .collect(),
    };
    let result = db::update_scim_group(&state.store, &id, &auth.org_id, |stored| {
        stored.clone_from(&replacement);
        Ok::<(), AttributeError>(())
    })
    .await;
    group_write_response(&state, &auth, &id, result, "replace").await
}

/// Maps the outcome of a Group PATCH or PUT onto its response: the error, or
/// an audit row and the stored resource. `operation` names the request in
/// the audit row.
async fn group_write_response(
    state: &AppState,
    auth: &ScimAuth,
    id: &str,
    result: Result<bool, db::ScimGroupUpdateError<AttributeError>>,
    operation: &'static str,
) -> Response {
    match result {
        Ok(true) => {}
        Ok(false) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ScimError::new(404, "Group not found")),
            )
                .into_response();
        }
        Err(db::ScimGroupUpdateError::Rejected(rejection)) => return rejection.into_response(),
        Err(db::ScimGroupUpdateError::OccConflict) => {
            // Concurrent writes to one group collide on its document and
            // retry; exhausting the budget is transient backpressure, not a
            // fault. Mirrors the User update path.
            tracing::warn!("SCIM group update exhausted OCC retries");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                [(axum::http::header::RETRY_AFTER, "1")],
                Json(ScimError::new(
                    503,
                    "Concurrent modification, retry the request",
                )),
            )
                .into_response();
        }
        Err(db::ScimGroupUpdateError::Other(e)) => {
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

    db::record_scim_audit(
        &state.audit,
        &db::ScimAuditData {
            operation,
            resource_type: "Group",
            resource_id: id,
            actor_token_id: Some(&auth.token_id),
            details: None,
            refusal: None,
        },
        auth.org_domain.as_deref(),
    )
    .await;

    let updated = match db::get_scim_group(&state.store, id, &auth.org_id).await {
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
    let Ok(members) =
        get_group_members_scim(&state.store, base_url, &updated.id, &auth.org_id).await
    else {
        return members_read_error_response();
    };
    Json(db_group_to_scim(base_url, updated, members)).into_response()
}

/// DELETE /scim/v2/Groups/:id (RFC 7644 Section 3.6).
///
/// Permanently deletes a Group resource. Returns 204 No Content on success.
/// Group membership records are cascade-deleted.
pub(crate) async fn delete_group(
    arrival: ArrivalTime,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    // Authenticate and check scope
    let auth = match authenticate_scim(&state, &headers, arrival).await {
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

    // Delete group (cascades to memberships). `false` means a concurrent
    // request deleted it after the existence check: nothing happened here, so
    // there is no audit event.
    match db::delete_scim_group(&state.store, &id, &auth.org_id).await {
        Ok(true) => {}
        Ok(false) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ScimError::new(404, "Group not found")),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("Failed to delete group: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ScimError::new(500, "Failed to delete group")),
            )
                .into_response();
        }
    }

    // Audit log
    db::record_scim_audit(
        &state.audit,
        &db::ScimAuditData {
            operation: "delete",
            resource_type: "Group",
            resource_id: &id,
            actor_token_id: Some(&auth.token_id),
            details: Some(&serde_json::json!({"displayName": &group.display_name}).to_string()),
            refusal: None,
        },
        auth.org_domain.as_deref(),
    )
    .await;

    StatusCode::NO_CONTENT.into_response()
}

/// Helper to get group members in SCIM format, scoped to the
/// caller's org. Cross-org user_ids in the membership table are
/// silently filtered out at read time by `db::get_scim_group_members`.
///
/// A read failure is an error rather than an empty list: the response body is
/// the resource as stored, so returning `members: []` for a group that has
/// members reports a membership change that never happened.
///
/// `Ok(None)` means the group is not in this org and stays an empty list.
///
/// # Errors
///
/// Returns [`ServiceError`] if the membership read fails.
pub(crate) async fn get_group_members_scim(
    db: &crate::db::store::DocumentStore,
    base_url: &str,
    group_id: &str,
    org_id: &str,
) -> Result<Vec<ScimGroupMember>, ServiceError> {
    match db::get_scim_group_members(db, group_id, org_id).await {
        Ok(Some(users)) => Ok(users
            .into_iter()
            .map(|u| ScimGroupMember {
                value: u.id.clone(),
                ref_url: Some(format!("{base_url}/scim/v2/Users/{}", u.id)),
                display: Some(u.email),
            })
            .collect()),
        Ok(None) => Ok(Vec::new()),
        Err(e) => {
            tracing::error!("Failed to read members for group {group_id}: {e}");
            Err(ServiceError::Internal(
                "failed to read group members".to_string(),
            ))
        }
    }
}

/// Convert database group to SCIM group.
pub(crate) fn db_group_to_scim(
    base_url: &str,
    group: db::ScimGroupRecord,
    members: Vec<ScimGroupMember>,
) -> ScimGroup {
    ScimGroup {
        schemas: vec![urn::GROUP.to_string()],
        id: Some(group.id.clone()),
        external_id: group.external_id,
        display_name: Some(group.display_name),
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

#[cfg(test)]
mod members_path_tests {
    use super::{MembersPath, parse_members_path};

    fn parsed(path: &str) -> Option<MembersPath<'_>> {
        parse_members_path(path).ok().flatten()
    }

    #[test]
    fn plain_members_path() {
        assert_eq!(
            parsed("Members"),
            Some(MembersPath {
                filter: None,
                sub_attribute: None
            })
        );
        assert_eq!(parse_members_path("displayName").ok(), Some(None));
    }

    // RFC 7643 §2.1 and RFC 7644 §3.4.2.2: attribute names and operators are
    // case insensitive; the filtered value keeps its case.
    #[test]
    fn value_filter_is_case_insensitive_and_preserves_the_id() {
        for path in [
            r#"members[value eq "AbC-123"]"#,
            r#"members[VALUE EQ "AbC-123"]"#,
            r#"MEMBERS[ Value Eq "AbC-123" ]"#,
            // RFC 7644 §3.5.2.2's own example has no space before the quote.
            r#"members[value eq"AbC-123"]"#,
        ] {
            assert_eq!(
                parsed(path),
                Some(MembersPath {
                    filter: Some("AbC-123"),
                    sub_attribute: None
                }),
                "{path}"
            );
        }
    }

    #[test]
    fn value_filter_with_sub_attribute() {
        assert_eq!(
            parsed(r#"members[value eq "u1"].display"#),
            Some(MembersPath {
                filter: Some("u1"),
                sub_attribute: Some("display")
            })
        );
        assert_eq!(
            parsed("members.value"),
            Some(MembersPath {
                filter: None,
                sub_attribute: Some("value")
            })
        );
    }

    #[test]
    fn non_ascii_before_the_filter_is_rejected_not_mis_sliced() {
        // Matching is positional, so no case folding can shift the slice
        // and truncate the id; anything but `value eq` is unsupported.
        for path in [
            "members[\u{0130} value eq \"victim\"]",
            "members[\u{00DF} value EQ \"victim\"]",
        ] {
            assert_eq!(
                parse_members_path(path).err().map(|e| e.scim_type),
                Some("invalidFilter"),
                "{path}"
            );
        }
        assert_eq!(
            parsed("members[value eq \"İstanbul-user\"]"),
            Some(MembersPath {
                filter: Some("İstanbul-user"),
                sub_attribute: None
            })
        );
    }

    // RFC 7644 §3.12 Table 9: `invalidFilter` covers "the specified attribute
    // and filter comparison combination is not supported".
    #[test]
    fn other_filters_are_invalid_filter() {
        for path in [
            "members[]",
            r#"members[display eq "Babs"]"#,
            r#"members[value co "u"]"#,
            r#"members[value eq "u1" and display eq "x"]"#,
            r#"members[value eq "u1""#,
        ] {
            assert_eq!(
                parse_members_path(path).err().map(|e| e.scim_type),
                Some("invalidFilter"),
                "{path}"
            );
        }
    }

    #[test]
    fn trailing_garbage_is_invalid_path() {
        for path in [r#"members[value eq "u1"]x"#, "members."] {
            assert_eq!(
                parse_members_path(path).err().map(|e| e.scim_type),
                Some("invalidPath"),
                "{path}"
            );
        }
    }
}
