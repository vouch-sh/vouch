// SPDX-License-Identifier: Apache-2.0 OR MIT
//! SCIM 2.0 User operations (RFC 7644).

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use std::sync::Arc;

use super::extract::{ScimJson, ScimQuery};
use super::patch::{
    Attribute, AttributeError, PatchOp, PatchOperation, apply_patch_op, optional_string,
    required_attribute, unqualified,
};
use super::types::{
    ScimEmail, ScimError, ScimListQuery, ScimListResponse, ScimMeta, ScimName, ScimPatchRequest,
    ScimUser,
};
use super::{ScimAuth, authenticate_scim, urn};
use crate::AppState;
use crate::arrival::ArrivalTime;
use crate::db;
use crate::db::{ScimFilterError, ScimScope};
use crate::email::Email;
use crate::redact_email;

/// The 400 returned when a SCIM write would leave the organization with no
/// active admin.
///
/// RFC 7644 §3.12 Table 9 defines `mutability` as "The attempted modification
/// is not compatible with the target attribute's mutability or **current
/// state**", applicable to PUT and PATCH — which is exactly this: `active` is
/// writable in general, but not on the organization's last active admin.
fn last_admin_scim_error() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(
            ScimError::new(
                400,
                "Cannot deactivate the organization's only remaining active admin",
            )
            .with_type("mutability"),
        ),
    )
        .into_response()
}

/// GET /scim/v2/Users (RFC 7644 Section 3.4.2).
///
/// Returns a paginated list of User resources, with optional filtering.
pub(crate) async fn list_users(
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
    if let Err((status, json)) = auth.require_scope(ScimScope::UsersRead) {
        return (status, json).into_response();
    }

    // Get users from database (returns page + total count in one call)
    let (users, total) = match db::list_scim_users(
        &state.store,
        &auth.org_id,
        // RFC 7644 §3.10: the attribute may carry its core schema URN prefix.
        query
            .filter
            .as_deref()
            .map(|filter| unqualified(filter.trim_start(), urn::USER)),
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
            tracing::error!("Failed to list users: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ScimError::new(500, "Failed to list users")),
            )
                .into_response();
        }
    };

    let base_url = &state.config().base_url;
    let resources: Vec<ScimUser> = users
        .into_iter()
        .map(|u| db_user_to_scim(base_url, u))
        .collect();

    // Audit log
    db::record_scim_audit(
        &state.audit,
        &db::ScimAuditData {
            operation: "list",
            resource_type: "User",
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

/// Map a [`db::CreateScimUserError`] onto its SCIM wire response.
///
/// Split from the create handler so every error arm — including the 503
/// backpressure mapping — has a test that triggers it directly.
pub(super) fn create_scim_user_error_response(
    org_id: &str,
    email: &str,
    err: db::CreateScimUserError,
) -> Response {
    match err {
        db::CreateScimUserError::DomainNotOwned => {
            tracing::warn!(
                org_id = %org_id,
                email = %redact_email(email),
                "rejected SCIM user creation: email domain is not verified for this organization"
            );
            (
                StatusCode::BAD_REQUEST,
                Json(
                    ScimError::new(400, "Email domain is not verified for this organization")
                        .with_type("invalidValue"),
                ),
            )
                .into_response()
        }
        db::CreateScimUserError::DuplicateEmail => {
            tracing::debug!(
                org_id = %org_id,
                email = %redact_email(email),
                "rejected SCIM user creation: user already exists"
            );
            (
                StatusCode::CONFLICT,
                Json(ScimError::new(409, "User already exists").with_type("uniqueness")),
            )
                .into_response()
        }
        db::CreateScimUserError::OccConflict => {
            // The org doc is the OCC serialization point for user creation
            // (domain validation version-bumps it), so bulk provisioning or
            // concurrent domain churn can exhaust the retry budget. That is
            // transient backpressure, not a server fault: return 503 with
            // Retry-After — IdP provisioners (Okta, Entra) retry on 503.
            tracing::warn!(
                org_id = %org_id,
                "SCIM user creation exhausted OCC retries (concurrent provisioning or domain churn)"
            );
            (
                StatusCode::SERVICE_UNAVAILABLE,
                [(axum::http::header::RETRY_AFTER, "1")],
                Json(ScimError::new(
                    503,
                    "Concurrent modification, retry the request",
                )),
            )
                .into_response()
        }
        db::CreateScimUserError::Other(e) => {
            if let Some(resp) = super::invalid_index_value_response(&e) {
                return resp.into_response();
            }
            tracing::error!("Failed to create user: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ScimError::new(500, "Failed to create user")),
            )
                .into_response()
        }
    }
}

/// POST /scim/v2/Users (RFC 7644 Section 3.3).
///
/// Creates a new User resource. Returns 201 Created on success,
/// 409 Conflict if the user already exists (RFC 7644 Section 3.3.1).
pub(crate) async fn create_user(
    arrival: ArrivalTime,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ScimJson(user): ScimJson<ScimUser>,
) -> Response {
    // Pure validation first — no DB cost for malformed requests
    let user_name = match required_attribute("userName", user.user_name.as_deref()) {
        Ok(user_name) => user_name,
        Err(invalid) => return invalid.into_response(),
    };

    // Authenticate and check scope
    let auth = match authenticate_scim(&state, &headers, arrival).await {
        Ok(auth) => auth,
        Err((status, json)) => return (status, json).into_response(),
    };
    if let Err((status, json)) = auth.require_scope(ScimScope::UsersWrite) {
        return (status, json).into_response();
    }

    // Extract email from userName or emails. RFC 7643 doesn't require
    // userName to be an email, but Vouch keys users by email — a userName
    // with no '@' and no emails[] fallback is rejected below.
    let email = if user_name.contains('@') {
        user_name.to_string()
    } else if let Some(emails) = &user.emails {
        emails
            .iter()
            .find(|e| e.primary)
            .or_else(|| emails.first())
            .map_or_else(|| user_name.to_string(), |e| e.value.clone())
    } else {
        user_name.to_string()
    };

    // Shape check (local part + domain suffix) — domain ownership is
    // validated inside `create_scim_user`'s transaction (reading the org
    // doc and version-bumping it via `compare_and_update`), which closes the
    // TOCTOU race with a concurrent `remove_additional_domain` that a
    // standalone pre-check here could not. `Email::is_valid_address`
    // inspects the local part too, so a `userName` that merely contains
    // `@` but is not an email (empty/whitespace/display-name-wrapped local
    // part) is rejected here; a NUL in the local part is still left to the
    // store's `validate_index_entry` guard, and an empty domain (`foo@`)
    // to the in-transaction ownership check.
    if !crate::email::Email::is_valid_address(&email) {
        tracing::warn!(
            org_id = %auth.org_id,
            "rejected SCIM user creation: userName is not an email address"
        );
        return (
            StatusCode::BAD_REQUEST,
            Json(
                ScimError::new(400, "userName must be an email address").with_type("invalidValue"),
            ),
        )
            .into_response();
    }

    let name = stored_name(user.name.as_ref());

    // Create user (domain ownership validated inside the transaction)
    let db_user = match db::create_scim_user(
        &state.store,
        Some(&auth.org_id),
        &email,
        name.as_deref(),
        user.external_id.as_deref(),
        user.active,
    )
    .await
    {
        Ok(u) => u,
        Err(e) => return create_scim_user_error_response(&auth.org_id, &email, e),
    };

    // Audit log
    db::record_scim_audit(
        &state.audit,
        &db::ScimAuditData {
            operation: "create",
            resource_type: "User",
            resource_id: &db_user.id,
            actor_token_id: Some(&auth.token_id),
            details: None,
            refusal: None,
        },
        auth.org_domain.as_deref(),
    )
    .await;

    let base_url = &state.config().base_url;
    let scim_user = db_user_to_scim(base_url, db_user);

    (StatusCode::CREATED, Json(scim_user)).into_response()
}

/// GET /scim/v2/Users/:id (RFC 7644 Section 3.4.1).
///
/// Retrieves a single User resource by ID.
pub(crate) async fn get_user(
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
    if let Err((status, json)) = auth.require_scope(ScimScope::UsersRead) {
        return (status, json).into_response();
    }

    let user = match db::get_scim_user(&state.store, &id, &auth.org_id).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ScimError::new(404, "User not found")),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("Failed to get user: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ScimError::new(500, "Failed to get user")),
            )
                .into_response();
        }
    };

    let base_url = &state.config().base_url;
    Json(db_user_to_scim(base_url, user)).into_response()
}

/// The single name Vouch stores for a User: `name.formatted`, or the given
/// and family names joined when the client sends only those.
fn stored_name(name: Option<&ScimName>) -> Option<String> {
    let name = name?;
    name.formatted
        .clone()
        .or_else(|| match (&name.given_name, &name.family_name) {
            (Some(g), Some(f)) => Some(format!("{g} {f}")),
            (Some(g), None) => Some(g.clone()),
            (None, Some(f)) => Some(f.clone()),
            (None, None) => None,
        })
}

/// The User state a PATCH or PUT writes, seeded from the stored record.
#[derive(Clone, PartialEq, Eq)]
struct UserUpdate {
    /// The stored email. `userName` and `emails` both present it and are
    /// `immutable`, so it is compared against, never written.
    email: Email,
    active: bool,
    name: Option<String>,
    external_id: Option<String>,
}

/// Rejects a presented `userName` that differs from the stored email.
///
/// `userName` is `immutable` (see `urn::USER_ATTRIBUTES`): RFC 7644 §3.5.1
/// says "the input value(s) MUST match, or HTTP status code 400 SHOULD be
/// returned with a "scimType" error code of "mutability"". Comparison is on
/// the canonical email, as RFC 7643 §4.1.1 makes `userName` case insensitive.
fn check_user_name(email: &Email, path: &str, presented: &str) -> Result<(), AttributeError> {
    if Email::new(presented) == *email {
        Ok(())
    } else {
        Err(AttributeError::mutability(format!(
            "{path} is immutable and must match the stored value"
        )))
    }
}

/// Rejects presented `emails` whose values differ from the stored email.
///
/// `emails` is `immutable`, and Vouch holds exactly one email, so every
/// presented `value` must be it. `value` is the only sub-attribute compared:
/// `type` and `primary` are assigned by Vouch on output and not stored.
/// `values` is an array of email objects or a single one; an empty array
/// would clear the attribute and is rejected unless `allow_empty` (a PATCH
/// `add` of nothing changes nothing).
fn check_emails(
    email: &Email,
    path: &str,
    values: &serde_json::Value,
    allow_empty: bool,
) -> Result<(), AttributeError> {
    let values = match values {
        serde_json::Value::Array(values) => values.as_slice(),
        serde_json::Value::Object(_) => std::slice::from_ref(values),
        serde_json::Value::Null
        | serde_json::Value::Bool(_)
        | serde_json::Value::Number(_)
        | serde_json::Value::String(_) => {
            return Err(AttributeError::invalid_value(format!(
                "{path} must be an array of email objects"
            )));
        }
    };
    if values.is_empty() && !allow_empty {
        return Err(AttributeError::mutability(format!(
            "{path} is immutable and cannot be cleared"
        )));
    }
    for value in values {
        let Some(presented) = value.get("value").and_then(serde_json::Value::as_str) else {
            return Err(AttributeError::invalid_value(format!(
                "{path} entries must carry a string value"
            )));
        };
        check_user_name(email, path, presented)?;
    }
    Ok(())
}

/// Applies a PATCH operation whose path addresses `emails`: the attribute
/// itself, a value filter (`emails[type eq "work"]`), or a sub-attribute
/// (`emails[type eq "work"].value`), which is what Entra sends.
///
/// RFC 7644 §3.5.2: "a client MUST NOT modify an attribute that has
/// mutability "readOnly" or "immutable"", and such an operation "SHALL
/// return the appropriate HTTP response status code and a JSON detail error
/// response". A removal or a differing value is that modification; a value
/// equal to the stored email changes nothing and succeeds.
fn apply_emails_op(email: &Email, path: &str, op: PatchOp<'_>) -> Result<(), AttributeError> {
    let (value, allow_empty) = match op {
        PatchOp::Remove(_) => {
            return Err(AttributeError::mutability(format!(
                "{path} is immutable and cannot be removed"
            )));
        }
        PatchOp::Add(value) => (value, true),
        PatchOp::Replace(value) => (value, false),
    };
    if let Some((_, rest)) = path.split_once('[') {
        let Some((filter, _)) = rest.split_once(']') else {
            return Err(AttributeError::invalid_filter(format!(
                "{path} has an unterminated value filter"
            )));
        };
        // RFC 7644 §3.5.2.3: "If the target location is a multi-valued
        // attribute for which a value selection filter ("valuePath") has been
        // supplied and no record match was made, the service provider SHALL
        // indicate failure by returning HTTP status code 400 and a "scimType"
        // error code of "noTarget"."
        if !email_filter_matches(email, path, filter)? {
            return Err(AttributeError::no_target(format!(
                "no email matches {path}"
            )));
        }
    }
    let sub_attribute = path
        .rsplit_once(']')
        .map_or(path, |(_, rest)| rest)
        .split_once('.')
        .map(|(_, sub_attribute)| sub_attribute);
    match sub_attribute {
        None => check_emails(email, path, value, allow_empty),
        Some(sub_attribute) if sub_attribute.eq_ignore_ascii_case("value") => {
            let Some(presented) = value.as_str() else {
                return Err(AttributeError::invalid_value(format!(
                    "{path} must be a string"
                )));
            };
            check_user_name(email, path, presented)
        }
        Some(_) => Ok(()),
    }
}

/// Whether a `valuePath` filter on `emails` matches the one email Vouch
/// presents: `value` is the stored email, `type` is `work`, and `primary` is
/// `true` (see `user_to_scim`). Vouch supports a single `eq` comparison.
fn email_filter_matches(email: &Email, path: &str, filter: &str) -> Result<bool, AttributeError> {
    let unsupported = || {
        AttributeError::invalid_filter(format!(
            "{path}: emails supports only a [value|type|primary eq <literal>] filter"
        ))
    };
    let mut parts = filter.trim().splitn(3, char::is_whitespace);
    let (Some(attribute), Some(operator), Some(literal)) =
        (parts.next(), parts.next(), parts.next())
    else {
        return Err(unsupported());
    };
    if !operator.eq_ignore_ascii_case("eq") {
        return Err(unsupported());
    }
    let literal = literal.trim();
    let string = || {
        literal
            .strip_prefix('"')
            .and_then(|l| l.strip_suffix('"'))
            .filter(|l| !l.contains('"'))
            .ok_or_else(unsupported)
    };
    if attribute.eq_ignore_ascii_case("value") {
        Ok(Email::new(string()?) == *email)
    } else if attribute.eq_ignore_ascii_case("type") {
        Ok(string()?.eq_ignore_ascii_case("work"))
    } else if attribute.eq_ignore_ascii_case("primary") {
        match literal {
            "true" => Ok(true),
            "false" => Ok(false),
            _ => Err(unsupported()),
        }
    } else {
        Err(unsupported())
    }
}

/// Whether a PATCH path addresses the `emails` attribute, with or without a
/// value filter or sub-attribute.
fn is_emails_path(path: &str) -> bool {
    path.split(['[', '.'])
        .next()
        .is_some_and(|attribute| attribute.eq_ignore_ascii_case("emails"))
}

/// The single-valued User attributes Vouch stores (RFC 7643 §4.1), with the
/// immutable `userName` a pathless PATCH can also present. `displayName`
/// addresses the same stored name as `name.formatted`.
///
/// `emails` has no entry: an empty `add` changes nothing while an empty
/// `replace` clears, and a table entry does not see the operation.
/// `patch_user` sends it to [`apply_emails_op`] for both the path-qualified
/// and pathless forms.
const USER_ATTRIBUTES: &[Attribute<UserUpdate>] = &[
    Attribute {
        paths: &["active"],
        set: |user, path, value| {
            // RFC 7643 §2.2 — `active` is a boolean. Coercing a non-boolean
            // (e.g. the string "false") to `true` would silently reactivate
            // a disabled user.
            let Some(active) = value.as_bool() else {
                return Err(AttributeError::invalid_value(format!(
                    "{path} must be a boolean"
                )));
            };
            // Deactivation is derived from the seed vs. final `active` after
            // all operations are applied (see `persist_user_update`);
            // assigning here keeps the setter focused on the stored field.
            user.active = active;
            Ok(())
        },
        // `active` is required (see `urn::USER_ATTRIBUTES`): it has no absent
        // state, and any default would change the user's access without the
        // identity provider asking. RFC 7644 §3.5.2.2: removing a required
        // attribute returns "a "scimType" error code of "mutability"".
        remove: |_, path| {
            Err(AttributeError::mutability(format!(
                "{path} is required and cannot be removed"
            )))
        },
    },
    Attribute {
        paths: &["name.formatted", "displayName"],
        set: |user, path, value| {
            user.name = optional_string(path, value)?;
            Ok(())
        },
        remove: |user, _| {
            user.name = None;
            Ok(())
        },
    },
    Attribute {
        paths: &["externalId"],
        set: |user, path, value| {
            user.external_id = optional_string(path, value)?;
            Ok(())
        },
        remove: |user, _| {
            user.external_id = None;
            Ok(())
        },
    },
    Attribute {
        paths: &["userName"],
        set: |user, path, value| {
            let Some(presented) = value.as_str() else {
                return Err(AttributeError::invalid_value(format!(
                    "{path} must be a string"
                )));
            };
            check_user_name(&user.email, path, presented)
        },
        // RFC 7644 §3.5.2: removing a required attribute returns
        // `mutability`, and `userName` is required (RFC 7643 §4.1.1).
        remove: |_, path| {
            Err(AttributeError::mutability(format!(
                "{path} is required and cannot be removed"
            )))
        },
    },
];

/// PATCH /scim/v2/Users/:id (RFC 7644 Section 3.5.2).
///
/// Modifies a User resource using SCIM PATCH operations (add, replace,
/// remove) applied against [`USER_ATTRIBUTES`]. Deactivating a user
/// invalidates all sessions and revokes SSH certificates.
pub(crate) async fn patch_user(
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
    if let Err((status, json)) = auth.require_scope(ScimScope::UsersWrite) {
        return (status, json).into_response();
    }

    let user = match get_user_for_write(&state, &id, &auth.org_id).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    // Apply patch operations
    let user_seed = UserUpdate {
        email: Email::new(&user.email),
        active: user.active,
        name: user.name,
        external_id: user.external_id,
    };
    let mut patched = user_seed.clone();

    let applied = patch.operations.iter().try_for_each(|op| {
        let operation = PatchOperation::parse(op, urn::USER)?;
        match operation.path.map(|path| unqualified(path, urn::USER)) {
            Some(path) if is_emails_path(path) => {
                apply_emails_op(&patched.email, path, operation.op)
            }
            Some(_) => apply_patch_op(USER_ATTRIBUTES, urn::USER, &mut patched, &operation),
            None => {
                if let Some(emails) = operation.attribute("emails") {
                    apply_emails_op(&patched.email, "emails", emails)?;
                }
                apply_patch_op(USER_ATTRIBUTES, urn::USER, &mut patched, &operation)
            }
        }
    });
    if let Err(invalid) = applied {
        return invalid.into_response();
    }

    persist_user_update(&state, &auth, &id, &user_seed, patched, "update").await
}

/// PUT /scim/v2/Users/:id (RFC 7644 Section 3.5.1).
///
/// Replaces a User's attributes. PUT never creates: an unknown id is 404.
/// Each attribute follows its mutability:
///
/// - `name` and `externalId` (`readWrite`) take the presented value, and an
///   omitted one is cleared — §3.5.1 lets the service provider "assume that
///   any existing values are to be cleared".
/// - `active` (`readWrite`) takes the presented value; omitted, it takes the
///   default `true`, as on create. A transition to `false` revokes access
///   exactly as a PATCH does.
/// - `userName` and `emails` (`immutable`) must match the stored email, or
///   the request is 400 `mutability`.
/// - `id`, `meta`, and `schemas` are ignored.
pub(crate) async fn put_user(
    arrival: ArrivalTime,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    ScimJson(user): ScimJson<ScimUser>,
) -> Response {
    // Pure validation first — no DB cost for malformed requests
    let user_name = match required_attribute("userName", user.user_name.as_deref()) {
        Ok(user_name) => user_name,
        Err(invalid) => return invalid.into_response(),
    };

    let auth = match authenticate_scim(&state, &headers, arrival).await {
        Ok(auth) => auth,
        Err((status, json)) => return (status, json).into_response(),
    };
    if let Err((status, json)) = auth.require_scope(ScimScope::UsersWrite) {
        return (status, json).into_response();
    }

    let stored = match get_user_for_write(&state, &id, &auth.org_id).await {
        Ok(stored) => stored,
        Err(response) => return response,
    };

    let email = Email::new(&stored.email);
    if let Err(invalid) = check_user_name(&email, "userName", user_name) {
        return invalid.into_response();
    }
    if let Some(emails) = &user.emails {
        if emails.is_empty() {
            return AttributeError::mutability("emails is immutable and cannot be cleared")
                .into_response();
        }
        for entry in emails {
            if let Err(invalid) = check_user_name(&email, "emails", &entry.value) {
                return invalid.into_response();
            }
        }
    }

    let replaced = UserUpdate {
        email,
        active: user.active,
        name: stored_name(user.name.as_ref()),
        external_id: user.external_id,
    };
    let stored = UserUpdate {
        email: Email::new(&stored.email),
        active: stored.active,
        name: stored.name,
        external_id: stored.external_id,
    };
    persist_user_update(&state, &auth, &id, &stored, replaced, "replace").await
}

/// Reads the User a write targets, answering 404 when it is not in the
/// caller's organization.
#[expect(
    clippy::result_large_err,
    reason = "Err is an HTTP Response; size is acceptable in error path"
)]
async fn get_user_for_write(
    state: &AppState,
    id: &str,
    org_id: &str,
) -> Result<db::ScimUserRecord, Response> {
    match db::get_scim_user(&state.store, id, org_id).await {
        Ok(Some(user)) => Ok(user),
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            Json(ScimError::new(404, "User not found")),
        )
            .into_response()),
        Err(e) => {
            tracing::error!("Failed to get user: {e}");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ScimError::new(500, "Failed to get user")),
            )
                .into_response())
        }
    }
}

/// Writes the User state a PATCH or PUT produced and returns the stored
/// resource.
///
/// `stored` is the state the request started from. An update equal to it
/// writes nothing, so `meta.lastModified` is unchanged: RFC 7644 §3.5.2.1
/// says re-adding a value already present "SHALL NOT change the modify
/// timestamp of the resource". RFC 7644
/// §3.5.2: operations are applied in array order to produce a final resource
/// state, so the deactivation decision is a function of the net `active`
/// transition — not of any single intermediate operation. Revocation fires
/// iff the user was active before the request and is inactive after it; a
/// PATCH such as `[active=false, active=true]` on an active user leaves
/// `active` true and must not destroy live credentials. `operation` names
/// the request in the audit row.
#[expect(
    clippy::too_many_lines,
    reason = "linear write path: guard the admin floor, revoke, persist, audit each outcome, re-read"
)]
async fn persist_user_update(
    state: &AppState,
    auth: &ScimAuth,
    id: &str,
    stored: &UserUpdate,
    updated: UserUpdate,
    operation: &'static str,
) -> Response {
    let deactivated = stored.active && !updated.active;

    // Refuse a last-admin deactivation *before* revoking, not after.
    // `revoke_then_persist` withdraws sessions and certificates first by
    // design, so letting the floor fire inside the persist step would log the
    // admin out and then decline the write. This read is advisory — the
    // authoritative check is inside `update_scim_user`'s transaction, and a
    // concurrent promotion or demotion can still flip the answer between the
    // two. Losing that race costs the admin their session, not their role.
    if deactivated {
        match db::is_last_active_org_admin(&state.store, id).await {
            Ok(true) => return last_admin_scim_error(),
            Ok(false) => {}
            Err(e) => {
                tracing::error!("Failed to count organization admins: {e}");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ScimError::new(500, "Failed to update user")),
                )
                    .into_response();
            }
        }
    }

    // A deactivation must revoke live credentials BEFORE the active=false write
    // commits: if the write landed first and revocation then failed, the user
    // would be left inactive with live SSH certificates, and the deactivation
    // transition gate would never re-fire revocation on retry (#1116). Any
    // other update just persists its field changes.
    let persist = || {
        db::update_scim_user(
            &state.store,
            id,
            &auth.org_id,
            updated.name.as_deref(),
            updated.external_id.as_deref(),
            updated.active,
        )
    };
    let result = if updated == *stored {
        Ok(true)
    } else if deactivated {
        tracing::info!(
            "User {} deactivated via SCIM: revoking sessions and SSH certificates before persisting",
            id
        );
        crate::services::auth::revoke_then_persist(
            state,
            id,
            "User deactivated via SCIM",
            "scim",
            persist,
        )
        .await
    } else {
        persist()
            .await
            .map_err(crate::services::auth::DeactivationError::Persist)
    };
    match result {
        Ok(true) => {}
        Ok(false) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ScimError::new(404, "User not found")),
            )
                .into_response();
        }
        Err(crate::services::auth::DeactivationError::Revoke(_)) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ScimError::new(500, "Failed to revoke user access")),
            )
                .into_response();
        }
        // Reached when an admin demotion commits between the advisory pre-check
        // and the in-transaction count. `revoke_then_persist` has already
        // committed the revocation, so it is audited; `refusal: "last_admin"`
        // separates a floor refusal from a failed write.
        Err(crate::services::auth::DeactivationError::Persist(db::ScimUpdateError::LastAdmin)) => {
            if deactivated {
                db::record_scim_audit(
                    &state.audit,
                    &db::ScimAuditData {
                        operation,
                        resource_type: "User",
                        resource_id: id,
                        actor_token_id: Some(&auth.token_id),
                        details: Some(
                            &serde_json::json!({
                                "active": updated.active,
                                "deactivated": true,
                                "accessRevoked": true,
                                "persisted": false
                            })
                            .to_string(),
                        ),
                        refusal: Some(db::Refusal::LastAdmin),
                    },
                    auth.org_domain.as_deref(),
                )
                .await;
            }
            return last_admin_scim_error();
        }
        Err(crate::services::auth::DeactivationError::Persist(e)) => {
            if deactivated {
                // `revoke_then_persist` already withdrew the user's sessions
                // and SSH certificates; that committed change gets its audit
                // row even though the `active = false` write then failed.
                db::record_scim_audit(
                    &state.audit,
                    &db::ScimAuditData {
                        operation,
                        resource_type: "User",
                        resource_id: id,
                        actor_token_id: Some(&auth.token_id),
                        details: Some(
                            &serde_json::json!({
                                "active": updated.active,
                                "deactivated": true,
                                "accessRevoked": true,
                                "persisted": false
                            })
                            .to_string(),
                        ),
                        refusal: None,
                    },
                    auth.org_domain.as_deref(),
                )
                .await;
            }
            if let db::ScimUpdateError::Other(ref inner) = e
                && let Some(resp) = super::invalid_index_value_response(inner)
            {
                return resp.into_response();
            }
            if matches!(e, db::ScimUpdateError::OccConflict) {
                // The org doc serializes the admin-count guard, so bulk
                // provisioning can exhaust the retry budget. Transient
                // backpressure, not a fault — 503 with Retry-After, which
                // IdP provisioners honor. Mirrors the create path.
                tracing::warn!("SCIM user update exhausted OCC retries");
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
            tracing::error!("Failed to update user: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ScimError::new(500, "Failed to update user")),
            )
                .into_response();
        }
    }

    // Audit log
    db::record_scim_audit(
        &state.audit,
        &db::ScimAuditData {
            operation,
            resource_type: "User",
            resource_id: id,
            actor_token_id: Some(&auth.token_id),
            details: Some(
                &serde_json::json!({"active": updated.active, "deactivated": deactivated})
                    .to_string(),
            ),
            refusal: None,
        },
        auth.org_domain.as_deref(),
    )
    .await;

    // Return updated user
    let stored = match db::get_scim_user(&state.store, id, &auth.org_id).await {
        Ok(Some(u)) => u,
        Ok(None) | Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ScimError::new(500, "Failed to get updated user")),
            )
                .into_response();
        }
    };

    let base_url = &state.config().base_url;
    Json(db_user_to_scim(base_url, stored)).into_response()
}

/// DELETE /scim/v2/Users/:id (RFC 7644 Section 3.6).
///
/// Permanently deletes a User resource. Returns 204 No Content on success.
/// All sessions are invalidated and SSH certificates are revoked.
pub(crate) async fn delete_user(
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
    if let Err((status, json)) = auth.require_scope(ScimScope::UsersWrite) {
        return (status, json).into_response();
    };

    // Check user exists
    let user = match db::get_scim_user(&state.store, &id, &auth.org_id).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ScimError::new(404, "User not found")),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("Failed to get user: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ScimError::new(500, "Failed to get user")),
            )
                .into_response();
        }
    };

    // Refuse a last-admin delete *before* revoking, as `patch_user` does.
    // `revoke_user_access` commits in its own transactions, so a floor that
    // fires only inside `delete_user` would log the admin out and then
    // decline the write. This read is advisory; the in-transaction
    // `LastAdminGuard::Enforce` check below stays authoritative, and losing
    // the race between the two costs the admin a session, not their role.
    match db::is_last_active_org_admin(&state.store, &id).await {
        Ok(true) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ScimError::new(
                    400,
                    "Cannot delete the organization's only remaining active admin",
                )),
            )
                .into_response();
        }
        Ok(false) => {}
        Err(e) => {
            tracing::error!("Failed to count organization admins: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ScimError::new(500, "Failed to delete user")),
            )
                .into_response();
        }
    }

    // Delete all sessions first (immediate invalidation)
    tracing::info!(
        "Deleting user {} ({}) via SCIM, invalidating sessions and revoking SSH certificates",
        id,
        redact_email(&user.email)
    );
    // Revoke access before deleting. If revocation fails, abort — delete_user
    // would destroy the issued cert records, making the certs permanently
    // unrevocable.
    if crate::services::auth::revoke_user_access(&state, &id, "User deleted via SCIM", "scim")
        .await
        .is_err()
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ScimError::new(500, "Failed to revoke user access")),
        )
            .into_response();
    }

    // Delete user (cascades to authenticators). A `false` return means the
    // user vanished between the existence check above and the delete (e.g. a
    // concurrent request deleted it). Surface a 404 and skip the audit event
    // rather than reporting a successful delete — and logging a fraudulent
    // audit entry — for a change that never happened.
    match db::delete_user(&state.store, &id, db::LastAdminGuard::Enforce).await {
        Ok(true) => {}
        Ok(false) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ScimError::new(404, "User not found")),
            )
                .into_response();
        }
        // A `UsersWrite` token could otherwise delete every admin in sequence,
        // leaving the organization with no way back in: `delete_user` keeps
        // `organization.created_by_user_id` pointing at the deleted admin, and
        // `enroll_user_with_org` only auto-promotes when that field is unset.
        //
        // RFC 7644 §3.6 does not describe refusing a delete, and Table 9 in
        // §3.12 lists no `scimType` applicable to DELETE, so this is a plain
        // 400 with a human-readable `detail`.
        Err(db::DeleteUserError::LastAdmin) => {
            // Access was revoked above and that commit stands, so it is
            // audited; `refusal: "last_admin"` separates a floor refusal from a
            // failed delete.
            db::record_scim_audit(
                &state.audit,
                &db::ScimAuditData {
                    operation: "delete",
                    resource_type: "User",
                    resource_id: &id,
                    actor_token_id: Some(&auth.token_id),
                    details: Some(
                        &serde_json::json!({
                            "accessRevoked": true,
                            "deleted": false
                        })
                        .to_string(),
                    ),
                    refusal: Some(db::Refusal::LastAdmin),
                },
                auth.org_domain.as_deref(),
            )
            .await;
            return (
                StatusCode::BAD_REQUEST,
                Json(ScimError::new(
                    400,
                    "Cannot delete the organization's only remaining active admin",
                )),
            )
                .into_response();
        }
        Err(e) => {
            // Access was already revoked above; that committed change gets
            // its audit row even though the delete itself failed.
            db::record_scim_audit(
                &state.audit,
                &db::ScimAuditData {
                    operation: "delete",
                    resource_type: "User",
                    resource_id: &id,
                    actor_token_id: Some(&auth.token_id),
                    details: Some(
                        &serde_json::json!({"accessRevoked": true, "deleted": false}).to_string(),
                    ),
                    refusal: None,
                },
                auth.org_domain.as_deref(),
            )
            .await;
            tracing::error!("Failed to delete user: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ScimError::new(500, "Failed to delete user")),
            )
                .into_response();
        }
    }

    // Audit log
    db::record_scim_audit(
        &state.audit,
        &db::ScimAuditData {
            operation: "delete",
            resource_type: "User",
            resource_id: &id,
            actor_token_id: Some(&auth.token_id),
            details: None,
            refusal: None,
        },
        auth.org_domain.as_deref(),
    )
    .await;

    StatusCode::NO_CONTENT.into_response()
}

/// Convert database user to SCIM user.
pub(crate) fn db_user_to_scim(base_url: &str, user: db::ScimUserRecord) -> ScimUser {
    ScimUser {
        schemas: vec![urn::USER.to_string()],
        id: Some(user.id.clone()),
        external_id: user.external_id,
        user_name: Some(user.email.clone()),
        name: user.name.map(|n| ScimName {
            formatted: Some(n),
            family_name: None,
            given_name: None,
        }),
        emails: Some(vec![ScimEmail {
            value: user.email,
            primary: true,
            email_type: Some("work".to_string()),
        }]),
        active: user.active,
        meta: Some(ScimMeta {
            resource_type: "User".to_string(),
            created: user.created_at,
            last_modified: Some(user.updated_at),
            location: format!("{base_url}/scim/v2/Users/{}", user.id),
        }),
    }
}
