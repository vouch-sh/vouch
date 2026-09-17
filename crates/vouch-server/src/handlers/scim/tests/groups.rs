// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Group resource CRUD, PATCH, membership, and schema validation
//! (RFC 7643 §4.2).
#![expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable"
)]

use super::*;

// ========================================================================
// RFC 7643 Section 4.2 — Group CRUD Positive Tests
// ========================================================================

#[tokio::test]
async fn test_scim_create_group() {
    // POST /scim/v2/Groups returns 201 with id, displayName, schemas, meta
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-create-group", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Groups",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"], "displayName": "Engineering"}"#,
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::CREATED);
    let group: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert!(group.get("id").is_some(), "Created group must have id");
    assert_eq!(group["displayName"], "Engineering");
    assert!(group.get("schemas").is_some(), "Group must have schemas");
    assert!(group.get("meta").is_some(), "Group must have meta");
}

#[tokio::test]
async fn test_scim_create_group_with_external_id() {
    // POST with externalId should return it in the response
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-create-group-extid", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Groups",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"], "displayName": "Sales", "externalId": "ext-sales-42"}"#,
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::CREATED);
    let group: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(group["externalId"], "ext-sales-42");
    assert_eq!(group["displayName"], "Sales");
}

#[tokio::test]
async fn test_scim_get_group_by_id() {
    // GET /scim/v2/Groups/{id} returns the group
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-get-group", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    // Create a group first
    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Groups",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"], "displayName": "Platform"}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let group_id = created["id"].as_str().expect("group id");

    // Fetch the group by ID
    let (status, body) = http_get(
        &app,
        &format!("/scim/v2/Groups/{}", group_id),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let group: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(group["id"], group_id);
    assert_eq!(group["displayName"], "Platform");
}

#[tokio::test]
async fn test_scim_list_groups_empty() {
    // GET /scim/v2/Groups on fresh DB returns empty Resources and totalResults: 0
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-list-groups-empty", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    let (status, body) =
        http_get(&app, "/scim/v2/Groups", &[("Authorization", &auth_header)]).await;

    assert_eq!(status, StatusCode::OK);
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(response["totalResults"], 0);
    let resources = response["Resources"].as_array().expect("Resources array");
    assert!(resources.is_empty(), "Empty DB must return empty Resources");
}

#[tokio::test]
async fn test_scim_list_groups_returns_created() {
    // Create a group then list — it should appear in the results
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-list-groups-created", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    let (status, _) = http_post_json(
        &app,
        "/scim/v2/Groups",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"], "displayName": "Infra"}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, body) =
        http_get(&app, "/scim/v2/Groups", &[("Authorization", &auth_header)]).await;

    assert_eq!(status, StatusCode::OK);
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert!(
        response["totalResults"].as_u64().unwrap_or(0) >= 1,
        "totalResults must be at least 1 after creating a group"
    );
    let resources = response["Resources"].as_array().expect("Resources array");
    assert!(
        resources.iter().any(|r| r["displayName"] == "Infra"),
        "Created group must appear in list response"
    );
}

#[tokio::test]
async fn test_scim_delete_group() {
    // DELETE returns 204; subsequent GET returns 404
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-delete-group", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    // Create group to delete
    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Groups",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"], "displayName": "ToDelete"}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let group_id = created["id"].as_str().expect("group id");

    // Delete it
    let (status, _) = http_delete(
        &app,
        &format!("/scim/v2/Groups/{}", group_id),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Verify the group is gone
    let (status, _) = http_get(
        &app,
        &format!("/scim/v2/Groups/{}", group_id),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_scim_delete_group_writes_success_audit_event() {
    // A successful DELETE returns 204 and records exactly one
    // `scim_operation` delete audit row with `refusal` absent (OCSF Success).
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-delete-group-audit", "test-org").await;
    let auth_header = format!("Bearer {token}");

    // Create a group to delete.
    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Groups",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"], "displayName": "AuditMe"}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "body: {body}");
    let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let group_id = created["id"].as_str().expect("group id").to_string();

    // Delete it.
    let (status, _body) = http_delete(
        &app,
        &format!("/scim/v2/Groups/{group_id}"),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Exactly one `scim_operation` delete row for the target, with `refusal`
    // absent (the operation happened).
    let rows = scim_audit_rows(&state).await;
    let delete_rows: Vec<_> = rows
        .iter()
        .filter(|e| {
            e.get("operation").and_then(|o| o.as_str()) == Some("delete")
                && e.get("resource_id").and_then(|r| r.as_str()) == Some(&group_id)
        })
        .collect();
    assert_eq!(
        delete_rows.len(),
        1,
        "one scim_operation delete audit event must be written on success; got {}",
        delete_rows
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join(", "),
    );
    assert!(
        delete_rows[0].get("refusal").is_none(),
        "success delete audit row must omit `refusal` (operation happened); got {}",
        delete_rows[0],
    );
}

#[tokio::test]
async fn test_scim_patch_group_replace_display_name() {
    // PATCH replace displayName, verify the change is persisted
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-patch-group-name", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    // Create group
    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Groups",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"], "displayName": "OldName"}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let group_id = created["id"].as_str().expect("group id");

    // PATCH to replace displayName
    let (status, body) = http_request(
        &app,
        "PATCH",
        &format!("/scim/v2/Groups/{}", group_id),
        Some(r#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "replace", "path": "displayName", "value": "NewName"}]}"#.to_string()),
        &[
            ("Content-Type", "application/json"),
            ("Authorization", &auth_header),
        ],
    )
    .await;

    assert_eq!(status, StatusCode::OK, "PATCH must return 200: {body}");
    let updated: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(updated["displayName"], "NewName");
}

#[tokio::test]
async fn test_scim_patch_group_replace_external_id() {
    // PATCH replace externalId, verify the change is persisted
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-patch-group-extid", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    // Create group without externalId
    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Groups",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"], "displayName": "DevOps"}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let group_id = created["id"].as_str().expect("group id");

    // PATCH to set externalId
    let (status, body) = http_request(
        &app,
        "PATCH",
        &format!("/scim/v2/Groups/{}", group_id),
        Some(r#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "replace", "path": "externalId", "value": "ext-devops-99"}]}"#.to_string()),
        &[
            ("Content-Type", "application/json"),
            ("Authorization", &auth_header),
        ],
    )
    .await;

    assert_eq!(status, StatusCode::OK, "PATCH must return 200: {body}");
    let updated: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(updated["externalId"], "ext-devops-99");
}

// ========================================================================
// RFC 7644 Section 3.5.2.1 — Group Add operation on single-valued attrs
// ========================================================================
//
// RFC 7644 §3.5.2.1: "If the target location specifies a single-valued
// attribute, the existing value is replaced." These tests confirm the Add
// operation applies displayName and externalId updates for Groups — the
// same behavior as Replace — rather than silently ignoring them.

#[tokio::test]
async fn test_scim_patch_group_add_display_name() {
    // RFC 7644 §3.5.2.1: Add with path "displayName" must replace the
    // existing group displayName, not be silently ignored.
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-add-group-name", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    // Create group with initial displayName.
    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Groups",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"], "displayName": "OldGroupName"}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "setup create failed: {body}");
    let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let group_id = created["id"].as_str().expect("group id");
    assert_eq!(created["displayName"], "OldGroupName");

    // PATCH add displayName.
    let (status, body) = http_request(
        &app,
        "PATCH",
        &format!("/scim/v2/Groups/{}", group_id),
        Some(r#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "add", "path": "displayName", "value": "NewGroupName"}]}"#.to_string()),
        &[
            ("Content-Type", "application/json"),
            ("Authorization", &auth_header),
        ],
    )
    .await;

    assert_eq!(status, StatusCode::OK, "PATCH add must return 200: {body}");
    let updated: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        updated["displayName"], "NewGroupName",
        "Add displayName must replace the existing group name (RFC 7644 §3.5.2.1)"
    );

    // Re-GET to confirm persistence.
    let (status, body) = http_get(
        &app,
        &format!("/scim/v2/Groups/{}", group_id),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let fetched: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(fetched["displayName"], "NewGroupName");
}

#[tokio::test]
async fn test_scim_patch_group_add_external_id() {
    // RFC 7644 §3.5.2.1: Add with path "externalId" must set/replace the
    // group's externalId, not be silently ignored.
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-add-group-extid", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Groups",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"], "displayName": "AddExtIdGroup"}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "setup create failed: {body}");
    let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let group_id = created["id"].as_str().expect("group id");
    assert!(
        created.get("externalId").is_none(),
        "group created without externalId"
    );

    // Add externalId via Add operation.
    let (status, body) = http_request(
        &app,
        "PATCH",
        &format!("/scim/v2/Groups/{}", group_id),
        Some(r#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "add", "path": "externalId", "value": "group-ext-1"}]}"#.to_string()),
        &[
            ("Content-Type", "application/json"),
            ("Authorization", &auth_header),
        ],
    )
    .await;

    assert_eq!(status, StatusCode::OK, "PATCH add must return 200: {body}");
    let updated: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        updated["externalId"], "group-ext-1",
        "Add externalId must set the value (RFC 7644 §3.5.2.1)"
    );

    // Add a different externalId — should replace, not accumulate.
    let (status, body) = http_request(
        &app,
        "PATCH",
        &format!("/scim/v2/Groups/{}", group_id),
        Some(r#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "add", "path": "externalId", "value": "group-ext-2"}]}"#.to_string()),
        &[
            ("Content-Type", "application/json"),
            ("Authorization", &auth_header),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "PATCH add must return 200: {body}");
    let updated: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        updated["externalId"], "group-ext-2",
        "Add externalId must replace the previous value"
    );
}

#[tokio::test]
async fn test_scim_patch_group_add_bulk_merges_attributes() {
    // RFC 7644 §3.5.2: Add without a path carries a complex value object
    // whose presented attributes are merged into the resource — the same
    // semantics as Replace without a path.
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-add-group-bulk", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Groups",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"], "displayName": "BulkOriginal"}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "setup create failed: {body}");
    let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let group_id = created["id"].as_str().expect("group id");

    // Bulk add: merge displayName and externalId in one op.
    let (status, body) = http_request(
        &app,
        "PATCH",
        &format!("/scim/v2/Groups/{}", group_id),
        Some(r#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "add", "value": {"displayName": "BulkNew", "externalId": "bulk-group-ext"}}]}"#.to_string()),
        &[
            ("Content-Type", "application/json"),
            ("Authorization", &auth_header),
        ],
    )
    .await;

    assert_eq!(status, StatusCode::OK, "PATCH add must return 200: {body}");
    let updated: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(updated["displayName"], "BulkNew");
    assert_eq!(updated["externalId"], "bulk-group-ext");
}

// ========================================================================
// RFC 7644 Section 3.5.2.2 — Group Remove operation
// ========================================================================

#[tokio::test]
async fn test_scim_patch_group_remove_external_id_clears() {
    // RFC 7644 §3.5.2.2: Remove on a single-valued attribute clears it.
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-group-remove-extid", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Groups",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"], "displayName": "RemoveExtId", "externalId": "ext-removable"}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "setup create failed: {body}");
    let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let group_id = created["id"].as_str().expect("group id");
    assert_eq!(created["externalId"], "ext-removable");

    let (status, body) = http_request(
        &app,
        "PATCH",
        &format!("/scim/v2/Groups/{group_id}"),
        Some(r#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "remove", "path": "externalId"}]}"#.to_string()),
        &[
            ("Content-Type", "application/json"),
            ("Authorization", &auth_header),
        ],
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    let updated: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert!(
        updated.get("externalId").is_none(),
        "Remove externalId must clear it: {body}"
    );
    assert_eq!(
        updated["displayName"], "RemoveExtId",
        "the other attributes are untouched"
    );
}

/// `displayName` is required (RFC 7643 §4.2), so a group has no state in
/// which it carries none: the removal is rejected as `invalidValue` rather
/// than storing an empty name.
#[tokio::test]
async fn test_scim_patch_group_remove_display_name_rejected() {
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-group-remove-name", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Groups",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"], "displayName": "Required"}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "setup create failed: {body}");
    let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let group_id = created["id"].as_str().expect("group id");

    let (status, body) = http_request(
        &app,
        "PATCH",
        &format!("/scim/v2/Groups/{group_id}"),
        Some(r#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "remove", "path": "displayName"}]}"#.to_string()),
        &[
            ("Content-Type", "application/json"),
            ("Authorization", &auth_header),
        ],
    )
    .await;

    // RFC 7644 §3.5.2.2: removing a required attribute returns "a "scimType"
    // error code of "mutability"", and RFC 7643 §4.2 requires displayName.
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["scimType"], "mutability");

    let (status, body) = http_get(
        &app,
        &format!("/scim/v2/Groups/{group_id}"),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let after: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        after["displayName"], "Required",
        "a rejected removal changes nothing"
    );
}

/// A `displayName` a group cannot carry — empty, or not a string — is
/// rejected on PATCH, matching the check `POST /scim/v2/Groups` applies.
#[tokio::test]
async fn test_scim_patch_group_empty_display_name_rejected() {
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-group-empty-name", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Groups",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"], "displayName": "NotEmpty"}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "setup create failed: {body}");
    let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let group_id = created["id"].as_str().expect("group id");

    for value in [serde_json::json!("   "), serde_json::json!(42)] {
        let patch = serde_json::json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "replace", "path": "displayName", "value": value}]
        });
        let (status, body) = http_request(
            &app,
            "PATCH",
            &format!("/scim/v2/Groups/{group_id}"),
            Some(patch.to_string()),
            &[
                ("Content-Type", "application/json"),
                ("Authorization", &auth_header),
            ],
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "value {value}: {body}");
        let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert_eq!(error["scimType"], "invalidValue", "value {value}");
    }
}

#[tokio::test]
async fn test_scim_patch_group_unknown_path_ignored_for_every_op() {
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-group-unknown-paths", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Groups",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"], "displayName": "UntouchedGroup", "externalId": "ext-untouched"}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "setup create failed: {body}");
    let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let group_id = created["id"].as_str().expect("group id");

    for op in ["add", "replace", "remove"] {
        for path in ["description", "urn:example:params:scim:schemas:Group:owner"] {
            let patch = serde_json::json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [{"op": op, "path": path, "value": "ignored"}]
            });
            let (status, body) = http_request(
                &app,
                "PATCH",
                &format!("/scim/v2/Groups/{group_id}"),
                Some(patch.to_string()),
                &[
                    ("Content-Type", "application/json"),
                    ("Authorization", &auth_header),
                ],
            )
            .await;

            assert_eq!(
                status,
                StatusCode::OK,
                "{op} {path} must be ignored: {body}"
            );
            let updated: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
            assert_eq!(updated["displayName"], "UntouchedGroup", "{op} {path}");
            assert_eq!(updated["externalId"], "ext-untouched", "{op} {path}");
        }
    }
}

#[tokio::test]
async fn test_scim_patch_group_add_and_replace_agree_on_single_valued_attributes() {
    // The same property as the User test: on a single-valued attribute,
    // add and replace of one value leave the same resource.
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-group-add-eq-replace", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    let mut results = Vec::new();
    for op in ["add", "replace"] {
        let (status, body) = http_post_json(
            &app,
            "/scim/v2/Groups",
            &format!(
                r#"{{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"], "displayName": "Before-{op}"}}"#
            ),
            &[("Authorization", &auth_header)],
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "setup create failed: {body}");
        let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        let group_id = created["id"].as_str().expect("group id");

        let patch = serde_json::json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [
                {"op": op, "path": "displayName", "value": "After"},
                {"op": op, "path": "externalId", "value": "ext-after"},
            ]
        });
        let (status, body) = http_request(
            &app,
            "PATCH",
            &format!("/scim/v2/Groups/{group_id}"),
            Some(patch.to_string()),
            &[
                ("Content-Type", "application/json"),
                ("Authorization", &auth_header),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{op} must return 200: {body}");

        let mut updated: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        for field in ["id", "meta"] {
            updated
                .as_object_mut()
                .expect("SCIM group object")
                .remove(field);
        }
        results.push(updated);
    }

    assert_eq!(
        results.first(),
        results.last(),
        "add and replace must leave the same resource"
    );
    assert_eq!(results[0]["displayName"], "After");
    assert_eq!(results[0]["externalId"], "ext-after");
}

// ========================================================================
// RFC 7643 Section 4.2 — Group Members Positive Tests
// ========================================================================

#[tokio::test]
async fn test_scim_create_group_with_members() {
    // Create group with members array; verify members appear in GET response
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-create-group-members", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    // Create a user first
    let (_, user_body) = http_post_json(
        &app,
        "/scim/v2/Users",
        r#"{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"member-create@test-org.example.com"}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    let user: serde_json::Value = serde_json::from_str(&user_body).expect("Valid JSON");
    let user_id = user["id"].as_str().expect("user id");

    // Create group with that user as a member
    let create_body = format!(
        r#"{{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"TeamA","members":[{{"value":"{}"}}]}}"#,
        user_id
    );
    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Groups",
        &create_body,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let group_id = created["id"].as_str().expect("group id");

    // GET the group and verify members
    let (status, body) = http_get(
        &app,
        &format!("/scim/v2/Groups/{}", group_id),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let group: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let members = group["members"].as_array().expect("members array");
    assert!(
        members.iter().any(|m| m["value"] == user_id),
        "Group must contain the created member"
    );
}

#[tokio::test]
async fn test_scim_patch_group_add_members() {
    // PATCH add members operation adds the user to the group
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-patch-add-members", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    // Create a user
    let (_, user_body) = http_post_json(
        &app,
        "/scim/v2/Users",
        r#"{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"member-add@test-org.example.com"}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    let user: serde_json::Value = serde_json::from_str(&user_body).expect("Valid JSON");
    let user_id = user["id"].as_str().expect("user id");

    // Create group without members
    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Groups",
        r#"{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"TeamB"}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let group_id = created["id"].as_str().expect("group id");

    // PATCH add the user as a member
    let patch_body = format!(
        r#"{{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{{"op":"add","path":"members","value":[{{"value":"{}"}}]}}]}}"#,
        user_id
    );
    let (status, body) = http_request(
        &app,
        "PATCH",
        &format!("/scim/v2/Groups/{}", group_id),
        Some(patch_body),
        &[
            ("Content-Type", "application/json"),
            ("Authorization", &auth_header),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "PATCH add must return 200: {body}");

    // Verify the member appears in the group
    let (status, body) = http_get(
        &app,
        &format!("/scim/v2/Groups/{}", group_id),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let group: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let members = group["members"].as_array().expect("members array");
    assert!(
        members.iter().any(|m| m["value"] == user_id),
        "Added member must appear in GET response"
    );
}

#[tokio::test]
async fn test_scim_patch_group_remove_member() {
    // PATCH remove with path `members[value eq "user-id"]` removes the member
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-patch-remove-member", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    // Create a user
    let (_, user_body) = http_post_json(
        &app,
        "/scim/v2/Users",
        r#"{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"member-remove@test-org.example.com"}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    let user: serde_json::Value = serde_json::from_str(&user_body).expect("Valid JSON");
    let user_id = user["id"].as_str().expect("user id");

    // Create group with that user as a member
    let create_body = format!(
        r#"{{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"TeamC","members":[{{"value":"{}"}}]}}"#,
        user_id
    );
    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Groups",
        &create_body,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let group_id = created["id"].as_str().expect("group id");

    // PATCH remove the member using filter path — value eq requires escaped quotes in JSON
    let patch_body = format!(
        r#"{{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{{"op":"remove","path":"members[value eq \"{}\"]"}}]}}"#,
        user_id
    );
    let (status, body) = http_request(
        &app,
        "PATCH",
        &format!("/scim/v2/Groups/{}", group_id),
        Some(patch_body),
        &[
            ("Content-Type", "application/json"),
            ("Authorization", &auth_header),
        ],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "PATCH remove must return 200: {body}"
    );

    // Verify the member is gone
    let (status, body) = http_get(
        &app,
        &format!("/scim/v2/Groups/{}", group_id),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let group: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    // members should be absent or empty after removal
    let has_member = group
        .get("members")
        .and_then(|m| m.as_array())
        .is_some_and(|arr| arr.iter().any(|m| m["value"] == user_id));
    assert!(
        !has_member,
        "Removed member must not appear in GET response"
    );
}

#[tokio::test]
async fn test_scim_patch_group_remove_member_uppercase_eq() {
    // RFC 7643 §2.1 makes ABNF `compareOp` tokens case-insensitive, so a
    // PATCH remove with `members[value EQ "user-id"]` (operator in
    // non-lowercase casing) must remove the member exactly as the
    // lowercase `eq` form does. Previously `parse_member_filter` only
    // matched the literal lowercase `value eq "` needle and silently
    // no-op'd, leaving the membership intact while returning 200 OK.
    let (app, state) = test_app().await;
    let token = create_test_scim_token(
        &state.store,
        "test-patch-remove-member-upper-eq",
        "test-org",
    )
    .await;
    let auth_header = format!("Bearer {}", token);

    // Create a user
    let (_, user_body) = http_post_json(
        &app,
        "/scim/v2/Users",
        r#"{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"upper-eq@test-org.example.com"}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    let user: serde_json::Value = serde_json::from_str(&user_body).expect("Valid JSON");
    let user_id = user["id"].as_str().expect("user id");

    // Create group with that user as a member
    let create_body = format!(
        r#"{{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"TeamUE","members":[{{"value":"{}"}}]}}"#,
        user_id
    );
    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Groups",
        &create_body,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let group_id = created["id"].as_str().expect("group id");

    // PATCH remove using the capitalised operator — RFC-mandated equivalent
    // of the lowercase form exercised by test_scim_patch_group_remove_member.
    let patch_body = format!(
        r#"{{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{{"op":"remove","path":"members[value EQ \"{}\"]"}}]}}"#,
        user_id
    );
    let (status, body) = http_request(
        &app,
        "PATCH",
        &format!("/scim/v2/Groups/{}", group_id),
        Some(patch_body),
        &[
            ("Content-Type", "application/json"),
            ("Authorization", &auth_header),
        ],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "uppercase-EQ remove must return 200: {body}"
    );

    // Verify the member is gone — the fix routes the capitalised operator
    // through the same deletion path as the lowercase form.
    let (status, body) = http_get(
        &app,
        &format!("/scim/v2/Groups/{}", group_id),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let group: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let has_member = group
        .get("members")
        .and_then(|m| m.as_array())
        .is_some_and(|arr| arr.iter().any(|m| m["value"] == user_id));
    assert!(
        !has_member,
        "capitalised-operator remove must delete the member, not silently no-op"
    );
}

// ========================================================================
// RFC 7644 — Group CRUD Negative Tests
// ========================================================================

#[tokio::test]
async fn test_scim_create_group_empty_display_name() {
    // Empty displayName should return 400
    let (app, state) = test_app().await;
    let token =
        create_test_scim_token(&state.store, "test-create-group-empty-name", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Groups",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"], "displayName": ""}"#,
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["status"], "400");
}

#[tokio::test]
async fn test_scim_create_group_requires_auth() {
    // No token should return 401
    let (app, _state) = test_app().await;

    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Groups",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"], "displayName": "Unauthorized"}"#,
        &[],
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body}");
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert!(
        error.get("schemas").is_some(),
        "SCIM error must have schemas"
    );
}

#[tokio::test]
async fn test_scim_get_group_not_found() {
    // Valid UUID that doesn't exist returns 404
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-group-not-found", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    let (status, body) = http_get(
        &app,
        "/scim/v2/Groups/00000000-0000-7000-0000-000000000000",
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["status"], "404");
}

#[tokio::test]
async fn test_scim_delete_group_not_found() {
    // DELETE on a valid UUID that doesn't exist returns 404
    let (app, state) = test_app().await;
    let token =
        create_test_scim_token(&state.store, "test-delete-group-not-found", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    let (status, body) = http_delete(
        &app,
        "/scim/v2/Groups/00000000-0000-7000-0000-000000000099",
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["status"], "404");
}

/// A group deleted between the handler's existence check and
/// `delete_scim_group` yields 404 and no `scim_operation` delete audit event.
/// The `delete_test_hook` deletes the group from a separate transaction
/// inside `delete_scim_group`, before its own existence check.
#[tokio::test]
async fn test_scim_delete_group_returns_404_when_target_vanishes_mid_delete() {
    use std::sync::{Arc, Mutex};

    let target_slot: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let slot = Arc::clone(&target_slot);
    let (app, state) = test_app_with_modify_hook(move |store| {
        let writer = store.clone();
        store.set_delete_test_hook(Arc::new(move |group_id: &str| {
            let writer = writer.clone();
            let group_id = group_id.to_string();
            let slot = Arc::clone(&slot);
            Box::pin(async move {
                let is_target =
                    slot.lock().expect("slot lock").as_deref() == Some(group_id.as_str());
                if is_target {
                    writer
                        .delete(&group_id)
                        .await
                        .expect("delete target group doc mid-race");
                }
            })
        }));
    })
    .await;

    let token = create_test_scim_token(&state.store, "test-race-delete-group", "test-org").await;
    let auth_header = format!("Bearer {token}");

    // Create a group to delete.
    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Groups",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"], "displayName": "RaceDelete"}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "body: {body}");
    let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let group_id = created["id"].as_str().expect("group id").to_string();
    *target_slot.lock().expect("slot lock") = Some(group_id.clone());

    // Delete the group. The delete hook races the deletion; the handler must
    // observe the miss and return 404.
    let (status, body) = http_delete(
        &app,
        &format!("/scim/v2/Groups/{group_id}"),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "SCIM delete: a group deleted mid-delete must produce 404, got {status}: {body}"
    );

    // No `delete` scim_operation audit event may be logged when the delete
    // did not occur.
    let rows = scim_audit_rows(&state).await;
    let delete_events: Vec<_> = rows
        .iter()
        .filter(|e| {
            e.get("operation").and_then(|o| o.as_str()) == Some("delete")
                && e.get("resource_id").and_then(|r| r.as_str()) == Some(&group_id)
        })
        .collect();
    assert!(
        delete_events.is_empty(),
        "SCIM delete: no scim_operation delete audit event may be logged when the delete did not occur; got {}",
        delete_events
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join(", "),
    );

    // The group is gone (the hook deleted it), so a follow-up GET is 404 —
    // confirms no phantom row remains.
    let (status, _body) = http_get(
        &app,
        &format!("/scim/v2/Groups/{group_id}"),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_scim_patch_group_not_found() {
    // PATCH on a non-existent group returns 404
    let (app, state) = test_app().await;
    let token =
        create_test_scim_token(&state.store, "test-patch-group-not-found", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    let (status, body) = http_request(
        &app,
        "PATCH",
        "/scim/v2/Groups/00000000-0000-7000-0000-000000000088",
        Some(r#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "replace", "path": "displayName", "value": "Ghost"}]}"#.to_string()),
        &[
            ("Content-Type", "application/json"),
            ("Authorization", &auth_header),
        ],
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND, "body: {body}");
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["status"], "404");
}

#[tokio::test]
async fn test_scim_list_groups_requires_auth() {
    // No token returns 401
    let (app, _state) = test_app().await;

    let (status, body) = http_get(&app, "/scim/v2/Groups", &[]).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body}");
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert!(
        error.get("schemas").is_some(),
        "SCIM error must have schemas"
    );
}

// ========================================================================
// RFC 7643 Section 4.2 — Group Schema Validation Tests
// ========================================================================

#[tokio::test]
async fn test_scim_group_response_has_correct_schema() {
    // Schemas array must contain the Group schema URN
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-group-schema-urn", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Groups",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"], "displayName": "SchemaCheck"}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let group: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    let schemas = group["schemas"].as_array().expect("schemas array");
    assert!(
        schemas
            .iter()
            .any(|s| s == "urn:ietf:params:scim:schemas:core:2.0:Group"),
        "Group schemas must contain the Group URN, got: {:?}",
        schemas
    );
}

#[tokio::test]
async fn test_scim_group_response_has_meta() {
    // meta must include resourceType, location, and created
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-group-meta", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Groups",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"], "displayName": "MetaCheck"}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let group: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    let meta = group.get("meta").expect("Group must have meta");
    assert_eq!(
        meta["resourceType"], "Group",
        "meta.resourceType must be 'Group'"
    );
    assert!(meta.get("location").is_some(), "meta must include location");
    assert!(
        meta["location"]
            .as_str()
            .unwrap_or("")
            .contains("/scim/v2/Groups/"),
        "meta.location must point to the Groups endpoint"
    );
    assert!(meta.get("created").is_some(), "meta must include created");
}

// ========================================================================
// scim_operation audit events carry the org's domain (NULL-domain fix)
// ========================================================================

#[tokio::test]
async fn test_scim_operation_audit_event_carries_org_domain() {
    // Regression test: `scim_operation` audit events have no user/email of
    // their own (the actor is a bearer token, not a person), so without
    // stamping the org's primary domain at write time they'd have a NULL
    // `email_domain` and be invisible to org-scoped audit reads.
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-audit-domain", "test-org").await;

    let (status, _) = http_post_json(
        &app,
        "/scim/v2/Users",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "audit-domain@test-org.example.com"}"#,
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let events = state
        .audit
        .query_events(&crate::db::AuditEventFilter {
            event_types: Some(vec!["scim_operation".to_string()]),
            ..crate::db::AuditEventFilter::default()
        })
        .await
        .expect("query audit events");
    assert_eq!(events.len(), 1, "one scim_operation event must be written");
    assert_eq!(
        events[0].email_domain.as_deref(),
        Some("test-org.example.com"),
        "event must carry the org's primary domain, not NULL"
    );
}

#[tokio::test]
async fn test_scim_create_and_delete_user_audit_events_never_carry_a_raw_email() {
    // Regression test: `create`/`delete` scim_operation events used to
    // embed the user's raw email in `details` (-> `data`), even though
    // `resource_id` already identifies the affected user and emails are
    // documented as masked to domain-only in the audit log.
    let (app, state) = test_app().await;
    let email = "no-raw-email@test-org.example.com";
    let token = create_test_scim_token(&state.store, "test-no-raw-email", "test-org").await;

    let (status, create_body) = http_post_json(
        &app,
        "/scim/v2/Users",
        &format!(
            r#"{{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "{email}"}}"#
        ),
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "body: {create_body}");
    let created: serde_json::Value = serde_json::from_str(&create_body).expect("valid JSON");
    let user_id = created["id"].as_str().expect("id present");

    let (status, _) = http_delete(
        &app,
        &format!("/scim/v2/Users/{user_id}"),
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let events = state
        .audit
        .query_events(&crate::db::AuditEventFilter {
            event_types: Some(vec!["scim_operation".to_string()]),
            ..crate::db::AuditEventFilter::default()
        })
        .await
        .expect("query audit events");
    let create_and_delete: Vec<_> = events
        .iter()
        .filter(|e| e.data.contains("\"create\"") || e.data.contains("\"delete\""))
        .collect();
    assert_eq!(
        create_and_delete.len(),
        2,
        "one create and one delete event"
    );
    for event in create_and_delete {
        assert!(
            !event.data.contains(email),
            "scim_operation data must not contain the raw email; got {}",
            event.data
        );
        assert!(
            event.data.contains(user_id),
            "scim_operation data must still identify the resource via resource_id; got {}",
            event.data
        );
    }
}

// ========================================================================
// Atomic group writes: a failing request commits nothing and audits nothing
// ========================================================================

/// The `scim_operation` audit rows recorded so far, parsed.
async fn scim_audit_rows(state: &crate::AppState) -> Vec<serde_json::Value> {
    state
        .audit
        .query_events(&crate::db::AuditEventFilter {
            event_types: Some(vec!["scim_operation".to_string()]),
            ..crate::db::AuditEventFilter::default()
        })
        .await
        .expect("query audit events")
        .into_iter()
        .map(|e| serde_json::from_str(&e.data).expect("scim audit data is JSON"))
        .collect()
}

#[tokio::test]
async fn test_scim_create_group_with_a_rejected_member_creates_nothing() {
    // The group and its members commit in one transaction, so a member the
    // store rejects leaves no group behind for a retried POST to duplicate.
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-create-atomic", "test-org").await;
    let auth_header = format!("Bearer {token}");

    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Groups",
        r#"{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"TeamAtomic","members":[{"value":"bad\u0000member"}]}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["scimType"], "invalidValue",
        "rejected by the store: {body}"
    );

    let (_, listed) = http_get(&app, "/scim/v2/Groups", &[("Authorization", &auth_header)]).await;
    let listed: serde_json::Value = serde_json::from_str(&listed).expect("Valid JSON");
    assert_eq!(listed["totalResults"], 0, "no group was created: {listed}");
    let rows = scim_audit_rows(&state).await;
    assert!(
        !rows.iter().any(|row| row["operation"] == "create"),
        "nothing was created, so nothing is audited: {rows:?}"
    );
}

// RFC 7644 §3.5.2: "A PATCH request, regardless of the number of operations,
// SHALL be treated as atomic. If a single operation encounters an error
// condition, the original SCIM resource MUST be restored, and a failure
// status SHALL be returned."
#[tokio::test]
async fn test_scim_patch_group_failing_member_write_restores_the_group() {
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-patch-atomic", "test-org").await;
    let auth_header = format!("Bearer {token}");

    let (_, user_body) = http_post_json(
        &app,
        "/scim/v2/Users",
        r#"{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"atomic-patch@test-org.example.com"}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    let user: serde_json::Value = serde_json::from_str(&user_body).expect("Valid JSON");
    let user_id = user["id"].as_str().expect("user id");

    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Groups",
        r#"{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"TeamAtomic"}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let group_id = created["id"].as_str().expect("group id");

    // The first operations are valid; the last member id is one the store
    // rejects when the membership row is written.
    let patch_body = format!(
        r#"{{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{{"op":"replace","path":"displayName","value":"Renamed"}},{{"op":"add","path":"members","value":[{{"value":"{user_id}"}}]}},{{"op":"add","path":"members","value":[{{"value":"bad\u0000member"}}]}}]}}"#
    );
    let (status, body) = http_request(
        &app,
        "PATCH",
        &format!("/scim/v2/Groups/{group_id}"),
        Some(patch_body),
        &[
            ("Content-Type", "application/json"),
            ("Authorization", &auth_header),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["scimType"], "invalidValue",
        "rejected by the store: {body}"
    );

    let (_, body) = http_get(
        &app,
        &format!("/scim/v2/Groups/{group_id}"),
        &[("Authorization", &auth_header)],
    )
    .await;
    let group: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(group["displayName"], "TeamAtomic", "rename rolled back");
    assert!(
        group.get("members").is_none(),
        "member add rolled back: {group}"
    );
    let rows = scim_audit_rows(&state).await;
    assert!(
        !rows.iter().any(|row| row["operation"] == "update"),
        "nothing changed, so no update is audited: {rows:?}"
    );
}

// ========================================================================
// RFC 7644 Section 3.5.1 — PUT Group
// ========================================================================

const GROUP_URN: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";

/// Creates a user through `POST /scim/v2/Users` and returns its id.
async fn post_member(app: &axum::Router, auth_header: &str, email: &str) -> String {
    let (status, body) = http_post_json(
        app,
        "/scim/v2/Users",
        &serde_json::json!({"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": email}).to_string(),
        &[("Authorization", auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    created["id"].as_str().expect("user id").to_string()
}

/// Creates a group through `POST /scim/v2/Groups` and returns its id.
async fn post_group(app: &axum::Router, auth_header: &str, body: serde_json::Value) -> String {
    let (status, body) = http_post_json(
        app,
        "/scim/v2/Groups",
        &body.to_string(),
        &[("Authorization", auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    created["id"].as_str().expect("group id").to_string()
}

/// Sends `PUT` with `body` and returns the status and parsed body.
async fn put_group_json(
    app: &axum::Router,
    auth_header: &str,
    group_id: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let (status, body) = http_put_json(
        app,
        &format!("/scim/v2/Groups/{group_id}"),
        &body.to_string(),
        &[("Authorization", auth_header)],
    )
    .await;
    (status, serde_json::from_str(&body).expect("Valid JSON"))
}

fn member_ids(group: &serde_json::Value) -> Vec<String> {
    let mut ids: Vec<String> = group["members"]
        .as_array()
        .map(|members| {
            members
                .iter()
                .filter_map(|member| member["value"].as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    ids.sort();
    ids
}

// RFC 7644 §3.5.1: readWrite "Any values provided SHALL replace the existing
// attribute values", and a successful PUT "returns a 200 OK response code and
// the entire resource within the response body".
#[tokio::test]
async fn test_rfc7644_put_group_replaces_attributes_and_members() {
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-put-group", "test-org").await;
    let auth_header = format!("Bearer {token}");
    let alice = post_member(&app, &auth_header, "alice@test-org.example.com").await;
    let bob = post_member(&app, &auth_header, "bob@test-org.example.com").await;
    let group_id = post_group(
        &app,
        &auth_header,
        serde_json::json!({"schemas": [GROUP_URN], "displayName": "Old", "externalId": "old", "members": [{"value": alice}]}),
    )
    .await;

    let (status, body) = put_group_json(
        &app,
        &auth_header,
        &group_id,
        serde_json::json!({"schemas": [GROUP_URN], "displayName": "New", "externalId": "new", "members": [{"value": bob}]}),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["id"], group_id.as_str());
    assert_eq!(body["displayName"], "New");
    assert_eq!(body["externalId"], "new");
    assert_eq!(member_ids(&body), vec![bob]);
}

// RFC 7644 §3.5.1: omitted readWrite attributes — "The service provider MAY
// assume that any existing values are to be cleared".
#[tokio::test]
async fn test_rfc7644_put_group_clears_omitted_attributes_and_members() {
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-put-group-clear", "test-org").await;
    let auth_header = format!("Bearer {token}");
    let alice = post_member(&app, &auth_header, "alice@test-org.example.com").await;
    let group_id = post_group(
        &app,
        &auth_header,
        serde_json::json!({"schemas": [GROUP_URN], "displayName": "Team", "externalId": "ext", "members": [{"value": alice}]}),
    )
    .await;

    let (status, body) = put_group_json(
        &app,
        &auth_header,
        &group_id,
        serde_json::json!({"schemas": [GROUP_URN], "displayName": "Team"}),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.get("externalId").is_none(), "{body}");
    assert!(member_ids(&body).is_empty(), "{body}");
}

// RFC 7644 §3.5.1: "HTTP PUT MUST NOT be used to create new resources."
#[tokio::test]
async fn test_rfc7644_put_group_unknown_id_is_404() {
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-put-group-404", "test-org").await;
    let auth_header = format!("Bearer {token}");

    let (status, body) = put_group_json(
        &app,
        &auth_header,
        "00000000-0000-7000-0000-0000000000cc",
        serde_json::json!({"schemas": [GROUP_URN], "displayName": "Ghost"}),
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    let (_, listed) = http_get(
        &app,
        "/scim/v2/Groups?filter=displayName%20eq%20%22Ghost%22",
        &[("Authorization", &auth_header)],
    )
    .await;
    let listed: serde_json::Value = serde_json::from_str(&listed).expect("Valid JSON");
    assert_eq!(listed["totalResults"], 0, "PUT must not create a group");
}

// RFC 7644 §3.5.1: "If an attribute is "required", clients MUST specify the
// attribute in the PUT request"; an empty displayName is checked before
// authentication, as on create.
#[tokio::test]
async fn test_rfc7644_put_group_requires_display_name() {
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-put-group-name", "test-org").await;
    let auth_header = format!("Bearer {token}");
    let group_id = post_group(
        &app,
        &auth_header,
        serde_json::json!({"schemas": [GROUP_URN], "displayName": "Keep"}),
    )
    .await;

    let (status, error) = put_group_json(
        &app,
        &auth_header,
        &group_id,
        serde_json::json!({"schemas": [GROUP_URN], "externalId": "x"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{error}");
    assert_eq!(error["scimType"], "invalidSyntax");

    let (status, error) = put_group_json(
        &app,
        "",
        &group_id,
        serde_json::json!({"schemas": [GROUP_URN], "displayName": "  "}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "400 before 401: {error}");
    assert_eq!(error["scimType"], "invalidValue");
}

#[tokio::test]
async fn test_put_group_audits_a_replace() {
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-put-group-audit", "test-org").await;
    let auth_header = format!("Bearer {token}");
    let group_id = post_group(
        &app,
        &auth_header,
        serde_json::json!({"schemas": [GROUP_URN], "displayName": "Audited"}),
    )
    .await;

    let (status, _) = put_group_json(
        &app,
        &auth_header,
        &group_id,
        serde_json::json!({"schemas": [GROUP_URN], "displayName": "Audited 2"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let events = state
        .audit
        .query_events(&crate::db::AuditEventFilter {
            event_types: Some(vec!["scim_operation".to_string()]),
            ..crate::db::AuditEventFilter::default()
        })
        .await
        .expect("query audit events");
    assert!(
        events.iter().any(|event| {
            serde_json::from_str::<serde_json::Value>(&event.data).is_ok_and(|data| {
                data["operation"] == "replace" && data["resource_id"] == group_id.as_str()
            })
        }),
        "a replace audit row names the group: {:?}",
        events.iter().map(|event| &event.data).collect::<Vec<_>>()
    );
}

// ========================================================================
// RFC 7644 §3.5.2 — PATCH Group member paths and operation rules
// ========================================================================

/// Sends `PATCH` with `operations` to the group and returns the status and
/// parsed body.
async fn patch_group_ops(
    app: &axum::Router,
    auth_header: &str,
    group_id: &str,
    operations: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let body = serde_json::json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": operations,
    });
    let (status, body) = http_request(
        app,
        "PATCH",
        &format!("/scim/v2/Groups/{group_id}"),
        Some(body.to_string()),
        &[
            ("Authorization", auth_header),
            ("Content-Type", "application/scim+json"),
        ],
    )
    .await;
    (status, serde_json::from_str(&body).expect("Valid JSON"))
}

/// A group with members alice and bob, and a third user carol outside it.
async fn group_with_members(
    app: &axum::Router,
    auth_header: &str,
) -> (String, String, String, String) {
    let alice = post_member(app, auth_header, "alice@test-org.example.com").await;
    let bob = post_member(app, auth_header, "bob@test-org.example.com").await;
    let carol = post_member(app, auth_header, "carol@test-org.example.com").await;
    let group_id = post_group(
        app,
        auth_header,
        serde_json::json!({"schemas": [GROUP_URN], "displayName": "Team", "members": [{"value": alice}, {"value": bob}]}),
    )
    .await;
    (group_id, alice, bob, carol)
}

// RFC 7644 §3.5.2.2: "If the target location is a multi-valued attribute and
// no filter is specified, the attribute and all values are removed".
#[tokio::test]
async fn test_rfc7644_patch_group_remove_members_without_filter_removes_all() {
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-remove-all", "test-org").await;
    let auth_header = format!("Bearer {token}");
    let (group_id, ..) = group_with_members(&app, &auth_header).await;

    let (status, body) = patch_group_ops(
        &app,
        &auth_header,
        &group_id,
        serde_json::json!([{"op": "remove", "path": "members"}]),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(member_ids(&body).is_empty(), "{body}");
}

// RFC 7644 §3.5.2.3: with a value filter, "all matching record values SHALL
// be replaced", and with no match the service provider "SHALL indicate
// failure by returning HTTP status code 400 and a "scimType" error code of
// "noTarget"."
#[tokio::test]
async fn test_rfc7644_patch_group_replace_filtered_member() {
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-replace-filter", "test-org").await;
    let auth_header = format!("Bearer {token}");
    let (group_id, alice, bob, carol) = group_with_members(&app, &auth_header).await;

    let (status, body) = patch_group_ops(
        &app,
        &auth_header,
        &group_id,
        serde_json::json!([{"op": "replace", "path": format!("members[value eq \"{alice}\"]"), "value": {"value": carol}}]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let mut expected = vec![bob.clone(), carol.clone()];
    expected.sort();
    assert_eq!(member_ids(&body), expected);

    let (status, body) = patch_group_ops(
        &app,
        &auth_header,
        &group_id,
        serde_json::json!([{"op": "replace", "path": format!("members[value eq \"{bob}\"].value"), "value": alice}]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let mut expected = vec![alice.clone(), carol.clone()];
    expected.sort();
    assert_eq!(member_ids(&body), expected);

    let (status, error) = patch_group_ops(
        &app,
        &auth_header,
        &group_id,
        serde_json::json!([{"op": "replace", "path": format!("members[value eq \"{bob}\"]"), "value": {"value": bob}}]),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{error}");
    assert_eq!(error["scimType"], "noTarget");
}

#[tokio::test]
async fn test_patch_group_member_path_errors() {
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-member-path", "test-org").await;
    let auth_header = format!("Bearer {token}");
    let (group_id, alice, ..) = group_with_members(&app, &auth_header).await;

    for (operations, scim_type) in [
        // RFC 7644 §3.12 Table 9 `invalidFilter`: "the specified attribute
        // and filter comparison combination is not supported".
        (
            serde_json::json!([{"op": "remove", "path": "members[display eq \"Alice\"]"}]),
            "invalidFilter",
        ),
        // `add` appends to the attribute; a filter selects existing values.
        (
            serde_json::json!([{"op": "add", "path": format!("members[value eq \"{alice}\"]"), "value": {"value": alice}}]),
            "invalidPath",
        ),
        // RFC 7644 §3.5.2.1: "The operation MUST contain a "value" member".
        (
            serde_json::json!([{"op": "add", "path": "members"}]),
            "invalidValue",
        ),
        (
            serde_json::json!([{"op": "add", "path": "members", "value": [{"display": "no value"}]}]),
            "invalidValue",
        ),
        // RFC 7644 §3.5.2.2: a pathless remove "fails with HTTP status code
        // 400 and a "scimType" error code of "noTarget"".
        (serde_json::json!([{"op": "remove"}]), "noTarget"),
    ] {
        let (status, error) =
            patch_group_ops(&app, &auth_header, &group_id, operations.clone()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{operations} -> {error}");
        assert_eq!(error["scimType"], scim_type, "{operations}");
    }

    let (_, body) = http_get(
        &app,
        &format!("/scim/v2/Groups/{group_id}"),
        &[("Authorization", &auth_header)],
    )
    .await;
    let group: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        member_ids(&group).len(),
        2,
        "rejected requests change nothing"
    );
}

// RFC 7644 §3.5.2.3: a pathless replace's "value" attribute "SHALL contain a
// list of one or more attributes that are to be replaced", `members`
// included; RFC 7643 §2.1 makes the attribute names case insensitive.
#[tokio::test]
async fn test_rfc7644_patch_group_pathless_value_carries_members() {
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-pathless-members", "test-org").await;
    let auth_header = format!("Bearer {token}");
    let (group_id, _alice, _bob, carol) = group_with_members(&app, &auth_header).await;

    let (status, body) = patch_group_ops(
        &app,
        &auth_header,
        &group_id,
        serde_json::json!([{"op": "replace", "value": {"DisplayName": "Renamed", "Members": [{"Value": carol}]}}]),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["displayName"], "Renamed");
    assert_eq!(member_ids(&body), vec![carol]);
}

// RFC 7644 §3.10: "Clients MAY omit core schema attribute URN prefixes", so a
// fully qualified path addresses the same attribute.
#[tokio::test]
async fn test_rfc7644_patch_group_core_urn_qualified_paths() {
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-urn-paths", "test-org").await;
    let auth_header = format!("Bearer {token}");
    let (group_id, alice, ..) = group_with_members(&app, &auth_header).await;

    let (status, body) = patch_group_ops(
        &app,
        &auth_header,
        &group_id,
        serde_json::json!([
            {"op": "replace", "path": "urn:ietf:params:scim:schemas:core:2.0:Group:displayName", "value": "Qualified"},
            {"op": "remove", "path": format!("urn:ietf:params:scim:schemas:core:2.0:Group:members[value eq \"{alice}\"]")}
        ]),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["displayName"], "Qualified");
    assert_eq!(member_ids(&body).len(), 1);
}

// RFC 7644 §3.5.2.1: "If the target location already contains the value
// specified, no changes SHOULD be made to the resource ... this operation
// SHALL NOT change the modify timestamp of the resource."
#[tokio::test]
async fn test_rfc7644_patch_group_adding_existing_member_keeps_last_modified() {
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-noop-group", "test-org").await;
    let auth_header = format!("Bearer {token}");
    let (group_id, alice, ..) = group_with_members(&app, &auth_header).await;
    let (_, before) = http_get(
        &app,
        &format!("/scim/v2/Groups/{group_id}"),
        &[("Authorization", &auth_header)],
    )
    .await;
    let before: serde_json::Value = serde_json::from_str(&before).expect("Valid JSON");

    let (status, body) = patch_group_ops(
        &app,
        &auth_header,
        &group_id,
        serde_json::json!([{"op": "add", "path": "members", "value": [{"value": alice}]}]),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["meta"]["lastModified"], before["meta"]["lastModified"]);
}
