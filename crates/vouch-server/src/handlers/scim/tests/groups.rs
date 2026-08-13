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

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["scimType"], "invalidValue");

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
async fn test_scim_get_group_invalid_id() {
    // Non-UUID id should return 400
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-group-invalid-id", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    let (status, body) = http_get(
        &app,
        "/scim/v2/Groups/not-a-uuid",
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["status"], "400");
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

#[tokio::test]
async fn test_scim_delete_group_invalid_id() {
    // DELETE with non-UUID id returns 400
    let (app, state) = test_app().await;
    let token =
        create_test_scim_token(&state.store, "test-delete-group-invalid-id", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    let (status, body) = http_delete(
        &app,
        "/scim/v2/Groups/not-a-uuid",
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["status"], "400");
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
