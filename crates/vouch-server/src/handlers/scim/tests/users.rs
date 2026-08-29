// SPDX-License-Identifier: Apache-2.0 OR MIT
//! User resource CRUD and PATCH semantics (RFC 7643 §4.1;
//! RFC 7644 §3.4–3.6).
#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable"
)]

use super::*;

// ========================================================================
// RFC 7643 Section 4.1 - User Resource Tests
// ========================================================================

#[tokio::test]
async fn test_rfc7643_create_user_requires_username() {
    // RFC 7643 Section 4.1: userName is REQUIRED for User resource
    let (app, state) = test_app().await;

    let token = create_test_scim_token(&state.store, "test-create-user", "test-org").await;

    // Create user with valid userName
    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Users",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "test@test-org.example.com", "active": true}"#,
        &[("Authorization", &format!("Bearer {}", token))],
    )
    .await;

    assert_eq!(status, StatusCode::CREATED);
    let user: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert!(user.get("id").is_some(), "Created user should have id");
    assert_eq!(user["userName"], "test@test-org.example.com");
}

#[tokio::test]
async fn test_rfc7644_create_user_conflict() {
    // RFC 7644 Section 3.3: Duplicate user returns 409 Conflict
    let (app, state) = test_app().await;

    let token = create_test_scim_token(&state.store, "test-conflict", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    // Create first user
    let (status, _) = http_post_json(
        &app,
        "/scim/v2/Users",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "duplicate@test-org.example.com"}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // Try to create duplicate user
    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Users",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "duplicate@test-org.example.com"}"#,
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::CONFLICT);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["status"], "409");
    assert_eq!(error["scimType"], "uniqueness");
}

// ========================================================================
// RFC 7644 Section 3.4.1 - GET User Tests
// ========================================================================

#[tokio::test]
async fn test_rfc7644_get_user_by_id() {
    // RFC 7644 Section 3.4.1: GET user by ID
    let (app, state) = test_app().await;

    let token = create_test_scim_token(&state.store, "test-get-user", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    // Create a user first
    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Users",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "gettest@test-org.example.com"}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let user_id = created["id"].as_str().expect("user id");

    // Get the user by ID
    let (status, body) = http_get(
        &app,
        &format!("/scim/v2/Users/{}", user_id),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let user: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(user["id"], user_id);
    assert_eq!(user["userName"], "gettest@test-org.example.com");
}

#[tokio::test]
async fn test_rfc7644_get_user_not_found() {
    // RFC 7644 Section 3.4.1: Non-existent user returns 404
    let (app, state) = test_app().await;

    let token = create_test_scim_token(&state.store, "test-not-found", "test-org").await;

    // Use a valid UUID format that doesn't exist in the database
    let (status, body) = http_get(
        &app,
        "/scim/v2/Users/00000000-0000-7000-0000-000000000000",
        &[("Authorization", &format!("Bearer {}", token))],
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["status"], "404");
}

// ========================================================================
// RFC 7644 Section 3.4.2 - List Users Tests
// ========================================================================

#[tokio::test]
async fn test_rfc7644_list_users_pagination() {
    // RFC 7644 Section 3.4.2: Pagination with startIndex and count
    let (app, state) = test_app().await;

    let token = create_test_scim_token(&state.store, "test-pagination", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    // Create several users
    for i in 1..=5 {
        let _ = http_post_json(
            &app,
            "/scim/v2/Users",
            &format!(
                r#"{{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "page{}@test-org.example.com"}}"#,
                i
            ),
            &[("Authorization", &auth_header)],
        )
        .await;
    }

    // List with pagination
    let (status, body) = http_get(
        &app,
        "/scim/v2/Users?startIndex=1&count=2",
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    // Verify ListResponse format
    assert_eq!(response["startIndex"], 1);
    assert!(response["itemsPerPage"].as_u64().unwrap() <= 2);
    assert!(response["totalResults"].as_u64().unwrap() >= 5);
}

#[tokio::test]
async fn test_rfc7644_list_users_filter() {
    // RFC 7644 Section 3.4.2: Filter users by userName
    let (app, state) = test_app().await;

    let token = create_test_scim_token(&state.store, "test-filter", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    // Create users
    let _ = http_post_json(
        &app,
        "/scim/v2/Users",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "filtertest@test-org.example.com"}"#,
        &[("Authorization", &auth_header)],
    )
    .await;

    // Filter by userName
    let (status, body) = http_get(
        &app,
        "/scim/v2/Users?filter=userName%20eq%20%22filtertest@test-org.example.com%22",
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let resources = response["Resources"].as_array().expect("Resources array");
    assert!(!resources.is_empty());
}

// ========================================================================
// RFC 7644 Section 3.5.2 - PATCH User Tests
// ========================================================================

#[tokio::test]
async fn test_rfc7644_patch_user_deactivate() {
    // RFC 7644 Section 3.5.2: PATCH to deactivate user
    let (app, state) = test_app().await;

    let token = create_test_scim_token(&state.store, "test-patch-deactivate", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    // Create an active user
    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Users",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "deactivate@test-org.example.com", "active": true}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let user_id = created["id"].as_str().expect("user id");

    // PATCH to deactivate
    let (status, body) = http_request(
        &app,
        "PATCH",
        &format!("/scim/v2/Users/{}", user_id),
        Some(r#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "replace", "path": "active", "value": false}]}"#.to_string()),
        &[
            ("Authorization", &auth_header),
            ("Content-Type", "application/json"),
        ],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let updated: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(updated["active"], false);
}

#[tokio::test]
async fn test_patch_user_active_string_rejected() {
    // PATCH with `"active": "false"` (string, not bool) must return 400
    // invalidValue per RFC 7643 §2.2 — it must never be coerced to a
    // boolean, which could silently reactivate deactivated users.
    let (app, state) = test_app().await;

    let token = create_test_scim_token(&state.store, "test-patch-string", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Users",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "stringactive@test-org.example.com", "active": false}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let user_id = created["id"].as_str().expect("user id");

    // PATCH with stringified "false" — must be rejected, not silently coerced to true.
    let (status, body) = http_request(
        &app,
        "PATCH",
        &format!("/scim/v2/Users/{}", user_id),
        Some(r#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "replace", "path": "active", "value": "false"}]}"#.to_string()),
        &[
            ("Authorization", &auth_header),
            ("Content-Type", "application/json"),
        ],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["scimType"], "invalidValue");

    // Verify the user is still inactive — the bug would have flipped it to active.
    let (status, body) = http_get(
        &app,
        &format!("/scim/v2/Users/{}", user_id),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let after: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(after["active"], false, "user must remain inactive");
}

#[tokio::test]
async fn test_patch_user_active_add_op_string_rejected() {
    // Same regression but exercising the `Add` op path, which had its own
    // copy of the `unwrap_or(true)` coercion.
    let (app, state) = test_app().await;

    let token = create_test_scim_token(&state.store, "test-patch-add-string", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Users",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "addactive@test-org.example.com", "active": false}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let user_id = created["id"].as_str().expect("user id");

    let (status, body) = http_request(
        &app,
        "PATCH",
        &format!("/scim/v2/Users/{}", user_id),
        Some(r#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "add", "path": "active", "value": "false"}]}"#.to_string()),
        &[
            ("Authorization", &auth_header),
            ("Content-Type", "application/json"),
        ],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["scimType"], "invalidValue");
}

// ========================================================================
// RFC 7644 Section 3.5.2.1 — Add operation on single-valued attributes
// ========================================================================
//
// RFC 7644 §3.5.2.1: "If the target location specifies a single-valued
// attribute, the existing value is replaced." These tests confirm the Add
// operation applies displayName, name.formatted, externalId, and active
// updates — the same behavior as Replace — rather than silently ignoring
// them and returning 200 OK.

#[tokio::test]
async fn test_patch_user_add_display_name_applies() {
    // RFC 7644 §3.5.2.1: on a single-valued attribute, Add replaces the
    // existing value — a 200 OK that leaves the stored name unchanged
    // silently drops the operation.
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-add-displayname", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    // Create a user with an initial formatted name.
    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Users",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "add-displayname@test-org.example.com", "name": {"formatted": "Original Name"}, "active": true}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "setup create failed: {body}");
    let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let user_id = created["id"].as_str().expect("user id");
    assert_eq!(created["name"]["formatted"], "Original Name");

    // PATCH add displayName.
    let (status, body) = http_request(
        &app,
        "PATCH",
        &format!("/scim/v2/Users/{}", user_id),
        Some(r#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "add", "path": "displayName", "value": "New Name"}]}"#.to_string()),
        &[
            ("Authorization", &auth_header),
            ("Content-Type", "application/json"),
        ],
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    let updated: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        updated["name"]["formatted"], "New Name",
        "Add displayName must replace the existing name (RFC 7644 §3.5.2.1)"
    );

    // Re-GET to confirm persistence.
    let (status, body) = http_get(
        &app,
        &format!("/scim/v2/Users/{}", user_id),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let fetched: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(fetched["name"]["formatted"], "New Name");
}

#[tokio::test]
async fn test_patch_user_add_name_formatted_applies() {
    // RFC 7644 §3.5.2.1: Add with path "name.formatted" must replace the
    // existing name, not be silently ignored.
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-add-name-formatted", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Users",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "add-name-formatted@test-org.example.com", "name": {"formatted": "Old Formatted"}, "active": true}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "setup create failed: {body}");
    let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let user_id = created["id"].as_str().expect("user id");

    let (status, body) = http_request(
        &app,
        "PATCH",
        &format!("/scim/v2/Users/{}", user_id),
        Some(r#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "add", "path": "name.formatted", "value": "New Formatted"}]}"#.to_string()),
        &[
            ("Authorization", &auth_header),
            ("Content-Type", "application/json"),
        ],
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    let updated: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        updated["name"]["formatted"], "New Formatted",
        "Add name.formatted must replace the existing name (RFC 7644 §3.5.2.1)"
    );
}

#[tokio::test]
async fn test_patch_user_add_external_id_applies() {
    // RFC 7644 §3.5.2.1: Add with path "externalId" must set/replace the
    // externalId, not be silently ignored.
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-add-external-id", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Users",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "add-extid@test-org.example.com", "active": true}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "setup create failed: {body}");
    let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let user_id = created["id"].as_str().expect("user id");
    assert!(
        created.get("externalId").is_none(),
        "user created without externalId"
    );

    // Add externalId via Add operation.
    let (status, body) = http_request(
        &app,
        "PATCH",
        &format!("/scim/v2/Users/{}", user_id),
        Some(r#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "add", "path": "externalId", "value": "ext-add-123"}]}"#.to_string()),
        &[
            ("Authorization", &auth_header),
            ("Content-Type", "application/json"),
        ],
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    let updated: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        updated["externalId"], "ext-add-123",
        "Add externalId must set the value (RFC 7644 §3.5.2.1)"
    );

    // Add a different externalId — should replace, not accumulate.
    let (status, body) = http_request(
        &app,
        "PATCH",
        &format!("/scim/v2/Users/{}", user_id),
        Some(r#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "add", "path": "externalId", "value": "ext-add-456"}]}"#.to_string()),
        &[
            ("Authorization", &auth_header),
            ("Content-Type", "application/json"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let updated: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        updated["externalId"], "ext-add-456",
        "Add externalId must replace the previous value"
    );
}

#[tokio::test]
async fn test_patch_user_add_active_deactivates() {
    // Regression: Add with path "active" must still work after extending
    // the handler to cover displayName/externalId. Deactivation must set
    // active=false and trigger session invalidation side-effects.
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-add-active", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Users",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "add-active@test-org.example.com", "active": true}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "setup create failed: {body}");
    let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let user_id = created["id"].as_str().expect("user id");

    let (status, body) = http_request(
        &app,
        "PATCH",
        &format!("/scim/v2/Users/{}", user_id),
        Some(r#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "add", "path": "active", "value": false}]}"#.to_string()),
        &[
            ("Authorization", &auth_header),
            ("Content-Type", "application/json"),
        ],
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    let updated: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(updated["active"], false, "Add active=false must deactivate");
}

#[tokio::test]
async fn test_patch_user_add_bulk_merges_attributes() {
    // RFC 7644 §3.5.2: Add without a path carries a complex value object
    // whose presented attributes are merged into the resource — the same
    // semantics as Replace without a path.
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-add-bulk", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Users",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "add-bulk@test-org.example.com", "active": true}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "setup create failed: {body}");
    let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let user_id = created["id"].as_str().expect("user id");

    // Bulk add: merge name.formatted, externalId, and active in one op.
    let (status, body) = http_request(
        &app,
        "PATCH",
        &format!("/scim/v2/Users/{}", user_id),
        Some(r#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "add", "value": {"name": {"formatted": "Bulk Name"}, "externalId": "bulk-ext-1", "active": false}}]}"#.to_string()),
        &[
            ("Authorization", &auth_header),
            ("Content-Type", "application/json"),
        ],
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    let updated: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(updated["name"]["formatted"], "Bulk Name");
    assert_eq!(updated["externalId"], "bulk-ext-1");
    assert_eq!(updated["active"], false);
}

#[tokio::test]
async fn test_patch_user_add_unsupported_path_is_ignored() {
    // An Add on an attribute Vouch does not store is a no-op that still
    // returns 200. Okta and Entra push attributes outside Vouch's schema
    // (title, department, enterprise extensions) on every sync; rejecting
    // them fails the whole sync at the IdP over data Vouch never persists.
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-add-unknown-path", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Users",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "add-unknown@test-org.example.com", "name": {"formatted": "Kept Name"}, "active": true}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "setup create failed: {body}");
    let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let user_id = created["id"].as_str().expect("user id");

    let (status, body) = http_request(
        &app,
        "PATCH",
        &format!("/scim/v2/Users/{}", user_id),
        Some(r#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "add", "path": "unknownField", "value": "test"}]}"#.to_string()),
        &[
            ("Authorization", &auth_header),
            ("Content-Type", "application/json"),
        ],
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    let updated: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        updated["name"]["formatted"], "Kept Name",
        "an ignored path must leave the stored attributes alone"
    );
    assert_eq!(updated["active"], true);
}

// ========================================================================
// RFC 7644 Section 3.5.2.2 — Remove operation on single-valued attributes
// ========================================================================
//
// RFC 7644 §3.5.2.2: "If the target location is a single-valued attribute,
// the attribute and its associated value is removed." Every removable
// attribute — externalId, displayName, name.formatted — must actually be
// cleared; a 200 OK with the value still set silently drops the operation.

#[tokio::test]
async fn test_patch_user_remove_display_name_clears() {
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-remove-displayname", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Users",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "remove-displayname@test-org.example.com", "name": {"formatted": "Removable Name"}, "active": true}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "setup create failed: {body}");
    let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let user_id = created["id"].as_str().expect("user id");
    assert_eq!(created["name"]["formatted"], "Removable Name");

    let (status, body) = http_request(
        &app,
        "PATCH",
        &format!("/scim/v2/Users/{}", user_id),
        Some(r#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "remove", "path": "displayName"}]}"#.to_string()),
        &[
            ("Authorization", &auth_header),
            ("Content-Type", "application/json"),
        ],
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    let updated: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        updated["name"]["formatted"],
        serde_json::Value::Null,
        "Remove displayName must clear the stored name (RFC 7644 §3.5.2.2)"
    );

    // Re-GET to confirm persistence.
    let (status, body) = http_get(
        &app,
        &format!("/scim/v2/Users/{}", user_id),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let fetched: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(fetched["name"]["formatted"], serde_json::Value::Null);
}

#[tokio::test]
async fn test_patch_user_remove_name_formatted_clears() {
    let (app, state) = test_app().await;
    let token =
        create_test_scim_token(&state.store, "test-remove-name-formatted", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Users",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "remove-name-formatted@test-org.example.com", "name": {"formatted": "Removable Formatted"}, "active": true}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "setup create failed: {body}");
    let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let user_id = created["id"].as_str().expect("user id");

    let (status, body) = http_request(
        &app,
        "PATCH",
        &format!("/scim/v2/Users/{}", user_id),
        Some(r#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "remove", "path": "name.formatted"}]}"#.to_string()),
        &[
            ("Authorization", &auth_header),
            ("Content-Type", "application/json"),
        ],
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    let updated: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        updated["name"]["formatted"],
        serde_json::Value::Null,
        "Remove name.formatted must clear the stored name (RFC 7644 §3.5.2.2)"
    );
}

// ========================================================================
// RFC 7644 Section 3.5.2 - PATCH Unsupported Paths
// ========================================================================
//
// A path outside the attributes Vouch stores is ignored, for every
// operation and both resources: identity providers sync attributes the
// directory does not hold, and a rejection there fails the whole sync.

#[tokio::test]
async fn test_rfc7644_patch_unsupported_path_is_ignored() {
    let (app, state) = test_app().await;

    let token = create_test_scim_token(&state.store, "test-patch-invalid-path", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    // Create a user first
    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Users",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "patchpath@test-org.example.com", "active": true}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let user_id = created["id"].as_str().expect("user id");

    let (status, body) = http_request(
        &app,
        "PATCH",
        &format!("/scim/v2/Users/{}", user_id),
        Some(
            r#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "replace", "path": "nonExistentField", "value": "test"}]}"#.to_string(),
        ),
        &[
            ("Authorization", &auth_header),
            ("Content-Type", "application/json"),
        ],
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    let updated: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(updated["active"], true, "the resource must be unchanged");
}

/// Every operation ignores a path Vouch does not store, and none of them
/// disturbs the attributes it does store. `title` and the enterprise
/// extension are the attributes Okta and Entra actually push.
#[tokio::test]
async fn test_patch_user_unknown_path_ignored_for_every_op() {
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-user-unknown-paths", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Users",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "unknown-paths@test-org.example.com", "name": {"formatted": "Untouched"}, "externalId": "ext-untouched", "active": true}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "setup create failed: {body}");
    let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let user_id = created["id"].as_str().expect("user id");

    for op in ["add", "replace", "remove"] {
        for path in [
            "title",
            "name.givenName",
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department",
        ] {
            let patch = serde_json::json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [{"op": op, "path": path, "value": "Sales"}]
            });
            let (status, body) = http_request(
                &app,
                "PATCH",
                &format!("/scim/v2/Users/{user_id}"),
                Some(patch.to_string()),
                &[
                    ("Authorization", &auth_header),
                    ("Content-Type", "application/json"),
                ],
            )
            .await;

            assert_eq!(
                status,
                StatusCode::OK,
                "{op} {path} must be ignored: {body}"
            );
            let updated: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
            assert_eq!(updated["name"]["formatted"], "Untouched", "{op} {path}");
            assert_eq!(updated["externalId"], "ext-untouched", "{op} {path}");
            assert_eq!(updated["active"], true, "{op} {path}");
        }
    }
}

/// The property the shared applier exists to hold: for a single-valued
/// attribute, `add` and `replace` of the same value leave the same
/// resource (RFC 7644 §3.5.2.1).
#[tokio::test]
async fn test_patch_user_add_and_replace_agree_on_single_valued_attributes() {
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-user-add-eq-replace", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    let mut results = Vec::new();
    for op in ["add", "replace"] {
        let (status, body) = http_post_json(
            &app,
            "/scim/v2/Users",
            &format!(
                r#"{{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "{op}-eq@test-org.example.com", "name": {{"formatted": "Before"}}, "active": true}}"#
            ),
            &[("Authorization", &auth_header)],
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "setup create failed: {body}");
        let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        let user_id = created["id"].as_str().expect("user id");

        let patch = serde_json::json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [
                {"op": op, "path": "displayName", "value": "After"},
                {"op": op, "path": "externalId", "value": "ext-after"},
                {"op": op, "path": "active", "value": false},
            ]
        });
        let (status, body) = http_request(
            &app,
            "PATCH",
            &format!("/scim/v2/Users/{user_id}"),
            Some(patch.to_string()),
            &[
                ("Authorization", &auth_header),
                ("Content-Type", "application/json"),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{op} must return 200: {body}");

        let mut updated: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        // Identity and timestamps differ between the two users by design.
        for field in ["id", "userName", "meta", "emails"] {
            updated
                .as_object_mut()
                .expect("SCIM user object")
                .remove(field);
        }
        results.push(updated);
    }

    assert_eq!(
        results.first(),
        results.last(),
        "add and replace must leave the same resource"
    );
    assert_eq!(results[0]["name"]["formatted"], "After");
    assert_eq!(results[0]["externalId"], "ext-after");
    assert_eq!(results[0]["active"], false);
}

/// `active` is a stored boolean with no absent state, so a removal has no
/// value to fall back to and is rejected rather than guessing (RFC 7644
/// §3.12 `invalidValue`).
#[tokio::test]
async fn test_patch_user_remove_active_rejected() {
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-user-remove-active", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Users",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "remove-active@test-org.example.com", "active": true}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "setup create failed: {body}");
    let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let user_id = created["id"].as_str().expect("user id");

    let (status, body) = http_request(
        &app,
        "PATCH",
        &format!("/scim/v2/Users/{user_id}"),
        Some(r#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "remove", "path": "active"}]}"#.to_string()),
        &[
            ("Authorization", &auth_header),
            ("Content-Type", "application/json"),
        ],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["scimType"], "invalidValue");

    let (status, body) = http_get(
        &app,
        &format!("/scim/v2/Users/{user_id}"),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let after: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(after["active"], true, "a rejected removal changes nothing");
}

// ========================================================================
// RFC 7644 Section 3.6 - DELETE User Tests
// ========================================================================

#[tokio::test]
async fn test_rfc7644_delete_user() {
    // RFC 7644 Section 3.6: DELETE removes user
    let (app, state) = test_app().await;

    let token = create_test_scim_token(&state.store, "test-delete", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    // Create a user
    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Users",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "todelete@test-org.example.com"}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let user_id = created["id"].as_str().expect("user id");

    // Delete the user
    let (status, _body) = http_request(
        &app,
        "DELETE",
        &format!("/scim/v2/Users/{}", user_id),
        None,
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::NO_CONTENT);

    // Verify user no longer exists
    let (status, _body) = http_get(
        &app,
        &format!("/scim/v2/Users/{}", user_id),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// A user deleted between the SCIM existence check and `delete_user` must
/// yield 404 (not 204) and no `scim_operation` delete audit event.
///
/// `delete_user` returns `Result<bool>`; the SCIM handler must honor a
/// `false` return instead of unconditionally reporting a successful delete.
/// The `delete_test_hook` deletes the target's user document from a separate
/// transaction inside `delete_user`, after the handler's existence check but
/// before `delete_user`'s own existence check — deterministically forcing the
/// miss without relying on task-scheduling races.
#[tokio::test]
async fn test_scim_delete_user_returns_404_when_target_vanishes_mid_delete() {
    use std::sync::{Arc, Mutex};

    let target_slot: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let slot = Arc::clone(&target_slot);
    let (app, state) = test_app_with_modify_hook(move |store| {
        let writer = store.clone();
        store.set_delete_test_hook(Arc::new(move |user_id: &str| {
            let writer = writer.clone();
            let user_id = user_id.to_string();
            let slot = Arc::clone(&slot);
            Box::pin(async move {
                let is_target =
                    slot.lock().expect("slot lock").as_deref() == Some(user_id.as_str());
                if is_target {
                    writer
                        .delete(&user_id)
                        .await
                        .expect("delete target user doc mid-race");
                }
            })
        }));
    })
    .await;

    let token = create_test_scim_token(&state.store, "test-race-delete", "test-org").await;
    let auth_header = format!("Bearer {token}");

    // Create a user to delete.
    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Users",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "race-delete@test-org.example.com"}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "body: {body}");
    let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let user_id = created["id"].as_str().expect("user id").to_string();
    *target_slot.lock().expect("slot lock") = Some(user_id.clone());

    // Delete the user. The delete hook races the deletion; the handler must
    // observe the miss and return 404.
    let (status, body) = http_delete(
        &app,
        &format!("/scim/v2/Users/{user_id}"),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "SCIM delete: a user deleted mid-delete must produce 404, got {status}: {body}"
    );

    // No `delete` scim_operation audit event may be logged when the delete
    // did not occur.
    let events = state
        .audit
        .query_events(&crate::db::AuditEventFilter {
            event_types: Some(vec!["scim_operation".to_string()]),
            ..crate::db::AuditEventFilter::default()
        })
        .await
        .expect("query audit events");
    let delete_events: Vec<_> = events
        .iter()
        .filter(|e| e.data.contains("\"delete\"") && e.data.contains(&user_id))
        .collect();
    assert!(
        delete_events.is_empty(),
        "SCIM delete: no scim_operation delete audit event may be logged when the delete did not occur; got {}",
        delete_events
            .iter()
            .map(|e| e.data.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
}

// ========================================================================
// Deactivation side-effects: SSH certificate revocation & ordering
// ========================================================================
//
// A SCIM PATCH that flips `active` true→false must revoke the user's
// previously-issued SSH certificates, and must do so BEFORE persisting
// `active=false`. Persisting the deactivation first and then failing to
// revoke leaves an "inactive" user with live SSH certs, and an IdP retry
// won't re-enter the revocation arm because `patched.deactivated` is gated on
// the true→false transition. See `delete_user` for the equivalent
// revoke-before-mutate ordering. Mirrors
// `handlers::admin::members::test_deactivate_member_revokes_ssh_certificates`.

/// Record an issued SSH cert for `user_id` so revocation has something to act on.
async fn record_test_ssh_cert(state: &crate::AppState, user_id: &str, serial: u64) {
    let expires_at = jiff::Timestamp::now()
        .checked_add(jiff::Span::new().hours(8))
        .expect("future timestamp");
    crate::db::record_ssh_certificate_issuance(
        &state.store,
        serial,
        user_id,
        "scim-test@example.com",
        &["scim-test".to_string()],
        expires_at,
    )
    .await
    .expect("record issuance");
}

#[tokio::test]
async fn test_patch_user_deactivate_revokes_ssh_certificates() {
    // A SCIM PATCH deactivation must revoke all previously-issued SSH
    // certificates — a deactivated user must not retain valid SSH access
    // (RFC 7644 §3.5.2; the deactivation semantics invalidate credentials).
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-patch-revoke-ssh", "test-org").await;
    let auth_header = format!("Bearer {token}");

    // Create an active user.
    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Users",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "patch-revoke@test-org.example.com", "active": true}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "setup create failed: {body}");
    let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let user_id = created["id"].as_str().expect("user id").to_string();

    // Record an issued SSH cert so revocation has something to act on.
    record_test_ssh_cert(&state, &user_id, 42_000_001).await;

    // Pre-condition: one issued cert, zero revoked.
    let issued_before = crate::db::get_issued_ssh_certificates_for_user(&state.store, &user_id)
        .await
        .expect("issued certs");
    assert_eq!(issued_before.len(), 1, "setup: one cert should be issued");
    let revoked_before = crate::db::get_revoked_ssh_certificates(&state.store)
        .await
        .expect("revoked certs");
    assert!(revoked_before.is_empty(), "setup: no revocations yet");

    // PATCH to deactivate (Replace op, the canonical IdP path).
    let (status, body) = http_request(
        &app,
        "PATCH",
        &format!("/scim/v2/Users/{user_id}"),
        Some(r#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "replace", "path": "active", "value": false}]}"#.to_string()),
        &[
            ("Authorization", &auth_header),
            ("Content-Type", "application/json"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "deactivate should succeed: {body}");

    // The user is now active=false...
    let updated: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(updated["active"], false, "PATCH must deactivate the user");

    // ...and the issued cert must appear on the revocation list.
    let revoked = crate::db::get_revoked_ssh_certificates(&state.store)
        .await
        .expect("revoked certs");
    assert_eq!(
        revoked.len(),
        1,
        "patch_user deactivation must revoke all SSH certificates"
    );
    assert_eq!(
        revoked[0].serial, issued_before[0].serial,
        "revoked serial must match the issued cert"
    );
    assert_eq!(revoked[0].user_id, user_id);

    // The serial reports revoked via the KRL lookup path used at auth time.
    assert!(
        crate::db::is_ssh_certificate_revoked(&state.store, &issued_before[0].serial)
            .await
            .expect("revocation check"),
        "revoked serial must be reported revoked by is_ssh_certificate_revoked"
    );

    // Re-GET to confirm persistence.
    let (status, body) = http_get(
        &app,
        &format!("/scim/v2/Users/{user_id}"),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let fetched: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(fetched["active"], false, "deactivation must persist");
}

#[tokio::test]
async fn test_patch_user_deactivate_revokes_before_persisting_active_false() {
    // The fix reverses patch_user's order: revoke credentials BEFORE
    // committing `active=false` (matching delete_user). This test pins that
    // ordering by installing a `modify_test_hook` on the user document: at
    // the moment `update_scim_user`'s `store.modify` runs (and
    // `clear_user_github_refresh_token`'s modify inside revocation), the SSH
    // certificate must ALREADY be revoked. With the buggy update-then-revoke
    // order the modify would fire while the cert is still live, so this test
    // fails on the pre-fix code.
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};

    const SERIAL_STR: &str = "42000002";

    let target_slot: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let slot = Arc::clone(&target_slot);
    let modify_fires: Arc<AtomicU32> = Arc::new(AtomicU32::new(0));
    let not_revoked: Arc<AtomicU32> = Arc::new(AtomicU32::new(0));
    let fires = Arc::clone(&modify_fires);
    let notok = Arc::clone(&not_revoked);
    let (app, state) = test_app_with_modify_hook(move |store| {
        let writer = store.clone();
        store.set_modify_test_hook(Arc::new(move |doc_id: &str, _attempt: u32| {
            let writer = writer.clone();
            let doc_id = doc_id.to_string();
            let slot = Arc::clone(&slot);
            let fires = Arc::clone(&fires);
            let notok = Arc::clone(&notok);
            Box::pin(async move {
                let target = slot.lock().expect("slot lock").clone();
                let Some(target) = target else { return };
                if doc_id != target {
                    return;
                }
                fires.fetch_add(1, Ordering::Relaxed);
                let revoked = crate::db::is_ssh_certificate_revoked(&writer, SERIAL_STR)
                    .await
                    .unwrap_or(false);
                if !revoked {
                    notok.fetch_add(1, Ordering::Relaxed);
                }
            })
        }));
    })
    .await;

    let token = create_test_scim_token(&state.store, "test-patch-order", "test-org").await;
    let auth_header = format!("Bearer {token}");

    // Create an active user.
    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Users",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "patch-order@test-org.example.com", "active": true}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "setup create failed: {body}");
    let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let user_id = created["id"].as_str().expect("user id").to_string();
    *target_slot.lock().expect("slot lock") = Some(user_id.clone());

    // Record an issued SSH cert so revocation has something to revoke.
    record_test_ssh_cert(&state, &user_id, 42_000_002).await;

    // Deactivate via PATCH. The hook observes whether the cert is revoked at
    // the moment `update_scim_user`'s (and `clear_user_github_refresh_token`'s)
    // `store.modify` runs on the user document.
    let (status, body) = http_request(
        &app,
        "PATCH",
        &format!("/scim/v2/Users/{user_id}"),
        Some(r#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "replace", "path": "active", "value": false}]}"#.to_string()),
        &[
            ("Authorization", &auth_header),
            ("Content-Type", "application/json"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "deactivate should succeed: {body}");

    // The user-doc modify must have fired at least once during the request.
    assert!(
        modify_fires.load(Ordering::Relaxed) >= 1,
        "the modify_test_hook must fire on the user document during PATCH"
    );
    // And at every user-doc modify the cert was already revoked — proving
    // revocation ran before `update_scim_user`'s persist. The buggy
    // update-then-revoke order would observe the cert as still live here.
    assert_eq!(
        not_revoked.load(Ordering::Relaxed),
        0,
        "SSH cert must be revoked BEFORE update_scim_user persists active=false; \
         the buggy update-then-revoke order would leave the cert live during the modify"
    );

    // Sanity: the cert is revoked and the user is inactive after the request.
    assert!(
        crate::db::is_ssh_certificate_revoked(&state.store, SERIAL_STR)
            .await
            .expect("revocation check"),
        "cert must be revoked after PATCH deactivation"
    );
    let updated: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(updated["active"], false, "PATCH must deactivate the user");
}
