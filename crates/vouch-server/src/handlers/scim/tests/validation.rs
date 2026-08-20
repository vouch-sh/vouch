// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Input validation: resource-ID format, filter length, startIndex
//! bounds, validation-before-auth ordering, and NUL-byte rejection.
#![expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable"
)]

use super::*;

// ========================================================================
// Input Validation Tests — Resource ID Format
// ========================================================================

#[tokio::test]
async fn test_validation_get_user_invalid_uuid_returns_400() {
    // Non-UUID resource IDs must be rejected with 400 before hitting the DB
    let (app, state) = test_app().await;

    let token = create_test_scim_token(&state.store, "test-invalid-uuid", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    let (status, body) = http_get(
        &app,
        "/scim/v2/Users/not-a-uuid",
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["status"], "400");
    assert!(
        error["detail"]
            .as_str()
            .unwrap_or("")
            .contains("Invalid resource ID"),
        "Error detail should mention invalid resource ID"
    );
}

#[tokio::test]
async fn test_validation_get_group_invalid_uuid_returns_400() {
    let (app, state) = test_app().await;

    let token = create_test_scim_token(&state.store, "test-invalid-group-uuid", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    let (status, body) = http_get(
        &app,
        "/scim/v2/Groups/not-a-valid-id",
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["status"], "400");
}

#[tokio::test]
async fn test_validation_patch_user_invalid_uuid_returns_400() {
    let (app, state) = test_app().await;

    let token = create_test_scim_token(&state.store, "test-patch-invalid-uuid", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    let (status, body) = http_request(
        &app,
        "PATCH",
        "/scim/v2/Users/xyz-not-uuid",
        Some(r#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "replace", "path": "active", "value": false}]}"#.to_string()),
        &[
            ("Authorization", &auth_header),
            ("Content-Type", "application/json"),
        ],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["status"], "400");
}

#[tokio::test]
async fn test_validation_delete_user_invalid_uuid_returns_400() {
    let (app, state) = test_app().await;

    let token = create_test_scim_token(&state.store, "test-delete-invalid-uuid", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    let (status, body) = http_request(
        &app,
        "DELETE",
        "/scim/v2/Users/drop-table-users",
        None,
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["status"], "400");
}

#[tokio::test]
async fn test_validation_valid_uuid_passes_to_not_found() {
    // A valid UUID that doesn't exist should return 404, not 400
    let (app, state) = test_app().await;

    let token = create_test_scim_token(&state.store, "test-valid-uuid-404", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    let (status, _body) = http_get(
        &app,
        "/scim/v2/Users/aaaaaaaa-bbbb-7ccc-dddd-eeeeeeeeeeee",
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "Valid UUID format should pass validation and reach the DB (404)"
    );
}

// ========================================================================
// Input Validation Tests — Filter Length
// ========================================================================

#[tokio::test]
async fn test_validation_filter_too_long_returns_400() {
    let (app, state) = test_app().await;

    let token = create_test_scim_token(&state.store, "test-long-filter", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    // Build a filter that exceeds the 1024 character limit
    let long_filter = format!("userName eq \"{}\"", "a".repeat(1100));
    let encoded_filter = urlencoding::encode(&long_filter);

    let (status, body) = http_get(
        &app,
        &format!("/scim/v2/Users?filter={}", encoded_filter),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["status"], "400");
    assert_eq!(error["scimType"], "invalidFilter");
}

#[tokio::test]
async fn test_validation_filter_within_limit_succeeds() {
    let (app, state) = test_app().await;

    let token = create_test_scim_token(&state.store, "test-normal-filter", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    // A normal-length filter should succeed
    let (status, _body) = http_get(
        &app,
        "/scim/v2/Users?filter=userName%20eq%20%22test@test-org.example.com%22",
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
}

// ========================================================================
// Input Validation Tests — startIndex Bounds
// ========================================================================

#[tokio::test]
async fn test_validation_start_index_too_large_returns_400() {
    let (app, state) = test_app().await;

    let token = create_test_scim_token(&state.store, "test-large-start-index", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    let (status, body) = http_get(
        &app,
        "/scim/v2/Users?startIndex=9999999",
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["status"], "400");
}

#[tokio::test]
async fn test_validation_start_index_at_boundary_succeeds() {
    let (app, state) = test_app().await;

    let token = create_test_scim_token(&state.store, "test-boundary-start-index", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    // startIndex = 10001 is exactly at the boundary (should pass)
    let (status, _body) = http_get(
        &app,
        "/scim/v2/Users?startIndex=10001",
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
}

// ========================================================================
// Validation-Before-Auth Tests (defense-in-depth)
// ========================================================================

#[tokio::test]
async fn test_validation_before_auth_filter_too_long_no_token() {
    // Malformed filter should return 400 without requiring auth
    let (app, _state) = test_app().await;

    let long_filter = format!("userName eq \"{}\"", "a".repeat(1100));
    let encoded_filter = urlencoding::encode(&long_filter);

    let (status, body) = http_get(
        &app,
        &format!("/scim/v2/Users?filter={}", encoded_filter),
        &[], // No auth header
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Oversized filter must return 400 (not 401) even without auth: {body}"
    );
}

#[tokio::test]
async fn test_validation_before_auth_start_index_too_large_no_token() {
    // Oversized startIndex should return 400 without requiring auth
    let (app, _state) = test_app().await;

    let (status, body) = http_get(
        &app,
        "/scim/v2/Users?startIndex=9999999",
        &[], // No auth header
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Oversized startIndex must return 400 (not 401) even without auth: {body}"
    );
}

#[tokio::test]
async fn test_validation_before_auth_groups_start_index_no_token() {
    // Groups endpoint also validates before auth
    let (app, _state) = test_app().await;

    let (status, body) = http_get(
        &app,
        "/scim/v2/Groups?startIndex=9999999",
        &[], // No auth header
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Groups: oversized startIndex must return 400 (not 401) even without auth: {body}"
    );
}

#[tokio::test]
async fn test_validation_before_auth_create_group_empty_name_no_token() {
    // Empty displayName should return 400 without requiring auth
    let (app, _state) = test_app().await;

    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Groups",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"], "displayName": "  "}"#,
        &[], // No auth header
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Empty displayName must return 400 (not 401) even without auth: {body}"
    );
}

// ========================================================================
// NUL-byte rejection (issue #883)
// ========================================================================
//
// Postgres/DSQL reject 0x00 in text columns while SQLite stores it; the
// document store refuses NUL in index values so every backend behaves the
// same. These tests pin the SCIM surfaces to a 400, not a 500.

#[tokio::test]
async fn test_scim_create_user_rejects_nul_external_id() {
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-nul-extid", "test-org").await;

    let body = serde_json::json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "nul-extid@test-org.example.com",
        "externalId": "ext\u{0}42"
    });
    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Users",
        &body.to_string(),
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "NUL in externalId must be a 400, not a 500: {body}"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["scimType"], "invalidValue");
    assert!(
        error["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("external_id"),
        "detail must name the field: {body}"
    );
}

#[tokio::test]
async fn test_scim_create_user_rejects_nul_in_username_local_part() {
    // The domain is clean, so this passes the userName shape check and is
    // caught by the store's index guard on the email field instead.
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-nul-local", "test-org").await;

    let body = serde_json::json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "nul\u{0}user@test-org.example.com"
    });
    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Users",
        &body.to_string(),
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "NUL in userName local part must be a 400, not a 500: {body}"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["scimType"], "invalidValue");
}

#[tokio::test]
async fn test_scim_create_user_rejects_nul_in_username_domain() {
    // A NUL in the domain fails Email::domain_of, so the userName shape
    // check rejects it before any database write.
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-nul-domain", "test-org").await;

    let body = serde_json::json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "user@test-org.exam\u{0}ple.com"
    });
    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Users",
        &body.to_string(),
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "NUL in userName domain must be a 400, not a 500: {body}"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["scimType"], "invalidValue");
}

#[tokio::test]
async fn test_scim_patch_user_rejects_nul_external_id() {
    // PATCH pulls externalId out of a raw serde_json::Value (no DTO
    // validation), so the rejection must come from the store guard.
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-nul-patch", "test-org").await;
    let auth_header = format!("Bearer {token}");

    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Users",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "nul-patch@test-org.example.com"}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "setup create failed: {body}");
    let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let user_id = created["id"].as_str().expect("user id");

    let patch = serde_json::json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "replace", "path": "externalId", "value": "ext\u{0}42"}]
    });
    let (status, body) = http_request(
        &app,
        "PATCH",
        &format!("/scim/v2/Users/{user_id}"),
        Some(patch.to_string()),
        &[
            ("Content-Type", "application/json"),
            ("Authorization", &auth_header),
        ],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "NUL in PATCHed externalId must be a 400, not a 500: {body}"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["scimType"], "invalidValue");
    assert!(
        error["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("external_id"),
        "detail must name the field: {body}"
    );
}

#[tokio::test]
async fn test_scim_create_group_rejects_nul_display_name() {
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-nul-group", "test-org").await;

    let body = serde_json::json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Sal\u{0}es"
    });
    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Groups",
        &body.to_string(),
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "NUL in displayName must be a 400, not a 500: {body}"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["scimType"], "invalidValue");
    assert!(
        error["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("display_name"),
        "detail must name the field: {body}"
    );
}

// ========================================================================
// NUL-byte rejection in Group member operations (issue #883)
// ========================================================================
//
// A NUL in `members[*].value` (the `user_id` index) must fail the request
// with a SCIM 400 `invalidValue` on every member write surface —
// create-group members, PATCH replace members, and PATCH add member —
// matching the displayName/externalId handling above.

#[tokio::test]
async fn test_scim_create_group_rejects_nul_member_user_id() {
    // POST /scim/v2/Groups with a NUL in members[0].value must be a 400,
    // not a 201 CREATED with the invalid member dropped.
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-nul-member-create", "test-org").await;
    let auth_header = format!("Bearer {token}");

    let body = serde_json::json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "NulMemberCreate",
        "members": [{"value": "user\u{0}id"}]
    });
    let (status, resp_body) = http_post_json(
        &app,
        "/scim/v2/Groups",
        &body.to_string(),
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "NUL in member user_id must be a 400, not 201 CREATED: {resp_body}"
    );
    let error: serde_json::Value = serde_json::from_str(&resp_body).expect("Valid JSON");
    assert_eq!(error["scimType"], "invalidValue");
    assert!(
        error["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("user_id"),
        "detail must name the user_id field: {resp_body}"
    );
}

#[tokio::test]
async fn test_scim_patch_group_replace_members_rejects_nul_user_id() {
    // PATCH replace members with a NUL in value must be a 400, not 200 OK.
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-nul-member-replace", "test-org").await;
    let auth_header = format!("Bearer {token}");

    // Create a group to PATCH.
    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Groups",
        r#"{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"NulMemberReplace"}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "setup create failed: {body}");
    let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let group_id = created["id"].as_str().expect("group id");

    let patch = serde_json::json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "replace", "path": "members", "value": [{"value": "bad\u{0}user"}]}]
    });
    let (status, resp_body) = http_request(
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
        StatusCode::BAD_REQUEST,
        "NUL in replace-members user_id must be a 400, not 200 OK: {resp_body}"
    );
    let error: serde_json::Value = serde_json::from_str(&resp_body).expect("Valid JSON");
    assert_eq!(error["scimType"], "invalidValue");
    assert!(
        error["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("user_id"),
        "detail must name the user_id field: {resp_body}"
    );
}

#[tokio::test]
async fn test_scim_patch_group_add_member_rejects_nul_user_id() {
    // PATCH add member with a NUL in value must be a 400, not 200 OK.
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-nul-member-add", "test-org").await;
    let auth_header = format!("Bearer {token}");

    // Create a group to PATCH.
    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Groups",
        r#"{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"NulMemberAdd"}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "setup create failed: {body}");
    let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let group_id = created["id"].as_str().expect("group id");

    let patch = serde_json::json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "add", "path": "members", "value": [{"value": "bad\u{0}user"}]}]
    });
    let (status, resp_body) = http_request(
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
        StatusCode::BAD_REQUEST,
        "NUL in add-member user_id must be a 400, not 200 OK: {resp_body}"
    );
    let error: serde_json::Value = serde_json::from_str(&resp_body).expect("Valid JSON");
    assert_eq!(error["scimType"], "invalidValue");
    assert!(
        error["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("user_id"),
        "detail must name the user_id field: {resp_body}"
    );
}

#[tokio::test]
async fn test_scim_patch_group_replace_members() {
    // PATCH replace members swaps the full member set and returns 200 —
    // valid user_ids must not be caught by the invalid-value handling.
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-replace-members", "test-org").await;
    let auth_header = format!("Bearer {token}");

    // Create two users.
    let (_, body) = http_post_json(
        &app,
        "/scim/v2/Users",
        r#"{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"replace-a@test-org.example.com"}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    let user_a: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let user_a_id = user_a["id"].as_str().expect("user a id");

    let (_, body) = http_post_json(
        &app,
        "/scim/v2/Users",
        r#"{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"replace-b@test-org.example.com"}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    let user_b: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let user_b_id = user_b["id"].as_str().expect("user b id");

    // Create a group with user_a as a member.
    let create_body = format!(
        r#"{{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"ReplaceTeam","members":[{{"value":"{user_a_id}"}}]}}"#
    );
    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Groups",
        &create_body,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "setup create failed: {body}");
    let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let group_id = created["id"].as_str().expect("group id");

    // PATCH replace members with user_b only.
    let patch = serde_json::json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "replace", "path": "members", "value": [{"value": user_b_id}]}]
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
        "PATCH replace must return 200: {body}"
    );

    // GET the group: user_a must be gone, user_b must be present.
    let (status, body) = http_get(
        &app,
        &format!("/scim/v2/Groups/{group_id}"),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let group: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let members = group["members"].as_array().expect("members array");
    assert!(
        members.iter().any(|m| m["value"] == user_b_id),
        "replaced member (user_b) must appear in GET response"
    );
    assert!(
        !members.iter().any(|m| m["value"] == user_a_id),
        "previous member (user_a) must be removed after replace"
    );
}

/// E2E regression for the SCIM group-member concurrent-add race through the
/// full HTTP stack: two concurrent `PATCH /scim/v2/Groups/{id}` requests
/// adding the same member must result in exactly one membership, and both
/// must return 200 OK (the operation is idempotent).
///
/// Exercises the full axum router → SCIM auth middleware → handler →
/// `add_scim_group_member` → `DocumentStore::insert_with_id` path, verifying
/// the deterministic-ID fix holds end-to-end and not just at the DB layer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_scim_patch_group_add_member_concurrent_same_user() {
    let (app, state) = test_app().await;
    let token =
        create_test_scim_token(&state.store, "test-concurrent-add-member", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    // Create a user.
    let (_, user_body) = http_post_json(
        &app,
        "/scim/v2/Users",
        r#"{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"concurrent-add@test-org.example.com"}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    let user: serde_json::Value = serde_json::from_str(&user_body).expect("Valid JSON");
    let user_id = user["id"].as_str().expect("user id");

    // Create a group without members.
    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Groups",
        r#"{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"ConcurrentGroup"}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let group_id = created["id"].as_str().expect("group id");

    // Build the same PATCH body for both concurrent requests.
    let patch_body = format!(
        r#"{{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{{"op":"add","path":"members","value":[{{"value":"{}"}}]}}]}}"#,
        user_id
    );
    let uri = format!("/scim/v2/Groups/{}", group_id);
    let headers: [(&str, &str); 2] = [
        ("Content-Type", "application/json"),
        ("Authorization", &auth_header),
    ];

    // Fire two concurrent PATCH requests adding the same member.
    let (r1, r2) = tokio::join!(
        http_request(&app, "PATCH", &uri, Some(patch_body.clone()), &headers),
        http_request(&app, "PATCH", &uri, Some(patch_body), &headers),
    );

    // Both must return 200 OK — the operation is idempotent.
    assert_eq!(
        r1.0,
        StatusCode::OK,
        "first concurrent PATCH add must return 200: {}",
        r1.1
    );
    assert_eq!(
        r2.0,
        StatusCode::OK,
        "second concurrent PATCH add must return 200: {}",
        r2.1
    );

    // GET the group: the member must appear exactly once.
    let (status, body) = http_get(
        &app,
        &format!("/scim/v2/Groups/{}", group_id),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let group: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let members = group["members"].as_array().expect("members array");
    let count = members.iter().filter(|m| m["value"] == user_id).count();
    assert_eq!(
        count, 1,
        "member must appear exactly once after concurrent add, got {}",
        count
    );
}

/// A pathless bulk merge carrying both `name.formatted` and its alias
/// `displayName` stores the canonical path's value. Applying every alias in
/// table order would let `displayName` overwrite it — and a `null` alias
/// clear a name the canonical path had just set.
#[tokio::test]
async fn test_patch_user_bulk_prefers_canonical_path_over_alias() {
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-bulk-alias", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Users",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "bulk-alias@test-org.example.com", "name": {"formatted": "Original"}, "active": true}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "setup create failed: {body}");
    let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let user_id = created["id"].as_str().expect("user id");

    // Both names present: the canonical `name.formatted` must win.
    let (status, body) = http_request(
        &app,
        "PATCH",
        &format!("/scim/v2/Users/{}", user_id),
        Some(r#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "replace", "value": {"name": {"formatted": "Canonical"}, "displayName": "Alias"}}]}"#.to_string()),
        &[
            ("Authorization", &auth_header),
            ("Content-Type", "application/json"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let updated: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        updated["name"]["formatted"], "Canonical",
        "the canonical path must win over its alias: {body}"
    );

    // A null alias must not clear the value the canonical path sets.
    let (status, body) = http_request(
        &app,
        "PATCH",
        &format!("/scim/v2/Users/{}", user_id),
        Some(r#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "replace", "value": {"name": {"formatted": "Still Set"}, "displayName": null}}]}"#.to_string()),
        &[
            ("Authorization", &auth_header),
            ("Content-Type", "application/json"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let updated: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        updated["name"]["formatted"], "Still Set",
        "a null alias must not clear the canonical value: {body}"
    );
}

/// A group PATCH whose member operation precedes an operation that fails
/// validation must not change membership: the request is rejected whole.
#[tokio::test]
async fn test_scim_patch_group_rejected_op_leaves_membership_unchanged() {
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-partial-apply", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Groups",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"], "displayName": "Partial Apply"}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "setup create failed: {body}");
    let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let group_id = created["id"].as_str().expect("group id");

    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Users",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "partial-apply@test-org.example.com", "active": true}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "setup create failed: {body}");
    let user: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let user_id = user["id"].as_str().expect("user id");

    // Add a member, then remove the required displayName in the same request.
    let (status, body) = http_request(
        &app,
        "PATCH",
        &format!("/scim/v2/Groups/{}", group_id),
        Some(format!(
            r#"{{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{{"op": "add", "path": "members", "value": [{{"value": "{user_id}"}}]}}, {{"op": "remove", "path": "displayName"}}]}}"#
        )),
        &[
            ("Authorization", &auth_header),
            ("Content-Type", "application/json"),
        ],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "removing the required displayName must be rejected: {body}"
    );

    // The rejected request must not have added the member.
    let (status, body) = http_get(
        &app,
        &format!("/scim/v2/Groups/{}", group_id),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let group: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let members = group["members"].as_array().map_or(0, Vec::len);
    assert_eq!(
        members, 0,
        "a rejected PATCH must not leave membership changed: {body}"
    );
}

/// Entra sends member removals as `path: "members"` with the members in
/// `value`, rather than a `members[value eq "…"]` filter. Both forms remove.
#[tokio::test]
async fn test_scim_patch_group_remove_members_by_value_list() {
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-remove-value", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Groups",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"], "displayName": "Remove By Value"}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "setup create failed: {body}");
    let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let group_id = created["id"].as_str().expect("group id");

    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Users",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "remove-by-value@test-org.example.com", "active": true}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "setup create failed: {body}");
    let user: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let user_id = user["id"].as_str().expect("user id");

    let (status, body) = http_request(
        &app,
        "PATCH",
        &format!("/scim/v2/Groups/{}", group_id),
        Some(format!(
            r#"{{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{{"op": "add", "path": "members", "value": [{{"value": "{user_id}"}}]}}]}}"#
        )),
        &[
            ("Authorization", &auth_header),
            ("Content-Type", "application/json"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "add member failed: {body}");

    let (status, body) = http_request(
        &app,
        "PATCH",
        &format!("/scim/v2/Groups/{}", group_id),
        Some(format!(
            r#"{{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{{"op": "remove", "path": "members", "value": [{{"value": "{user_id}"}}]}}]}}"#
        )),
        &[
            ("Authorization", &auth_header),
            ("Content-Type", "application/json"),
        ],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "remove by value list failed: {body}"
    );

    let (status, body) = http_get(
        &app,
        &format!("/scim/v2/Groups/{}", group_id),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let group: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let members = group["members"].as_array().map_or(0, Vec::len);
    assert_eq!(members, 0, "member must have been removed: {body}");
}

// ========================================================================
// Infrastructure errors in member operations — 500, not 200/201
// ========================================================================
//
// A NUL byte in `user_id` is a client error (400 invalidValue), tested
// above. But `add_scim_group_member` / `remove_scim_group_member` also
// call `find_by_indexes`, which can fail with non-retryable infrastructure
// errors: HPKE decryption failure, JSON parse failure on a corrupted
// document, or timestamp parse failure. These must surface as 500
// INTERNAL_SERVER_ERROR, not be swallowed into a 200 OK with stale
// membership — the documented atomicity guarantee says a rejected
// operation leaves the record untouched.
//
// Each test corrupts a membership document's `data` column in the DB so
// `find_by_indexes` hits a JSON parse error, then verifies the PATCH
// returns 500 through the full axum router.

/// Corrupt every `scim_group_member` document for `group_id` so that
/// `find_by_indexes` fails with a deserialization (infrastructure) error
/// rather than an `InvalidIndexValue` client error.
async fn corrupt_group_member_docs(state: &crate::AppState, group_id: &str) {
    use crate::db::Pool;
    if let Pool::Sqlite(p) = state.store.pool() {
        sqlx::query(
            "UPDATE documents SET data = 'not-valid-json' \
             WHERE doc_type = 'scim_group_member' \
             AND id IN (\
                SELECT document_id FROM document_indexes \
                WHERE index_field = 'group_id' AND index_value = ?\
             )",
        )
        .bind(group_id)
        .execute(p)
        .await
        .expect("corrupt member docs");
    }
}

#[tokio::test]
async fn test_scim_patch_group_add_member_infrastructure_error_returns_500() {
    // If `find_by_indexes` fails with a deserialization error while
    // checking whether the member already exists, the PATCH must return
    // 500 — not 200 OK with the member silently absent.
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-infra-add-member", "test-org").await;
    let auth_header = format!("Bearer {token}");

    // Create a user.
    let (_, body) = http_post_json(
        &app,
        "/scim/v2/Users",
        r#"{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"infra-add@test-org.example.com"}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    let user: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let user_id = user["id"].as_str().expect("user id");

    // Create a group with that user as a member.
    let create_body = format!(
        r#"{{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"InfraAdd","members":[{{"value":"{user_id}"}}]}}"#
    );
    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Groups",
        &create_body,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "setup create failed: {body}");
    let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let group_id = created["id"].as_str().expect("group id");

    // Corrupt the membership document so `find_by_indexes` fails.
    corrupt_group_member_docs(&state, group_id).await;

    // PATCH add the same member — `add_scim_group_member` calls
    // `find_by_indexes` which hits the corrupted doc and fails.
    let patch = serde_json::json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "add", "path": "members", "value": [{"value": user_id}]}]
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
        StatusCode::INTERNAL_SERVER_ERROR,
        "infrastructure error in add-member must return 500, not 200: {body}"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["status"], "500");
    assert!(
        error.get("scimType").is_none_or(|v| v.is_null()),
        "infrastructure errors must not carry a scimType: {body}"
    );
}

#[tokio::test]
async fn test_scim_patch_group_remove_member_infrastructure_error_returns_500() {
    // If `find_by_indexes` fails with a deserialization error while
    // locating the member to remove, the PATCH must return 500 — not
    // 200 OK with the member silently left in place.
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-infra-remove-member", "test-org").await;
    let auth_header = format!("Bearer {token}");

    // Create a user.
    let (_, body) = http_post_json(
        &app,
        "/scim/v2/Users",
        r#"{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"infra-remove@test-org.example.com"}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    let user: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let user_id = user["id"].as_str().expect("user id");

    // Create a group with that user as a member.
    let create_body = format!(
        r#"{{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"InfraRemove","members":[{{"value":"{user_id}"}}]}}"#
    );
    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Groups",
        &create_body,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "setup create failed: {body}");
    let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let group_id = created["id"].as_str().expect("group id");

    // Corrupt the membership document so `find_by_indexes` fails.
    corrupt_group_member_docs(&state, group_id).await;

    // PATCH remove the member — `remove_scim_group_member` calls
    // `find_by_indexes` which hits the corrupted doc and fails.
    let patch = format!(
        r#"{{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{{"op":"remove","path":"members[value eq \"{user_id}\"]"}}]}}"#
    );
    let (status, body) = http_request(
        &app,
        "PATCH",
        &format!("/scim/v2/Groups/{group_id}"),
        Some(patch),
        &[
            ("Content-Type", "application/json"),
            ("Authorization", &auth_header),
        ],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "infrastructure error in remove-member must return 500, not 200: {body}"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["status"], "500");
    assert!(
        error.get("scimType").is_none_or(|v| v.is_null()),
        "infrastructure errors must not carry a scimType: {body}"
    );
}

#[tokio::test]
async fn test_scim_patch_group_replace_members_infrastructure_error_returns_500() {
    // `replace_scim_group_members` deletes existing members by index and
    // inserts new ones. Corrupting an existing membership document's data
    // makes the `delete_by_index` scan fail to deserialize it, surfacing
    // as 500 rather than 200 OK with a partial replacement.
    let (app, state) = test_app().await;
    let token =
        create_test_scim_token(&state.store, "test-infra-replace-members", "test-org").await;
    let auth_header = format!("Bearer {token}");

    // Create a user.
    let (_, body) = http_post_json(
        &app,
        "/scim/v2/Users",
        r#"{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"infra-replace@test-org.example.com"}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    let user: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let user_id = user["id"].as_str().expect("user id");

    // Create a group with that user as a member.
    let create_body = format!(
        r#"{{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"InfraReplace","members":[{{"value":"{user_id}"}}]}}"#
    );
    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Groups",
        &create_body,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "setup create failed: {body}");
    let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let group_id = created["id"].as_str().expect("group id");

    // Corrupt the membership document so deserialization fails during
    // `replace_scim_group_members`'s `delete_by_index` scan.
    corrupt_group_member_docs(&state, group_id).await;

    // PATCH replace members with a new (valid) user_id.
    let patch = serde_json::json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "replace", "path": "members", "value": [{"value": "00000000-0000-7000-0000-000000000001"}]}]
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
        StatusCode::INTERNAL_SERVER_ERROR,
        "infrastructure error in replace-members must return 500, not 200: {body}"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["status"], "500");
}
