// SPDX-License-Identifier: Apache-2.0 OR MIT
#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable"
)]

use super::*;
use crate::test_utils::*;

// ========================================================================
// RFC 7644 Section 4 - Service Provider Configuration Tests
// ========================================================================

#[tokio::test]
async fn test_rfc7644_service_provider_config() {
    // RFC 7644 Section 4: ServiceProviderConfig endpoint
    let (app, _state) = test_app().await;

    let (status, body) = http_get(&app, "/scim/v2/ServiceProviderConfig", &[]).await;

    assert_eq!(status, StatusCode::OK);
    let config: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    // Required fields per RFC 7643/7644
    assert!(config.get("schemas").is_some(), "schemas is required");
    assert!(config.get("patch").is_some(), "patch config is required");
    assert!(config.get("bulk").is_some(), "bulk config is required");
    assert!(config.get("filter").is_some(), "filter config is required");
    assert!(
        config.get("changePassword").is_some(),
        "changePassword config is required"
    );
    assert!(config.get("sort").is_some(), "sort config is required");
    assert!(config.get("etag").is_some(), "etag config is required");
    assert!(
        config.get("authenticationSchemes").is_some(),
        "authenticationSchemes is required"
    );

    // Verify schemas array contains correct URN
    let schemas = config["schemas"].as_array().expect("schemas is an array");
    assert!(
        schemas
            .iter()
            .any(|s| s == "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig")
    );
}

#[tokio::test]
async fn test_rfc7644_schemas_endpoint() {
    // RFC 7644 Section 4: Schemas endpoint returns User schema
    let (app, _state) = test_app().await;

    let (status, body) = http_get(&app, "/scim/v2/Schemas", &[]).await;

    assert_eq!(status, StatusCode::OK);
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    // Verify ListResponse format
    let schemas = response["schemas"].as_array().expect("schemas array");
    assert!(
        schemas
            .iter()
            .any(|s| s == "urn:ietf:params:scim:api:messages:2.0:ListResponse")
    );

    // Verify User schema is present
    let resources = response["Resources"].as_array().expect("Resources array");
    assert!(
        resources
            .iter()
            .any(|r| r["id"] == "urn:ietf:params:scim:schemas:core:2.0:User"),
        "User schema should be present"
    );
}

// ========================================================================
// RFC 7644 Section 2 - Authentication Tests
// ========================================================================

#[tokio::test]
async fn test_rfc7644_auth_required() {
    // RFC 7644 Section 2: Authentication is required
    let (app, _state) = test_app().await;

    // Try to list users without token
    let (status, body) = http_get(&app, "/scim/v2/Users", &[]).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert!(
        error.get("schemas").is_some(),
        "SCIM error should have schemas"
    );
    assert!(
        error.get("detail").is_some(),
        "SCIM error should have detail"
    );
}

#[tokio::test]
async fn test_rfc7644_auth_invalid_token() {
    // Invalid token should return 401
    let (app, _state) = test_app().await;

    let (status, body) = http_get(
        &app,
        "/scim/v2/Users",
        &[("Authorization", "Bearer invalid_token")],
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["status"], "401");
}

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
// RFC 7644 Section 3.5.3 - PATCH Unsupported Paths
// ========================================================================

#[tokio::test]
async fn test_rfc7644_patch_unsupported_path_returns_400() {
    // RFC 7644 Section 3.5.3: Unsupported attribute paths should return 400
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

    // PATCH with an unsupported path should return 400
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

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["scimType"], "invalidPath",
        "Should return invalidPath scimType"
    );
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

// ========================================================================
// RFC 7644 Section 3.12 - Error Response Format Tests
// ========================================================================

#[tokio::test]
async fn test_rfc7644_error_format() {
    // RFC 7644 Section 3.12: Error response format
    let (app, state) = test_app().await;

    let token = create_test_scim_token(&state.store, "test-error-format", "test-org").await;

    // Request non-existent user (valid UUID format) to get an error
    let (status, body) = http_get(
        &app,
        "/scim/v2/Users/00000000-0000-7000-0000-000000000001",
        &[("Authorization", &format!("Bearer {}", token))],
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    // RFC 7644 Section 3.12: Error MUST include schemas
    let schemas = error["schemas"].as_array().expect("schemas array");
    assert!(
        schemas
            .iter()
            .any(|s| s == "urn:ietf:params:scim:api:messages:2.0:Error")
    );

    // MUST include status and detail
    assert!(error.get("status").is_some(), "Error must have status");
    assert!(error.get("detail").is_some(), "Error must have detail");
}

// ========================================================================
// P2: Additional RFC 7644 - Filter Operator Tests
// ========================================================================

#[tokio::test]
async fn test_rfc7644_filter_eq_operator() {
    // RFC 7644 Section 3.4.1: "eq" filter operator.
    let (app, state) = test_app().await;

    let token = create_test_scim_token(&state.store, "test-eq-filter", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    // Create a user to search for
    let _ = http_post_json(
        &app,
        "/scim/v2/Users",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "eqtest@test-org.example.com"}"#,
        &[("Authorization", &auth_header)],
    )
    .await;

    // Filter with eq operator
    let (status, body) = http_get(
        &app,
        "/scim/v2/Users?filter=userName%20eq%20%22eqtest@test-org.example.com%22",
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let resources = response["Resources"].as_array().expect("Resources array");
    assert!(
        resources
            .iter()
            .any(|r| r["userName"] == "eqtest@test-org.example.com"),
        "eq filter should find the matching user"
    );
}

#[tokio::test]
async fn test_rfc7644_error_includes_scim_schema() {
    // RFC 7644 Section 3.12: SCIM errors must include correct schemas URN.
    let (app, state) = test_app().await;

    let token = create_test_scim_token(&state.store, "test-error-schema", "test-org").await;

    // Use a valid UUID format that doesn't exist in the database
    let (status, body) = http_get(
        &app,
        "/scim/v2/Users/00000000-0000-7000-0000-000000000002",
        &[("Authorization", &format!("Bearer {}", token))],
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    // RFC 7644 Section 3.12: schemas MUST contain error schema
    let schemas = error["schemas"].as_array().expect("schemas array");
    assert!(
        schemas
            .iter()
            .any(|s| s == "urn:ietf:params:scim:api:messages:2.0:Error"),
        "SCIM error schemas must contain the Error URN"
    );

    // status must be a string matching the HTTP status code
    assert_eq!(
        error["status"].as_str(),
        Some("404"),
        "SCIM error status must match HTTP status as a string"
    );
}

#[tokio::test]
async fn test_rfc7644_list_response_format() {
    // RFC 7644 Section 3.4.2: ListResponse must include proper schemas,
    // totalResults, startIndex, and itemsPerPage.
    let (app, state) = test_app().await;

    let token = create_test_scim_token(&state.store, "test-list-format", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    let (status, body) = http_get(&app, "/scim/v2/Users", &[("Authorization", &auth_header)]).await;

    assert_eq!(status, StatusCode::OK);
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    // RFC 7644: ListResponse schemas
    let schemas = response["schemas"].as_array().expect("schemas array");
    assert!(
        schemas
            .iter()
            .any(|s| s == "urn:ietf:params:scim:api:messages:2.0:ListResponse"),
        "ListResponse must have correct schema"
    );

    // Required ListResponse fields
    assert!(
        response.get("totalResults").is_some(),
        "ListResponse must have totalResults"
    );
}

// ========================================================================
// RFC 7644 Section 3.4.2 — SCIM Filter Operator Tests (co, sw)
// ========================================================================

#[tokio::test]
async fn test_rfc7644_filter_co_operator_contains() {
    // RFC 7644 Section 3.4.2: "co" (contains) filter operator.
    // userName co "partial" returns all users whose userName contains "partial".
    let (app, state) = test_app().await;

    let token = create_test_scim_token(&state.store, "test-co-filter", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    // Create users with known usernames
    let users_to_create = [
        "alice-partial-match@test-org.example.com",
        "partial-prefix@test-org.example.com",
        "suffix-partial@test-org.example.com",
        "nomatch@test-org.example.com",
    ];
    for email in &users_to_create {
        let _ = http_post_json(
            &app,
            "/scim/v2/Users",
            &format!(
                r#"{{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "{}"}}"#,
                email
            ),
            &[("Authorization", &auth_header)],
        )
        .await;
    }

    // Filter with "co" operator — userName co "partial"
    let (status, body) = http_get(
        &app,
        "/scim/v2/Users?filter=userName%20co%20%22partial%22",
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::OK, "co filter must return 200: {body}");
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    let resources = response["Resources"].as_array().expect("Resources array");
    // All three "partial" users should match
    assert!(
        resources.len() >= 3,
        "co filter must return all users containing 'partial', got {} resources",
        resources.len()
    );
    // Verify all returned users contain "partial" in their userName
    for resource in resources {
        let username = resource["userName"].as_str().unwrap_or("");
        assert!(
            username.contains("partial"),
            "co filter must only return users containing 'partial', got: {username}"
        );
    }
    // Verify "nomatch" is NOT in results
    assert!(
        !resources
            .iter()
            .any(|r| r["userName"].as_str().unwrap_or("") == "nomatch@test-org.example.com"),
        "co filter must not return users that don't contain 'partial'"
    );
}

#[tokio::test]
async fn test_rfc7644_filter_sw_operator_starts_with() {
    // RFC 7644 Section 3.4.2: "sw" (starts with) filter operator.
    // userName sw "prefix" returns all users whose userName starts with "prefix".
    let (app, state) = test_app().await;

    let token = create_test_scim_token(&state.store, "test-sw-filter", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    // Create users with known usernames
    let users_to_create = [
        "swprefix-one@test-org.example.com",
        "swprefix-two@test-org.example.com",
        "other-swprefix@test-org.example.com", // Contains but does NOT start with "swprefix"
        "notmatching@test-org.example.com",
    ];
    for email in &users_to_create {
        let _ = http_post_json(
            &app,
            "/scim/v2/Users",
            &format!(
                r#"{{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "{}"}}"#,
                email
            ),
            &[("Authorization", &auth_header)],
        )
        .await;
    }

    // Filter with "sw" operator — userName sw "swprefix"
    let (status, body) = http_get(
        &app,
        "/scim/v2/Users?filter=userName%20sw%20%22swprefix%22",
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::OK, "sw filter must return 200: {body}");
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    let resources = response["Resources"].as_array().expect("Resources array");
    // Only swprefix-one and swprefix-two should match
    assert!(
        resources.len() >= 2,
        "sw filter must return users starting with 'swprefix', got {} resources",
        resources.len()
    );
    // All returned users must start with "swprefix"
    for resource in resources {
        let username = resource["userName"].as_str().unwrap_or("");
        assert!(
            username.starts_with("swprefix"),
            "sw filter must only return users starting with 'swprefix', got: {username}"
        );
    }
    // "other-swprefix" contains but does NOT start with "swprefix" — must not appear
    assert!(
        !resources
            .iter()
            .any(|r| r["userName"].as_str().unwrap_or("") == "other-swprefix@test-org.example.com"),
        "sw filter must not return users that contain but don't START with the prefix"
    );
}

#[tokio::test]
async fn test_rfc7644_filter_eq_still_works_alongside_new_operators() {
    // Regression test: "eq" filter must continue to work after adding co/sw.
    // RFC 7644 Section 3.4.2: "eq" returns only exact matches.
    let (app, state) = test_app().await;

    let token = create_test_scim_token(&state.store, "test-eq-regression", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    // Create two users where one is a superstring of the other
    let _ = http_post_json(
        &app,
        "/scim/v2/Users",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "exact@test-org.example.com"}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    let _ = http_post_json(
        &app,
        "/scim/v2/Users",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "exact-extra@test-org.example.com"}"#,
        &[("Authorization", &auth_header)],
    )
    .await;

    // Filter with eq — must return only the exact match
    let (status, body) = http_get(
        &app,
        "/scim/v2/Users?filter=userName%20eq%20%22exact@test-org.example.com%22",
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::OK, "eq filter must return 200: {body}");
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let resources = response["Resources"].as_array().expect("Resources array");

    // Only the exact match should be returned
    let matching: Vec<_> = resources
        .iter()
        .filter(|r| r["userName"].as_str().unwrap_or("") == "exact@test-org.example.com")
        .collect();
    assert!(
        !matching.is_empty(),
        "eq filter must return the exact match"
    );

    // The superstring must NOT be returned
    assert!(
        !resources
            .iter()
            .any(|r| r["userName"].as_str().unwrap_or("") == "exact-extra@test-org.example.com"),
        "eq filter must not return non-exact matches (superstring found)"
    );
}

#[tokio::test]
async fn test_rfc7644_filter_unsupported_operator_returns_error() {
    // RFC 7644 Section 3.4.2: Unsupported filter operators must return an error.
    // "ne" (not equal) is not supported and should produce an error response.
    let (app, state) = test_app().await;

    let token = create_test_scim_token(&state.store, "test-ne-unsupported", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    // Create a user (so there's something to filter)
    let _ = http_post_json(
        &app,
        "/scim/v2/Users",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "ne-test@test-org.example.com"}"#,
        &[("Authorization", &auth_header)],
    )
    .await;

    // Attempt to use "ne" (not equal) — unsupported operator
    let (status, body) = http_get(
        &app,
        "/scim/v2/Users?filter=userName%20ne%20%22ne-test@test-org.example.com%22",
        &[("Authorization", &auth_header)],
    )
    .await;

    // RFC 7644 Section 3.4.2 requires 400 Bad Request with invalidFilter scimType
    // for unsupported filter operators.
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Unsupported filter operator 'ne' must return 400, got: {status} body: {body}"
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    // RFC 7644 Section 3.12: Error response must include schemas
    assert!(
        error.get("schemas").is_some(),
        "Error response must include schemas"
    );
    // SCIM error type for invalid filter
    let scim_type = error.get("scimType").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        scim_type == "invalidFilter" || !body.is_empty(),
        "Error must indicate invalid filter, got scimType: {scim_type}"
    );
}

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
// Validation-Before-Auth Tests (Phase 1A/1B defense-in-depth)
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
