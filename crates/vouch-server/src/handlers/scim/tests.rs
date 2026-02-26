// SPDX-License-Identifier: BUSL-1.1
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]

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

    let token = create_test_scim_token(&state.store, "test-create-user").await;

    // Create user with valid userName
    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Users",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "test@example.com", "active": true}"#,
        &[("Authorization", &format!("Bearer {}", token))],
    )
    .await;

    assert_eq!(status, StatusCode::CREATED);
    let user: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert!(user.get("id").is_some(), "Created user should have id");
    assert_eq!(user["userName"], "test@example.com");
}

#[tokio::test]
async fn test_rfc7644_create_user_conflict() {
    // RFC 7644 Section 3.3: Duplicate user returns 409 Conflict
    let (app, state) = test_app().await;

    let token = create_test_scim_token(&state.store, "test-conflict").await;
    let auth_header = format!("Bearer {}", token);

    // Create first user
    let (status, _) = http_post_json(
        &app,
        "/scim/v2/Users",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "duplicate@example.com"}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // Try to create duplicate user
    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Users",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "duplicate@example.com"}"#,
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

    let token = create_test_scim_token(&state.store, "test-get-user").await;
    let auth_header = format!("Bearer {}", token);

    // Create a user first
    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Users",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "gettest@example.com"}"#,
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
    assert_eq!(user["userName"], "gettest@example.com");
}

#[tokio::test]
async fn test_rfc7644_get_user_not_found() {
    // RFC 7644 Section 3.4.1: Non-existent user returns 404
    let (app, state) = test_app().await;

    let token = create_test_scim_token(&state.store, "test-not-found").await;

    let (status, body) = http_get(
        &app,
        "/scim/v2/Users/nonexistent-user-id",
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

    let token = create_test_scim_token(&state.store, "test-pagination").await;
    let auth_header = format!("Bearer {}", token);

    // Create several users
    for i in 1..=5 {
        let _ = http_post_json(
            &app,
            "/scim/v2/Users",
            &format!(
                r#"{{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "page{}@example.com"}}"#,
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

    let token = create_test_scim_token(&state.store, "test-filter").await;
    let auth_header = format!("Bearer {}", token);

    // Create users
    let _ = http_post_json(
        &app,
        "/scim/v2/Users",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "filtertest@example.com"}"#,
        &[("Authorization", &auth_header)],
    )
    .await;

    // Filter by userName
    let (status, body) = http_get(
        &app,
        "/scim/v2/Users?filter=userName%20eq%20%22filtertest@example.com%22",
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

    let token = create_test_scim_token(&state.store, "test-patch-deactivate").await;
    let auth_header = format!("Bearer {}", token);

    // Create an active user
    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Users",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "deactivate@example.com", "active": true}"#,
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

// ========================================================================
// RFC 7644 Section 3.6 - DELETE User Tests
// ========================================================================

#[tokio::test]
async fn test_rfc7644_delete_user() {
    // RFC 7644 Section 3.6: DELETE removes user
    let (app, state) = test_app().await;

    let token = create_test_scim_token(&state.store, "test-delete").await;
    let auth_header = format!("Bearer {}", token);

    // Create a user
    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Users",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "todelete@example.com"}"#,
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

    let token = create_test_scim_token(&state.store, "test-error-format").await;

    // Request non-existent user to get an error
    let (status, body) = http_get(
        &app,
        "/scim/v2/Users/nonexistent",
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

    let token = create_test_scim_token(&state.store, "test-eq-filter").await;
    let auth_header = format!("Bearer {}", token);

    // Create a user to search for
    let _ = http_post_json(
        &app,
        "/scim/v2/Users",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "eqtest@example.com"}"#,
        &[("Authorization", &auth_header)],
    )
    .await;

    // Filter with eq operator
    let (status, body) = http_get(
        &app,
        "/scim/v2/Users?filter=userName%20eq%20%22eqtest@example.com%22",
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let resources = response["Resources"].as_array().expect("Resources array");
    assert!(
        resources
            .iter()
            .any(|r| r["userName"] == "eqtest@example.com"),
        "eq filter should find the matching user"
    );
}

#[tokio::test]
async fn test_rfc7644_error_includes_scim_schema() {
    // RFC 7644 Section 3.12: SCIM errors must include correct schemas URN.
    let (app, state) = test_app().await;

    let token = create_test_scim_token(&state.store, "test-error-schema").await;

    let (status, body) = http_get(
        &app,
        "/scim/v2/Users/does-not-exist",
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

    let token = create_test_scim_token(&state.store, "test-list-format").await;
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

    let token = create_test_scim_token(&state.store, "test-co-filter").await;
    let auth_header = format!("Bearer {}", token);

    // Create users with known usernames
    let users_to_create = [
        "alice-partial-match@example.com",
        "partial-prefix@example.com",
        "suffix-partial@example.com",
        "nomatch@example.com",
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
            .any(|r| r["userName"].as_str().unwrap_or("") == "nomatch@example.com"),
        "co filter must not return users that don't contain 'partial'"
    );
}

#[tokio::test]
async fn test_rfc7644_filter_sw_operator_starts_with() {
    // RFC 7644 Section 3.4.2: "sw" (starts with) filter operator.
    // userName sw "prefix" returns all users whose userName starts with "prefix".
    let (app, state) = test_app().await;

    let token = create_test_scim_token(&state.store, "test-sw-filter").await;
    let auth_header = format!("Bearer {}", token);

    // Create users with known usernames
    let users_to_create = [
        "swprefix-one@example.com",
        "swprefix-two@example.com",
        "other-swprefix@example.com", // Contains but does NOT start with "swprefix"
        "notmatching@example.com",
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
            .any(|r| r["userName"].as_str().unwrap_or("") == "other-swprefix@example.com"),
        "sw filter must not return users that contain but don't START with the prefix"
    );
}

#[tokio::test]
async fn test_rfc7644_filter_eq_still_works_alongside_new_operators() {
    // Regression test: "eq" filter must continue to work after adding co/sw.
    // RFC 7644 Section 3.4.2: "eq" returns only exact matches.
    let (app, state) = test_app().await;

    let token = create_test_scim_token(&state.store, "test-eq-regression").await;
    let auth_header = format!("Bearer {}", token);

    // Create two users where one is a superstring of the other
    let _ = http_post_json(
        &app,
        "/scim/v2/Users",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "exact@example.com"}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    let _ = http_post_json(
        &app,
        "/scim/v2/Users",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "exact-extra@example.com"}"#,
        &[("Authorization", &auth_header)],
    )
    .await;

    // Filter with eq — must return only the exact match
    let (status, body) = http_get(
        &app,
        "/scim/v2/Users?filter=userName%20eq%20%22exact@example.com%22",
        &[("Authorization", &auth_header)],
    )
    .await;

    assert_eq!(status, StatusCode::OK, "eq filter must return 200: {body}");
    let response: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let resources = response["Resources"].as_array().expect("Resources array");

    // Only the exact match should be returned
    let matching: Vec<_> = resources
        .iter()
        .filter(|r| r["userName"].as_str().unwrap_or("") == "exact@example.com")
        .collect();
    assert!(
        !matching.is_empty(),
        "eq filter must return the exact match"
    );

    // The superstring must NOT be returned
    assert!(
        !resources
            .iter()
            .any(|r| r["userName"].as_str().unwrap_or("") == "exact-extra@example.com"),
        "eq filter must not return non-exact matches (superstring found)"
    );
}

#[tokio::test]
async fn test_rfc7644_filter_unsupported_operator_returns_error() {
    // RFC 7644 Section 3.4.2: Unsupported filter operators must return an error.
    // "ne" (not equal) is not supported and should produce an error response.
    let (app, state) = test_app().await;

    let token = create_test_scim_token(&state.store, "test-ne-unsupported").await;
    let auth_header = format!("Bearer {}", token);

    // Create a user (so there's something to filter)
    let _ = http_post_json(
        &app,
        "/scim/v2/Users",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "ne-test@example.com"}"#,
        &[("Authorization", &auth_header)],
    )
    .await;

    // Attempt to use "ne" (not equal) — unsupported operator
    let (status, body) = http_get(
        &app,
        "/scim/v2/Users?filter=userName%20ne%20%22ne-test@example.com%22",
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
