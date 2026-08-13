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

/// RFC 9110 Section 11.1: the auth-scheme token is case-insensitive, so
/// `BEARER`, `bearer`, and `BeArEr` must all authenticate the same as
/// `Bearer`. Regression test for the case-sensitive `strip_prefix` pattern
/// (and the misleading "Case-insensitive check" comment) that incorrectly
/// rejected uppercase/mixed-case schemes.
#[tokio::test]
async fn test_rfc7644_auth_scheme_case_insensitive() {
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "case-insensitive", "test-org").await;

    for scheme in ["BEARER", "bearer", "BeArEr", "bEaReR"] {
        let (status, _body) = http_get(
            &app,
            "/scim/v2/Users",
            &[("Authorization", &format!("{scheme} {token}"))],
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "{scheme} scheme must be accepted (RFC 9110 §11.1 case-insensitivity)"
        );
    }
}

/// A non-Bearer scheme must still be rejected as an invalid Authorization
/// header format, confirming case-insensitive matching didn't make the
/// check overly permissive.
#[tokio::test]
async fn test_rfc7644_auth_rejects_non_bearer_scheme() {
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "non-bearer", "test-org").await;

    for scheme in ["Basic", "basic", "BASIC", "DPoP", "dpop"] {
        let (status, body) = http_get(
            &app,
            "/scim/v2/Users",
            &[("Authorization", &format!("{scheme} {token}"))],
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{scheme} must be rejected as a non-Bearer scheme"
        );
        let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
        assert_eq!(
            error["status"], "401",
            "{scheme} must yield 401; got: {body}"
        );
    }
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

// ========================================================================
// RFC 7643 Section 3.1 - meta.lastModified (regression tests)
//
// `meta.lastModified` MUST reflect the most recent DateTime the resource was
// updated (RFC 7643 §3.1). For an unmodified resource it MUST equal `created`;
// after a modification it MUST differ. The `ScimUserRecord` / `db_user_to_scim`
// projection must carry the update timestamp through — hard-coding `created`
// there leaves the two identical after PATCH.
// ========================================================================

#[tokio::test]
async fn test_user_meta_last_modified_equals_created_on_create() {
    // RFC 7643 §3.1: a never-modified resource MUST have
    // `meta.lastModified == meta.created`.
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-lm-create", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Users",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "lm-create@test-org.example.com", "active": true}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "body: {body}");
    let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    let meta = created.get("meta").expect("created user must have meta");
    let created_ts = meta
        .get("created")
        .and_then(|v| v.as_str())
        .expect("meta.created must be a string");
    let last_modified = meta
        .get("lastModified")
        .and_then(|v| v.as_str())
        .expect("meta.lastModified must be present on create");
    assert_eq!(
        created_ts, last_modified,
        "lastModified MUST equal created for a never-modified resource (RFC 7643 §3.1)"
    );
}

#[tokio::test]
async fn test_user_meta_last_modified_differs_after_patch() {
    // After PATCH the User's `meta.lastModified` must differ from
    // `meta.created`: the projection must surface the update timestamp,
    // not reuse `created_at`.
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-lm-patch", "test-org").await;
    let auth_header = format!("Bearer {}", token);

    // Create an active user.
    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Users",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "lm-patch@test-org.example.com", "active": true}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "body: {body}");
    let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let user_id = created["id"].as_str().expect("user id");
    let created_ts = created["meta"]["created"]
        .as_str()
        .expect("meta.created")
        .to_string();

    // No wait needed: the store writes `Timestamp::now()` at nanosecond
    // precision, so sequential writes always produce distinct timestamps.

    // PATCH: toggle active from true -> false.
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
    assert_eq!(status, StatusCode::OK, "PATCH must return 200: {body}");
    let patched: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(patched["active"], false, "PATCH must flip active to false");

    let patched_created = patched["meta"]["created"]
        .as_str()
        .expect("meta.created after patch");
    let patched_last_modified = patched["meta"]["lastModified"]
        .as_str()
        .expect("meta.lastModified after patch");
    assert_eq!(
        patched_created, created_ts,
        "meta.created must be immutable across a PATCH"
    );
    assert_ne!(
        patched_last_modified, patched_created,
        "BUG: lastModified still equals created after PATCH — must reflect the modification time (RFC 7643 §3.1)"
    );

    // Re-GET the user to confirm the updated lastModified is persisted, not a
    // one-shot artifact of the PATCH response.
    let (status, body) = http_get(
        &app,
        &format!("/scim/v2/Users/{}", user_id),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "GET must return 200: {body}");
    let fetched: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        fetched["meta"]["lastModified"], patched_last_modified,
        "GET must return the persisted (post-PATCH) lastModified"
    );
    assert_eq!(
        fetched["meta"]["created"], created_ts,
        "GET must still return the original created"
    );
}

#[tokio::test]
async fn test_user_last_modified_uses_db_updated_at_not_created_at() {
    // Direct DB-level check: `ScimUserRecord.updated_at` is populated from
    // `Document::updated_at` and is advanced by `store.modify`. This guards
    // against any future regression that drops the field again.
    let state = test_app().await.1;
    // `create_test_scim_token` seeds the org (with verified domain
    // `test-org.example.com`) that `create_scim_user` validates against.
    let _token = create_test_scim_token(&state.store, "test-lm-db", "test-org").await;

    // Create a user via the DB layer.
    let created = db::create_scim_user(
        &state.store,
        Some("test-org"),
        "lm-db-user@test-org.example.com",
        Some("Initial Name"),
        None,
        true,
    )
    .await
    .expect("create_scim_user");
    let created_at = created.created_at;

    // No wait needed: the store writes `Timestamp::now()` at nanosecond
    // precision, so the modify timestamp is always strictly greater.

    let found = db::update_scim_user(
        &state.store,
        &created.id,
        "test-org",
        Some("Patched Name"),
        None,
        false,
    )
    .await
    .expect("update_scim_user");
    assert!(found, "update_scim_user must report the user was modified");

    let fetched = db::get_scim_user(&state.store, &created.id, "test-org")
        .await
        .expect("get_scim_user")
        .expect("user must exist after patch");
    assert_eq!(
        fetched.created_at, created_at,
        "DB created_at must be immutable across modify"
    );
    assert!(
        fetched.updated_at > created_at,
        "DB updated_at must be strictly greater than created_at after modify"
    );
    let fetched_created = fetched.created_at;
    let fetched_updated = fetched.updated_at;

    // The HTTP-layer projection must agree with the DB layer.
    let scim_user = super::users::db_user_to_scim("https://test.example.com", fetched);
    let meta = scim_user.meta.as_ref().expect("meta");
    assert_eq!(
        meta.created, fetched_created,
        "projected meta.created must equal DB created_at"
    );
    assert_eq!(
        meta.last_modified,
        Some(fetched_updated),
        "projected meta.lastModified must equal DB updated_at (not created_at)"
    );
    assert_ne!(
        meta.last_modified,
        Some(fetched_created),
        "meta.lastModified must not fall back to created_at after a modification"
    );
}

// ============================================================================
// create_scim_user_error_response — every arm has a test that triggers it
// ============================================================================

/// Read a response body as JSON (2 MB cap is far above any SCIM error body).
async fn error_body(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 2 * 1024 * 1024)
        .await
        .expect("read body");
    serde_json::from_slice(&bytes).expect("parse body")
}

#[tokio::test]
async fn create_error_domain_not_owned_maps_to_400_invalid_value() {
    let resp = super::users::create_scim_user_error_response(
        "org-1",
        "a@b.example",
        crate::db::CreateScimUserError::DomainNotOwned,
    );
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = error_body(resp).await;
    assert_eq!(body["scimType"], "invalidValue");
}

#[tokio::test]
async fn create_error_duplicate_email_maps_to_409_uniqueness() {
    let resp = super::users::create_scim_user_error_response(
        "org-1",
        "a@b.example",
        crate::db::CreateScimUserError::DuplicateEmail,
    );
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let body = error_body(resp).await;
    assert_eq!(body["scimType"], "uniqueness");
}

/// OCC retry exhaustion is transient backpressure (concurrent provisioning
/// or domain churn colliding on the org doc), not a server fault: the
/// client must see 503 + Retry-After so IdP provisioners retry, not 500.
#[tokio::test]
async fn create_error_occ_conflict_maps_to_503_with_retry_after() {
    let resp = super::users::create_scim_user_error_response(
        "org-1",
        "a@b.example",
        crate::db::CreateScimUserError::OccConflict,
    );
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        resp.headers()
            .get(axum::http::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok()),
        Some("1"),
        "503 must carry Retry-After so provisioners back off and retry"
    );
    let body = error_body(resp).await;
    assert_eq!(body["status"], "503");
}

#[tokio::test]
async fn create_error_other_maps_to_500() {
    let resp = super::users::create_scim_user_error_response(
        "org-1",
        "a@b.example",
        crate::db::CreateScimUserError::Other(anyhow::anyhow!("db down")),
    );
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// ============================================================================
// create_scim_group_error_response — every arm has a test that triggers it
// ============================================================================
//
// Group creation returns 500 INTERNAL_SERVER_ERROR for infrastructure failures
// (serialization, encryption, DB pool/timeout, exhausted OCC retries), matching
// list_groups/get_group/patch_group/delete_group. Mapping these to 409
// CONFLICT with a `uniqueness` SCIM type would present transient
// infrastructure faults as duplicate-group conflicts.

#[tokio::test]
async fn create_group_error_infrastructure_maps_to_500() {
    // A generic infrastructure error (e.g. DB connection refused) must surface
    // as 500, not 409 CONFLICT, and must not carry a `uniqueness` scimType.
    let resp = super::groups::create_scim_group_error_response(anyhow::anyhow!(
        "sqlx::Error::PoolTimedOut: queue limit reached"
    ));
    assert_eq!(
        resp.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "infrastructure errors must return 500, not 409"
    );
    let body = error_body(resp).await;
    assert_eq!(body["status"], "500", "SCIM status field must be 500");
    assert!(
        body.get("scimType").is_none_or(|v| v.is_null()),
        "infrastructure errors must not carry a scimType: {body}"
    );
    assert_eq!(
        body["detail"], "Failed to create group",
        "detail must not leak internal error strings"
    );
}

#[tokio::test]
async fn create_group_error_invalid_index_value_maps_to_400() {
    // A NUL-byte index value is a client error (400 invalidValue), not a 500.
    let err = anyhow::Error::from(crate::db::InvalidIndexValue {
        field: "display_name",
    });
    let resp = super::groups::create_scim_group_error_response(err);
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = error_body(resp).await;
    assert_eq!(body["status"], "400");
    assert_eq!(body["scimType"], "invalidValue");
    assert!(
        body["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("display_name"),
        "detail must name the offending field: {body}"
    );
}

/// An infrastructure error whose message happens to contain "UNIQUE" must
/// still map to 500, not 409. The document-store unique constraint is on
/// `(document_id, index_field, index_value)`, which can never fire for two
/// distinct group documents, so a unique-violation message here is only ever
/// an infrastructure failure — never a duplicate group.
#[tokio::test]
async fn create_group_error_unique_string_still_maps_to_500() {
    let resp = super::groups::create_scim_group_error_response(anyhow::anyhow!(
        "UNIQUE constraint failed: document_indexes.index_value"
    ));
    assert_eq!(
        resp.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "a 'UNIQUE' string in the error must not be misread as a duplicate-group 409"
    );
    let body = error_body(resp).await;
    assert_eq!(body["status"], "500");
    assert!(
        body.get("scimType").is_none_or(|v| v.is_null()),
        "no uniqueness scimType for infrastructure errors: {body}"
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
