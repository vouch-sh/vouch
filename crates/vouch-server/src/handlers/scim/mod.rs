// SPDX-License-Identifier: BUSL-1.1
//! SCIM 2.0 API handlers (RFC 7643/7644).
//!
//! Implements user provisioning for enterprise identity providers.
//!
//! # Module Organization
//!
//! - [`types`] - SCIM types (error, list, user, group)
//! - [`discovery`] - Discovery endpoints (ServiceProviderConfig, Schemas, ResourceTypes)
//! - [`users`] - User CRUD operations
//! - [`groups`] - Group CRUD operations

pub mod discovery;
pub mod groups;
pub mod types;
pub mod users;

use aws_lc_rs::digest::{self, SHA256};
use axum::{
    Json,
    http::{HeaderMap, StatusCode},
};

use crate::AppState;
use crate::db;

// Re-export types for convenience (used by tests via `use super::*`)
pub use types::*;

// Re-export handlers
pub use discovery::{resource_types, schemas, service_provider_config};
pub use groups::{create_group, delete_group, get_group, list_groups, patch_group};
pub use users::{create_user, delete_user, get_user, list_users, patch_user};

// ============================================================================
// Authentication
// ============================================================================

/// Extract and validate SCIM bearer token (RFC 7644 Section 2).
///
/// SCIM endpoints require authentication via OAuth 2.0 Bearer Token
/// (RFC 6750). The token is validated against the SCIM token store.
pub async fn authenticate_scim(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<String, (StatusCode, Json<ScimError>)> {
    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ScimError::new(401, "Missing Authorization header")),
            )
        })?;

    // Case-insensitive check for "Bearer " prefix, extract token safely
    let token = auth_header
        .strip_prefix("Bearer ")
        .or_else(|| auth_header.strip_prefix("bearer "))
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ScimError::new(401, "Invalid Authorization header format")),
            )
        })?;
    let token_hash = hex::encode(digest::digest(&SHA256, token.as_bytes()));

    // Verify token exists and is valid
    let token_record = db::get_scim_token_by_hash(&state.db, &token_hash)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ScimError::new(500, "Database error")),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ScimError::new(401, "Invalid token")),
            )
        })?;

    // Update last_used_at
    if let Err(e) = db::update_scim_token_last_used(&state.db, &token_record.id).await {
        tracing::warn!("Failed to update SCIM token last_used_at: {e}");
    }

    Ok(token_record.id)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
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

        let token = create_test_scim_token(&state.db, "test-create-user").await;

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

        let token = create_test_scim_token(&state.db, "test-conflict").await;
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

        let token = create_test_scim_token(&state.db, "test-get-user").await;
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

        let token = create_test_scim_token(&state.db, "test-not-found").await;

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

        let token = create_test_scim_token(&state.db, "test-pagination").await;
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

        let token = create_test_scim_token(&state.db, "test-filter").await;
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

        let token = create_test_scim_token(&state.db, "test-patch-deactivate").await;
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

        let token = create_test_scim_token(&state.db, "test-delete").await;
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

        let token = create_test_scim_token(&state.db, "test-error-format").await;

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
}
