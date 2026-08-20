// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Service-provider configuration, authentication, error response
//! format, and error-classification mapping (RFC 7644 §2, §3.12, §4).
#![expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable"
)]

use super::*;

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
    let resp = crate::handlers::scim::users::create_scim_user_error_response(
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
    let resp = crate::handlers::scim::users::create_scim_user_error_response(
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
    let resp = crate::handlers::scim::users::create_scim_user_error_response(
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
    let resp = crate::handlers::scim::users::create_scim_user_error_response(
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
    let resp = crate::handlers::scim::groups::create_scim_group_error_response(anyhow::anyhow!(
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
    let resp = crate::handlers::scim::groups::create_scim_group_error_response(err);
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
    let resp = crate::handlers::scim::groups::create_scim_group_error_response(anyhow::anyhow!(
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

// ============================================================================
// member_op_error_response — every arm has a test that triggers it
// ============================================================================
//
// Group member operations (add/replace/remove in PATCH, add in POST create)
// route their errors through `member_op_error_response`. A NUL byte in the
// `user_id` index is a 400 `invalidValue` client error; every other failure
// (HPKE decryption, JSON/timestamp parse, DB connection/timeout, exhausted
// OCC retries) is a 500 infrastructure error — matching
// `create_scim_group_error_response` so a failed member write never leaves
// a PATCH/POST returning 200/201 with stale membership.

#[tokio::test]
async fn member_op_error_infrastructure_maps_to_500() {
    // A generic infrastructure error (e.g. DB connection refused, HPKE
    // decrypt failure, JSON parse error) must surface as 500, not 200 OK.
    let resp = crate::handlers::scim::groups::member_op_error_response(anyhow::anyhow!(
        "sqlx::Error::PoolTimedOut: queue limit reached"
    ));
    assert_eq!(
        resp.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "infrastructure errors must return 500, not 200"
    );
    let body = error_body(resp).await;
    assert_eq!(body["status"], "500", "SCIM status field must be 500");
    assert!(
        body.get("scimType").is_none_or(|v| v.is_null()),
        "infrastructure errors must not carry a scimType: {body}"
    );
    assert_eq!(
        body["detail"], "Failed to update group members",
        "detail must not leak internal error strings"
    );
}

#[tokio::test]
async fn member_op_error_invalid_index_value_maps_to_400() {
    // A NUL-byte index value is a client error (400 invalidValue), not a 500.
    let err = anyhow::Error::from(crate::db::InvalidIndexValue { field: "user_id" });
    let resp = crate::handlers::scim::groups::member_op_error_response(err);
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = error_body(resp).await;
    assert_eq!(body["status"], "400");
    assert_eq!(body["scimType"], "invalidValue");
    assert!(
        body["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("user_id"),
        "detail must name the offending field: {body}"
    );
}

/// An infrastructure error whose message happens to contain "UNIQUE" must
/// still map to 500, not be misread as a duplicate-member conflict. Member
/// documents use deterministic IDs, so a unique violation on the primary
/// key is the concurrent-add idempotency guard — caught inside
/// `add_scim_group_member` and returned as `Ok(true)`. An error that
/// escapes to `member_op_error_response` is by definition not that case.
#[tokio::test]
async fn member_op_error_unique_string_still_maps_to_500() {
    let resp = crate::handlers::scim::groups::member_op_error_response(anyhow::anyhow!(
        "UNIQUE constraint failed: documents.id"
    ));
    assert_eq!(
        resp.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "a 'UNIQUE' string must not be misread as a duplicate-member 409"
    );
    let body = error_body(resp).await;
    assert_eq!(body["status"], "500");
    assert!(
        body.get("scimType").is_none_or(|v| v.is_null()),
        "no uniqueness scimType for infrastructure errors: {body}"
    );
}
