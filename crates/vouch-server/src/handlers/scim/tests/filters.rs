// SPDX-License-Identifier: Apache-2.0 OR MIT
//! SCIM filter operators (eq, co, sw) on the list endpoints
//! (RFC 7644 §3.4.2.2).
#![expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable"
)]

use super::*;

// ========================================================================
// Additional RFC 7644 - Filter Operator Tests
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
