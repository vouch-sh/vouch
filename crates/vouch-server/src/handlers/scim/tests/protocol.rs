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

// =========================================================================
// Advertised-vs-emitted schema guard
// =========================================================================

/// A resource the handlers actually emit must carry a schema that
/// `/ResourceTypes` advertises.
///
/// Creating a real user and reading back its `schemas` is the point: an
/// assertion that compares discovery output against the constant discovery
/// is derived from would agree with itself no matter what either side said.
#[tokio::test]
async fn emitted_user_schema_is_advertised_by_resource_types() {
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "advertised-vs-emitted", "test-org").await;

    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Users",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "drift@test-org.example.com", "active": true}"#,
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let user: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");

    let emitted: Vec<&str> = user["schemas"]
        .as_array()
        .expect("created user carries a schemas array")
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();

    let (status, body) = http_get(&app, "/scim/v2/ResourceTypes", &[]).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let types: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let advertised: Vec<&str> = types["Resources"]
        .as_array()
        .expect("Resources array")
        .iter()
        .filter_map(|r| r["schema"].as_str())
        .collect();

    for schema in &emitted {
        assert!(
            advertised.contains(schema),
            "the User handler emits {schema}, which /ResourceTypes does not \
             advertise; advertised: {advertised:?}"
        );
    }
}

/// Each advertised resource type's endpoint must be a live route, so a
/// resource cannot be advertised without somewhere to serve it.
#[tokio::test]
async fn advertised_resource_type_endpoints_are_routed() {
    let (app, _state) = test_app().await;

    // Unauthenticated: a 401 proves the route exists just as well as a 200,
    // and avoids minting a token to answer a routing question.
    for resource in crate::handlers::scim::urn::RESOURCE_SCHEMAS {
        let path = format!("/scim/v2{}", resource.endpoint);
        let (status, _) = http_get(&app, &path, &[]).await;
        assert_ne!(
            status,
            StatusCode::NOT_FOUND,
            "advertised resource endpoint {path} is not routed"
        );
    }
}

/// A resource the handlers emit must appear in `/Schemas` as well, so the two
/// discovery endpoints cannot disagree with each other.
#[tokio::test]
async fn schemas_endpoint_lists_every_emitted_resource_schema() {
    let (app, _state) = test_app().await;

    let (status, body) = http_get(&app, "/scim/v2/Schemas", &[]).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let listed: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");

    let ids: Vec<&str> = listed["Resources"]
        .as_array()
        .expect("Resources array")
        .iter()
        .filter_map(|r| r["id"].as_str())
        .collect();

    for resource in crate::handlers::scim::urn::RESOURCE_SCHEMAS {
        assert!(
            ids.contains(&resource.id),
            "/Schemas does not list {}, which the handlers emit; listed: {ids:?}",
            resource.id
        );
    }
}

// =========================================================================
// RFC 7644 Section 3.4.2 — `totalResults` accuracy for discovery endpoints
// =========================================================================
//
// `totalResults` MUST equal the number of returned resources, and both must
// equal the single-sourced `RESOURCE_SCHEMAS` table. Regression guard for
// commit af8ec098, which left `/Schemas` deriving its counts from
// `RESOURCE_SCHEMAS.len()` but hardcoding its `resources` array (overcount),
// and `/ResourceTypes` deriving `resources` from `RESOURCE_SCHEMAS` but
// hardcoding its counts (undercount). With both endpoints single-sourced,
// adding a resource stays one edit and the counts cannot diverge.

#[tokio::test]
async fn schemas_endpoint_total_results_matches_resources_length() {
    let (app, _state) = test_app().await;

    let (status, body) = http_get(&app, "/scim/v2/Schemas", &[]).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let listed: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");

    let resources = listed["Resources"].as_array().expect("Resources array");
    let total_results = listed["totalResults"]
        .as_u64()
        .expect("totalResults is a number");
    let items_per_page = listed["itemsPerPage"]
        .as_u64()
        .expect("itemsPerPage is a number");
    let start_index = listed["startIndex"]
        .as_u64()
        .expect("startIndex is a number");

    let expected = crate::handlers::scim::urn::RESOURCE_SCHEMAS.len() as u64;
    assert_eq!(
        total_results, expected,
        "/Schemas totalResults must equal RESOURCE_SCHEMAS.len()"
    );
    assert_eq!(
        total_results,
        resources.len() as u64,
        "/Schemas totalResults ({total_results}) must equal Resources.len() ({})",
        resources.len()
    );
    assert_eq!(items_per_page, total_results);
    assert_eq!(start_index, 1);
}

#[tokio::test]
async fn resource_types_endpoint_total_results_matches_resources_length() {
    let (app, state) = test_app().await;

    let (status, body) = http_get(&app, "/scim/v2/ResourceTypes", &[]).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let listed: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");

    let resources = listed["Resources"].as_array().expect("Resources array");
    let total_results = listed["totalResults"]
        .as_u64()
        .expect("totalResults is a number");
    let items_per_page = listed["itemsPerPage"]
        .as_u64()
        .expect("itemsPerPage is a number");
    let start_index = listed["startIndex"]
        .as_u64()
        .expect("startIndex is a number");

    let expected = crate::handlers::scim::urn::RESOURCE_SCHEMAS.len() as u64;
    assert_eq!(
        total_results, expected,
        "/ResourceTypes totalResults must equal RESOURCE_SCHEMAS.len()"
    );
    assert_eq!(
        total_results,
        resources.len() as u64,
        "/ResourceTypes totalResults ({total_results}) must equal Resources.len() ({})",
        resources.len()
    );
    assert_eq!(items_per_page, total_results);
    assert_eq!(start_index, 1);

    // Each advertised resource type must point at a live, absolute endpoint
    // rooted at this server's base_url, and carry the schema its handler
    // emits — the two fields `/ResourceTypes` exists to advertise.
    let base_url = &state.config().base_url;
    for resource in crate::handlers::scim::urn::RESOURCE_SCHEMAS {
        let entry = resources
            .iter()
            .find(|r| r["schema"] == resource.id)
            .expect("each RESOURCE_SCHEMAS entry is advertised by /ResourceTypes");
        assert_eq!(
            entry["endpoint"],
            format!("{base_url}/scim/v2{}", resource.endpoint),
            "endpoint for {} must be the absolute route",
            resource.id
        );
        assert_eq!(entry["name"], resource.name);
        assert_eq!(entry["description"], resource.description);
    }
}

/// `/Schemas` must carry full attribute definitions (RFC 7643 Section 7)
/// after single-sourcing, so the static table feeds `/Schemas` intact and no
/// attribute was dropped in the conversion from the constant.
#[tokio::test]
async fn schemas_endpoint_carries_attribute_definitions() {
    let (app, _state) = test_app().await;

    let (status, body) = http_get(&app, "/scim/v2/Schemas", &[]).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let listed: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");

    let resources = listed["Resources"].as_array().expect("Resources array");

    let user = resources
        .iter()
        .find(|r| r["id"] == "urn:ietf:params:scim:schemas:core:2.0:User")
        .expect("User schema present");

    let attr_names: Vec<&str> = user["attributes"]
        .as_array()
        .expect("attributes array")
        .iter()
        .filter_map(|a| a["name"].as_str())
        .collect();
    assert_eq!(
        attr_names,
        ["userName", "name", "emails", "active"],
        "User schema attribute names and order"
    );

    // Spot-check that per-attribute fields survived the single-sourcing.
    let user_name = user["attributes"]
        .as_array()
        .expect("attributes array")
        .iter()
        .find(|a| a["name"] == "userName")
        .expect("userName attribute");
    assert_eq!(user_name["type"], "string");
    assert_eq!(user_name["required"], true);
    assert_eq!(user_name["multiValued"], false);
    assert_eq!(user_name["uniqueness"], "server");
    // `userName` and `emails` are immutable: Vouch cannot change a user's
    // email, so it must not advertise them as `readWrite`, which RFC 7644
    // §3.5.1 says "SHALL replace the existing attribute values".
    for immutable in ["userName", "emails"] {
        let attribute = user["attributes"]
            .as_array()
            .expect("attributes array")
            .iter()
            .find(|a| a["name"] == immutable)
            .expect("attribute present");
        assert_eq!(attribute["mutability"], "immutable", "{immutable}");
    }

    let group = resources
        .iter()
        .find(|r| r["id"] == "urn:ietf:params:scim:schemas:core:2.0:Group")
        .expect("Group schema present");
    let group_attr_names: Vec<&str> = group["attributes"]
        .as_array()
        .expect("attributes array")
        .iter()
        .filter_map(|a| a["name"].as_str())
        .collect();
    assert_eq!(group_attr_names, ["displayName", "members"]);

    // `active` is required: it has no absent state, so RFC 7644 §3.5.2.2
    // makes its removal a `mutability` error rather than an unassigned value.
    let active = user["attributes"]
        .as_array()
        .expect("attributes array")
        .iter()
        .find(|a| a["name"] == "active")
        .expect("active attribute");
    assert_eq!(active["required"], true);

    // RFC 7643 §7: `uniqueness` "specifies how the service provider enforces
    // uniqueness"; nothing refuses a second group with the same name.
    let display_name = group["attributes"]
        .as_array()
        .expect("attributes array")
        .iter()
        .find(|a| a["name"] == "displayName")
        .expect("displayName attribute");
    assert_eq!(display_name["uniqueness"], "none");
}

// ============================================================================
// Error bodies for rejections raised before a handler runs
// ============================================================================

const SCIM_ERROR_URN: &str = "urn:ietf:params:scim:api:messages:2.0:Error";

/// Asserts `response` is a SCIM error with `status` and, when given,
/// `scim_type`, and returns the parsed body.
fn assert_scim_error(
    response: &HttpResponse,
    status: StatusCode,
    scim_type: Option<&str>,
) -> serde_json::Value {
    assert_eq!(response.status, status, "{}", response.body);
    let error: serde_json::Value =
        serde_json::from_str(&response.body).expect("error body is JSON");
    assert_eq!(error["schemas"], serde_json::json!([SCIM_ERROR_URN]));
    assert_eq!(error["status"], status.as_str());
    match scim_type {
        Some(scim_type) => assert_eq!(error["scimType"], scim_type),
        None => assert!(error["scimType"].is_null(), "{error}"),
    }
    error
}

// RFC 7644 §3.12: "implementers MUST return the errors in the body of the
// response in a JSON format", and 400 covers a request that "violates
// schema"; Table 9 `invalidValue` is "A required value was missing".
#[tokio::test]
async fn test_scim_missing_required_attribute_is_400_invalid_value() {
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-missing-attr", "test-org").await;
    let auth_header = format!("Bearer {token}");

    let response = http_request_full(
        &app,
        "POST",
        "/scim/v2/Groups",
        Some(r#"{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"]}"#.to_string()),
        &[
            ("Authorization", &auth_header),
            ("Content-Type", "application/scim+json"),
        ],
    )
    .await;

    let error = assert_scim_error(&response, StatusCode::BAD_REQUEST, Some("invalidValue"));
    assert!(
        error["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains("displayName")),
        "detail names the missing attribute: {error}"
    );
}

// RFC 7644 §3.12 Table 9: `invalidSyntax` is "The request body message
// structure was invalid".
#[tokio::test]
async fn test_scim_malformed_json_is_400_invalid_syntax() {
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-bad-json", "test-org").await;
    let auth_header = format!("Bearer {token}");

    let response = http_request_full(
        &app,
        "PUT",
        "/scim/v2/Users/00000000-0000-7000-0000-000000000001",
        Some("{not json".to_string()),
        &[
            ("Authorization", &auth_header),
            ("Content-Type", "application/scim+json"),
        ],
    )
    .await;

    assert_scim_error(&response, StatusCode::BAD_REQUEST, Some("invalidSyntax"));
}

// RFC 7644 §3.12: every error carries the JSON body, including a body sent
// with a media type that is not JSON.
#[tokio::test]
async fn test_scim_non_json_content_type_keeps_415_with_scim_body() {
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-bad-ctype", "test-org").await;
    let auth_header = format!("Bearer {token}");

    let response = http_request_full(
        &app,
        "POST",
        "/scim/v2/Users",
        Some(r#"{"userName":"a@test-org.example.com"}"#.to_string()),
        &[
            ("Authorization", &auth_header),
            ("Content-Type", "text/plain"),
        ],
    )
    .await;

    assert_scim_error(&response, StatusCode::UNSUPPORTED_MEDIA_TYPE, None);
}

// RFC 7644 §3.12: the body-size limit's rejection carries the JSON body.
#[tokio::test]
async fn test_scim_oversized_body_is_413_with_scim_body() {
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-too-large", "test-org").await;
    let auth_header = format!("Bearer {token}");
    let body = format!(
        r#"{{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"{}"}}"#,
        "a".repeat(128 * 1024)
    );

    let response = http_request_full(
        &app,
        "POST",
        "/scim/v2/Groups",
        Some(body),
        &[
            ("Authorization", &auth_header),
            ("Content-Type", "application/scim+json"),
        ],
    )
    .await;

    assert_scim_error(&response, StatusCode::PAYLOAD_TOO_LARGE, None);
}

// RFC 7644 §3.12 Table 9 lists `invalidValue` for GET (Section 3.4.2): a
// query parameter of the wrong type is a value the parameter cannot take.
#[tokio::test]
async fn test_scim_unparsable_query_parameter_is_400_invalid_value() {
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-bad-query", "test-org").await;
    let auth_header = format!("Bearer {token}");

    for uri in ["/scim/v2/Users?startIndex=abc", "/scim/v2/Groups?count=-1"] {
        let response =
            http_request_full(&app, "GET", uri, None, &[("Authorization", &auth_header)]).await;
        assert_scim_error(&response, StatusCode::BAD_REQUEST, Some("invalidValue"));
    }
}

// RFC 7644 §3.12: the method router's 405 carries the JSON body, and the
// `Allow` header it sets survives.
#[tokio::test]
async fn test_scim_unrouted_method_is_405_with_scim_body() {
    let (app, _state) = test_app().await;

    let response = http_request_full(
        &app,
        "POST",
        "/scim/v2/Users/00000000-0000-7000-0000-000000000001",
        None,
        &[],
    )
    .await;

    let error = assert_scim_error(&response, StatusCode::METHOD_NOT_ALLOWED, None);
    assert_eq!(error["detail"], "Method Not Allowed");
    let allow = response
        .headers
        .get(axum::http::header::ALLOW)
        .and_then(|value| value.to_str().ok())
        .expect("Allow header");
    assert!(allow.contains("PUT"), "Allow lists PUT: {allow}");
}

// RFC 7644 §3.12: 404 is "Specified resource (e.g., User) or endpoint does
// not exist."
#[tokio::test]
async fn test_scim_unknown_endpoint_is_404_with_scim_body() {
    let (app, _state) = test_app().await;

    for uri in ["/scim/v2/Bogus", "/scim/v2/Users/a/b"] {
        let response = http_request_full(&app, "GET", uri, None, &[]).await;
        assert_scim_error(&response, StatusCode::NOT_FOUND, None);
    }
}

// RFC 7644 §3.12: the rate limiter's 429 carries the JSON body, and its
// `Retry-After` header survives.
#[tokio::test]
async fn test_scim_rate_limited_request_is_429_with_scim_body() {
    let (app, _state) = test_app().await;

    let mut limited = None;
    for _ in 0..100 {
        let response =
            http_request_full(&app, "GET", "/scim/v2/ServiceProviderConfig", None, &[]).await;
        if response.status == StatusCode::TOO_MANY_REQUESTS {
            limited = Some(response);
            break;
        }
    }
    let response = limited.expect("the general rate limiter answers 429 within 100 requests");

    assert_scim_error(&response, StatusCode::TOO_MANY_REQUESTS, None);
    assert!(
        response
            .headers
            .contains_key(axum::http::header::RETRY_AFTER),
        "Retry-After survives the body rewrite"
    );
}

#[tokio::test]
async fn test_scim_and_org_api_share_one_rate_limit_bucket() {
    // SCIM sits in its own router so only it gets SCIM error bodies; both
    // routers must still draw on the one per-IP bucket they shared before.
    let (app, _state) = test_app().await;

    let mut limited = false;
    for _ in 0..100 {
        let response =
            http_request_full(&app, "GET", "/scim/v2/ServiceProviderConfig", None, &[]).await;
        if response.status == StatusCode::TOO_MANY_REQUESTS {
            limited = true;
            break;
        }
    }
    assert!(limited, "setup: SCIM traffic exhausts the bucket");

    let response = http_request_full(&app, "GET", "/api/v1/org/scim-tokens", None, &[]).await;
    assert_eq!(response.status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn test_non_scim_routes_keep_their_own_error_bodies() {
    // The SCIM error middleware is scoped to /scim/v2/*; the org API sharing
    // its rate limiter must not start answering in SCIM format.
    let (app, _state) = test_app().await;

    let response = http_request_full(&app, "PUT", "/api/v1/org/audit-events", None, &[]).await;

    assert_eq!(response.status, StatusCode::METHOD_NOT_ALLOWED);
    assert!(
        !response.body.contains(SCIM_ERROR_URN),
        "non-SCIM 405 must not carry a SCIM body: {}",
        response.body
    );
}

#[tokio::test]
async fn test_scim_handler_json_errors_pass_through_unchanged() {
    // A handler's own SCIM error already is JSON; the middleware must not
    // replace its detail or scimType.
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-passthrough", "test-org").await;

    let response = http_request_full(
        &app,
        "GET",
        &format!("/scim/v2/Users?filter={}", "a".repeat(1100)),
        None,
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;

    let error = assert_scim_error(&response, StatusCode::BAD_REQUEST, Some("invalidFilter"));
    assert_eq!(error["detail"], "Filter exceeds maximum length");
}
