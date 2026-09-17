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
async fn test_patch_user_deactivate_revokes_ssh_certificates() {
    // #1116: SCIM deactivation must revoke previously-issued SSH certificates,
    // not merely flip active=false. `revoke_then_persist` runs revocation
    // before the active=false write commits.
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-patch-revoke", "test-org").await;
    let auth_header = format!("Bearer {token}");

    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Users",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "revoke-cert@test-org.example.com", "active": true}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let user_id = created["id"].as_str().expect("user id").to_string();

    let expires_at = jiff::Timestamp::now()
        .checked_add(jiff::Span::new().hours(8))
        .expect("future timestamp");
    crate::db::record_ssh_certificate_issuance(
        &state.store,
        42_000_003,
        &user_id,
        "revoke-cert@test-org.example.com",
        &["user".to_string()],
        expires_at,
    )
    .await
    .expect("record issuance");
    assert!(
        crate::db::get_revoked_ssh_certificates(&state.store)
            .await
            .expect("list revoked")
            .is_empty(),
        "setup: no revocations yet"
    );

    let (status, _body) = http_request(
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
    assert_eq!(status, StatusCode::OK);

    let revoked = crate::db::get_revoked_ssh_certificates(&state.store)
        .await
        .expect("list revoked");
    assert_eq!(
        revoked.len(),
        1,
        "SCIM deactivation must revoke the user's SSH certificate"
    );
}

/// Regression for the sticky `deactivated` flag: a multi-op PATCH
/// `[active=false, active=true]` on a previously-active user has the net
/// state change `active=true→true` (RFC 7644 §3.5.2: operations are applied
/// in array order to produce a final resource state), so revocation must
/// NOT fire. The pre-fix `deactivated |= user.active && !active` in the
/// `active` setter kept `deactivated` true after the first op, so
/// `revoke_then_persist` ran anyway — deleting sessions, revoking SSH
/// certificates, and clearing the GitHub refresh token while `persist`
/// wrote `active=true`. The audit row also recorded the contradiction
/// `{"active": true, "deactivated": true}`.
#[tokio::test]
async fn test_patch_user_active_round_trip_does_not_revoke() {
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-roundtrip", "test-org").await;
    let auth_header = format!("Bearer {token}");

    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Users",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "roundtrip@test-org.example.com", "active": true}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "body: {body}");
    let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let user_id = created["id"].as_str().expect("user id").to_string();

    let expires_at = jiff::Timestamp::now()
        .checked_add(jiff::Span::new().hours(8))
        .expect("future timestamp");
    crate::db::record_ssh_certificate_issuance(
        &state.store,
        42_000_077,
        &user_id,
        "roundtrip@test-org.example.com",
        &["user".to_string()],
        expires_at,
    )
    .await
    .expect("record issuance");
    assert!(
        crate::db::get_revoked_ssh_certificates(&state.store)
            .await
            .expect("list revoked")
            .is_empty(),
        "setup: no revocations yet"
    );

    let (status, body) = http_request(
        &app,
        "PATCH",
        &format!("/scim/v2/Users/{user_id}"),
        Some(r#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "replace", "path": "active", "value": false}, {"op": "replace", "path": "active", "value": true}]}"#.to_string()),
        &[
            ("Authorization", &auth_header),
            ("Content-Type", "application/json"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let resp: serde_json::Value = serde_json::from_str(&body).expect("Valid response");
    assert_eq!(
        resp["active"].as_bool(),
        Some(true),
        "final resource must remain active"
    );

    let revoked = crate::db::get_revoked_ssh_certificates(&state.store)
        .await
        .expect("list revoked");
    assert!(
        revoked.is_empty(),
        "a still-active user's SSH certificates must not be revoked; \
         got {} revocation(s)",
        revoked.len()
    );

    let events = state
        .audit
        .query_events(&crate::db::AuditEventFilter {
            event_types: Some(vec!["scim_operation".to_string()]),
            ..crate::db::AuditEventFilter::default()
        })
        .await
        .expect("query audit events");
    let update_events: Vec<_> = events
        .iter()
        .filter(|e| e.data.contains("\"update\"") && e.data.contains(&user_id))
        .collect();
    assert!(
        !update_events.is_empty(),
        "an scim_operation update audit event must be recorded"
    );
    let details = update_events
        .iter()
        .find_map(|e| serde_json::from_str::<serde_json::Value>(&e.data).ok())
        .and_then(|v| {
            v.get("details")
                .and_then(|d| d.as_str())
                .map(str::to_string)
        })
        .expect("audit event has a details string");
    let details: serde_json::Value = serde_json::from_str(&details).expect("details is JSON");
    assert_eq!(details["active"].as_bool(), Some(true));
    assert_eq!(
        details["deactivated"].as_bool(),
        Some(false),
        "deactivated must be false; with seed true and final true there is no \
         net transition. The audit row must not contradict the persisted state."
    );
}

/// Companion guard against over-correcting: a multi-op PATCH whose net
/// effect genuinely deactivates (seed `active=true`, final `active=false`)
/// must still revoke SSH certificates, even when the deactivation is one
/// of several operations applied in array order.
#[tokio::test]
async fn test_patch_user_multi_op_deactivation_still_revokes() {
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-multi-op-deactivate", "test-org").await;
    let auth_header = format!("Bearer {token}");

    let (status, body) = http_post_json(
        &app,
        "/scim/v2/Users",
        r#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "multi-op-deactivate@test-org.example.com", "active": true}"#,
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "body: {body}");
    let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    let user_id = created["id"].as_str().expect("user id").to_string();

    let expires_at = jiff::Timestamp::now()
        .checked_add(jiff::Span::new().hours(8))
        .expect("future timestamp");
    crate::db::record_ssh_certificate_issuance(
        &state.store,
        42_000_078,
        &user_id,
        "multi-op-deactivate@test-org.example.com",
        &["user".to_string()],
        expires_at,
    )
    .await
    .expect("record issuance");
    assert!(
        crate::db::get_revoked_ssh_certificates(&state.store)
            .await
            .expect("list revoked")
            .is_empty(),
        "setup: no revocations yet"
    );

    // Two operations in array order: a name change and a deactivation. The
    // net transition is active=true→false, so revocation must fire.
    let (status, _body) = http_request(
        &app,
        "PATCH",
        &format!("/scim/v2/Users/{user_id}"),
        Some(r#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "replace", "path": "displayName", "value": "Renamed"}, {"op": "replace", "path": "active", "value": false}]}"#.to_string()),
        &[
            ("Authorization", &auth_header),
            ("Content-Type", "application/json"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let revoked = crate::db::get_revoked_ssh_certificates(&state.store)
        .await
        .expect("list revoked");
    assert_eq!(
        revoked.len(),
        1,
        "a genuine multi-op deactivation must still revoke the SSH certificate"
    );
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

// RFC 7644 §3.5.2.2: "If an attribute is removed or becomes unassigned and
// is defined as a required attribute ..., the server SHALL return ... a
// "scimType" error code of "mutability"." `active` is advertised as required.
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
    assert_eq!(error["scimType"], "mutability");

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

/// Regression for the SCIM DELETE last-admin floor: deleting the only
/// remaining active admin must refuse with a 400 *before* revoking their
/// sessions and SSH certificates, not after.
///
/// `revoke_user_access` runs as separate committed transactions (delete
/// sessions, invalidate cache, revoke credentials), so letting the floor
/// fire inside `db::delete_user` (`LastAdminGuard::Enforce`, the
/// authoritative in-transaction re-check) — as the SCIM DELETE handler
/// did before this fix — destroys the admin's active sessions and live
/// SSH certificates and then refuses the delete. The "at least one
/// active admin per organization" invariant (CLAUDE.md rule 10) only
/// protects the admin record, not credentials, so a `users:write` token
/// cycling DELETEs against the sole admin left them logged out
/// indefinitely with each retry, requiring an out-of-band token
/// rotation. The advisory pre-check at the top of `delete_user` mirrors
/// `patch_user`'s and refuses up front; the in-tx re-check is the
/// authoritative floor.
///
/// `users:write` alone is the only scope the DELETE handler authorizes
/// (handlers/scim/users.rs), so the test exercises that narrow scope to
/// pin the actual attack vector.
#[tokio::test]
async fn test_scim_delete_user_refuses_to_remove_the_last_active_admin_without_revoking_access() {
    use crate::db::documents::session::SessionDoc;

    let (app, state) = test_app().await;

    // Sole remaining active admin of an org. `create_test_org_admin`
    // also stands up a session for them.
    let (admin, _admin_session_token) = create_test_org_admin(&state).await;

    // Live SSH certificate for the admin.
    let expires_at = jiff::Timestamp::now()
        .checked_add(jiff::Span::new().hours(8))
        .expect("future timestamp");
    crate::db::record_ssh_certificate_issuance(
        &state.store,
        42_010_001,
        &admin.id,
        &admin.email,
        &["user".to_string()],
        expires_at,
    )
    .await
    .expect("record issuance");

    // An attacker with only `users:write` — the sole scope the DELETE
    // handler checks. No `users:read` is required to mount the harm.
    let token = create_test_org_token_with_scope(
        &state.store,
        "attacker",
        admin.org_id.as_deref().expect("admin has org"),
        crate::db::ScimScopeSet::from_scopes(vec![crate::db::ScimScope::UsersWrite]),
    )
    .await;
    let auth_header = format!("Bearer {token}");

    // Sanity: the admin is the sole active admin, has at least one live
    // session, and no SSH cert has been revoked yet.
    assert!(
        crate::db::is_last_active_org_admin(&state.store, &admin.id)
            .await
            .expect("count admins"),
        "setup: the org has exactly one active admin",
    );
    let session_count_before = state
        .store
        .count::<SessionDoc>("user_id", &admin.id)
        .await
        .expect("count sessions");
    assert!(
        session_count_before >= 1,
        "setup: the admin has at least one session",
    );
    assert!(
        crate::db::get_revoked_ssh_certificates(&state.store)
            .await
            .expect("list revoked")
            .is_empty(),
        "setup: no SSH revocations yet",
    );

    // DELETE the admin via SCIM. The floor must refuse with the same
    // plain 400 shape the `DeleteUserError::LastAdmin` arm returns.
    let (status, body) = http_delete(
        &app,
        &format!("/scim/v2/Users/{}", admin.id),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "SCIM delete of the only remaining active admin must be 400: got {status}: {body}",
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["status"], "400");
    assert!(
        error["detail"].as_str().is_some_and(
            |d| d.contains("Cannot delete the organization's only remaining active admin")
        ),
        "SCIM delete refusal detail must name the floor: body={body}",
    );

    // The admin record itself survives: `revoke_user_access` would have
    // left `active`/`is_org_admin` untouched anyway, but more importantly
    // the delete never ran — the in-tx guard never fired.
    let admin_after = crate::db::get_user_by_id(&state.store, &admin.id)
        .await
        .expect("fetch admin after")
        .expect("admin record still exists");
    assert!(admin_after.active, "admin record still active");
    assert!(admin_after.is_org_admin, "admin record still admin");
    assert!(
        crate::db::is_last_active_org_admin(&state.store, &admin.id)
            .await
            .expect("rerun floor"),
        "admin still the sole active admin after the refused delete",
    );

    // Sessions must be intact — `revoke_user_access` would have called
    // `delete_sessions_for_user`, but the pre-check short-circuited
    // before that ran.
    let session_count_after = state
        .store
        .count::<SessionDoc>("user_id", &admin.id)
        .await
        .expect("count sessions after");
    assert_eq!(
        session_count_after, session_count_before,
        "SCIM delete refusal must not delete any of the admin's sessions",
    );

    // The live SSH cert must remain live — no `SshRevokedCertDoc` rows
    // may have been written by `revoke_user_credentials`.
    assert!(
        crate::db::get_revoked_ssh_certificates(&state.store)
            .await
            .expect("list revoked after")
            .is_empty(),
        "SCIM delete refusal must not revoke the admin's SSH certificate",
    );

    // No `scim_operation` delete audit event: the existing 5xx arm logs
    // an `accessRevoked: true` row precisely because revocation had
    // already committed; the floor refusal must not write such a row.
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
        .filter(|e| e.data.contains("\"delete\"") && e.data.contains(&admin.id))
        .collect();
    assert!(
        delete_events.is_empty(),
        "SCIM delete: no scim_operation delete audit event may be logged \
         when the floor refused; got {}",
        delete_events
            .iter()
            .map(|e| e.data.as_str())
            .collect::<Vec<_>>()
            .join(", "),
    );

    // The admin must still be discoverable by the same SCIM token — proof
    // the existence-check (which the advisory pre-check sits between) and
    // the GET-by-id path are unaffected.
    let (status, body) = http_get(
        &app,
        &format!("/scim/v2/Users/{}", admin.id),
        &[("Authorization", &auth_header)],
    )
    .await;
    // `users:write` alone is not enough for GET (the GET path requires
    // `users:read`), so this returns 403 — but that is the *only* allowed
    // failure mode; a 404 would mean the admin record had been removed.
    assert!(
        status == StatusCode::OK || status == StatusCode::FORBIDDEN,
        "admin record must still be reachable; got {status}: {body}",
    );
}

/// A `UsersWrite`-scoped token must still succeed against a non-last
/// admin: the floor only protects the *last* admin. Guards against the
/// advisory pre-check becoming overly strict (false-positiving) and
/// refusing unrelated non-last-admin deletes, and confirms the
/// revoke-then-delete ordering is preserved on the happy path.
#[tokio::test]
async fn test_scim_delete_user_removes_a_non_last_active_admin() {
    use crate::db::documents::session::SessionDoc;

    let (app, state) = test_app().await;

    // Two active admins in the same org. admin1 carries a session from
    // `create_test_org_admin`; admin2 gets one explicitly.
    let (admin1, _admin1_session_token) = create_test_org_admin(&state).await;
    let admin2 = create_test_user_in_org(
        &state.store,
        "admin2@example.com",
        admin1.org_id.as_deref().expect("admin1 has org"),
        true,
    )
    .await;
    let admin2_auth_id = create_test_authenticator(&state.store, &admin2.id).await;
    let _admin2_session_token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &admin2.id,
            email: &admin2.email,
            auth_id: Some(&admin2_auth_id),
            ..Default::default()
        },
    )
    .await;

    // Both admins have live SSH certs. admin1's will be revoked by the
    // delete; admin2's must remain live.
    let expires_at = jiff::Timestamp::now()
        .checked_add(jiff::Span::new().hours(8))
        .expect("future timestamp");
    crate::db::record_ssh_certificate_issuance(
        &state.store,
        42_010_010,
        &admin1.id,
        &admin1.email,
        &["user".to_string()],
        expires_at,
    )
    .await
    .expect("record admin1 issuance");
    crate::db::record_ssh_certificate_issuance(
        &state.store,
        42_010_011,
        &admin2.id,
        &admin2.email,
        &["user".to_string()],
        expires_at,
    )
    .await
    .expect("record admin2 issuance");

    // Default SCIM provisioning scopes (incl. `users:write`); the
    // DELETE handler checks only `users:write`.
    let token = create_test_scim_token(
        &state.store,
        "test-delete-non-last-admin",
        admin1.org_id.as_deref().expect("admin1 has org"),
    )
    .await;
    let auth_header = format!("Bearer {token}");

    // Sanity: each admin is *not* the last active one (the other
    // still counts).
    assert!(
        !crate::db::is_last_active_org_admin(&state.store, &admin1.id)
            .await
            .expect("count admins for admin1"),
        "setup: admin1 has a second admin in the org",
    );
    assert!(
        !crate::db::is_last_active_org_admin(&state.store, &admin2.id)
            .await
            .expect("count admins for admin2"),
        "setup: admin2 has a second admin in the org",
    );

    // DELETE admin1 — the floor must not refuse, since admin2 remains.
    let (status, body) = http_delete(
        &app,
        &format!("/scim/v2/Users/{}", admin1.id),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "SCIM delete of a non-last admin must succeed with 204: got {status}: {body}",
    );

    // admin1's user doc is gone.
    assert!(
        crate::db::get_user_by_id(&state.store, &admin1.id)
            .await
            .expect("fetch admin1 after")
            .is_none(),
        "admin1 user record must be gone after the delete",
    );

    // admin1's sessions were swept by `revoke_user_access` ahead of the
    // delete (the floor did not refuse; the post-floor revocation ran).
    let admin1_sessions_after = state
        .store
        .count::<SessionDoc>("user_id", &admin1.id)
        .await
        .expect("count admin1 sessions after");
    assert_eq!(
        admin1_sessions_after, 0,
        "SCIM delete must revoke the deleted admin's sessions",
    );

    // admin1's cert is in the revocation list; admin2's is not.
    let revoked = crate::db::get_revoked_ssh_certificates(&state.store)
        .await
        .expect("list revoked after");
    assert_eq!(
        revoked.len(),
        1,
        "exactly one cert revoked — the deleted admin's; got {}",
        revoked
            .iter()
            .map(|r| r.serial.clone())
            .collect::<Vec<_>>()
            .join(", "),
    );
    assert_eq!(
        revoked[0].user_id, admin1.id,
        "the revoked cert belonged to admin1",
    );

    // admin2 is now the sole remaining active admin.
    let admin2_after = crate::db::get_user_by_id(&state.store, &admin2.id)
        .await
        .expect("fetch admin2 after")
        .expect("admin2 record still exists");
    assert!(admin2_after.active, "admin2 still active");
    assert!(admin2_after.is_org_admin, "admin2 still admin");
    assert!(
        crate::db::is_last_active_org_admin(&state.store, &admin2.id)
            .await
            .expect("count admins after"),
        "admin2 is now the last active admin",
    );

    // The successful delete was logged as a `scim_operation` audit event.
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
        .filter(|e| e.data.contains("\"delete\"") && e.data.contains(&admin1.id))
        .collect();
    assert!(
        !delete_events.is_empty(),
        "SCIM delete must record a `scim_operation` audit event for the successful delete",
    );
}

/// Mirror of the DELETE last-admin regression test for the PATCH
/// deactivation path. The advisory pre-check at the top of `patch_user`
/// (handlers/scim/users.rs:504) refuses a last-admin deactivation before
/// `revoke_then_persist` runs — `revoke_then_persist` withdraws sessions
/// and SSH certificates first by design, so letting the floor fire
/// inside the persist step would log the admin out and then decline the
/// write. This pins that pre-check, which has no handler-level coverage
/// today: the existing PATCH deactivation tests target
/// `db::create_scim_user` users (`is_org_admin: false`), so the floor
/// never fires.
#[tokio::test]
async fn test_scim_patch_user_refuses_to_deactivate_the_last_active_admin_without_revoking_access()
{
    use crate::db::documents::session::SessionDoc;

    let (app, state) = test_app().await;

    // Sole remaining active admin of an org, with a session and a live
    // SSH cert.
    let (admin, _admin_session_token) = create_test_org_admin(&state).await;
    let expires_at = jiff::Timestamp::now()
        .checked_add(jiff::Span::new().hours(8))
        .expect("future timestamp");
    crate::db::record_ssh_certificate_issuance(
        &state.store,
        42_010_020,
        &admin.id,
        &admin.email,
        &["user".to_string()],
        expires_at,
    )
    .await
    .expect("record issuance");

    // `users:write` alone is all the PATCH handler checks; no
    // `users:read` needed.
    let token = create_test_org_token_with_scope(
        &state.store,
        "attacker",
        admin.org_id.as_deref().expect("admin has org"),
        crate::db::ScimScopeSet::from_scopes(vec![crate::db::ScimScope::UsersWrite]),
    )
    .await;
    let auth_header = format!("Bearer {token}");

    // Sanity: the admin is the sole active admin, has a session, and no
    // SSH cert has been revoked.
    assert!(
        crate::db::is_last_active_org_admin(&state.store, &admin.id)
            .await
            .expect("count admins"),
        "setup: the org has exactly one active admin",
    );
    let session_count_before = state
        .store
        .count::<SessionDoc>("user_id", &admin.id)
        .await
        .expect("count sessions");
    assert!(
        session_count_before >= 1,
        "setup: the admin has at least one session",
    );
    assert!(
        crate::db::get_revoked_ssh_certificates(&state.store)
            .await
            .expect("list revoked")
            .is_empty(),
        "setup: no SSH revocations yet",
    );

    // PATCH `active=false`. The floor must refuse with the PATCH-specific
    // 400 (`mutability` scimType, see `last_admin_scim_error`).
    let (status, body) = http_request(
        &app,
        "PATCH",
        &format!("/scim/v2/Users/{}", admin.id),
        Some(
            r#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "replace", "path": "active", "value": false}]}"#
                .to_string(),
        ),
        &[
            ("Authorization", &auth_header),
            ("Content-Type", "application/json"),
        ],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "SCIM PATCH deactivation of the last active admin must be 400: got {status}: {body}",
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["scimType"], "mutability",
        "PATCH last-admin refusal uses the PATCH-specific `mutability` scimType",
    );
    assert!(
        error["detail"].as_str().is_some_and(
            |d| d.contains("Cannot deactivate the organization's only remaining active admin")
        ),
        "SCIM PATCH refusal detail must name the floor: body={body}",
    );

    // The admin record is untouched: `active` is still true.
    let admin_after = crate::db::get_user_by_id(&state.store, &admin.id)
        .await
        .expect("fetch admin after")
        .expect("admin record still exists");
    assert!(admin_after.active, "admin record still active");
    assert!(admin_after.is_org_admin, "admin record still admin");
    assert!(
        crate::db::is_last_active_org_admin(&state.store, &admin.id)
            .await
            .expect("rerun floor"),
        "admin still the sole active admin after the refused PATCH",
    );

    // Sessions and SSH cert must both remain live.
    let session_count_after = state
        .store
        .count::<SessionDoc>("user_id", &admin.id)
        .await
        .expect("count sessions after");
    assert_eq!(
        session_count_after, session_count_before,
        "SCIM PATCH refusal must not delete any of the admin's sessions",
    );
    assert!(
        crate::db::get_revoked_ssh_certificates(&state.store)
            .await
            .expect("list revoked after")
            .is_empty(),
        "SCIM PATCH refusal must not revoke the admin's SSH certificate",
    );

    // No `scim_operation` PATCH audit event for a refusal that did not
    // persist: a row claiming `accessRevoked: true` would be a fraudulent
    // record of a side effect that never committed.
    let events = state
        .audit
        .query_events(&crate::db::AuditEventFilter {
            event_types: Some(vec!["scim_operation".to_string()]),
            ..crate::db::AuditEventFilter::default()
        })
        .await
        .expect("query audit events");
    let update_events: Vec<_> = events
        .iter()
        .filter(|e| e.data.contains("\"update\"") && e.data.contains(&admin.id))
        .collect();
    assert!(
        update_events.is_empty(),
        "SCIM PATCH: no scim_operation update audit event may be logged \
         when the floor refused; got {}",
        update_events
            .iter()
            .map(|e| e.data.as_str())
            .collect::<Vec<_>>()
            .join(", "),
    );
}

// ========================================================================
// In-transaction LastAdmin refusal after revocation committed
// ========================================================================
//
// The in-transaction count refuses only when an admin demotion commits between
// the advisory pre-check and the count, after revocation has committed. The
// tests produce that by deactivating a sibling admin from a hook that runs
// inside the transaction before its first read: `last_admin_count_test_hook`
// for PATCH, `delete_test_hook` for DELETE.

/// Records a `scim_operation` audit row when the in-transaction `LastAdmin`
/// guard refuses a PATCH *after* `revoke_then_persist` already committed the
/// target's session deletions and SSH-cert revocations. The row carries
/// `auth.token_id` (audit after commit, #1249).
#[expect(
    clippy::too_many_lines,
    reason = "end-to-end race regression: stand up two admins, drive the in-tx floor, assert revocation + audit"
)]
#[tokio::test]
async fn test_scim_patch_user_audits_when_in_tx_last_admin_refuses_after_revocation() {
    use crate::db::documents::session::SessionDoc;
    use crate::db::documents::user::UserDoc;
    use std::sync::{Arc, Mutex};

    // Slots carry the target (admin1) and sibling (admin2) ids from the test
    // thread into the hook closure; both are `None` until set after the two
    // admins are stood up, so the hook stays dormant during setup.
    let target_slot: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let sibling_slot: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let t = Arc::clone(&target_slot);
    let s = Arc::clone(&sibling_slot);
    let (app, state) = test_app_with_modify_hook(move |store| {
        // `writer` is a hookless clone taken before the seam is installed, so
        // the sibling deactivation never re-enters `update_scim_user`.
        let writer = store.clone();
        store.set_last_admin_count_test_hook(Arc::new(move |user_id: &str| {
            let writer = writer.clone();
            let user_id = user_id.to_string();
            let t = Arc::clone(&t);
            let s = Arc::clone(&s);
            Box::pin(async move {
                let is_target = t.lock().expect("target lock").as_deref() == Some(user_id.as_str());
                if !is_target {
                    return;
                }
                let sibling = s.lock().expect("sibling lock").clone();
                if let Some(sibling_id) = sibling {
                    writer
                        .modify::<UserDoc, _>(&sibling_id, |d| d.active = false)
                        .await
                        .expect("deactivate sibling admin from hook");
                }
            })
        }));
    })
    .await;

    // Two active admins in one org. admin1 carries a session from
    // `create_test_org_admin`; admin2 gets one explicitly so its session count
    // is non-zero too (proving the hook only deactivates admin2's *record*,
    // not its sessions).
    let (admin1, _admin1_session_token) = create_test_org_admin(&state).await;
    let org_id = admin1
        .org_id
        .as_deref()
        .expect("admin1 has org")
        .to_string();
    let admin2 = create_test_user_in_org(&state.store, "admin2@example.com", &org_id, true).await;
    let admin2_auth_id = create_test_authenticator(&state.store, &admin2.id).await;
    let _admin2_session_token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &admin2.id,
            email: &admin2.email,
            auth_id: Some(&admin2_auth_id),
            ..Default::default()
        },
    )
    .await;

    // Live SSH certs for both admins. admin1's is revoked by the PATCH;
    // admin2's stays live (the hook only flips its user doc `active=false`).
    let expires_at = jiff::Timestamp::now()
        .checked_add(jiff::Span::new().hours(8))
        .expect("future timestamp");
    crate::db::record_ssh_certificate_issuance(
        &state.store,
        42_010_030,
        &admin1.id,
        &admin1.email,
        &["user".to_string()],
        expires_at,
    )
    .await
    .expect("record admin1 issuance");
    crate::db::record_ssh_certificate_issuance(
        &state.store,
        42_010_031,
        &admin2.id,
        &admin2.email,
        &["user".to_string()],
        expires_at,
    )
    .await
    .expect("record admin2 issuance");

    // `users:write` alone is all the PATCH handler checks.
    let token = create_test_org_token_with_scope(
        &state.store,
        "attacker",
        &org_id,
        crate::db::ScimScopeSet::from_scopes(vec![crate::db::ScimScope::UsersWrite]),
    )
    .await;
    let auth_header = format!("Bearer {token}");

    // Sanity: neither admin is the last active one (the other still counts),
    // so the advisory pre-check passes for admin1. admin1 has a live session
    // and no cert has been revoked yet.
    assert!(
        !crate::db::is_last_active_org_admin(&state.store, &admin1.id)
            .await
            .expect("count admins for admin1"),
        "setup: admin1 has a second active admin",
    );
    let session_count_before = state
        .store
        .count::<SessionDoc>("user_id", &admin1.id)
        .await
        .expect("count admin1 sessions");
    assert!(session_count_before >= 1, "setup: admin1 has a session");
    assert!(
        crate::db::get_revoked_ssh_certificates(&state.store)
            .await
            .expect("list revoked")
            .is_empty(),
        "setup: no SSH revocations yet",
    );

    // Arm the hook: when `update_scim_user(admin1)` runs (after `revoke_user_access`
    // has committed), deactivate admin2 so the in-transaction count sees zero
    // other active admins and the authoritative floor fires.
    *target_slot.lock().expect("target lock") = Some(admin1.id.clone());
    *sibling_slot.lock().expect("sibling lock") = Some(admin2.id.clone());

    // PATCH admin1 active=false. The pre-check passes (2 admins);
    // `revoke_then_persist` commits admin1's revocation, then `update_scim_user`
    // counts 0 other active admins (admin2 deactivated by the hook) and the
    // floor refuses with `LastAdmin`.
    let (status, body) = http_request(
        &app,
        "PATCH",
        &format!("/scim/v2/Users/{}", admin1.id),
        Some(
            r#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "replace", "path": "active", "value": false}]}"#
                .to_string(),
        ),
        &[
            ("Authorization", &auth_header),
            ("Content-Type", "application/json"),
        ],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "in-tx LastAdmin refusal must be a 400: got {status}: {body}",
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(
        error["scimType"], "mutability",
        "in-tx LastAdmin refusal on PATCH uses the `mutability` scimType",
    );

    // Revocation committed before the floor refused: admin1's sessions are
    // gone and its SSH cert is in the revocation list — the durable side
    // effect the audit row must tie to this operation.
    let session_count_after = state
        .store
        .count::<SessionDoc>("user_id", &admin1.id)
        .await
        .expect("count admin1 sessions after");
    assert_eq!(
        session_count_after, 0,
        "SCIM PATCH revocation must delete the target's sessions before the floor refuses",
    );
    let revoked = crate::db::get_revoked_ssh_certificates(&state.store)
        .await
        .expect("list revoked after");
    assert_eq!(
        revoked.len(),
        1,
        "exactly one cert revoked — the target's; got {}",
        revoked
            .iter()
            .map(|r| r.serial.clone())
            .collect::<Vec<_>>()
            .join(", "),
    );
    assert_eq!(
        revoked[0].user_id, admin1.id,
        "the revoked cert was admin1's"
    );

    // admin1's record is untouched: the `active=false` write never committed,
    // so it stays active/admin and is now the floor's only live admin (admin2
    // was deactivated by the hook).
    let admin1_after = crate::db::get_user_by_id(&state.store, &admin1.id)
        .await
        .expect("fetch admin1 after")
        .expect("admin1 record still exists");
    assert!(
        admin1_after.active,
        "admin1 still active — the persist was refused"
    );
    assert!(admin1_after.is_org_admin, "admin1 still admin");
    assert!(
        crate::db::is_last_active_org_admin(&state.store, &admin1.id)
            .await
            .expect("rerun floor"),
        "admin1 is the last active admin after admin2 was demoted by the hook",
    );

    // The fix: a `scim_operation` update audit event records the committed
    // revocation, tying it to the issuing SCIM token. The payload mirrors the
    // generic arm's `accessRevoked`/`persisted` shape but carries
    // `refusal: "last_admin"` to distinguish a floor refusal from a write that
    // was attempted and failed. `refusal` is nested inside the `details` JSON
    // string, so parse the event and its details rather than substring-match.
    let events = state
        .audit
        .query_events(&crate::db::AuditEventFilter {
            event_types: Some(vec!["scim_operation".to_string()]),
            ..crate::db::AuditEventFilter::default()
        })
        .await
        .expect("query audit events");
    let update_events: Vec<_> = events
        .iter()
        .filter(|e| e.data.contains("\"update\"") && e.data.contains(&admin1.id))
        .collect();
    assert!(
        !update_events.is_empty(),
        "SCIM PATCH in-tx LastAdmin: a committed revocation must record a \
         `scim_operation` update audit event; got {}",
        events
            .iter()
            .map(|e| e.data.as_str())
            .collect::<Vec<_>>()
            .join(", "),
    );

    // `actor_token_id` is the token record's id, recoverable by hashing the
    // bearer the same way `authenticate_scim` does — proving the row ties the
    // revocation to the specific SCIM token that issued the operation.
    let token_hash = {
        use aws_lc_rs::digest::{self, SHA256};
        hex::encode(digest::digest(&SHA256, token.as_bytes()))
    };
    let token_record =
        crate::db::get_scim_token_by_hash(&state.store, &token_hash, jiff::Timestamp::now())
            .await
            .expect("look up token record")
            .expect("token record exists");

    let refusal_event = update_events
        .iter()
        .find_map(|e| {
            let v = serde_json::from_str::<serde_json::Value>(&e.data).ok()?;
            (v.get("refusal")?.as_str()? == "last_admin").then_some(v)
        })
        .expect("the update audit event for a LastAdmin refusal carries `refusal: \"last_admin\"`");
    assert_eq!(refusal_event["operation"], "update");
    assert_eq!(refusal_event["resource_type"], "User");
    assert_eq!(refusal_event["resource_id"], admin1.id);
    assert_eq!(
        refusal_event["actor_token_id"].as_str(),
        Some(token_record.id.as_str()),
        "the audit row ties the revocation to the issuing SCIM token",
    );
    let details: serde_json::Value =
        serde_json::from_str(refusal_event["details"].as_str().expect("details string"))
            .expect("details is JSON");
    assert_eq!(details["active"].as_bool(), Some(false));
    assert_eq!(details["deactivated"].as_bool(), Some(true));
    assert_eq!(details["accessRevoked"].as_bool(), Some(true));
    assert_eq!(details["persisted"].as_bool(), Some(false));
    assert!(
        details.get("refusal").is_none(),
        "the refusal is recorded top-level, not inside details: {details}",
    );
}

/// Records a `scim_operation` audit row when the in-transaction `LastAdmin`
/// guard refuses a DELETE *after* the handler's `revoke_user_access` already
/// committed the target's session deletions and SSH-cert revocations. The row
/// carries `auth.token_id`.
#[expect(
    clippy::too_many_lines,
    reason = "end-to-end race regression: stand up two admins, drive the in-tx floor, assert revocation + audit"
)]
#[tokio::test]
async fn test_scim_delete_user_audits_when_in_tx_last_admin_refuses_after_revocation() {
    use crate::db::documents::session::SessionDoc;
    use crate::db::documents::user::UserDoc;
    use std::sync::{Arc, Mutex};

    let target_slot: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let sibling_slot: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let t = Arc::clone(&target_slot);
    let s = Arc::clone(&sibling_slot);
    let (app, state) = test_app_with_modify_hook(move |store| {
        let writer = store.clone();
        store.set_delete_test_hook(Arc::new(move |user_id: &str| {
            let writer = writer.clone();
            let user_id = user_id.to_string();
            let t = Arc::clone(&t);
            let s = Arc::clone(&s);
            Box::pin(async move {
                let is_target = t.lock().expect("target lock").as_deref() == Some(user_id.as_str());
                if !is_target {
                    return;
                }
                let sibling = s.lock().expect("sibling lock").clone();
                if let Some(sibling_id) = sibling {
                    writer
                        .modify::<UserDoc, _>(&sibling_id, |d| d.active = false)
                        .await
                        .expect("deactivate sibling admin from hook");
                }
            })
        }));
    })
    .await;

    let (admin1, _admin1_session_token) = create_test_org_admin(&state).await;
    let org_id = admin1
        .org_id
        .as_deref()
        .expect("admin1 has org")
        .to_string();
    let admin2 = create_test_user_in_org(&state.store, "admin2@example.com", &org_id, true).await;
    let admin2_auth_id = create_test_authenticator(&state.store, &admin2.id).await;
    let _admin2_session_token = create_test_session_with(
        &state,
        TestSessionSpec {
            user_id: &admin2.id,
            email: &admin2.email,
            auth_id: Some(&admin2_auth_id),
            ..Default::default()
        },
    )
    .await;

    let expires_at = jiff::Timestamp::now()
        .checked_add(jiff::Span::new().hours(8))
        .expect("future timestamp");
    crate::db::record_ssh_certificate_issuance(
        &state.store,
        42_010_040,
        &admin1.id,
        &admin1.email,
        &["user".to_string()],
        expires_at,
    )
    .await
    .expect("record admin1 issuance");
    crate::db::record_ssh_certificate_issuance(
        &state.store,
        42_010_041,
        &admin2.id,
        &admin2.email,
        &["user".to_string()],
        expires_at,
    )
    .await
    .expect("record admin2 issuance");

    let token = create_test_org_token_with_scope(
        &state.store,
        "attacker",
        &org_id,
        crate::db::ScimScopeSet::from_scopes(vec![crate::db::ScimScope::UsersWrite]),
    )
    .await;
    let auth_header = format!("Bearer {token}");

    // Sanity: the advisory pre-check passes for admin1 (2 active admins),
    // admin1 has a live session, and no cert is revoked yet.
    assert!(
        !crate::db::is_last_active_org_admin(&state.store, &admin1.id)
            .await
            .expect("count admins for admin1"),
        "setup: admin1 has a second active admin",
    );
    let session_count_before = state
        .store
        .count::<SessionDoc>("user_id", &admin1.id)
        .await
        .expect("count admin1 sessions");
    assert!(session_count_before >= 1, "setup: admin1 has a session");
    assert!(
        crate::db::get_revoked_ssh_certificates(&state.store)
            .await
            .expect("list revoked")
            .is_empty(),
        "setup: no SSH revocations yet",
    );

    // Arm the hook: when `delete_user(admin1)` runs (after the handler's
    // `revoke_user_access` has committed), deactivate admin2 so the
    // in-transaction count sees zero other active admins.
    *target_slot.lock().expect("target lock") = Some(admin1.id.clone());
    *sibling_slot.lock().expect("sibling lock") = Some(admin2.id.clone());

    // DELETE admin1. The pre-check passes (2 admins); the handler commits
    // revocation, then `delete_user` counts 0 other active admins (admin2
    // deactivated by the hook) and the floor refuses with `LastAdmin`.
    let (status, body) = http_delete(
        &app,
        &format!("/scim/v2/Users/{}", admin1.id),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "in-tx LastAdmin refusal must be a 400: got {status}: {body}",
    );
    let error: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    assert_eq!(error["status"], "400");
    assert!(
        error["detail"].as_str().is_some_and(
            |d| d.contains("Cannot delete the organization's only remaining active admin")
        ),
        "SCIM delete refusal detail must name the floor: body={body}",
    );

    // Revocation committed before the floor refused: admin1's sessions are
    // gone and its SSH cert is revoked.
    let session_count_after = state
        .store
        .count::<SessionDoc>("user_id", &admin1.id)
        .await
        .expect("count admin1 sessions after");
    assert_eq!(
        session_count_after, 0,
        "SCIM delete revocation must delete the target's sessions before the floor refuses",
    );
    let revoked = crate::db::get_revoked_ssh_certificates(&state.store)
        .await
        .expect("list revoked after");
    assert_eq!(
        revoked.len(),
        1,
        "exactly one cert revoked — the target's; got {}",
        revoked
            .iter()
            .map(|r| r.serial.clone())
            .collect::<Vec<_>>()
            .join(", "),
    );
    assert_eq!(
        revoked[0].user_id, admin1.id,
        "the revoked cert was admin1's"
    );

    // admin1's record survives: the delete never committed (the floor returned
    // before the user-row delete and the org-row OCC), so admin1 stays
    // active/admin and is now the floor's only live admin.
    let admin1_after = crate::db::get_user_by_id(&state.store, &admin1.id)
        .await
        .expect("fetch admin1 after")
        .expect("admin1 record still exists");
    assert!(
        admin1_after.active,
        "admin1 still active — the delete was refused"
    );
    assert!(admin1_after.is_org_admin, "admin1 still admin");
    assert!(
        crate::db::is_last_active_org_admin(&state.store, &admin1.id)
            .await
            .expect("rerun floor"),
        "admin1 is the last active admin after admin2 was demoted by the hook",
    );

    // The fix: a `scim_operation` delete audit event records the committed
    // revocation, tying it to the issuing SCIM token. `refusal` is nested
    // inside the `details` JSON string, so parse the event and its details
    // rather than substring-match.
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
        .filter(|e| e.data.contains("\"delete\"") && e.data.contains(&admin1.id))
        .collect();
    assert!(
        !delete_events.is_empty(),
        "SCIM DELETE in-tx LastAdmin: a committed revocation must record a \
         `scim_operation` delete audit event; got {}",
        events
            .iter()
            .map(|e| e.data.as_str())
            .collect::<Vec<_>>()
            .join(", "),
    );

    let token_hash = {
        use aws_lc_rs::digest::{self, SHA256};
        hex::encode(digest::digest(&SHA256, token.as_bytes()))
    };
    let token_record =
        crate::db::get_scim_token_by_hash(&state.store, &token_hash, jiff::Timestamp::now())
            .await
            .expect("look up token record")
            .expect("token record exists");

    let refusal_event = delete_events
        .iter()
        .find_map(|e| {
            let v = serde_json::from_str::<serde_json::Value>(&e.data).ok()?;
            (v.get("refusal")?.as_str()? == "last_admin").then_some(v)
        })
        .expect("the delete audit event for a LastAdmin refusal carries `refusal: \"last_admin\"`");
    assert_eq!(refusal_event["operation"], "delete");
    assert_eq!(refusal_event["resource_type"], "User");
    assert_eq!(refusal_event["resource_id"], admin1.id);
    assert_eq!(
        refusal_event["actor_token_id"].as_str(),
        Some(token_record.id.as_str()),
        "the audit row ties the revocation to the issuing SCIM token",
    );
    let details: serde_json::Value =
        serde_json::from_str(refusal_event["details"].as_str().expect("details string"))
            .expect("details is JSON");
    assert_eq!(details["accessRevoked"].as_bool(), Some(true));
    assert_eq!(details["deleted"].as_bool(), Some(false));
    assert!(
        details.get("refusal").is_none(),
        "the refusal is recorded top-level, not inside details: {details}",
    );
}

// ========================================================================
// RFC 7644 Section 3.5.1 - PUT User Tests
// ========================================================================

const USER_URN: &str = "urn:ietf:params:scim:schemas:core:2.0:User";

/// Creates a user through `POST /scim/v2/Users` and returns its id.
async fn post_user(app: &axum::Router, auth_header: &str, body: serde_json::Value) -> String {
    let (status, body) = http_post_json(
        app,
        "/scim/v2/Users",
        &body.to_string(),
        &[("Authorization", auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let created: serde_json::Value = serde_json::from_str(&body).expect("Valid JSON");
    created["id"].as_str().expect("user id").to_string()
}

/// Sends `PATCH` with `operations` and returns the status and parsed body.
async fn patch_user_ops(
    app: &axum::Router,
    auth_header: &str,
    user_id: &str,
    operations: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let body = serde_json::json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": operations,
    });
    let (status, body) = http_request(
        app,
        "PATCH",
        &format!("/scim/v2/Users/{user_id}"),
        Some(body.to_string()),
        &[
            ("Authorization", auth_header),
            ("Content-Type", "application/scim+json"),
        ],
    )
    .await;
    (status, serde_json::from_str(&body).expect("Valid JSON"))
}

/// Sends `PUT` with `body` and returns the status and parsed body.
async fn put_user_json(
    app: &axum::Router,
    auth_header: &str,
    user_id: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let (status, body) = http_put_json(
        app,
        &format!("/scim/v2/Users/{user_id}"),
        &body.to_string(),
        &[("Authorization", auth_header)],
    )
    .await;
    (status, serde_json::from_str(&body).expect("Valid JSON"))
}

// RFC 7644 §3.5.1: readWrite "Any values provided SHALL replace the existing
// attribute values", and "a successful PUT operation returns a 200 OK
// response code and the entire resource within the response body".
#[tokio::test]
async fn test_rfc7644_put_user_replaces_attributes() {
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-put-user", "test-org").await;
    let auth_header = format!("Bearer {token}");
    let user_id = post_user(
        &app,
        &auth_header,
        serde_json::json!({"schemas": [USER_URN], "userName": "bjensen@test-org.example.com", "externalId": "old", "name": {"formatted": "Old Name"}}),
    )
    .await;

    let (status, body) = put_user_json(
        &app,
        &auth_header,
        &user_id,
        serde_json::json!({
            "schemas": [USER_URN],
            "userName": "bjensen@test-org.example.com",
            "externalId": "bjensen",
            "name": {"givenName": "Barbara", "familyName": "Jensen"},
            "emails": [{"value": "bjensen@test-org.example.com", "type": "work", "primary": true}],
            "active": true,
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["id"], user_id.as_str());
    assert_eq!(body["externalId"], "bjensen");
    assert_eq!(body["name"]["formatted"], "Barbara Jensen");
    assert_eq!(body["userName"], "bjensen@test-org.example.com");

    let (status, fetched) = http_get(
        &app,
        &format!("/scim/v2/Users/{user_id}"),
        &[("Authorization", &auth_header)],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let fetched: serde_json::Value = serde_json::from_str(&fetched).expect("Valid JSON");
    assert_eq!(
        fetched["externalId"], "bjensen",
        "the replacement was stored"
    );
}

// RFC 7644 §3.5.1: omitted readWrite attributes — "The service provider MAY
// assume that any existing values are to be cleared".
#[tokio::test]
async fn test_rfc7644_put_user_clears_omitted_attributes() {
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-put-clear", "test-org").await;
    let auth_header = format!("Bearer {token}");
    let user_id = post_user(
        &app,
        &auth_header,
        serde_json::json!({"schemas": [USER_URN], "userName": "clear@test-org.example.com", "externalId": "ext", "name": {"formatted": "Named"}}),
    )
    .await;

    let (status, body) = put_user_json(
        &app,
        &auth_header,
        &user_id,
        serde_json::json!({"schemas": [USER_URN], "userName": "clear@test-org.example.com"}),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.get("externalId").is_none(), "{body}");
    assert!(body.get("name").is_none(), "{body}");
    assert_eq!(body["active"], true);
}

// RFC 7644 §3.5.1: "HTTP PUT MUST NOT be used to create new resources."
#[tokio::test]
async fn test_rfc7644_put_user_unknown_id_is_404_and_creates_nothing() {
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-put-unknown", "test-org").await;
    let auth_header = format!("Bearer {token}");

    let (status, body) = put_user_json(
        &app,
        &auth_header,
        "00000000-0000-7000-0000-0000000000aa",
        serde_json::json!({"schemas": [USER_URN], "userName": "ghost@test-org.example.com"}),
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    let (_, listed) = http_get(
        &app,
        "/scim/v2/Users?filter=userName%20eq%20%22ghost@test-org.example.com%22",
        &[("Authorization", &auth_header)],
    )
    .await;
    let listed: serde_json::Value = serde_json::from_str(&listed).expect("Valid JSON");
    assert_eq!(listed["totalResults"], 0, "PUT must not create a user");
}

// RFC 7644 §3.5.1: immutable "If one or more values are already set for the
// attribute, the input value(s) MUST match, or HTTP status code 400 SHOULD be
// returned with a "scimType" error code of "mutability"."
#[tokio::test]
async fn test_rfc7644_put_user_immutable_mismatch_is_400_mutability() {
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-put-immutable", "test-org").await;
    let auth_header = format!("Bearer {token}");
    let user_id = post_user(
        &app,
        &auth_header,
        serde_json::json!({"schemas": [USER_URN], "userName": "fixed@test-org.example.com", "externalId": "keep"}),
    )
    .await;

    for body in [
        serde_json::json!({"schemas": [USER_URN], "userName": "renamed@test-org.example.com"}),
        serde_json::json!({"schemas": [USER_URN], "userName": "fixed@test-org.example.com", "emails": [{"value": "other@test-org.example.com"}]}),
        serde_json::json!({"schemas": [USER_URN], "userName": "fixed@test-org.example.com", "emails": []}),
    ] {
        let (status, error) = put_user_json(&app, &auth_header, &user_id, body.clone()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body} -> {error}");
        assert_eq!(error["scimType"], "mutability", "{body}");
    }

    let (_, fetched) = http_get(
        &app,
        &format!("/scim/v2/Users/{user_id}"),
        &[("Authorization", &auth_header)],
    )
    .await;
    let fetched: serde_json::Value = serde_json::from_str(&fetched).expect("Valid JSON");
    assert_eq!(
        fetched["externalId"], "keep",
        "a rejected PUT writes nothing"
    );
}

// RFC 7643 §4.1.1: userName "is case insensitive", so a matching value that
// differs only in case is the same value for the immutable check.
#[tokio::test]
async fn test_put_user_immutable_match_is_case_insensitive() {
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-put-case", "test-org").await;
    let auth_header = format!("Bearer {token}");
    let user_id = post_user(
        &app,
        &auth_header,
        serde_json::json!({"schemas": [USER_URN], "userName": "casey@test-org.example.com"}),
    )
    .await;

    let (status, body) = put_user_json(
        &app,
        &auth_header,
        &user_id,
        serde_json::json!({"schemas": [USER_URN], "userName": "Casey@Test-Org.Example.com", "emails": [{"value": "CASEY@test-org.example.com"}]}),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
}

// RFC 7644 §3.5.1: readOnly "Any values provided SHALL be ignored."
#[tokio::test]
async fn test_rfc7644_put_user_ignores_read_only_attributes() {
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-put-readonly", "test-org").await;
    let auth_header = format!("Bearer {token}");
    let user_id = post_user(
        &app,
        &auth_header,
        serde_json::json!({"schemas": [USER_URN], "userName": "ro@test-org.example.com"}),
    )
    .await;

    let (status, body) = put_user_json(
        &app,
        &auth_header,
        &user_id,
        serde_json::json!({
            "schemas": [USER_URN],
            "id": "00000000-0000-7000-0000-0000000000bb",
            "userName": "ro@test-org.example.com",
            "meta": {"resourceType": "Group", "created": "2000-01-01T00:00:00Z", "location": "https://evil.example.com"},
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["id"], user_id.as_str());
    assert_eq!(body["meta"]["resourceType"], "User");
}

// RFC 7644 §3.5.1: "If an attribute is "required", clients MUST specify the
// attribute in the PUT request"; a body without it "did not conform to the
// request schema", RFC 7644 §3.12 Table 9 `invalidSyntax`.
#[tokio::test]
async fn test_rfc7644_put_user_without_user_name_is_400_invalid_syntax() {
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-put-required", "test-org").await;
    let auth_header = format!("Bearer {token}");
    let user_id = post_user(
        &app,
        &auth_header,
        serde_json::json!({"schemas": [USER_URN], "userName": "req@test-org.example.com"}),
    )
    .await;

    let (status, error) = put_user_json(
        &app,
        &auth_header,
        &user_id,
        serde_json::json!({"schemas": [USER_URN], "active": true}),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{error}");
    assert_eq!(error["scimType"], "invalidSyntax");
}

#[tokio::test]
async fn test_put_user_deactivation_revokes_access() {
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-put-deactivate", "test-org").await;
    let auth_header = format!("Bearer {token}");
    let user_id = post_user(
        &app,
        &auth_header,
        serde_json::json!({"schemas": [USER_URN], "userName": "leaver@test-org.example.com"}),
    )
    .await;
    let expires_at = jiff::Timestamp::now()
        .checked_add(jiff::Span::new().hours(8))
        .expect("future timestamp");
    crate::db::record_ssh_certificate_issuance(
        &state.store,
        42_000_411,
        &user_id,
        "leaver@test-org.example.com",
        &["user".to_string()],
        expires_at,
    )
    .await
    .expect("record issuance");

    let (status, body) = put_user_json(
        &app,
        &auth_header,
        &user_id,
        serde_json::json!({"schemas": [USER_URN], "userName": "leaver@test-org.example.com", "active": false}),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["active"], false);
    let revoked = crate::db::get_revoked_ssh_certificates(&state.store)
        .await
        .expect("list revoked");
    assert_eq!(revoked.len(), 1, "a deactivating PUT revokes like PATCH");
}

#[tokio::test]
async fn test_put_user_omitting_active_defaults_to_true() {
    // RFC 7644 §3.5.1 lets an omitted readWrite attribute take a default;
    // `active` takes `true`, the default create applies.
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-put-default", "test-org").await;
    let auth_header = format!("Bearer {token}");
    let user_id = post_user(
        &app,
        &auth_header,
        serde_json::json!({"schemas": [USER_URN], "userName": "returning@test-org.example.com", "active": false}),
    )
    .await;

    let (status, body) = put_user_json(
        &app,
        &auth_header,
        &user_id,
        serde_json::json!({"schemas": [USER_URN], "userName": "returning@test-org.example.com"}),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["active"], true);
}

#[tokio::test]
async fn test_put_user_refuses_to_deactivate_the_last_active_admin() {
    use crate::db::documents::session::SessionDoc;

    let (app, state) = test_app().await;
    let (admin, _session) = create_test_org_admin(&state).await;
    let token = create_test_org_token_with_scope(
        &state.store,
        "put-last-admin",
        admin.org_id.as_deref().expect("admin has org"),
        crate::db::ScimScopeSet::from_scopes(vec![crate::db::ScimScope::UsersWrite]),
    )
    .await;
    let auth_header = format!("Bearer {token}");
    let sessions_before = state
        .store
        .count::<SessionDoc>("user_id", &admin.id)
        .await
        .expect("count sessions");

    let (status, error) = put_user_json(
        &app,
        &auth_header,
        &admin.id,
        serde_json::json!({"schemas": [USER_URN], "userName": admin.email, "active": false}),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{error}");
    assert_eq!(error["scimType"], "mutability");
    let sessions_after = state
        .store
        .count::<SessionDoc>("user_id", &admin.id)
        .await
        .expect("count sessions");
    assert_eq!(sessions_after, sessions_before, "refused before revoking");
}

#[tokio::test]
async fn test_put_user_requires_users_write_scope() {
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-put-scope", "test-org").await;
    let auth_header = format!("Bearer {token}");
    let user_id = post_user(
        &app,
        &auth_header,
        serde_json::json!({"schemas": [USER_URN], "userName": "scoped@test-org.example.com"}),
    )
    .await;
    let read_only = create_test_org_token_with_scope(
        &state.store,
        "read-only",
        "test-org",
        crate::db::ScimScopeSet::from_scopes(vec![crate::db::ScimScope::UsersRead]),
    )
    .await;

    let (status, _) = put_user_json(
        &app,
        &format!("Bearer {read_only}"),
        &user_id,
        serde_json::json!({"schemas": [USER_URN], "userName": "scoped@test-org.example.com"}),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}

// RFC 7644 §3.5.2: "a client MUST NOT modify an attribute that has mutability
// "readOnly" or "immutable"", and "An operation that is not compatible with an
// attribute's mutability or schema SHALL return the appropriate HTTP response
// status code and a JSON detail error response".
#[tokio::test]
async fn test_rfc7644_patch_user_immutable_attributes_reject_changes() {
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-patch-immutable", "test-org").await;
    let auth_header = format!("Bearer {token}");
    let user_id = post_user(
        &app,
        &auth_header,
        serde_json::json!({"schemas": [USER_URN], "userName": "stay@test-org.example.com", "externalId": "keep"}),
    )
    .await;

    for operations in [
        serde_json::json!([{"op": "replace", "path": "userName", "value": "moved@test-org.example.com"}]),
        serde_json::json!([{"op": "replace", "value": {"userName": "moved@test-org.example.com"}}]),
        serde_json::json!([{"op": "replace", "path": "emails[type eq \"work\"].value", "value": "moved@test-org.example.com"}]),
        serde_json::json!([{"op": "add", "path": "emails", "value": [{"value": "second@test-org.example.com"}]}]),
        serde_json::json!([{"op": "replace", "path": "emails", "value": []}]),
        serde_json::json!([{"op": "remove", "path": "emails"}]),
        serde_json::json!([{"op": "remove", "path": "userName"}]),
        // A rejected operation fails the request after an accepted one, and
        // the accepted one is not written.
        serde_json::json!([
            {"op": "replace", "path": "externalId", "value": "changed"},
            {"op": "replace", "path": "userName", "value": "moved@test-org.example.com"}
        ]),
    ] {
        let (status, error) =
            patch_user_ops(&app, &auth_header, &user_id, operations.clone()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{operations} -> {error}");
        assert_eq!(error["scimType"], "mutability", "{operations}");
    }

    let (_, fetched) = http_get(
        &app,
        &format!("/scim/v2/Users/{user_id}"),
        &[("Authorization", &auth_header)],
    )
    .await;
    let fetched: serde_json::Value = serde_json::from_str(&fetched).expect("Valid JSON");
    assert_eq!(fetched["userName"], "stay@test-org.example.com");
    assert_eq!(fetched["externalId"], "keep");
}

#[tokio::test]
async fn test_patch_user_immutable_attributes_accept_the_stored_value() {
    // Entra sends `emails[type eq "work"].value` and `userName` with the
    // unchanged address on ordinary syncs; those change nothing and succeed.
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-patch-same", "test-org").await;
    let auth_header = format!("Bearer {token}");
    let user_id = post_user(
        &app,
        &auth_header,
        serde_json::json!({"schemas": [USER_URN], "userName": "same@test-org.example.com"}),
    )
    .await;

    let (status, body) = patch_user_ops(
        &app,
        &auth_header,
        &user_id,
        serde_json::json!([
            {"op": "replace", "path": "userName", "value": "SAME@test-org.example.com"},
            {"op": "replace", "path": "emails[type eq \"work\"].value", "value": "same@test-org.example.com"},
            {"op": "add", "path": "emails", "value": [{"value": "same@test-org.example.com", "type": "work", "primary": true}]},
            {"op": "replace", "path": "externalId", "value": "synced"}
        ]),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["externalId"], "synced");
}

// A path-qualified `add` of an empty `emails` array is a documented no-op
// (RFC 7644 §3.5.2.1: "a PATCH `add` of nothing changes nothing"). A pathless
// aggregate `add` carrying `emails: []` is the same operation in a different
// wire form and MUST agree — it is a no-op (200 OK), not a `mutability`
// rejection of an attempted clear of an immutable attribute.
#[tokio::test]
async fn test_rfc7644_patch_user_pathless_add_empty_emails_is_a_noop() {
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-pathless-add-empty", "test-org").await;
    let auth_header = format!("Bearer {token}");
    let user_id = post_user(
        &app,
        &auth_header,
        serde_json::json!({"schemas": [USER_URN], "userName": "add-empty@test-org.example.com", "externalId": "keep"}),
    )
    .await;

    // Baseline: the path-qualified form is a documented no-op → 200 OK.
    let (status, body) = patch_user_ops(
        &app,
        &auth_header,
        &user_id,
        serde_json::json!([{"op": "add", "path": "emails", "value": []}]),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "path-qualified add emails [] is a no-op: {body}"
    );

    // Pathless equivalent: a pathless aggregate `add` of `emails: []` must
    // agree with the path-qualified form — a no-op → 200 OK — and must not
    // reject as a `mutability` clear of an immutable attribute.
    let (status, body) = patch_user_ops(
        &app,
        &auth_header,
        &user_id,
        serde_json::json!([{"op": "add", "value": {"emails": []}}]),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "pathless add {{emails: []}} must be a no-op: {body}"
    );

    let (_, fetched) = http_get(
        &app,
        &format!("/scim/v2/Users/{user_id}"),
        &[("Authorization", &auth_header)],
    )
    .await;
    let fetched: serde_json::Value = serde_json::from_str(&fetched).expect("Valid JSON");
    assert_eq!(fetched["userName"], "add-empty@test-org.example.com");
    assert_eq!(
        fetched["emails"][0]["value"], "add-empty@test-org.example.com",
        "an empty emails add changes nothing"
    );
    assert_eq!(fetched["externalId"], "keep");
}

// A SCIM PATCH operation is atomic: a rejected attribute aborts the whole op,
// so a pathless `add` bundling an empty `emails` (a no-op) with a real
// `externalId` change MUST persist the `externalId` — the empty `emails` add
// must not reject and silently drop the bundled, unrelated attribute write.
#[tokio::test]
async fn test_rfc7644_patch_user_pathless_add_empty_emails_with_other_attr_persists() {
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-pathless-add-bundle", "test-org").await;
    let auth_header = format!("Bearer {token}");
    let user_id = post_user(
        &app,
        &auth_header,
        serde_json::json!({"schemas": [USER_URN], "userName": "bundle@test-org.example.com", "externalId": "keep"}),
    )
    .await;

    let (status, body) = patch_user_ops(
        &app,
        &auth_header,
        &user_id,
        serde_json::json!([{"op": "add", "value": {"emails": [], "externalId": "changed"}}]),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the bundled op must not reject on the empty emails no-op: {body}"
    );
    assert_eq!(body["externalId"], "changed");

    let (_, fetched) = http_get(
        &app,
        &format!("/scim/v2/Users/{user_id}"),
        &[("Authorization", &auth_header)],
    )
    .await;
    let fetched: serde_json::Value = serde_json::from_str(&fetched).expect("Valid JSON");
    assert_eq!(
        fetched["externalId"], "changed",
        "the bundled externalId change persisted"
    );
    assert_eq!(
        fetched["emails"][0]["value"], "bundle@test-org.example.com",
        "the empty emails add changed nothing"
    );
}

// The fix must not loosen `replace`: a pathless `replace` of `emails: []` is a
// clear of an immutable attribute and MUST still reject with `mutability`,
// matching the path-qualified `replace` of an empty array. Bundling it with a
// real `externalId` change must still reject the whole op (atomic) and leave
// the `externalId` unchanged.
#[tokio::test]
async fn test_rfc7644_patch_user_pathless_replace_empty_emails_still_rejects() {
    let (app, state) = test_app().await;
    let token =
        create_test_scim_token(&state.store, "test-pathless-replace-empty", "test-org").await;
    let auth_header = format!("Bearer {token}");
    let user_id = post_user(
        &app,
        &auth_header,
        serde_json::json!({"schemas": [USER_URN], "userName": "replace-empty@test-org.example.com", "externalId": "keep"}),
    )
    .await;

    for operations in [
        serde_json::json!([{"op": "replace", "value": {"emails": []}}]),
        serde_json::json!([{"op": "replace", "value": {"emails": [], "externalId": "changed"}}]),
    ] {
        let (status, error) =
            patch_user_ops(&app, &auth_header, &user_id, operations.clone()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{operations} -> {error}");
        assert_eq!(error["scimType"], "mutability", "{operations}");
    }

    let (_, fetched) = http_get(
        &app,
        &format!("/scim/v2/Users/{user_id}"),
        &[("Authorization", &auth_header)],
    )
    .await;
    let fetched: serde_json::Value = serde_json::from_str(&fetched).expect("Valid JSON");
    assert_eq!(
        fetched["externalId"], "keep",
        "a rejected replace must not persist a bundled externalId change"
    );
}

// RFC 7644 §3.5.2.1: re-adding a value already present "SHALL NOT change the
// modify timestamp of the resource."
#[tokio::test]
async fn test_rfc7644_patch_user_unchanged_value_keeps_last_modified() {
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-noop-user", "test-org").await;
    let auth_header = format!("Bearer {token}");
    let user_id = post_user(
        &app,
        &auth_header,
        serde_json::json!({"schemas": [USER_URN], "userName": "noop@test-org.example.com", "externalId": "same"}),
    )
    .await;
    let (_, before) = http_get(
        &app,
        &format!("/scim/v2/Users/{user_id}"),
        &[("Authorization", &auth_header)],
    )
    .await;
    let before: serde_json::Value = serde_json::from_str(&before).expect("Valid JSON");

    let (status, body) = patch_user_ops(
        &app,
        &auth_header,
        &user_id,
        serde_json::json!([{"op": "add", "path": "externalId", "value": "same"}, {"op": "replace", "path": "active", "value": true}]),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["meta"]["lastModified"], before["meta"]["lastModified"]);
}

// RFC 7644 §3.10: "Clients MAY omit core schema attribute URN prefixes", and
// every facet of the fully encoded name is case insensitive.
#[tokio::test]
async fn test_rfc7644_patch_user_core_urn_qualified_paths() {
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-user-urn", "test-org").await;
    let auth_header = format!("Bearer {token}");
    let user_id = post_user(
        &app,
        &auth_header,
        serde_json::json!({"schemas": [USER_URN], "userName": "urn@test-org.example.com"}),
    )
    .await;

    let (status, body) = patch_user_ops(
        &app,
        &auth_header,
        &user_id,
        serde_json::json!([{"op": "replace", "path": "urn:ietf:params:scim:schemas:core:2.0:User:externalId", "value": "qualified"}]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["externalId"], "qualified");

    let (status, error) = patch_user_ops(
        &app,
        &auth_header,
        &user_id,
        serde_json::json!([{"op": "replace", "path": "URN:IETF:params:scim:schemas:core:2.0:User:emails[type eq \"work\"].value", "value": "other@test-org.example.com"}]),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{error}");
    assert_eq!(error["scimType"], "mutability");
}

// RFC 7644 §3.5.2.2: a pathless remove "fails with HTTP status code 400 and a
// "scimType" error code of "noTarget""; RFC 7644 §3.5.2.1: an add "MUST
// contain a "value" member".
#[tokio::test]
async fn test_rfc7644_patch_user_operation_shape_errors() {
    let (app, state) = test_app().await;
    let token = create_test_scim_token(&state.store, "test-user-shape", "test-org").await;
    let auth_header = format!("Bearer {token}");
    let user_id = post_user(
        &app,
        &auth_header,
        serde_json::json!({"schemas": [USER_URN], "userName": "shape@test-org.example.com"}),
    )
    .await;

    for (operations, scim_type) in [
        (serde_json::json!([{"op": "remove"}]), "noTarget"),
        (
            serde_json::json!([{"op": "add", "path": "externalId"}]),
            "invalidValue",
        ),
        (serde_json::json!([{"op": "replace"}]), "invalidValue"),
    ] {
        let (status, error) =
            patch_user_ops(&app, &auth_header, &user_id, operations.clone()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{operations} -> {error}");
        assert_eq!(error["scimType"], scim_type, "{operations}");
    }
}
