// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `meta.created` / `meta.lastModified` timestamp semantics
//! (RFC 7643 §3.1).
#![expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable"
)]

use super::*;

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
    let scim_user =
        crate::handlers::scim::users::db_user_to_scim("https://test.example.com", fetched);
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
