// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Cross-tenant SCIM org-isolation tests (IDOR regression suite).
//!
//! Each test creates two independent orgs (A and B) with separate SCIM tokens
//! and verifies that token A cannot read, modify, or enumerate org B's
//! resources. These tests are the primary evidence that the IDOR is closed.

use vouch_tests::TestHarness;

// ============================================================================
// Shared setup
// ============================================================================

/// Create org A + token A, org B + token B, and a user in org B.
/// Returns (token_a, token_b, user_b_id).
async fn setup_two_orgs_with_user(harness: &TestHarness) -> (String, String, String) {
    let org_a = harness
        .create_org("org-a.example.com")
        .await
        .expect("create org_a");
    let org_b = harness
        .create_org("org-b.example.com")
        .await
        .expect("create org_b");

    let token_a = harness
        .create_scim_token("Token A", &org_a.id)
        .await
        .expect("create token_a");
    let token_b = harness
        .create_scim_token("Token B", &org_b.id)
        .await
        .expect("create token_b");

    // Create user_b in org_b via SCIM POST using token_b.
    let body = serde_json::json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "user-b@org-b.example.com",
        "active": true
    });
    let resp = harness
        .post_json_authenticated("/scim/v2/Users", &body, &token_b)
        .await
        .expect("create user_b via SCIM");
    assert_eq!(resp.status, 201, "expected 201 creating user_b");
    let created: serde_json::Value = resp.json().expect("parse user_b response");
    let user_b_id = created["id"].as_str().expect("user_b has id").to_string();

    (token_a, token_b, user_b_id)
}

/// Create org A + token A, org B + token B, and a group in org B.
/// Returns (token_a, token_b, group_b_id).
async fn setup_two_orgs_with_group(harness: &TestHarness) -> (String, String, String) {
    let org_a = harness
        .create_org("grp-a.example.com")
        .await
        .expect("create org_a");
    let org_b = harness
        .create_org("grp-b.example.com")
        .await
        .expect("create org_b");

    let token_a = harness
        .create_scim_token("Token A", &org_a.id)
        .await
        .expect("create token_a");
    let token_b = harness
        .create_scim_token("Token B", &org_b.id)
        .await
        .expect("create token_b");

    // Create group_b in org_b via SCIM POST using token_b.
    let body = serde_json::json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Group B"
    });
    let resp = harness
        .post_json_authenticated("/scim/v2/Groups", &body, &token_b)
        .await
        .expect("create group_b via SCIM");
    assert_eq!(resp.status, 201, "expected 201 creating group_b");
    let created: serde_json::Value = resp.json().expect("parse group_b response");
    let group_b_id = created["id"].as_str().expect("group_b has id").to_string();

    (token_a, token_b, group_b_id)
}

// ============================================================================
// User isolation
// ============================================================================

/// GET /scim/v2/Users/{user_b.id} with token_a must return 404.
#[tokio::test]
async fn test_cross_tenant_user_get_returns_404() {
    let harness = TestHarness::new().await;
    let (token_a, _token_b, user_b_id) = setup_two_orgs_with_user(&harness).await;

    let resp = harness
        .get_authenticated(&format!("/scim/v2/Users/{user_b_id}"), &token_a)
        .await
        .expect("GET user_b with token_a");

    assert_eq!(resp.status, 404, "cross-tenant GET user must return 404");
}

/// PATCH /scim/v2/Users/{user_b.id} with token_a must return 404 and leave U_B unchanged.
/// This is the critical deactivation vector: if this returned 200, an attacker
/// could deactivate any user across any tenant.
#[tokio::test]
async fn test_cross_tenant_user_patch_returns_404() {
    let harness = TestHarness::new().await;
    let (token_a, token_b, user_b_id) = setup_two_orgs_with_user(&harness).await;

    let body = serde_json::json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "replace", "path": "active", "value": false}]
    });
    let resp = harness
        .patch_json_authenticated(&format!("/scim/v2/Users/{user_b_id}"), &body, &token_a)
        .await
        .expect("PATCH user_b with token_a");

    assert_eq!(resp.status, 404, "cross-tenant PATCH user must return 404");

    // Confirm no mutation: U_B must still be active from org B's perspective.
    let verify = harness
        .get_authenticated(&format!("/scim/v2/Users/{user_b_id}"), &token_b)
        .await
        .expect("GET user_b with token_b after failed PATCH");
    assert_eq!(verify.status, 200, "org B must still see user_b");
    let verify_body: serde_json::Value = verify.json().expect("parse verify response");
    assert_eq!(
        verify_body["active"], true,
        "user_b must still be active — cross-tenant PATCH must not mutate"
    );
}

/// DELETE /scim/v2/Users/{user_b.id} with token_a must return 404 and leave U_B intact.
#[tokio::test]
async fn test_cross_tenant_user_delete_returns_404() {
    let harness = TestHarness::new().await;
    let (token_a, token_b, user_b_id) = setup_two_orgs_with_user(&harness).await;

    let resp = harness
        .delete_authenticated(&format!("/scim/v2/Users/{user_b_id}"), &token_a)
        .await
        .expect("DELETE user_b with token_a");

    assert_eq!(resp.status, 404, "cross-tenant DELETE user must return 404");

    // Confirm no mutation: U_B must still exist from org B's perspective.
    let verify = harness
        .get_authenticated(&format!("/scim/v2/Users/{user_b_id}"), &token_b)
        .await
        .expect("GET user_b with token_b after failed DELETE");
    assert_eq!(
        verify.status, 200,
        "user_b must still exist — cross-tenant DELETE must not remove the user"
    );
}

/// GET /scim/v2/Users with token_a must not include user_b in the response.
#[tokio::test]
async fn test_list_users_excludes_other_org() {
    let harness = TestHarness::new().await;
    let (token_a, _token_b, user_b_id) = setup_two_orgs_with_user(&harness).await;

    let resp = harness
        .get_authenticated("/scim/v2/Users", &token_a)
        .await
        .expect("list users with token_a");

    assert_eq!(resp.status, 200);
    let body: serde_json::Value = resp.json().expect("parse list response");
    let resources = body["Resources"].as_array().expect("Resources array");
    let ids: Vec<&str> = resources.iter().filter_map(|r| r["id"].as_str()).collect();
    assert!(
        !ids.contains(&user_b_id.as_str()),
        "user_b must not appear in org_a's user list; got ids: {ids:?}"
    );
}

/// GET /scim/v2/Users?filter=userName eq "user_b@..." with token_a must return empty.
#[tokio::test]
async fn test_filter_username_other_org_returns_empty() {
    let harness = TestHarness::new().await;
    let (token_a, _token_b, _user_b_id) = setup_two_orgs_with_user(&harness).await;

    let resp = harness
        .get_authenticated(
            r#"/scim/v2/Users?filter=userName eq "user-b@org-b.example.com""#,
            &token_a,
        )
        .await
        .expect("filter users with token_a");

    assert_eq!(resp.status, 200);
    let body: serde_json::Value = resp.json().expect("parse filter response");
    let total = body["totalResults"].as_u64().unwrap_or(0);
    assert_eq!(total, 0, "filter for org_b user must return totalResults=0");
    let resources = body["Resources"].as_array().map(Vec::len).unwrap_or(0);
    assert_eq!(resources, 0, "Resources array must be empty");
}

// ============================================================================
// Group isolation
// ============================================================================

/// GET /scim/v2/Groups/{group_b.id} with token_a must return 404.
#[tokio::test]
async fn test_cross_tenant_group_get_returns_404() {
    let harness = TestHarness::new().await;
    let (token_a, _token_b, group_b_id) = setup_two_orgs_with_group(&harness).await;

    let resp = harness
        .get_authenticated(&format!("/scim/v2/Groups/{group_b_id}"), &token_a)
        .await
        .expect("GET group_b with token_a");

    assert_eq!(resp.status, 404, "cross-tenant GET group must return 404");
}

/// PATCH /scim/v2/Groups/{group_b.id} with token_a must return 404 and leave G_B unchanged.
#[tokio::test]
async fn test_cross_tenant_group_patch_returns_404() {
    let harness = TestHarness::new().await;
    let (token_a, token_b, group_b_id) = setup_two_orgs_with_group(&harness).await;

    let body = serde_json::json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "replace", "path": "displayName", "value": "Hijacked"}]
    });
    let resp = harness
        .patch_json_authenticated(&format!("/scim/v2/Groups/{group_b_id}"), &body, &token_a)
        .await
        .expect("PATCH group_b with token_a");

    assert_eq!(resp.status, 404, "cross-tenant PATCH group must return 404");

    // Confirm no mutation: G_B must still have its original name from org B's perspective.
    let verify = harness
        .get_authenticated(&format!("/scim/v2/Groups/{group_b_id}"), &token_b)
        .await
        .expect("GET group_b with token_b after failed PATCH");
    assert_eq!(verify.status, 200, "org B must still see group_b");
    let verify_body: serde_json::Value = verify.json().expect("parse verify response");
    assert_eq!(
        verify_body["displayName"], "Group B",
        "group_b displayName must be unchanged — cross-tenant PATCH must not mutate"
    );
}

/// DELETE /scim/v2/Groups/{group_b.id} with token_a must return 404 and leave G_B intact.
#[tokio::test]
async fn test_cross_tenant_group_delete_returns_404() {
    let harness = TestHarness::new().await;
    let (token_a, token_b, group_b_id) = setup_two_orgs_with_group(&harness).await;

    let resp = harness
        .delete_authenticated(&format!("/scim/v2/Groups/{group_b_id}"), &token_a)
        .await
        .expect("DELETE group_b with token_a");

    assert_eq!(
        resp.status, 404,
        "cross-tenant DELETE group must return 404"
    );

    // Confirm no mutation: G_B must still exist from org B's perspective.
    let verify = harness
        .get_authenticated(&format!("/scim/v2/Groups/{group_b_id}"), &token_b)
        .await
        .expect("GET group_b with token_b after failed DELETE");
    assert_eq!(
        verify.status, 200,
        "group_b must still exist — cross-tenant DELETE must not remove the group"
    );
}

/// GET /scim/v2/Groups with token_a must not include group_b in the response.
#[tokio::test]
async fn test_list_groups_excludes_other_org() {
    let harness = TestHarness::new().await;
    let (token_a, _token_b, group_b_id) = setup_two_orgs_with_group(&harness).await;

    let resp = harness
        .get_authenticated("/scim/v2/Groups", &token_a)
        .await
        .expect("list groups with token_a");

    assert_eq!(resp.status, 200);
    let body: serde_json::Value = resp.json().expect("parse list response");
    let resources = body["Resources"].as_array().expect("Resources array");
    let ids: Vec<&str> = resources.iter().filter_map(|r| r["id"].as_str()).collect();
    assert!(
        !ids.contains(&group_b_id.as_str()),
        "group_b must not appear in org_a's group list; got ids: {ids:?}"
    );
}
