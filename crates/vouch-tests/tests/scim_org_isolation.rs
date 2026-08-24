// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Cross-tenant isolation tests for the SCIM 2.0 endpoints.
//!
//! These prove that a SCIM token scoped to org A cannot read,
//! enumerate, modify, or delete resources owned by org B. Together
//! they are the negative-path evidence the IDOR is closed.

#![expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code: panicking on an assertion failure is the point"
)]

use serde_json::json;
use vouch_tests::TestHarness;

/// Build a two-org SCIM fixture: org A with a user `U_B` provisioned
/// in org B, plus a group `G_B` provisioned in org B.
struct Fixture {
    harness: TestHarness,
    token_a: String,
    token_b: String,
    user_b_id: String,
    user_b_email: String,
    group_b_id: String,
}

async fn fixture() -> Fixture {
    let harness = TestHarness::new().await;

    let org_a = harness
        .create_org("org-a.example.com")
        .await
        .expect("create org a");
    let org_b = harness
        .create_org("org-b.example.com")
        .await
        .expect("create org b");

    let token_a = harness
        .create_scim_token("org A token", &org_a.id)
        .await
        .expect("scim token a");
    let token_b = harness
        .create_scim_token("org B token", &org_b.id)
        .await
        .expect("scim token b");

    let user_b_email = "alice@org-b.example.com".to_string();
    let resp = harness
        .post_json_authenticated(
            "/scim/v2/Users",
            &json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "userName": user_b_email,
                "active": true,
            }),
            &token_b,
        )
        .await
        .expect("create user_b");
    assert_eq!(resp.status, 201);
    let user_b: serde_json::Value = resp.json().expect("user_b json");
    let user_b_id = user_b["id"].as_str().expect("user_b id").to_string();

    let resp = harness
        .post_json_authenticated(
            "/scim/v2/Groups",
            &json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
                "displayName": "Engineers",
            }),
            &token_b,
        )
        .await
        .expect("create group_b");
    assert_eq!(resp.status, 201);
    let group_b: serde_json::Value = resp.json().expect("group_b json");
    let group_b_id = group_b["id"].as_str().expect("group_b id").to_string();

    Fixture {
        harness,
        token_a,
        token_b,
        user_b_id,
        user_b_email,
        group_b_id,
    }
}

#[tokio::test]
async fn cross_tenant_get_user_returns_404() {
    let f = fixture().await;
    let resp = f
        .harness
        .get_authenticated(&format!("/scim/v2/Users/{}", f.user_b_id), &f.token_a)
        .await
        .expect("get user_b from org A");
    assert_eq!(resp.status, 404);
}

#[tokio::test]
async fn cross_tenant_patch_user_returns_404_no_mutation() {
    let f = fixture().await;
    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [
            {"op": "replace", "path": "active", "value": false},
        ],
    });
    let resp = f
        .harness
        .patch_json_authenticated(
            &format!("/scim/v2/Users/{}", f.user_b_id),
            &patch_body,
            &f.token_a,
        )
        .await
        .expect("patch user_b from org A");
    assert_eq!(resp.status, 404);

    // Verify with org B's token that user_b is still active.
    let resp = f
        .harness
        .get_authenticated(&format!("/scim/v2/Users/{}", f.user_b_id), &f.token_b)
        .await
        .expect("re-read user_b from org B");
    assert_eq!(resp.status, 200);
    let body: serde_json::Value = resp.json().expect("user_b json");
    assert_eq!(body["active"], serde_json::Value::Bool(true));
}

#[tokio::test]
async fn cross_tenant_delete_user_returns_404_no_mutation() {
    let f = fixture().await;
    let resp = f
        .harness
        .delete_authenticated(&format!("/scim/v2/Users/{}", f.user_b_id), &f.token_a)
        .await
        .expect("delete user_b from org A");
    assert_eq!(resp.status, 404);

    let resp = f
        .harness
        .get_authenticated(&format!("/scim/v2/Users/{}", f.user_b_id), &f.token_b)
        .await
        .expect("re-read user_b from org B");
    assert_eq!(resp.status, 200);
}

#[tokio::test]
async fn list_users_excludes_other_org() {
    let f = fixture().await;
    let resp = f
        .harness
        .get_authenticated("/scim/v2/Users", &f.token_a)
        .await
        .expect("list users from org A");
    assert_eq!(resp.status, 200);
    let body: serde_json::Value = resp.json().expect("list json");
    let resources = body["Resources"].as_array().expect("Resources array");
    let ids: Vec<&str> = resources.iter().filter_map(|r| r["id"].as_str()).collect();
    assert!(
        !ids.contains(&f.user_b_id.as_str()),
        "Org A's list should not contain org B's user; got {ids:?}"
    );
}

#[tokio::test]
async fn filter_username_other_org_returns_empty() {
    let f = fixture().await;
    // The email is fixed and URL-safe except for `@` (-> %40); inline the
    // encoded form so the test crate doesn't need urlencoding as a dep.
    let encoded_email = f.user_b_email.replace('@', "%40");
    let path = format!("/scim/v2/Users?filter=userName%20eq%20%22{encoded_email}%22");
    let resp = f
        .harness
        .get_authenticated(&path, &f.token_a)
        .await
        .expect("filter from org A");
    assert_eq!(resp.status, 200);
    let body: serde_json::Value = resp.json().expect("filter json");
    assert_eq!(body["totalResults"], serde_json::Value::from(0));
    assert!(
        body["Resources"]
            .as_array()
            .is_some_and(std::vec::Vec::is_empty),
        "filter result must be empty",
    );
}

#[tokio::test]
async fn cross_tenant_get_group_returns_404() {
    let f = fixture().await;
    let resp = f
        .harness
        .get_authenticated(&format!("/scim/v2/Groups/{}", f.group_b_id), &f.token_a)
        .await
        .expect("get group_b from org A");
    assert_eq!(resp.status, 404);
}

#[tokio::test]
async fn cross_tenant_patch_group_returns_404_no_mutation() {
    let f = fixture().await;
    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [
            {"op": "replace", "path": "displayName", "value": "Hijacked"},
        ],
    });
    let resp = f
        .harness
        .patch_json_authenticated(
            &format!("/scim/v2/Groups/{}", f.group_b_id),
            &patch_body,
            &f.token_a,
        )
        .await
        .expect("patch group_b from org A");
    assert_eq!(resp.status, 404);

    let resp = f
        .harness
        .get_authenticated(&format!("/scim/v2/Groups/{}", f.group_b_id), &f.token_b)
        .await
        .expect("re-read group_b from org B");
    assert_eq!(resp.status, 200);
    let body: serde_json::Value = resp.json().expect("group_b json");
    assert_eq!(body["displayName"], serde_json::Value::from("Engineers"));
}

#[tokio::test]
async fn cross_tenant_delete_group_returns_404_no_mutation() {
    let f = fixture().await;
    let resp = f
        .harness
        .delete_authenticated(&format!("/scim/v2/Groups/{}", f.group_b_id), &f.token_a)
        .await
        .expect("delete group_b from org A");
    assert_eq!(resp.status, 404);

    let resp = f
        .harness
        .get_authenticated(&format!("/scim/v2/Groups/{}", f.group_b_id), &f.token_b)
        .await
        .expect("re-read group_b from org B");
    assert_eq!(resp.status, 200);
}

#[tokio::test]
async fn list_groups_excludes_other_org() {
    let f = fixture().await;
    let resp = f
        .harness
        .get_authenticated("/scim/v2/Groups", &f.token_a)
        .await
        .expect("list groups from org A");
    assert_eq!(resp.status, 200);
    let body: serde_json::Value = resp.json().expect("list json");
    let resources = body["Resources"].as_array().expect("Resources array");
    let ids: Vec<&str> = resources.iter().filter_map(|r| r["id"].as_str()).collect();
    assert!(
        !ids.contains(&f.group_b_id.as_str()),
        "Org A's list should not contain org B's group; got {ids:?}"
    );
}
