// SPDX-License-Identifier: Apache-2.0 OR MIT
//! End-to-end regression for the email-case-sensitivity bug.
//!
//! Bug: a user pre-provisioned via SCIM with `Alice@example.com` was not
//! found during OIDC enrollment with `alice@example.com`, producing a
//! duplicate user row. The fix normalizes email to ASCII lowercase in
//! `enroll_user_with_org`, `create_scim_user`, and `get_user_by_email`.
//!
//! These tests exercise the actual HTTP SCIM `POST /scim/v2/Users`
//! endpoint (the same path Entra/Okta hit) and then call the production
//! `enroll_user_with_org` function the OIDC callback handler invokes —
//! closing the gap between the two protocols at the integration level.

use serde_json::json;
use vouch_server::db::{enroll_user_with_org, get_user_by_email};
use vouch_tests::TestHarness;

/// A user provisioned via the SCIM HTTP endpoint with a mixed-case email
/// must be reused (not duplicated) when the same person enrolls via the
/// OIDC path with a different casing.
#[tokio::test]
async fn scim_provisioned_user_reused_by_oidc_enrollment_across_casing() {
    let harness = TestHarness::new().await;

    let org = harness
        .create_org("e2e-case.example.com")
        .await
        .expect("create org");
    let scim_token = harness
        .create_scim_token("E2E SCIM token", &org.id)
        .await
        .expect("create scim token");

    // 1. IdP/SCIM provisions the user with a mixed-case email.
    let resp = harness
        .post_json_authenticated(
            "/scim/v2/Users",
            &json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "userName": "Alice@E2E-Case.example.com",
                "active": true,
            }),
            &scim_token,
        )
        .await
        .expect("SCIM user creation HTTP call");
    assert_eq!(resp.status, 201, "SCIM user creation should succeed");
    let created: serde_json::Value = resp.json().expect("parse SCIM response");
    let scim_user_id = created["id"]
        .as_str()
        .expect("SCIM response must include user id")
        .to_string();
    // The SCIM endpoint must return the email lowercased.
    assert_eq!(
        created["userName"].as_str(),
        Some("alice@e2e-case.example.com"),
        "SCIM endpoint must store/return the email lowercased"
    );

    // 2. The same person enrolls via OIDC; the IdP returns the email in
    //    different casing. The OIDC callback handler calls
    //    `enroll_user_with_org` exactly like this.
    let oidc_user = enroll_user_with_org(
        &harness.state.store,
        "ALICE@e2e-case.example.com",
        Some("Alice Smith"),
        Some("e2e-case.example.com"),
    )
    .await
    .expect("OIDC enrollment should succeed");

    // The fix: the existing SCIM-provisioned user is found — no duplicate.
    assert_eq!(
        oidc_user.id, scim_user_id,
        "OIDC enrollment must reuse the SCIM-provisioned user id"
    );
    assert_eq!(
        oidc_user.email, "alice@e2e-case.example.com",
        "OIDC enrollment must report the normalized email"
    );
    assert_eq!(
        oidc_user.org_id.as_deref(),
        Some(org.id.as_str()),
        "OIDC user must be bound to the same org as the SCIM user"
    );

    // No duplicate user row: the SCIM list endpoint reports exactly one
    // user for this org (the totalResults field).
    let list_resp = harness
        .get_authenticated("/scim/v2/Users?count=100", &scim_token)
        .await
        .expect("SCIM list users HTTP call");
    assert_eq!(list_resp.status, 200);
    let list: serde_json::Value = list_resp.json().expect("parse SCIM list response");
    assert_eq!(
        list["totalResults"].as_u64(),
        Some(1),
        "exactly one user row must exist for the org; got {list}"
    );
}

/// A second SCIM provisioning with the same email in a different case is
/// rejected by the HTTP endpoint with a 409 and leaves exactly one row.
#[tokio::test]
async fn scim_duplicate_user_rejected_across_email_casing() {
    let harness = TestHarness::new().await;

    let org = harness
        .create_org("e2e-dup.example.com")
        .await
        .expect("create org");
    let scim_token = harness
        .create_scim_token("E2E SCIM token", &org.id)
        .await
        .expect("create scim token");

    let body = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "dup@e2e-dup.example.com",
        "active": true,
    });
    let first = harness
        .post_json_authenticated("/scim/v2/Users", &body, &scim_token)
        .await
        .expect("first SCIM provisioning HTTP call");
    assert_eq!(first.status, 201, "first provisioning should succeed");

    // Second provisioning with the same email in a different case.
    let body_diff_case = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "DUP@e2e-dup.example.com",
        "active": true,
    });
    let second = harness
        .post_json_authenticated("/scim/v2/Users", &body_diff_case, &scim_token)
        .await
        .expect("second SCIM provisioning HTTP call");
    assert_eq!(
        second.status, 409,
        "second provisioning with a different-case duplicate email must be rejected with 409"
    );

    // Exactly one row exists (totalResults == 1).
    let list_resp = harness
        .get_authenticated("/scim/v2/Users?count=100", &scim_token)
        .await
        .expect("SCIM list users HTTP call");
    assert_eq!(list_resp.status, 200);
    let list: serde_json::Value = list_resp.json().expect("parse SCIM list response");
    assert_eq!(
        list["totalResults"].as_u64(),
        Some(1),
        "only one user row should exist; got {list}"
    );
}

/// `get_user_by_email` (the production read path used by handlers) finds
/// a user provisioned via SCIM when given a different-cased email.
#[tokio::test]
async fn get_user_by_email_finds_scim_user_across_casing() {
    let harness = TestHarness::new().await;

    let org = harness
        .create_org("e2e-get.example.com")
        .await
        .expect("create org");
    let scim_token = harness
        .create_scim_token("E2E SCIM token", &org.id)
        .await
        .expect("create scim token");

    let resp = harness
        .post_json_authenticated(
            "/scim/v2/Users",
            &json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "userName": "Carol@E2E-Get.example.com",
                "active": true,
            }),
            &scim_token,
        )
        .await
        .expect("SCIM user creation HTTP call");
    assert_eq!(resp.status, 201);
    let created: serde_json::Value = resp.json().expect("parse SCIM response");
    let scim_user_id = created["id"].as_str().expect("user id").to_string();

    // Look up with a different casing than what was provisioned.
    let fetched = get_user_by_email(&harness.state.store, "carol@e2e-get.example.com")
        .await
        .expect("get_user_by_email query")
        .expect("user should be found via case-insensitive lookup");
    assert_eq!(fetched.id, scim_user_id);
    assert_eq!(fetched.email, "carol@e2e-get.example.com");
}
