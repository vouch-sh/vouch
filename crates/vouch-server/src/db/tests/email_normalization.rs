// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Email canonicalization across SCIM provisioning and OIDC enrollment.
#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code: panic on assertion failure is acceptable; cast bounds are obvious in test fixtures"
)]

use super::*;

// ========================================================================
// Email case normalization across SCIM and OIDC enrollment
// ========================================================================
//
// Regression for the duplicate-user bug: a user pre-provisioned via SCIM
// with `Alice@example.com` must be found (not duplicated) when the same
// person enrolls via OIDC with `alice@example.com`. Both `create_scim_user`
// and `enroll_user_with_org` now normalize email to ASCII lowercase before
// lookup and storage, matching the existing domain-normalization contract
// documented on `get_or_create_org`.

/// SCIM provisioning with a mixed-case email stores the row with the
/// email lowercased, and a subsequent OIDC enrollment for the same
/// person (with different casing) reuses the existing user row instead
/// of creating a duplicate.
#[tokio::test]
async fn test_enroll_finds_scim_user_with_different_email_casing() {
    use crate::db::{create_scim_user, enroll_user_with_org};

    let (store, _audit) = test_db().await;
    let domain = "case-example.com";

    // Org is required for SCIM token binding and is the one OIDC enrollment
    // will resolve to via the (lowercased) domain.
    let org_id = store
        .insert(&test_org_doc(domain))
        .await
        .expect("org insert")
        .id;

    // 1. SCIM creates a user with a mixed-case email, as an IdP directory
    //    API might return it.
    let scim_user = create_scim_user(
        &store,
        Some(&org_id),
        "Alice@Case-Example.com",
        Some("Alice Smith"),
        None,
        true,
    )
    .await
    .expect("SCIM user creation should succeed");

    // The stored email must be normalized to lowercase so that future
    // case-insensitive lookups match.
    assert_eq!(
        scim_user.email, "alice@case-example.com",
        "SCIM must store the email lowercased"
    );

    // 2. The same person enrolls via OIDC; the IdP returns the email in
    //    a different casing. The domain is lowercased by OIDC callers.
    let oidc_user = enroll_user_with_org(
        &store,
        "ALICE@Case-Example.com",
        Some("Alice Smith"),
        Some(domain),
        None,
    )
    .await
    .expect("OIDC enrollment should succeed");

    // The fix: the existing SCIM user is found — no duplicate user row.
    assert_eq!(
        scim_user.id, oidc_user.id,
        "SCIM and OIDC must resolve to the same user id"
    );
    assert_eq!(
        oidc_user.email, "alice@case-example.com",
        "OIDC enrollment must report the normalized (lowercase) email"
    );
    assert_eq!(
        oidc_user.org_id,
        Some(org_id.clone()),
        "OIDC user must be bound to the same org as the SCIM user"
    );

    // No duplicate user row exists in the store.
    let user_count = store
        .count::<crate::db::documents::user::UserDoc>("email", "alice@case-example.com")
        .await
        .expect("count users by email");
    assert_eq!(
        user_count, 1,
        "exactly one user row must exist for the email; got {user_count}"
    );
}

/// SCIM duplicate-email check is case-insensitive: provisioning
/// `Alice@example.com` after `alice@example.com` must be rejected
/// rather than producing a second row.
#[tokio::test]
async fn test_scim_duplicate_email_rejected_across_case() {
    let (store, _audit) = test_db().await;
    seed_test_org(&store).await;

    // First provisioning with lowercase email succeeds.
    create_scim_user(
        &store,
        Some(TEST_ORG_ID),
        "dup@example.com",
        Some("Original"),
        None,
        true,
    )
    .await
    .expect("first SCIM provisioning should succeed");

    // Second provisioning with the same email in a different case must
    // fail with the UNIQUE error — the application-level uniqueness
    // check uses the normalized (lowercase) email.
    let result = create_scim_user(
        &store,
        Some(TEST_ORG_ID),
        "DUP@example.com",
        Some("Duplicate"),
        None,
        true,
    )
    .await;
    assert!(
        result.is_err(),
        "SCIM provisioning with a different-case duplicate email must be rejected"
    );
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("UNIQUE"),
        "Error message should mention UNIQUE; got: {err}"
    );

    // And no second row was inserted.
    let count = store
        .count::<crate::db::documents::user::UserDoc>("email", "dup@example.com")
        .await
        .expect("count");
    assert_eq!(count, 1, "only one user row should exist; got {count}");
}

/// A user enrolling twice via OIDC with different email casing reuses
/// the same user row (no duplicate, no admin-claim regression).
#[tokio::test]
async fn test_enroll_twice_with_different_email_casing_reuses_user() {
    use crate::db::enroll_user_with_org;

    let (store, _audit) = test_db().await;
    let domain = "twice.example";

    let first = enroll_user_with_org(&store, "Bob@Twice.Example", Some("Bob"), Some(domain), None)
        .await
        .expect("first enrollment");
    assert!(first.is_org_admin, "first enrollee is admin");

    let second = enroll_user_with_org(&store, "bob@twice.example", Some("Bob"), Some(domain), None)
        .await
        .expect("second enrollment");

    assert_eq!(
        first.id, second.id,
        "second enrollment with different casing must reuse the same user"
    );
    assert_eq!(
        second.email, "bob@twice.example",
        "returned email must be normalized"
    );
    assert!(
        second.is_org_admin,
        "returning user must keep their admin status"
    );
}

/// `get_user_by_email` is case-insensitive: looking up a user by an
/// email with different casing than was stored returns the user.
#[tokio::test]
async fn test_get_user_by_email_is_case_insensitive() {
    let (store, _audit) = test_db().await;

    // The test helper canonicalizes to lowercase before storing.
    let (user_id, _) = upsert_user(&store, "Carol@example.com", Some("Carol"))
        .await
        .expect("upsert user");

    // Look up with the same email in a different case.
    let fetched = get_user_by_email(&store, "CAROL@EXAMPLE.COM")
        .await
        .expect("query")
        .expect("user should be found via case-insensitive lookup");
    assert_eq!(fetched.id, user_id);
    assert_eq!(fetched.email, "carol@example.com");
}

// A deactivated account must not re-enter through SSO enrollment: the
// refusal happens inside the transaction, before any identity binding or
// admin-slot side effect. Re-entry is only via SCIM `active: true` or an
// admin reactivating the account.
#[tokio::test]
async fn test_enroll_refuses_deactivated_account() {
    use crate::db::documents::user::UserDoc;
    use crate::db::{
        EnrollUserError, UpstreamLogin, enroll_user_with_org, update_user_active_status,
    };

    let (store, _audit) = test_db().await;
    let domain = "deactivated.example";
    let issuer = "https://idp.deactivated.example";
    let login = UpstreamLogin {
        issuer: issuer.to_string(),
        durable_subject: Some("subject-1".to_string()),
    };

    let enrolled = enroll_user_with_org(
        &store,
        "gone@deactivated.example",
        None,
        Some(domain),
        Some(&login),
    )
    .await
    .expect("initial enrollment");

    update_user_active_status(&store, &enrolled.id, false)
        .await
        .expect("deactivate");

    let result = enroll_user_with_org(
        &store,
        "gone@deactivated.example",
        None,
        Some(domain),
        Some(&login),
    )
    .await;

    match result {
        Err(EnrollUserError::Deactivated { user_id, email }) => {
            assert_eq!(user_id, enrolled.id);
            assert_eq!(email, "gone@deactivated.example");
        }
        other => panic!("expected Deactivated refusal, got {other:?}"),
    }

    let doc = store
        .get::<UserDoc>(&enrolled.id)
        .await
        .expect("get user")
        .expect("user exists");
    assert!(
        !doc.data.active,
        "the refused login must not reactivate the account"
    );
}
