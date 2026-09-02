// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Concurrent-replay and CAS regressions for single-use primitives and state-transition helpers.
#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable; cast bounds are obvious in test fixtures"
)]

use super::occ_modify::create_test_github_installation;
use super::*;
use crate::crypto::webauthn_verify::AuthTime;
use crate::db::DeviceApproval;

// ========================================================================
// Concurrent-replay regression coverage for single-use primitives:
// `tokio::join` two consume calls, assert exactly one wins and the loser
// is AlreadyConsumed. SQLite-only; the underlying OCC patterns are
// race-safe by construction on the other backends as well, but these
// tests guard against accidental regressions in the helper functions
// themselves.
// ========================================================================

#[tokio::test]
async fn test_authorization_code_consume_concurrent() {
    use crate::db::claim::ClaimError;
    let (store, _audit) = test_db().await;

    let expires_at: jiff::Timestamp = "2099-12-31T23:59:59Z".parse().unwrap();
    store_authorization_code(
        &store,
        "race-code-hash",
        "client-race",
        "user-race",
        expires_at,
        None,
    )
    .await
    .expect("seed authorization code");

    let store_a = store.clone();
    let store_b = store.clone();
    let (result_a, result_b) = tokio::join!(
        try_consume_authorization_code(&store_a, "race-code-hash"),
        try_consume_authorization_code(&store_b, "race-code-hash"),
    );

    let a_won = result_a.is_ok();
    let b_won = result_b.is_ok();
    assert!(
        a_won ^ b_won,
        "exactly one auth-code consume must win, got a={a_won}, b={b_won}"
    );
    for r in [result_a, result_b] {
        if let Err(e) = r {
            assert!(
                matches!(e, ClaimError::AlreadyConsumed),
                "loser must be AlreadyConsumed, got: {e:?}"
            );
        }
    }
}

#[tokio::test]
async fn test_device_auth_consume_concurrent() {
    use crate::db::claim::ClaimError;
    let (store, _audit) = test_db().await;

    let expires_at: jiff::Timestamp = "2099-12-31T23:59:59Z".parse().unwrap();
    let device_code_hash = "race-device-hash";
    let id = create_device_auth_request(&store, device_code_hash, "RACE-DC", None, expires_at, 5)
        .await
        .expect("create device auth");
    let (user_id, _) = upsert_user(&store, "race-device@example.com", Some("Test"))
        .await
        .expect("upsert user");
    let auth_id = create_authenticator(
        &store,
        &CreateAuthenticatorParams {
            user_id: &user_id,
            user_email: "race-device@example.com",
            name: "Key",
            credential_id: b"cred-race-device",
            public_key: &[0u8; 32],
            aaguid: None,
            user_handle: None,
            attestation_verified: false,
        },
    )
    .await
    .expect("create authenticator");
    authorize_device_auth(
        &store,
        AuthorizeDeviceAuthParams {
            id: &id,
            user_id: &user_id,
            user_email: "race-device@example.com",
            authenticator_id: &auth_id,
            verification: DeviceApproval::Observed(AuthTime::for_test(
                jiff::Timestamp::now().as_second(),
            )),
        },
    )
    .await
    .expect("authorize");

    let store_a = store.clone();
    let store_b = store.clone();
    let (result_a, result_b) = tokio::join!(
        try_consume_device_auth(&store_a, device_code_hash),
        try_consume_device_auth(&store_b, device_code_hash),
    );

    let a_won = result_a.is_ok();
    let b_won = result_b.is_ok();
    assert!(
        a_won ^ b_won,
        "exactly one device-auth consume must win, got a={a_won}, b={b_won}"
    );
    for r in [result_a, result_b] {
        if let Err(e) = r {
            assert!(
                matches!(e, ClaimError::AlreadyConsumed),
                "loser must be AlreadyConsumed, got: {e:?}"
            );
        }
    }
}

#[tokio::test]
async fn test_dpop_nonce_consume_concurrent() {
    use crate::db::claim::ClaimError;
    let (store, _audit) = test_db().await;

    // Seed a fresh nonce; the function returns the nonce string.
    let nonce = generate_dpop_nonce(&store, 300)
        .await
        .expect("generate_dpop_nonce");

    let store_a = store.clone();
    let store_b = store.clone();
    let nonce_a = nonce.clone();
    let nonce_b = nonce.clone();
    let (result_a, result_b) = tokio::join!(
        async move { validate_and_consume_dpop_nonce(&store_a, &nonce_a).await },
        async move { validate_and_consume_dpop_nonce(&store_b, &nonce_b).await },
    );

    let a_won = result_a.is_ok();
    let b_won = result_b.is_ok();
    assert!(
        a_won ^ b_won,
        "exactly one DPoP-nonce consume must win, got a={a_won}, b={b_won}"
    );
    for r in [result_a, result_b] {
        if let Err(e) = r {
            assert!(
                matches!(e, ClaimError::AlreadyConsumed),
                "loser must be AlreadyConsumed, got: {e:?}"
            );
        }
    }
}

#[tokio::test]
async fn test_pending_oauth_consume_concurrent() {
    use crate::db::claim::ClaimError;
    let (store, _audit) = test_db().await;

    let id = create_pending_oauth_authorization(
        &store,
        CreatePendingOAuthParams {
            client_id: "race-pending-client",
            redirect_uri: "https://example.com/cb",
            response_type: "code",
            state: None,
            scope: Some("openid"),
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            resource: None,
            acr_values: None,
            max_age: None,
            prompt: None,
            dpop_jkt: None,
            authorization_details: None,
            response_mode: Default::default(),
            par_request_uri: None,
        },
    )
    .await
    .expect("create pending_oauth");

    let store_a = store.clone();
    let store_b = store.clone();
    let id_a = id.clone();
    let id_b = id.clone();
    let (result_a, result_b) = tokio::join!(
        async move { consume_pending_oauth_authorization(&store_a, &id_a).await },
        async move { consume_pending_oauth_authorization(&store_b, &id_b).await },
    );

    let a_won = result_a.is_ok();
    let b_won = result_b.is_ok();
    assert!(
        a_won ^ b_won,
        "exactly one pending_oauth consume must win, got a={a_won}, b={b_won}"
    );
    for r in [result_a, result_b] {
        if let Err(e) = r {
            assert!(
                matches!(e, ClaimError::AlreadyConsumed),
                "loser must be AlreadyConsumed, got: {e:?}"
            );
        }
    }
}

// ============================================================================
// Concurrent CAS regression tests for state-transition helpers
// (non-consume helpers that share the same outer-tx + read + compare_and_update
// pattern — included to empirically confirm whether each site exhibits the
// SQLite shared-cache deadlock or not).
// ============================================================================

#[tokio::test]
async fn test_authorize_device_auth_concurrent() {
    let (store, _audit) = test_db().await;

    let expires_at: jiff::Timestamp = "2099-12-31T23:59:59Z".parse().unwrap();
    let device_code_hash = "race-authorize-hash";
    let id = create_device_auth_request(&store, device_code_hash, "RACE-AUTH", None, expires_at, 5)
        .await
        .expect("create device auth");
    let (user_id, _) = upsert_user(&store, "race-authorize@example.com", Some("Test"))
        .await
        .expect("upsert user");
    let auth_id = create_authenticator(
        &store,
        &CreateAuthenticatorParams {
            user_id: &user_id,
            user_email: "race-authorize@example.com",
            name: "Key",
            credential_id: b"cred-race-authorize",
            public_key: &[0u8; 32],
            aaguid: None,
            user_handle: None,
            attestation_verified: false,
        },
    )
    .await
    .expect("create authenticator");

    let store_a = store.clone();
    let store_b = store.clone();
    let id_a = id.clone();
    let id_b = id.clone();
    let uid_a = user_id.clone();
    let uid_b = user_id.clone();
    let aid_a = auth_id.clone();
    let aid_b = auth_id.clone();
    let (result_a, result_b) = tokio::join!(
        async move {
            authorize_device_auth(
                &store_a,
                AuthorizeDeviceAuthParams {
                    id: &id_a,
                    user_id: &uid_a,
                    user_email: "race-authorize@example.com",
                    authenticator_id: &aid_a,
                    verification: DeviceApproval::Observed(AuthTime::for_test(
                        jiff::Timestamp::now().as_second(),
                    )),
                },
            )
            .await
        },
        async move {
            authorize_device_auth(
                &store_b,
                AuthorizeDeviceAuthParams {
                    id: &id_b,
                    user_id: &uid_b,
                    user_email: "race-authorize@example.com",
                    authenticator_id: &aid_b,
                    verification: DeviceApproval::Observed(AuthTime::for_test(
                        jiff::Timestamp::now().as_second(),
                    )),
                },
            )
            .await
        },
    );

    for (label, r) in [("a", &result_a), ("b", &result_b)] {
        if let Err(e) = r {
            let msg = format!("{e:#}");
            assert!(
                !msg.contains("deadlock"),
                "task {label} should not fail with a DB deadlock: {msg}"
            );
        }
    }
    let a_won = result_a.is_ok();
    let b_won = result_b.is_ok();
    assert!(
        a_won ^ b_won,
        "exactly one authorize must win, got a={a_won}, b={b_won}"
    );
}

#[tokio::test]
async fn test_deny_device_auth_concurrent() {
    let (store, _audit) = test_db().await;

    let expires_at: jiff::Timestamp = "2099-12-31T23:59:59Z".parse().unwrap();
    let device_code_hash = "race-deny-hash";
    let id = create_device_auth_request(&store, device_code_hash, "RACE-DENY", None, expires_at, 5)
        .await
        .expect("create device auth");

    let store_a = store.clone();
    let store_b = store.clone();
    let id_a = id.clone();
    let id_b = id.clone();
    let (result_a, result_b) = tokio::join!(
        async move { deny_device_auth(&store_a, &id_a).await },
        async move { deny_device_auth(&store_b, &id_b).await },
    );

    for (label, r) in [("a", &result_a), ("b", &result_b)] {
        if let Err(e) = r {
            let msg = format!("{e:#}");
            assert!(
                !msg.contains("deadlock"),
                "task {label} should not fail with a DB deadlock: {msg}"
            );
        }
    }
    let a_won = result_a.is_ok();
    let b_won = result_b.is_ok();
    assert!(
        a_won ^ b_won,
        "exactly one deny must win, got a={a_won}, b={b_won}"
    );
}

#[tokio::test]
async fn test_remove_additional_domain_concurrent() {
    use crate::db::organizations::{
        add_additional_domain, mark_additional_domain_verified, remove_additional_domain,
    };

    let (store, _audit) = test_db().await;
    let org = create_organization(&store, "race-remove.com", Some("Race Org"), None)
        .await
        .expect("create org");
    let (uid, _) = upsert_user(&store, "race-remove-admin@race-remove.com", Some("Admin"))
        .await
        .expect("upsert admin");
    add_additional_domain(
        &store,
        &org.id,
        "extra-remove.com",
        &uid,
        "race-remove-admin@race-remove.com",
    )
    .await
    .expect("add additional domain");
    mark_additional_domain_verified(&store, &org.id, "extra-remove.com")
        .await
        .expect("verify additional domain");

    let store_a = store.clone();
    let store_b = store.clone();
    let org_a = org.id.clone();
    let org_b = org.id.clone();
    let (result_a, result_b) = tokio::join!(
        async move { remove_additional_domain(&store_a, &org_a, "extra-remove.com").await },
        async move { remove_additional_domain(&store_b, &org_b, "extra-remove.com").await },
    );

    for (label, r) in [("a", &result_a), ("b", &result_b)] {
        if let Err(e) = r {
            let msg = format!("{e:#}");
            assert!(
                !msg.contains("deadlock"),
                "task {label} should not fail with a DB deadlock: {msg}"
            );
        }
    }
    let some_count = [&result_a, &result_b]
        .iter()
        .filter(|r| matches!(r, Ok(Some(_))))
        .count();
    assert!(
        some_count == 1,
        "exactly one remove must return Ok(Some), got a={result_a:?}, b={result_b:?}"
    );
}

#[tokio::test]
async fn test_record_recheck_result_concurrent() {
    use crate::db::organizations::{
        RecheckOutcome, add_additional_domain, mark_additional_domain_verified,
        record_recheck_result,
    };

    let (store, _audit) = test_db().await;
    let org = create_organization(&store, "race-recheck.com", Some("Race Org"), None)
        .await
        .expect("create org");
    let (uid, _) = upsert_user(&store, "race-recheck-admin@race-recheck.com", Some("Admin"))
        .await
        .expect("upsert admin");
    add_additional_domain(
        &store,
        &org.id,
        "extra-recheck.com",
        &uid,
        "race-recheck-admin@race-recheck.com",
    )
    .await
    .expect("add additional domain");
    mark_additional_domain_verified(&store, &org.id, "extra-recheck.com")
        .await
        .expect("verify additional domain");

    let store_a = store.clone();
    let store_b = store.clone();
    let org_a = org.id.clone();
    let org_b = org.id.clone();
    let (result_a, result_b) = tokio::join!(
        async move {
            record_recheck_result(
                &store_a,
                &org_a,
                "extra-recheck.com",
                RecheckOutcome::Success,
            )
            .await
        },
        async move {
            record_recheck_result(
                &store_b,
                &org_b,
                "extra-recheck.com",
                RecheckOutcome::Success,
            )
            .await
        },
    );

    for (label, r) in [("a", &result_a), ("b", &result_b)] {
        if let Err(e) = r {
            let msg = format!("{e:#}");
            assert!(
                !msg.contains("deadlock"),
                "task {label} should not fail with a DB deadlock: {msg}"
            );
        }
    }
    assert!(
        result_a.is_ok() && result_b.is_ok(),
        "both record_recheck_result calls must succeed (CAS loser returns Ok(StillVerified))"
    );
}

// Regression for #389: two enrollments for the same domain must converge
// on a single organization. `enroll_user_with_org` derives a deterministic
// org ID from the domain, so concurrent enrollees collide on the same
// primary key instead of inserting distinct orgs.
//
// This test exercises the "second enrollee converges on first's org"
// property sequentially because multi-step transactions on SQLite WAL
// deadlock under real `tokio::join!` contention; the under-contention
// property is guaranteed by `store.insert_with_id`'s atomic primary-key
// behavior (covered by `test_dpop_jti_concurrent_insert_rejects_duplicates`)
// combined with the deterministic ID.
#[tokio::test]
async fn test_enroll_user_with_org_same_domain_converges_on_one_org() {
    use crate::db::documents::organization::OrganizationDoc;
    use crate::db::enroll_user_with_org;

    let (store, _audit) = test_db().await;
    let domain = "shared-domain.example";

    let alice = enroll_user_with_org(
        &store,
        "alice@shared-domain.example",
        None,
        Some(domain),
        None,
    )
    .await
    .expect("alice enrollment");
    let bob = enroll_user_with_org(
        &store,
        "bob@shared-domain.example",
        None,
        Some(domain),
        None,
    )
    .await
    .expect("bob enrollment");

    assert_eq!(
        alice.org_id, bob.org_id,
        "both enrollees must share the same org_id"
    );
    assert!(alice.org_id.is_some());

    let org_count = store
        .count::<OrganizationDoc>("domain", domain)
        .await
        .expect("count orgs by domain");
    assert_eq!(
        org_count, 1,
        "exactly one organization must exist for the domain; got {org_count}"
    );

    assert!(alice.is_org_admin, "first enrollee should be admin");
    assert!(!bob.is_org_admin, "second enrollee must not be admin");
}

// Enrolling into an existing org that has no admin must promote the
// enrollee to admin — this exercises the `compare_and_update` repair
// path in `enroll_user_with_org`.
#[tokio::test]
async fn test_enroll_promotes_admin_for_org_without_one() {
    use crate::db::documents::organization::OrganizationDoc;
    use crate::db::enroll_user_with_org;

    let (store, _audit) = test_db().await;
    let domain = "orphaned-org.example";

    // Seed an org row with no admin (e.g. previous enrollee crashed
    // mid-flow before Step 4 ran).
    store
        .insert(&test_org_doc(domain))
        .await
        .expect("seed org row");

    let user = enroll_user_with_org(
        &store,
        "rescuer@orphaned-org.example",
        None,
        Some(domain),
        None,
    )
    .await
    .expect("enrollment");

    assert!(
        user.is_org_admin,
        "an org with no admin must promote the next enrollee"
    );

    // The promotion must be persisted on the user doc, not just reported in
    // the return value — authorization reads `UserDoc.is_org_admin`.
    let persisted = store
        .find_one::<crate::db::documents::user::UserDoc>("email", "rescuer@orphaned-org.example")
        .await
        .expect("find enrolled user")
        .expect("enrolled user exists");
    assert!(persisted.data.is_org_admin);

    let org_count = store
        .count::<OrganizationDoc>("domain", domain)
        .await
        .expect("count orgs by domain");
    assert_eq!(
        org_count, 1,
        "no duplicate org may be created when one already exists"
    );
}

// Regression for #742: a user who already belongs to one org must not claim
// a different org's admin slot by enrolling through that org's domain. The
// slot has to stay open for that org's own first enrollee.
#[tokio::test]
async fn test_enroll_cross_org_user_does_not_claim_admin_slot() {
    use crate::db::documents::organization::OrganizationDoc;
    use crate::db::enroll_user_with_org;

    let (store, _audit) = test_db().await;
    let domain_a = "org-a.example";
    let domain_b = "org-b.example";

    // Alice belongs to org A, and is its admin.
    let alice = enroll_user_with_org(&store, "alice@org-a.example", None, Some(domain_a), None)
        .await
        .expect("alice enrollment");
    let org_a = alice.org_id.clone().expect("org a id");
    assert!(alice.is_org_admin, "alice is org A's first enrollee");

    // Alice now enrolls through org B's domain. Her user row keeps org A, so
    // she is not a member of B and must not take B's admin slot.
    let alice_again =
        enroll_user_with_org(&store, "alice@org-a.example", None, Some(domain_b), None)
            .await
            .expect("alice cross-org enrollment");
    assert_eq!(
        alice_again.org_id,
        Some(org_a),
        "enrolling via another domain must not move an existing user's org"
    );

    let org_b_doc = store
        .find_one::<OrganizationDoc>("domain", domain_b)
        .await
        .expect("find org b")
        .expect("org b exists");
    assert_eq!(
        org_b_doc.data.created_by_user_id, None,
        "a non-member must leave org B's admin slot unclaimed"
    );

    // ...and org B's own first enrollee still gets promoted.
    let bob = enroll_user_with_org(&store, "bob@org-b.example", None, Some(domain_b), None)
        .await
        .expect("bob enrollment");
    assert!(
        bob.is_org_admin,
        "org B's first genuine enrollee must still become admin"
    );

    let org_b_doc = store
        .find_one::<OrganizationDoc>("domain", domain_b)
        .await
        .expect("find org b")
        .expect("org b exists");
    assert_eq!(
        org_b_doc.data.created_by_user_id,
        Some(bob.id),
        "org B's admin slot must record its own first enrollee"
    );
}

// A retrying CAS loser must re-derive its admin decision from fresh state:
// with the winner's user row committed and the org's created_by_user_id
// still unset (the state a loser observes when it re-runs after aborting
// on the org-row conflict), the second enrollee must come out non-admin.
#[tokio::test]
async fn test_enroll_second_user_after_winner_commit_is_not_admin() {
    use crate::db::documents::organization::OrganizationDoc;
    use crate::db::enroll_user_with_org;

    let (store, _audit) = test_db().await;
    let domain = "retry-loser.example";

    let winner = enroll_user_with_org(
        &store,
        "winner@retry-loser.example",
        None,
        Some(domain),
        None,
    )
    .await
    .expect("winner enrollment");
    assert!(winner.is_org_admin);

    // Simulate the winner having committed its user row but NOT yet the org
    // admin slot (crash between the two would leave this state; a retrying
    // loser sees it after aborting on the org-row conflict).
    let org_id = winner.org_id.expect("org id");
    let org = store
        .get::<OrganizationDoc>(&org_id)
        .await
        .expect("get org")
        .expect("org exists");
    let mut data = org.data;
    data.created_by_user_id = None;
    store
        .update(&org_id, &data)
        .await
        .expect("clear admin slot");

    let loser = enroll_user_with_org(
        &store,
        "loser@retry-loser.example",
        None,
        Some(domain),
        None,
    )
    .await
    .expect("second enrollment");
    assert!(
        !loser.is_org_admin,
        "an enrollee joining an org that already has users must not become admin"
    );
}

// ========================================================================
// Regression tests for DB concurrency fixes (#537, #545, #543)
// ========================================================================

/// #537 — A concurrent `update_user_github_identity` must NOT revert a
/// demotion performed by a concurrent `update_user_admin_status`.
///
/// Both paths go through `store.modify`, which re-reads the document at
/// write time, so a GitHub-identity update applied after a demotion must
/// preserve `is_org_admin = false` rather than writing back a stale
/// pre-demotion snapshot.
#[tokio::test]
async fn test_user_update_lost_update_race() {
    let (store, _audit) = test_db().await;

    // Create an admin user.
    let (user_id, _) = upsert_user_with_org(
        &store,
        "race@example.com",
        Some("Race User"),
        Some("org-race"),
        true, // starts as admin
    )
    .await
    .expect("upsert admin user");

    // Demote the user — this must win regardless of ordering.
    update_user_admin_status(&store, &user_id, false)
        .await
        .expect("admin status update");

    // Update the GitHub identity. `modify` re-reads the post-demotion doc,
    // so is_org_admin must stay false.
    update_user_github_identity(&store, &user_id, 42, "gh-user", Some("refresh-tok"))
        .await
        .expect("github identity update");

    let user = get_user_by_id(&store, &user_id)
        .await
        .expect("get user")
        .expect("user must exist");

    assert!(
        !user.is_org_admin,
        "demotion must survive a concurrent github identity update"
    );
    assert_eq!(user.github_id, Some(42), "github_id must be set");
    assert_eq!(
        user.github_login.as_deref(),
        Some("gh-user"),
        "github_login must be set"
    );
}

/// #545 — Counter updates must never regress: after setting 50,
/// applying values 1..=49 must leave the counter at 50 (max semantics).
///
/// The sequential descent test verifies the `max(stored, incoming)` logic
/// in `update_authenticator_counter`. A small concurrent burst (4 tasks,
/// well within the 3-retry budget for in-memory SQLite) additionally
/// confirms the optimistic-concurrency path does not regress the counter.
#[tokio::test]
async fn test_update_authenticator_counter_high_concurrency_no_lost_update() {
    let (store, _audit) = test_db().await;

    let (user_id, _) = upsert_user(&store, "counter@example.com", None)
        .await
        .expect("upsert user");

    let auth_id = create_authenticator(
        &store,
        &CreateAuthenticatorParams {
            user_id: &user_id,
            user_email: "counter@example.com",
            name: "Counter Key",
            credential_id: b"cred-counter-race",
            public_key: &[0u8; 32],
            aaguid: None,
            user_handle: None,
            attestation_verified: false,
        },
    )
    .await
    .expect("create authenticator");

    // Part 1 — sequential regression guard.
    // Set the counter to 50, then apply lower values and confirm no regression.
    update_authenticator_counter(&store, &auth_id, 50)
        .await
        .expect("set counter to 50");

    for lower in (1_i32..50).rev() {
        update_authenticator_counter(&store, &auth_id, lower)
            .await
            .expect("apply lower value");
    }

    let auth = get_authenticator_by_id(&store, &auth_id)
        .await
        .expect("get authenticator")
        .expect("authenticator must exist");

    assert_eq!(
        auth.counter, 50,
        "counter must not regress after applying values < 50"
    );

    // Part 2 — concurrent burst (4 tasks, within the 3-retry budget for
    // in-memory SQLite). Each task tries to set a value; the stored result
    // must equal the maximum attempted value.
    let target = 100_i32;
    let handles: Vec<_> = [target, 51, 52, 53]
        .iter()
        .map(|&i| {
            let store = store.clone();
            let auth_id = auth_id.clone();
            tokio::spawn(async move {
                update_authenticator_counter(&store, &auth_id, i)
                    .await
                    .expect("concurrent counter update")
            })
        })
        .collect();

    for h in handles {
        h.await.expect("task must not panic");
    }

    let auth = get_authenticator_by_id(&store, &auth_id)
        .await
        .expect("get authenticator after burst")
        .expect("authenticator must exist");

    assert_eq!(
        auth.counter, target,
        "counter must equal the max value applied in the concurrent burst"
    );
}

/// Deterministic companion to the #545 burst test above (whose contention
/// depends on scheduling): a higher counter written inside the OCC window via
/// the modify test seam must win over the in-flight lower value — the retry
/// re-reads the fresh counter and `max()` keeps it. A blind write would
/// regress the counter to 50.
#[tokio::test]
async fn test_update_authenticator_counter_concurrent_higher_value_wins() {
    use crate::db::documents::authenticator::AuthenticatorDoc;

    let (store, _audit) = test_db().await;
    let (user_id, _) = upsert_user(&store, "counter-seam@example.com", None)
        .await
        .expect("upsert user");
    let auth_id = create_authenticator(
        &store,
        &CreateAuthenticatorParams {
            user_id: &user_id,
            user_email: "counter-seam@example.com",
            name: "Counter Seam Key",
            credential_id: b"cred-counter-seam",
            public_key: &[0u8; 32],
            aaguid: None,
            user_handle: None,
            attestation_verified: false,
        },
    )
    .await
    .expect("create authenticator");

    let writer = store.clone();
    let mut hooked = store.clone();
    hooked.set_modify_test_hook(Arc::new(move |doc_id: &str, attempt: u32| {
        let writer = writer.clone();
        let doc_id = doc_id.to_string();
        Box::pin(async move {
            if attempt != 0 {
                return;
            }
            let doc = writer
                .get::<AuthenticatorDoc>(&doc_id)
                .await
                .expect("hook get")
                .expect("hook doc must exist");
            let mut data = doc.data;
            data.counter = 100;
            writer.update(&doc_id, &data).await.expect("hook update");
        })
    }));

    update_authenticator_counter(&hooked, &auth_id, 50)
        .await
        .expect("counter update must not error");

    let auth = get_authenticator_by_id(&store, &auth_id)
        .await
        .expect("get authenticator")
        .expect("authenticator must exist");
    assert_eq!(
        auth.counter, 100,
        "the concurrent higher counter must survive the retried max()"
    );
}

/// The concurrent suspend/unsuspend test cannot distinguish OCC from a blind
/// write (its own comment says so — both bump the version). This
/// deterministic variant proves the re-read: a sibling-field write
/// (repositories) landing inside the OCC window must survive the suspend
/// that retries over it.
#[tokio::test]
async fn test_suspend_github_installation_preserves_concurrent_sibling_write() {
    use crate::db::documents::github::GitHubInstallationDoc;

    let (store, _audit) = test_db().await;
    let doc_id = create_test_github_installation(&store, 20_005, "org-sibling-preserve").await;

    let writer = store.clone();
    let mut hooked = store.clone();
    hooked.set_modify_test_hook(Arc::new(move |_doc_id: &str, attempt: u32| {
        let writer = writer.clone();
        Box::pin(async move {
            if attempt != 0 {
                return;
            }
            let found =
                update_github_installation_repos(&writer, 20_005, &["hook/repo".to_string()])
                    .await
                    .expect("hook repos update must not error");
            assert!(found, "hook must find the installation");
        })
    }));

    let found = suspend_github_installation(&hooked, 20_005)
        .await
        .expect("suspend must not error");
    assert!(found, "suspend must find the installation");

    let after = store
        .get::<GitHubInstallationDoc>(&doc_id)
        .await
        .expect("get after")
        .expect("must exist");
    assert!(after.data.suspended_at.is_some(), "suspend must land");
    assert_eq!(
        after.data.repositories.as_deref(),
        Some(&["hook/repo".to_string()][..]),
        "the concurrent repositories write must not be clobbered by the suspend"
    );
}

/// Deterministic companion to the #537 sequential test above: an admin
/// demotion landing inside the OCC window (not merely before the call) must
/// survive `update_user_github_identity`'s retry — the doc comment on that
/// function promises exactly this.
#[tokio::test]
async fn test_update_user_github_identity_preserves_concurrent_admin_change() {
    let (store, _audit) = test_db().await;
    let (user_id, _) = upsert_user_with_org(
        &store,
        "seam-race@example.com",
        Some("Seam Race User"),
        Some("org-seam-race"),
        true, // starts as admin
    )
    .await
    .expect("upsert admin user");

    let writer = store.clone();
    let demote_user_id = user_id.clone();
    let mut hooked = store.clone();
    hooked.set_modify_test_hook(Arc::new(move |_doc_id: &str, attempt: u32| {
        let writer = writer.clone();
        let demote_user_id = demote_user_id.clone();
        Box::pin(async move {
            if attempt != 0 {
                return;
            }
            let found = update_user_admin_status(&writer, &demote_user_id, false)
                .await
                .expect("hook demotion must not error");
            assert!(found, "hook must find the user");
        })
    }));

    update_user_github_identity(&hooked, &user_id, 42, "gh-user", None)
        .await
        .expect("github identity update must not error");

    let user = get_user_by_id(&store, &user_id)
        .await
        .expect("get user")
        .expect("user must exist");
    assert!(
        !user.is_org_admin,
        "the demotion inside the OCC window must survive the identity update"
    );
    assert_eq!(user.github_id, Some(42), "github_id must be set");
    assert_eq!(
        user.github_login.as_deref(),
        Some("gh-user"),
        "github_login must be set"
    );
}

/// #543 — Deleting an authenticator must cascade to clear
/// `authenticator_id` on `DeviceAuthRequestDoc`, which requires the
/// `authenticator_id` index to be emitted by `DeviceAuthRequestDoc::index_entries`.
///
/// Note: this index only covers docs written *after* the fix is deployed.
/// Pre-existing device_auth_request rows lack the index entry and will not
/// be cleared on authenticator delete. This is acceptable because
/// device_auth_request docs are short-lived (minutes), so any pre-fix
/// rows will have expired before the fix is deployed in production.
#[tokio::test]
async fn test_delete_authenticator_clears_device_auth_reference() {
    let (store, _audit) = test_db().await;

    // Create user + authenticator.
    let (user_id, _) = upsert_user(&store, "cascade@example.com", None)
        .await
        .expect("upsert user");

    let auth_id = create_authenticator(
        &store,
        &CreateAuthenticatorParams {
            user_id: &user_id,
            user_email: "cascade@example.com",
            name: "Cascade Key",
            credential_id: b"cred-cascade",
            public_key: &[0u8; 32],
            aaguid: None,
            user_handle: None,
            attestation_verified: false,
        },
    )
    .await
    .expect("create authenticator");

    // Create a device_auth_request that references the authenticator.
    let device_code_hash = "cascade_device_code";
    let user_code = "CSCD-1234";
    let request_id = create_device_auth_request(
        &store,
        device_code_hash,
        user_code,
        None,
        "2099-12-31T23:59:59Z".parse().unwrap(),
        5,
    )
    .await
    .expect("create device auth request");

    // Authorize to bind the authenticator_id.
    authorize_device_auth(
        &store,
        AuthorizeDeviceAuthParams {
            id: &request_id,
            user_id: &user_id,
            user_email: "cascade@example.com",
            authenticator_id: &auth_id,
            verification: DeviceApproval::Observed(AuthTime::for_test(
                jiff::Timestamp::now().as_second(),
            )),
        },
    )
    .await
    .expect("authorize device auth");

    // Verify the approval references the authenticator before the cascade.
    let before = get_device_auth_by_id(&store, &request_id)
        .await
        .expect("get device auth")
        .expect("must exist before cascade");
    let approval = match before.state {
        DeviceAuthState::Authorized(approval) => Some(approval),
        _ => None,
    }
    .expect("expected authorized state before cascade");
    assert_eq!(
        approval.authenticator_id, auth_id,
        "approval must reference the authenticator before cascade delete"
    );

    // Delete the authenticator — this triggers the cascade.
    crate::test_utils::remove_test_authenticator(&store, &auth_id).await;

    // The approval's evidence is gone, so the request must read as denied
    // rather than stay redeemable (RFC 8628 §3.5 access_denied).
    let after = get_device_auth_by_id(&store, &request_id)
        .await
        .expect("get device auth")
        .expect("device auth request must still exist after cascade");
    assert!(
        matches!(after.state, DeviceAuthState::Denied),
        "cascade delete must void the approval, got {:?}",
        after.state
    );
}
