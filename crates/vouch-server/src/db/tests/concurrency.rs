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
use crate::test_utils::test_domain;

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
        try_consume_authorization_code(&store_a, "race-code-hash", jiff::Timestamp::now()),
        try_consume_authorization_code(&store_b, "race-code-hash", jiff::Timestamp::now()),
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
            counter: 0,
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
        async move {
            validate_and_consume_dpop_nonce(&store_a, &nonce_a, &jiff::Timestamp::now()).await
        },
        async move {
            validate_and_consume_dpop_nonce(&store_b, &nonce_b, &jiff::Timestamp::now()).await
        },
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
        async move {
            consume_pending_oauth_authorization(&store_a, &id_a, jiff::Timestamp::now()).await
        },
        async move {
            consume_pending_oauth_authorization(&store_b, &id_b, jiff::Timestamp::now()).await
        },
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
            counter: 0,
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
    let cache_a = SessionCache::new(100, 30);
    let cache_b = SessionCache::new(100, 30);
    let (result_a, result_b) = tokio::join!(
        async move { remove_additional_domain(&store_a, &cache_a, &org_a, "extra-remove.com").await },
        async move { remove_additional_domain(&store_b, &cache_b, &org_b, "extra-remove.com").await },
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
    let domain = test_domain("shared-domain.example.com");

    let alice = enroll_user_with_org(
        &store,
        "alice@shared-domain.example.com",
        None,
        Some(&domain),
        None,
    )
    .await
    .expect("alice enrollment");
    let bob = enroll_user_with_org(
        &store,
        "bob@shared-domain.example.com",
        None,
        Some(&domain),
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
        .count::<OrganizationDoc>("domain", domain.as_str())
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
    let domain = test_domain("orphaned-org.example.com");

    // Seed an org row with no admin (e.g. previous enrollee crashed
    // mid-flow before Step 4 ran).
    store
        .insert(&test_org_doc(domain.as_str()))
        .await
        .expect("seed org row");

    let user = enroll_user_with_org(
        &store,
        "rescuer@orphaned-org.example.com",
        None,
        Some(&domain),
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
        .find_one::<crate::db::documents::user::UserDoc>(
            "email",
            "rescuer@orphaned-org.example.com",
        )
        .await
        .expect("find enrolled user")
        .expect("enrolled user exists");
    assert!(persisted.data.is_org_admin);

    let org_count = store
        .count::<OrganizationDoc>("domain", domain.as_str())
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
    let domain_a = test_domain("org-a.example.com");
    let domain_b = test_domain("org-b.example.com");

    // Alice belongs to org A, and is its admin.
    let alice = enroll_user_with_org(
        &store,
        "alice@org-a.example.com",
        None,
        Some(&domain_a),
        None,
    )
    .await
    .expect("alice enrollment");
    let org_a = alice.org_id.clone().expect("org a id");
    assert!(alice.is_org_admin, "alice is org A's first enrollee");

    // Alice now enrolls through org B's domain. Her user row keeps org A, so
    // she is not a member of B and must not take B's admin slot.
    let alice_again = enroll_user_with_org(
        &store,
        "alice@org-a.example.com",
        None,
        Some(&domain_b),
        None,
    )
    .await
    .expect("alice cross-org enrollment");
    assert_eq!(
        alice_again.org_id,
        Some(org_a),
        "enrolling via another domain must not move an existing user's org"
    );

    let org_b_doc = store
        .find_one::<OrganizationDoc>("domain", domain_b.as_str())
        .await
        .expect("find org b")
        .expect("org b exists");
    assert_eq!(
        org_b_doc.data.created_by_user_id, None,
        "a non-member must leave org B's admin slot unclaimed"
    );

    // ...and org B's own first enrollee still gets promoted.
    let bob = enroll_user_with_org(&store, "bob@org-b.example.com", None, Some(&domain_b), None)
        .await
        .expect("bob enrollment");
    assert!(
        bob.is_org_admin,
        "org B's first genuine enrollee must still become admin"
    );

    let org_b_doc = store
        .find_one::<OrganizationDoc>("domain", domain_b.as_str())
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
    let domain = test_domain("retry-loser.example.com");

    let winner = enroll_user_with_org(
        &store,
        "winner@retry-loser.example.com",
        None,
        Some(&domain),
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
        "loser@retry-loser.example.com",
        None,
        Some(&domain),
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
            counter: 0,
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
            counter: 0,
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
            counter: 0,
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

// ============================================================================
// Poll-vs-transition OCC window.
//
// `update_device_auth_poll_time` rewrites the full row through
// `compare_and_update`, bumping the OCC version even though it only changes
// `last_poll_at`. When that bump lands inside a state transition's
// read-to-CAS window, the transition's stale CAS loses. `authorize_device_auth`,
// `deny_device_auth`, and `try_consume_device_auth` all run through
// `DocumentStore::transition`, which re-reads, re-checks the precondition,
// and re-CASes on that mismatch, so a valid approval or redemption no longer
// spuriously fails. The `modify_test_hook` fires inside that window.
// ============================================================================

/// Deterministic proof that `authorize_device_auth` overcomes a poll-induced
/// version bump. A device-code poll is injected into the read-to-CAS window
/// on attempt 0 (forcing the stale CAS to lose), then the transition
/// re-reads the bumped row and succeeds on attempt 1 — the same outcome the
/// probabilistic poll-vs-authorize race must always produce now. The
/// `Pending` precondition is re-checked on every attempt, so an authorize
/// that re-reads a non-Pending row is still rejected (verified for two real
/// concurrent authorizes by `test_authorize_device_auth_concurrent`).
#[tokio::test]
async fn test_authorize_retries_over_concurrent_poll_version_bump() {
    use std::sync::atomic::{AtomicU32, Ordering};

    let (store, _audit) = test_db().await;
    let expires_at: jiff::Timestamp = "2099-12-31T23:59:59Z".parse().unwrap();
    let id = create_device_auth_request(
        &store,
        "retry-poll-auth-hash",
        "RETRY-AUTH",
        None,
        expires_at,
        5,
    )
    .await
    .expect("create device auth");
    let (user_id, _) = upsert_user(&store, "retry-poll@example.com", Some("Test"))
        .await
        .expect("upsert user");
    let auth_id = create_authenticator(
        &store,
        &CreateAuthenticatorParams {
            user_id: &user_id,
            user_email: "retry-poll@example.com",
            name: "Key",
            credential_id: b"cred-retry-poll",
            public_key: &[0u8; 32],
            aaguid: None,
            user_handle: None,
            attestation_verified: false,
            counter: 0,
        },
    )
    .await
    .expect("create authenticator");

    // The racing poll runs through a hookless clone so its own
    // compare_and_update does not re-enter the hook.
    let writer = store.clone();
    let poll_id = id.clone();
    let first_attempt_polls = Arc::new(AtomicU32::new(0));
    let counted = first_attempt_polls.clone();
    let mut hooked = store.clone();
    hooked.set_modify_test_hook(Arc::new(move |doc_id: &str, attempt: u32| {
        let writer = writer.clone();
        let poll_id = poll_id.clone();
        let counted = counted.clone();
        let is_target = doc_id == poll_id;
        Box::pin(async move {
            if attempt != 0 || !is_target {
                return;
            }
            counted.fetch_add(1, Ordering::SeqCst);
            let allowed = update_device_auth_poll_time(&writer, &poll_id, 5)
                .await
                .expect("hook poll must not error");
            assert!(allowed, "hook poll must clear the rate-limit gate");
        })
    }));

    authorize_device_auth(
        &hooked,
        AuthorizeDeviceAuthParams {
            id: &id,
            user_id: &user_id,
            user_email: "retry-poll@example.com",
            authenticator_id: &auth_id,
            verification: DeviceApproval::Observed(AuthTime::for_test(
                jiff::Timestamp::now().as_second(),
            )),
        },
    )
    .await
    .expect("authorize must succeed via retry after the poll bumped the version");

    // The poll really happened, proving the CAS legitimately lost attempt 0.
    assert_eq!(
        first_attempt_polls.load(Ordering::SeqCst),
        1,
        "the hook must have run the racing poll exactly once on attempt 0"
    );

    // The retry landed the authorization with the caller's attribution and
    // preserved the poll's sibling-field write.
    let after = get_device_auth_by_id(&store, &id)
        .await
        .expect("get after")
        .expect("device auth must exist");
    let approval = match after.state {
        DeviceAuthState::Authorized(approval) => Some(approval),
        _ => None,
    }
    .expect("authorize must have transitioned the row to Authorized");
    assert_eq!(approval.user_id, user_id);
    assert_eq!(approval.authenticator_id, auth_id);
    assert!(
        after.last_poll_at.is_some(),
        "the racing poll's last_poll_at must survive the retried authorize"
    );

    // End-to-end: the authorized device code is still redeemable.
    let _claim = try_consume_device_auth(&store, "retry-poll-auth-hash")
        .await
        .expect("authorized device code must be consumable after the retried authorize");
}

/// Pins the bounded-retry guarantee: if a concurrent writer bumps the row's
/// OCC version on *every* transition attempt (so every CAS loses), authorize
/// must return `Err` after `MAX_DSQL_RETRIES + 1` attempts — not loop
/// forever. The hook bypasses the poll rate limit by bumping the version
/// through a direct `compare_and_update` (only `last_poll_at` changes, so
/// the row stays `Pending`), which is the worst case the retry bound
/// defends against.
#[tokio::test]
async fn test_authorize_bounded_retries_exhausts_on_persistent_version_bump() {
    use crate::db::documents::device_auth::DeviceAuthRequestDoc;

    let (store, _audit) = test_db().await;
    let expires_at: jiff::Timestamp = "2099-12-31T23:59:59Z".parse().unwrap();
    let id =
        create_device_auth_request(&store, "exhaust-auth-hash", "EXHAUST", None, expires_at, 5)
            .await
            .expect("create device auth");
    let (user_id, _) = upsert_user(&store, "exhaust@example.com", Some("Test"))
        .await
        .expect("upsert user");
    let auth_id = create_authenticator(
        &store,
        &CreateAuthenticatorParams {
            user_id: &user_id,
            user_email: "exhaust@example.com",
            name: "Key",
            credential_id: b"cred-exhaust",
            public_key: &[0u8; 32],
            aaguid: None,
            user_handle: None,
            attestation_verified: false,
            counter: 0,
        },
    )
    .await
    .expect("create authenticator");

    let writer = store.clone();
    let bump_id = id.clone();
    let mut hooked = store.clone();
    hooked.set_modify_test_hook(Arc::new(move |doc_id: &str, _attempt: u32| {
        let writer = writer.clone();
        let bump_id = bump_id.clone();
        let is_target = doc_id == bump_id;
        Box::pin(async move {
            if !is_target {
                return;
            }
            // Unconditionally bump the version on every attempt (bypassing
            // the poll rate limit) so the authorize CAS always loses.
            let doc = writer
                .get::<DeviceAuthRequestDoc>(&bump_id)
                .await
                .expect("hook get")
                .expect("hook doc must exist");
            let mut data = doc.data;
            data.last_poll_at = Some(jiff::Timestamp::now());
            let won = writer
                .compare_and_update(&bump_id, doc.version, &data)
                .await
                .expect("hook cas must not error");
            assert!(won, "hook must win the version bump on every attempt");
        })
    }));

    let result = authorize_device_auth(
        &hooked,
        AuthorizeDeviceAuthParams {
            id: &id,
            user_id: &user_id,
            user_email: "exhaust@example.com",
            authenticator_id: &auth_id,
            verification: DeviceApproval::Observed(AuthTime::for_test(
                jiff::Timestamp::now().as_second(),
            )),
        },
    )
    .await;

    let err = result.expect_err("authorize must error after exhausting retries");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("concurrently modified after"),
        "error must report retry exhaustion, got: {msg}"
    );

    // The row never left Pending despite the repeated CAS losses.
    let after = get_device_auth_by_id(&store, &id)
        .await
        .expect("get after")
        .expect("device auth must exist");
    assert!(
        matches!(after.state, DeviceAuthState::Pending),
        "row must stay Pending after retry exhaustion, got {:?}",
        after.state
    );
}

/// The same poll-induced version bump inside `try_consume_device_auth`'s
/// read-to-CAS window. Before the shared transition, a single-shot CAS loss
/// surfaced as `AlreadyConsumed`, which the token handler treats as a
/// device-code replay — revoking the sessions issued from that code and
/// answering `invalid_grant` — for a code that was still redeemable.
#[tokio::test]
async fn test_consume_retries_over_concurrent_poll_version_bump() {
    use std::sync::atomic::{AtomicU32, Ordering};

    use crate::db::claim::ClaimError;

    let (store, _audit) = test_db().await;
    let expires_at: jiff::Timestamp = "2099-12-31T23:59:59Z".parse().unwrap();
    let device_code_hash = "retry-poll-consume-hash";
    let id =
        create_device_auth_request(&store, device_code_hash, "RETRY-CONS", None, expires_at, 5)
            .await
            .expect("create device auth");
    let (user_id, _) = upsert_user(&store, "retry-consume@example.com", Some("Test"))
        .await
        .expect("upsert user");
    let auth_id = create_authenticator(
        &store,
        &CreateAuthenticatorParams {
            user_id: &user_id,
            user_email: "retry-consume@example.com",
            name: "Key",
            credential_id: b"cred-retry-consume",
            public_key: &[0u8; 32],
            aaguid: None,
            user_handle: None,
            attestation_verified: false,
            counter: 0,
        },
    )
    .await
    .expect("create authenticator");
    authorize_device_auth(
        &store,
        AuthorizeDeviceAuthParams {
            id: &id,
            user_id: &user_id,
            user_email: "retry-consume@example.com",
            authenticator_id: &auth_id,
            verification: DeviceApproval::Observed(AuthTime::for_test(
                jiff::Timestamp::now().as_second(),
            )),
        },
    )
    .await
    .expect("authorize device auth");

    let writer = store.clone();
    let poll_id = id.clone();
    let polls = Arc::new(AtomicU32::new(0));
    let counted = polls.clone();
    let mut hooked = store.clone();
    hooked.set_modify_test_hook(Arc::new(move |doc_id: &str, attempt: u32| {
        let writer = writer.clone();
        let poll_id = poll_id.clone();
        let counted = counted.clone();
        let is_target = doc_id == poll_id;
        Box::pin(async move {
            if attempt != 0 || !is_target {
                return;
            }
            counted.fetch_add(1, Ordering::SeqCst);
            let allowed = update_device_auth_poll_time(&writer, &poll_id, 5)
                .await
                .expect("hook poll must not error");
            assert!(allowed, "hook poll must clear the rate-limit gate");
        })
    }));

    let (approval, _claim) = try_consume_device_auth(&hooked, device_code_hash)
        .await
        .expect("a redeemable code must be consumed despite the racing poll");
    assert_eq!(
        polls.load(Ordering::SeqCst),
        1,
        "the racing poll ran exactly once"
    );
    assert_eq!(approval.user_id, user_id);
    assert_eq!(approval.authenticator_id, auth_id);

    // Consumed exactly once: a second redemption is the real replay case.
    let replay = try_consume_device_auth(&store, device_code_hash).await;
    assert!(
        matches!(replay, Err(ClaimError::AlreadyConsumed)),
        "second consume must be rejected, got {replay:?}"
    );
    let after = get_device_auth_by_id(&store, &id)
        .await
        .expect("get after")
        .expect("device auth must exist");
    assert!(
        matches!(after.state, DeviceAuthState::Consumed { .. }),
        "row must be Consumed, got {:?}",
        after.state
    );
    assert!(
        after.last_poll_at.is_some(),
        "the racing poll's last_poll_at must survive the retried consume"
    );
}

/// Regression: `try_consume_device_auth`'s `transition` closure must re-stamp
/// `now = Timestamp::now()` on every retry attempt. `transition` re-reads and
/// re-evaluates the closure against the fresh row on each OCC retry (backoff
/// ~100/200/400 ms), so a single entry-time `now` is stale on retry: when a
/// benign concurrent version bump (a poll) forces a retry that lands after
/// `expires_at`, a stale `now` would make the `data.expires_at <= now`
/// precondition pass against a row that is already expired in wall-clock —
/// redeeming an expired code and back-dating `consumed_at` to before
/// `expires_at`.
///
/// This test pins the FIXED behavior: the per-attempt re-stamp makes the
/// retry reject an already-expired code with `ClaimError::AlreadyConsumed`,
/// leaves the row `Authorized`, and never stamps `consumed_at`. On the buggy
/// code (entry-time `now` reused on retry) this test fails — the expired code
/// is consumed and `consumed_at` is back-dated before `expires_at`.
#[tokio::test]
async fn test_consume_stale_now_lets_expired_code_be_redeemed() {
    use crate::db::claim::ClaimError;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;

    let (store, _audit) = test_db().await;

    let expires_at = jiff::Timestamp::now()
        .checked_add(jiff::SignedDuration::from_millis(300))
        .unwrap();
    let device_code_hash = "stale-now-hash";
    let id = create_device_auth_request(&store, device_code_hash, "STALE-NOW", None, expires_at, 5)
        .await
        .expect("create device auth");
    let (user_id, _) = upsert_user(&store, "stale@example.com", Some("Test"))
        .await
        .expect("upsert user");
    let auth_id = create_authenticator(
        &store,
        &CreateAuthenticatorParams {
            user_id: &user_id,
            user_email: "stale@example.com",
            name: "Key",
            credential_id: b"cred-stale",
            public_key: &[0u8; 32],
            aaguid: None,
            user_handle: None,
            attestation_verified: false,
            counter: 0,
        },
    )
    .await
    .expect("create authenticator");
    authorize_device_auth(
        &store,
        AuthorizeDeviceAuthParams {
            id: &id,
            user_id: &user_id,
            user_email: "stale@example.com",
            authenticator_id: &auth_id,
            verification: DeviceApproval::Observed(AuthTime::for_test(
                jiff::Timestamp::now().as_second(),
            )),
        },
    )
    .await
    .expect("authorize device auth");

    let writer = store.clone();
    let poll_id = id.clone();
    let polls = Arc::new(AtomicU32::new(0));
    let counted = polls.clone();
    let mut hooked = store.clone();
    hooked.set_modify_test_hook(Arc::new(move |doc_id: &str, attempt: u32| {
        let writer = writer.clone();
        let poll_id = poll_id.clone();
        let counted = counted.clone();
        let is_target = doc_id == poll_id;
        Box::pin(async move {
            if attempt != 0 || !is_target {
                return;
            }
            counted.fetch_add(1, Ordering::SeqCst);
            let allowed = update_device_auth_poll_time(&writer, &poll_id, 5)
                .await
                .expect("hook poll must not error");
            assert!(allowed, "hook poll must clear the rate-limit gate");
        })
    }));

    // Sleep until ~50 ms before expiry: `now` is captured BEFORE expiry
    // (pre-check passes), but the first retry backoff (~100 ms) lands AFTER
    // expiry — the exact window the stale-now bug fires in.
    tokio::time::sleep(Duration::from_millis(250)).await;

    let wall_before = jiff::Timestamp::now();
    let result = try_consume_device_auth(&hooked, device_code_hash).await;
    let wall_after = jiff::Timestamp::now();

    assert!(wall_before < expires_at, "consume started before expiry");
    assert!(wall_after > expires_at, "consume finished after expiry");
    // The racing poll ran exactly once, so attempt 0's CAS legitimately lost
    // and the closure re-ran on attempt 1 against the bumped row — i.e. the
    // retry path was actually exercised.
    assert_eq!(
        polls.load(Ordering::SeqCst),
        1,
        "the racing poll ran exactly once"
    );
    // FIXED behavior: the per-attempt re-stamp makes the retry reject the
    // already-expired code. On the buggy code this would be `Ok(..)` (expired
    // code redeemed).
    assert!(
        matches!(result, Err(ClaimError::AlreadyConsumed)),
        "expired code must NOT be redeemed — stale-now bug must not fire, got {result:?}"
    );

    // The row must remain `Authorized` with no `consumed_at`: nothing was
    // written. On the buggy code the row would be `Consumed` and
    // `consumed_at` would be back-dated before `expires_at`.
    let after = get_device_auth_by_id(&store, &id)
        .await
        .expect("get after")
        .expect("device auth must exist");
    assert!(
        matches!(after.state, DeviceAuthState::Authorized(..)),
        "row must stay Authorized (not Consumed), got {:?}",
        after.state
    );
    assert!(
        after.consumed_at.is_none(),
        "consumed_at must not be stamped on a rejected consume, got {:?}",
        after.consumed_at
    );
    // The racing poll's `last_poll_at` survives the rejected consume.
    assert!(
        after.last_poll_at.is_some(),
        "the racing poll's last_poll_at must survive the rejected consume"
    );

    // A later redemption (well past expiry, no hook) must also be rejected —
    // confirming the row is still redeemable-shaped but the expiry gate now
    // blocks it at the pre-check.
    let replay = try_consume_device_auth(&store, device_code_hash).await;
    assert!(
        matches!(replay, Err(ClaimError::AlreadyConsumed)),
        "post-expiry replay must be rejected, got {replay:?}"
    );
    let final_row = get_device_auth_by_id(&store, &id)
        .await
        .expect("get final")
        .expect("device auth must still exist");
    assert!(
        matches!(final_row.state, DeviceAuthState::Authorized(..)),
        "row must still be Authorized after post-expiry replay, got {:?}",
        final_row.state
    );
    assert!(
        final_row.consumed_at.is_none(),
        "consumed_at must remain unset after post-expiry replay"
    );
}

/// A `Consumed` device-auth row must survive the authenticator-deletion
/// cascade with its `Consumed` status and `user_id` attribution intact —
/// `handlers::device::revoke_sessions_for_device_replay` keys its post-hoc
/// replay-revocation sweep (RFC 6749 §10.5 defense-in-depth) on
/// `DeviceAuthState::Consumed { user_id }`, so corrupting the row back to
/// `Denied` would suppress that sweep on a detected device-code replay.
///
/// `delete_authenticator` detaches rows through `update_by_index`, whose
/// writes are guarded by the version read from the index, so a row a
/// concurrent `try_consume_device_auth` committed `Consumed` is never
/// overwritten with stale `Authorized → Denied` data — the cascade fails
/// with a retryable `VersionConflict` and re-runs against the fresh row.
/// This sequential test pins the helper's `Consumed`-preservation invariant
/// (it does not touch `status` when it is already `Consumed`); the guard
/// itself is pinned at the store level by
/// `store::tests::tx_update_by_index_rejects_row_changed_since_read`.
#[tokio::test]
async fn test_delete_authenticator_preserves_consumed_device_auth_for_replay_revocation() {
    let (store, _audit) = test_db().await;

    let (user_id, _) = upsert_user(&store, "consumed-cascade@example.com", None)
        .await
        .expect("upsert user");
    let auth_id = create_authenticator(
        &store,
        &CreateAuthenticatorParams {
            user_id: &user_id,
            user_email: "consumed-cascade@example.com",
            name: "Cascade Key",
            credential_id: b"cred-consumed-cascade",
            public_key: &[0u8; 32],
            aaguid: None,
            user_handle: None,
            attestation_verified: false,
            counter: 0,
        },
    )
    .await
    .expect("create authenticator");

    let device_code_hash = "consumed_cascade_device_code";
    let request_id = create_device_auth_request(
        &store,
        device_code_hash,
        "CSCD-CONS",
        None,
        "2099-12-31T23:59:59Z".parse().unwrap(),
        5,
    )
    .await
    .expect("create device auth request");
    authorize_device_auth(
        &store,
        AuthorizeDeviceAuthParams {
            id: &request_id,
            user_id: &user_id,
            user_email: "consumed-cascade@example.com",
            authenticator_id: &auth_id,
            verification: DeviceApproval::Observed(AuthTime::for_test(
                jiff::Timestamp::now().as_second(),
            )),
        },
    )
    .await
    .expect("authorize device auth");

    // Consume the device code first — the row is now `Consumed` with the
    // user attribution recorded by the atomic consume (`try_consume_device_auth`
    // is the only path to a `DeviceCodeClaim` witness).
    let (approval, _claim) = try_consume_device_auth(&store, device_code_hash)
        .await
        .expect("consume device auth");
    assert_eq!(
        approval.user_id, user_id,
        "consume must return the recorded user attribution"
    );

    // Delete the authenticator — the cascade must NOT regress the row.
    crate::test_utils::remove_test_authenticator(&store, &auth_id).await;

    let after = get_device_auth_by_id(&store, &request_id)
        .await
        .expect("get device auth")
        .expect("device auth request must still exist after cascade");
    let consumed_uid = match &after.state {
        DeviceAuthState::Consumed { user_id } => user_id.clone(),
        _ => None,
    };
    assert_eq!(
        consumed_uid.as_deref(),
        Some(user_id.as_str()),
        "cascade must not regress a Consumed device-auth row; got state {:?}",
        after.state
    );

    // The cascade must also have detached the row from the deleted
    // authenticator — `find_all` by the old `authenticator_id` no longer
    // reaches it — so a future cascade on a recreated (hypothetical) key id
    // never touches this consumed approval.
    use crate::db::documents::device_auth::DeviceAuthRequestDoc;
    let still_referencing = store
        .find_all::<DeviceAuthRequestDoc>("authenticator_id", &auth_id)
        .await
        .expect("find device-auth by authenticator_id")
        .into_iter()
        .any(|d| d.id == request_id);
    assert!(
        !still_referencing,
        "the cascade must detach the consumed device-auth row from the deleted authenticator"
    );
}

/// #1285 — Two admins demoting each other at the same time must not leave the
/// organization with zero admins.
///
/// Each write lands on a different user document, so per-document optimistic
/// concurrency never sees a conflict; the organization row is what the two
/// transactions are forced to collide on. Whichever ordering the backend
/// picks, the loser re-runs its admin count against the committed state and
/// finds itself removing the last admin.
#[tokio::test]
async fn test_mutual_admin_demote_concurrent() {
    use crate::db::users::{MemberDowngrade, demote_or_deactivate_member, upsert_user_with_org};

    let (store, _audit) = test_db().await;
    let org = create_organization(&store, "mutual-demote.com", Some("Mutual"), None)
        .await
        .expect("create org");
    let (admin_a, _) = upsert_user_with_org(
        &store,
        "a@mutual-demote.com",
        Some("A"),
        Some(&org.id),
        true,
    )
    .await
    .expect("create admin a");
    let (admin_b, _) = upsert_user_with_org(
        &store,
        "b@mutual-demote.com",
        Some("B"),
        Some(&org.id),
        true,
    )
    .await
    .expect("create admin b");

    let (store_a, store_b) = (store.clone(), store.clone());
    let (target_a, target_b) = (admin_b.clone(), admin_a.clone());
    let (result_a, result_b) = tokio::join!(
        async move { demote_or_deactivate_member(&store_a, &target_a, MemberDowngrade::Demote).await },
        async move { demote_or_deactivate_member(&store_b, &target_b, MemberDowngrade::Demote).await },
    );

    for (label, r) in [("a", &result_a), ("b", &result_b)] {
        if let Err(e) = r {
            let msg = format!("{e:#}");
            assert!(
                !msg.contains("deadlock"),
                "task {label} must not fail with a DB deadlock: {msg}"
            );
        }
    }

    // The invariant, stated directly: the org still has an admin.
    let members = crate::db::get_users_by_org_paginated(&store, &org.id, None, 100)
        .await
        .expect("list members")
        .0;
    let remaining = members
        .iter()
        .filter(|m| m.is_org_admin && m.active)
        .count();
    assert!(
        remaining >= 1,
        "at least one admin must survive; results a={result_a:?} b={result_b:?}"
    );
}
