// SPDX-License-Identifier: Apache-2.0 OR MIT
//! SCIM user creation: duplicate/uniqueness handling, in-transaction domain-ownership validation, deterministic IDs, cross-backend races.
#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test code: panic on assertion failure is acceptable; cast bounds are obvious in test fixtures"
)]

use super::*;

// ========================================================================
// SCIM — application-level uniqueness check
// ========================================================================

#[tokio::test]
async fn test_create_scim_user_duplicate_email_rejected() {
    let (store, _audit) = test_db().await;
    seed_test_org(&store).await;

    // First creation succeeds
    let user = create_scim_user(
        &store,
        Some(TEST_ORG_ID),
        "dup@example.com",
        Some("Original"),
        None,
        true,
    )
    .await
    .expect("First creation should succeed");

    // Second creation with the same email must fail with a UNIQUE error
    let result = create_scim_user(
        &store,
        Some(TEST_ORG_ID),
        "dup@example.com",
        Some("Duplicate"),
        None,
        true,
    )
    .await;
    assert!(result.is_err(), "Duplicate email should be rejected");
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("UNIQUE"),
        "Error message should mention UNIQUE; got: {err}"
    );

    // The created user must be addressable by its deterministic ID: the
    // SCIM handler's `validate_resource_id` only accepts `uuid::Uuid`-parseable
    // IDs, so a deterministic ID that isn't a valid UUID would make the user
    // unreachable via GET/PATCH/PUT/DELETE.
    use crate::db::documents::user::UserDoc;
    let by_id = store
        .get::<UserDoc>(&user.id)
        .await
        .expect("query by id")
        .expect("user must be findable by its deterministic ID");
    assert_eq!(by_id.data.email.as_str(), "dup@example.com");
    assert!(
        uuid::Uuid::try_parse(&user.id).is_ok(),
        "deterministic user ID must parse as a UUID; got {}",
        user.id
    );
}

// ============================================================================
// SCIM user creation — in-transaction domain-ownership validation
// ============================================================================
//
// Regression for the TOCTOU race in SCIM user provisioning: domain ownership
// must be validated inside the same transaction that inserts the user, with
// an OCC version-bump on the org doc forcing a conflict with concurrent
// domain removal. Before the fix, the check ran as a separate non-transactional
// read, so a `remove_additional_domain` committing between the check and the
// insert let a user be created on a domain the org no longer owned.

/// `create_scim_user` rejects when the org does not exist: a nonexistent org
/// owns no domains, so the in-transaction check returns `DomainNotOwned`.
#[tokio::test]
async fn test_create_scim_user_rejects_when_org_does_not_exist() {
    let (store, _audit) = test_db().await;

    let result = create_scim_user(
        &store,
        Some("nonexistent-org"),
        "alice@example.com",
        Some("Alice"),
        None,
        true,
    )
    .await;

    assert!(
        matches!(result, Err(CreateScimUserError::DomainNotOwned)),
        "expected DomainNotOwned for nonexistent org; got {result:?}"
    );

    // No user row was inserted.
    let count = store
        .count::<crate::db::documents::user::UserDoc>("email", "alice@example.com")
        .await
        .expect("count");
    assert_eq!(count, 0, "no user should be inserted when org is missing");
}

/// `create_scim_user` rejects when the email's domain is not in the org's
/// verified-domain set — the in-transaction read sees the org but the domain
/// is not among its verified domains.
#[tokio::test]
async fn test_create_scim_user_rejects_unowned_domain_in_transaction() {
    let (store, _audit) = test_db().await;
    seed_test_org(&store).await;

    let result = create_scim_user(
        &store,
        Some(TEST_ORG_ID),
        "alice@not-owned.example.com",
        Some("Alice"),
        None,
        true,
    )
    .await;

    assert!(
        matches!(result, Err(CreateScimUserError::DomainNotOwned)),
        "expected DomainNotOwned for unowned domain; got {result:?}"
    );

    let count = store
        .count::<crate::db::documents::user::UserDoc>("email", "alice@not-owned.example.com")
        .await
        .expect("count");
    assert_eq!(count, 0, "no user should be inserted for an unowned domain");
}

/// A pending (unverified) additional domain must not accept provisioning:
/// the in-transaction check is set membership against `verified_domains()`,
/// which yields only the primary domain and additional domains that have
/// passed DNS TXT verification.
#[tokio::test]
async fn test_create_scim_user_rejects_pending_additional_domain() {
    let (store, _audit) = test_db().await;
    let org = create_organization(&store, "primary.example.com", None, None)
        .await
        .expect("create org");
    add_additional_domain(
        &store,
        &org.id,
        "pending.example.com",
        "u1",
        "u1@primary.example.com",
    )
    .await
    .expect("add domain");

    let result = create_scim_user(
        &store,
        Some(&org.id),
        "alice@pending.example.com",
        None,
        None,
        true,
    )
    .await;

    assert!(
        matches!(result, Err(CreateScimUserError::DomainNotOwned)),
        "expected DomainNotOwned for a pending (unverified) additional domain; got {result:?}"
    );
}

/// A verified additional domain accepts provisioning, matching the primary
/// domain's behavior.
#[tokio::test]
async fn test_create_scim_user_accepts_verified_additional_domain() {
    let (store, _audit) = test_db().await;
    let org = create_organization(&store, "primary.example.com", None, None)
        .await
        .expect("create org");
    add_additional_domain(
        &store,
        &org.id,
        "alt.example.com",
        "u1",
        "u1@primary.example.com",
    )
    .await
    .expect("add domain");
    mark_additional_domain_verified(&store, &org.id, "alt.example.com")
        .await
        .expect("mark verified");

    let user = create_scim_user(
        &store,
        Some(&org.id),
        "alice@alt.example.com",
        None,
        None,
        true,
    )
    .await
    .expect("user creation on verified additional domain");
    assert_eq!(user.email, "alice@alt.example.com");
}

/// No repair of the candidate: an email whose domain part carries stray
/// whitespace (`bob@ example.com`) never matches a verified domain, rather
/// than being silently trimmed into a match.
#[tokio::test]
async fn test_create_scim_user_rejects_whitespace_padded_domain() {
    let (store, _audit) = test_db().await;
    seed_test_org(&store).await;

    let result = create_scim_user(
        &store,
        Some(TEST_ORG_ID),
        "bob@ example.com",
        None,
        None,
        true,
    )
    .await;

    assert!(
        matches!(result, Err(CreateScimUserError::DomainNotOwned)),
        "expected DomainNotOwned for a whitespace-padded domain; got {result:?}"
    );
}

/// A reserved-TLD primary domain (realistic for on-prem/AD-derived
/// enrollment) still accepts provisioning against itself: the check is set
/// membership against `verified_domains()`, not a re-run of
/// `normalize_domain` shape validation.
#[tokio::test]
async fn test_create_scim_user_accepts_reserved_tld_primary_domain() {
    let (store, _audit) = test_db().await;
    let org = create_organization(&store, "corp.internal", None, None)
        .await
        .expect("create org");

    let user = create_scim_user(
        &store,
        Some(&org.id),
        "alice@corp.internal",
        None,
        None,
        true,
    )
    .await
    .expect("user creation on reserved-TLD primary domain");
    assert_eq!(user.email, "alice@corp.internal");
}

/// `create_scim_user` version-bumps the org doc on success, proving the OCC
/// guard is in place. A concurrent domain removal that commits between the
/// in-transaction org-doc read and the CAS would change the version, causing
/// the CAS to fail and the transaction to retry against fresh state.
#[tokio::test]
async fn test_create_scim_user_version_bumps_org_doc() {
    use crate::db::documents::organization::OrganizationDoc;

    let (store, _audit) = test_db().await;
    seed_test_org(&store).await;

    // Read the org doc version before user creation.
    let before = store
        .get::<OrganizationDoc>(TEST_ORG_ID)
        .await
        .expect("get org")
        .expect("org exists");
    let version_before = before.version;

    create_scim_user(
        &store,
        Some(TEST_ORG_ID),
        "version-check@example.com",
        None,
        None,
        true,
    )
    .await
    .expect("user creation should succeed");

    // Read the org doc version after user creation — must have increased.
    let after = store
        .get::<OrganizationDoc>(TEST_ORG_ID)
        .await
        .expect("get org")
        .expect("org exists");
    assert!(
        after.version > version_before,
        "org doc version must increase after create_scim_user (OCC version-bump); \
         before={version_before}, after={}",
        after.version
    );
}

/// `create_scim_user` does NOT version-bump the org doc when `org_id` is
/// `None` (the certification test path): there is no org to validate or bump.
#[tokio::test]
async fn test_create_scim_user_no_org_does_not_touch_org_doc() {
    let (store, _audit) = test_db().await;
    seed_test_org(&store).await;

    // No org doc should be touched when org_id is None. Read the org version
    // before and after; it must not change.
    let before = store
        .get::<crate::db::documents::organization::OrganizationDoc>(TEST_ORG_ID)
        .await
        .expect("get org")
        .expect("org exists");

    create_scim_user(&store, None, "orgless@example.com", None, None, true)
        .await
        .expect("orgless user creation should succeed");

    let after = store
        .get::<crate::db::documents::organization::OrganizationDoc>(TEST_ORG_ID)
        .await
        .expect("get org")
        .expect("org exists");
    assert_eq!(
        before.version, after.version,
        "org doc version must not change when org_id is None"
    );
}

/// Concurrent `create_scim_user` and `remove_additional_domain` must not
/// produce a user on the removed domain.
///
/// This is a best-effort race, not a deterministic interleaving: the
/// transactional create path has no injection point, so the two tasks
/// simply run concurrently and every outcome's invariant is checked. The
/// `Ok` arm cannot distinguish "creation legitimately committed before the
/// removal" from the original bug (creation committing after the removal),
/// so this test alone cannot prove the guard; the deterministic regression
/// coverage is the sequential rejection tests above, and what this adds is
/// that no interleaving panics, double-creates, or strands a user row on a
/// rejected outcome.
///
/// Uses `multi_thread` so the two tasks can run on separate worker threads.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_create_scim_user_toctou_domain_removal_during_creation() {
    let (store, _audit) = test_db().await;
    let store = std::sync::Arc::new(store);

    let org = create_organization(&store, "primary.example.com", None, None)
        .await
        .expect("create org");
    add_additional_domain(
        &store,
        &org.id,
        "toctou.example.com",
        "u1",
        "u1@primary.example.com",
    )
    .await
    .expect("add domain");
    mark_additional_domain_verified(&store, &org.id, "toctou.example.com")
        .await
        .expect("mark verified");

    let org_id = org.id.clone();
    let store_for_create = std::sync::Arc::clone(&store);
    let store_for_remove = std::sync::Arc::clone(&store);

    // Spawn the user-creation task. It will either succeed (domain removal
    // lost the race and the user was created while the domain was still
    // owned — acceptable) or fail with DomainNotOwned (domain removal won
    // the race and the retry saw the removal — the TOCTOU guard working).
    // The OLD behavior (bug) would return Ok even when the domain was
    // already removed at the time of the insert's commit.
    let create_handle = tokio::spawn(async move {
        create_scim_user(
            &store_for_create,
            Some(&org_id),
            "racer@toctou.example.com",
            Some("Racer"),
            None,
            true,
        )
        .await
    });

    // Concurrently remove the domain. The removal commits independently;
    // if it lands before the user-creation's CAS, the CAS fails and retries.
    let org_id_for_remove = org.id.clone();
    let remove_handle = tokio::spawn(async move {
        remove_additional_domain(&store_for_remove, &org_id_for_remove, "toctou.example.com")
            .await
            .expect("remove domain")
    });

    let create_result = create_handle.await.expect("create task panicked");
    let remove_result = remove_handle.await.expect("remove task panicked");

    // The removal must succeed.
    assert!(
        remove_result.is_some(),
        "domain removal should have found and removed the domain"
    );

    // After both operations complete, check the invariant:
    // - If the user was created, the domain must still be attached to the org
    //   at the time of creation (the OCC guard ensured this). Since the
    //   domain was removed, the user creation must NOT have succeeded after
    //   the removal committed.
    // - If the user was not created, it must be because the domain was
    //   removed before or during the transaction (DomainNotOwned).
    match create_result {
        Err(CreateScimUserError::DomainNotOwned) => {
            // The TOCTOU guard worked: domain was removed, user creation
            // rejected. Verify no user row exists.
            let count = store
                .count::<crate::db::documents::user::UserDoc>("email", "racer@toctou.example.com")
                .await
                .expect("count");
            assert_eq!(
                count, 0,
                "no user should exist when DomainNotOwned was returned"
            );
        }
        Ok(user) => {
            // The user creation won the race: it committed before the removal.
            // This is acceptable — the domain was owned at creation time.
            // But the domain must now be removed (the removal succeeded).
            assert_eq!(user.email, "racer@toctou.example.com");
            let org_after = get_organization(&store, &org.id)
                .await
                .expect("get org")
                .expect("org exists");
            assert!(
                !org_after
                    .additional_domains
                    .iter()
                    .any(|d| d.domain == "toctou.example.com"),
                "domain must be removed after both operations complete"
            );
        }
        Err(CreateScimUserError::DuplicateEmail) => {
            panic!("DuplicateEmail unexpected for a fresh email");
        }
        Err(CreateScimUserError::OccConflict) => {
            // OCC retry budget exhausted — the domain was being removed and
            // re-added concurrently, or the retry kept losing. This is
            // acceptable: the user was NOT created on the removed domain.
            let count = store
                .count::<crate::db::documents::user::UserDoc>("email", "racer@toctou.example.com")
                .await
                .expect("count");
            assert_eq!(count, 0, "no user should exist after OccConflict");
        }
        Err(CreateScimUserError::Other(e)) => {
            panic!("unexpected error from create_scim_user: {e}");
        }
    }
}

/// Regression for the SCIM concurrent-create race: two concurrent
/// `create_scim_user` calls with the same email must produce exactly one
/// user row, not two. Before the deterministic-ID fix, each call generated
/// a fresh random UUID v7 primary key, so neither insert conflicted with the
/// other and both committed — producing duplicate accounts for the same email.
///
/// The fix derives the user ID from the email (an RFC 9562 version-8 UUID
/// packing a SHA-256 digest), so the two inserts collide on the `documents`
/// PRIMARY KEY. The losing insert fails with a unique/primary-key violation,
/// which `is_unique_violation` maps to the same `DuplicateEmail` error
/// returned by the explicit pre-check; the SCIM handler then returns
/// `409 Conflict` for the loser.
///
/// Mirrors `test_dpop_jti_concurrent_insert_rejects_duplicates`. Uses
/// `multi_thread` for defensive OS-level parallelism (SQLite `busy_timeout`
/// waits happen inside sqlx-sqlite's dedicated OS thread and don't block
/// tokio worker threads). Under DSQL's optimistic concurrency the loser
/// first receives a serialization error (`40001`), `with_dsql_retry!`
/// retries, and the retried insert then collides with the winner's
/// committed row (`23505`) — `23505` is not retryable, so the loser surfaces
/// as `Err`. This SQLite test exercises the post-retry collision path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_create_scim_user_concurrent_same_email_produces_one_user() {
    use crate::db::documents::user::UserDoc;
    let (store, _audit) = test_db().await;
    seed_test_org(&store).await;
    let store = std::sync::Arc::new(store);
    let email = "race@example.com";

    let num_tasks = 20;
    let mut handles = Vec::with_capacity(num_tasks);
    for _ in 0..num_tasks {
        let s = std::sync::Arc::clone(&store);
        handles.push(tokio::spawn(async move {
            create_scim_user(&s, Some(TEST_ORG_ID), email, Some("Racer"), None, true).await
        }));
    }

    let mut successes = 0u32;
    let mut unique_errors = 0u32;
    for handle in handles {
        let result = handle.await.expect("task should not panic");
        match result {
            Ok(_) => successes += 1,
            Err(ref e) if e.to_string().contains("UNIQUE") => unique_errors += 1,
            Err(ref e) => panic!("unexpected error from create_scim_user: {e}"),
        }
    }

    assert_eq!(
        successes, 1,
        "exactly one concurrent create should succeed; got {successes}"
    );
    assert_eq!(
        unique_errors,
        u32::try_from(num_tasks - 1).expect("num_tasks - 1 fits in u32"),
        "every other concurrent create should be rejected with a UNIQUE error"
    );

    // Verify at the DB level: exactly one user row for the email, and exactly
    // one row with the deterministic ID. No duplicate accounts can exist.
    let by_email = store
        .find_one::<UserDoc>("email", email)
        .await
        .expect("query by email")
        .expect("exactly one user must exist for the email");
    let all_for_email = store
        .find_all::<UserDoc>("email", email)
        .await
        .expect("find_all by email");
    assert_eq!(
        all_for_email.len(),
        1,
        "exactly one user row must exist for the email; got {}",
        all_for_email.len()
    );
    // The row found by email must be the same row found by the deterministic ID.
    let by_id = store
        .get::<UserDoc>(&by_email.id)
        .await
        .expect("query by id")
        .expect("user must be findable by its deterministic ID");
    assert_eq!(by_id.id, by_email.id);
    assert_eq!(by_id.data.email.as_str(), email);
    // And the ID must be a valid UUID (SCIM resource ID contract).
    assert!(
        uuid::Uuid::try_parse(&by_email.id).is_ok(),
        "the winning user's ID must be a valid UUID; got {}",
        by_email.id
    );
}

/// Concurrent creates for the same email in DIFFERENT casings must still
/// collide on one row: `create_scim_user` lowercases the email before
/// deriving the deterministic ID, so `Alice@…`, `ALICE@…`, and `alice@…`
/// all compute the same primary key. Deriving from the verbatim email
/// instead would give each casing its own ID, letting cross-case concurrent
/// creates commit distinct rows — reopening the duplicate-user bug the
/// deterministic ID exists to close.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_create_scim_user_concurrent_mixed_case_same_email_produces_one_user() {
    use crate::db::documents::user::UserDoc;
    let (store, _audit) = test_db().await;
    seed_test_org(&store).await;
    let store = std::sync::Arc::new(store);

    let casings = [
        "Case.Race@Example.com",
        "case.race@example.com",
        "CASE.RACE@EXAMPLE.COM",
        "case.Race@example.COM",
    ];
    let num_tasks = 20;
    let mut handles = Vec::with_capacity(num_tasks);
    for &email in casings.iter().cycle().take(num_tasks) {
        let s = std::sync::Arc::clone(&store);
        handles.push(tokio::spawn(async move {
            create_scim_user(&s, Some(TEST_ORG_ID), email, Some("Racer"), None, true).await
        }));
    }

    let mut successes = 0u32;
    let mut unique_errors = 0u32;
    for handle in handles {
        let result = handle.await.expect("task should not panic");
        match result {
            Ok(record) => {
                successes += 1;
                assert_eq!(
                    record.email, "case.race@example.com",
                    "the stored email must be the lowercase normalization"
                );
            }
            Err(ref e) if e.to_string().contains("UNIQUE") => unique_errors += 1,
            Err(ref e) => panic!("unexpected error from create_scim_user: {e}"),
        }
    }

    assert_eq!(
        successes, 1,
        "exactly one mixed-case concurrent create should succeed; got {successes}"
    );
    assert_eq!(
        unique_errors,
        u32::try_from(num_tasks - 1).expect("num_tasks - 1 fits in u32"),
        "every other mixed-case concurrent create should be rejected with a UNIQUE error"
    );

    // Exactly one row exists, stored under the lowercase email, with the
    // deterministic ID derived from that lowercase form.
    let all_for_email = store
        .find_all::<UserDoc>("email", "case.race@example.com")
        .await
        .expect("find_all by lowercase email");
    assert_eq!(
        all_for_email.len(),
        1,
        "exactly one user row must exist across all casings; got {}",
        all_for_email.len()
    );
    let expected_id = crate::db::documents::user::deterministic_user_id(&crate::email::Email::new(
        "case.race@example.com",
    ));
    let winner = all_for_email.first().expect("one row exists");
    assert_eq!(
        winner.id, expected_id,
        "the winning row's ID must derive from the lowercase email"
    );
}

/// The deterministic user ID is stable across calls and across process
/// restarts (it is a pure function of the email). A user created by
/// `create_scim_user`, deleted, then re-created with the same email must
/// receive the same ID — confirming the derivation has no per-process
/// randomness and that the `documents` PRIMARY KEY collision behaviour is
/// not an artifact of a single test run.
#[tokio::test]
async fn test_create_scim_user_deterministic_id_is_stable_across_recreate() {
    use crate::db::documents::user::UserDoc;
    let (store, _audit) = test_db().await;
    seed_test_org(&store).await;
    let email = "recreate@example.com";

    let first = create_scim_user(&store, Some(TEST_ORG_ID), email, Some("First"), None, true)
        .await
        .expect("first create");
    let first_id = first.id.clone();

    // Delete the user (and any associated data) so the email is free again.
    store.delete(&first.id).await.expect("delete user");

    // Re-create with the same email — must get the same ID.
    let second = create_scim_user(&store, Some(TEST_ORG_ID), email, Some("Second"), None, true)
        .await
        .expect("re-create after delete");
    assert_eq!(
        second.id, first_id,
        "re-creating a user with the same email must produce the same deterministic ID"
    );

    // Only one row exists for the email.
    let all_for_email = store
        .find_all::<UserDoc>("email", email)
        .await
        .expect("find_all by email");
    assert_eq!(all_for_email.len(), 1);
}

/// A pre-existing user created by a *different* code path that does not use
/// the deterministic ID (e.g. `enroll_user_with_org`, which still generates a
/// random UUID v7) must still block a subsequent `create_scim_user` for the
/// same email. The `find_one` pre-check catches this before the insert is
/// attempted, so the deterministic ID never collides with the random one —
/// the user sees the existing-user `UNIQUE` error, not a silent duplicate.
#[tokio::test]
async fn test_create_scim_user_blocked_by_preexisting_random_id_user() {
    use crate::db::documents::user::UserDoc;
    let (store, _audit) = test_db().await;
    seed_test_org(&store).await;
    let email = "preexisting@example.com";

    // Seed a user with a random UUID v7 ID, as `enroll_user_with_org` does.
    let seeded = UserDoc {
        email: crate::email::Email::new(email),
        name: Some("Seeded".to_string()),
        org_id: Some(TEST_ORG_ID.to_string()),
        org_domain: None,
        is_org_admin: false,
        active: true,
        external_id: None,
        github_id: None,
        github_login: None,
        github_refresh_token: None,
        idp_identities: Vec::new(),
    };
    let seeded_doc = store.insert(&seeded).await.expect("seed random-id user");
    assert!(
        uuid::Uuid::try_parse(&seeded_doc.id).is_ok(),
        "seeded user should have a valid UUID v7 id"
    );

    // SCIM create for the same email must be rejected with a UNIQUE error,
    // even though the seeded user's ID differs from the deterministic one.
    let result = create_scim_user(&store, Some(TEST_ORG_ID), email, Some("SCIM"), None, true).await;
    assert!(result.is_err(), "create should be rejected");
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("UNIQUE"),
        "error should mention UNIQUE; got: {err}"
    );

    // Exactly one user row exists — no duplicate created.
    let all_for_email = store
        .find_all::<UserDoc>("email", email)
        .await
        .expect("find_all by email");
    assert_eq!(
        all_for_email.len(),
        1,
        "no duplicate user should be created"
    );
    assert_eq!(all_for_email[0].id, seeded_doc.id);
}

/// Snapshot-isolation verification of the SCIM concurrent-create fix.
///
/// The SQLite `test_create_scim_user_concurrent_same_email_produces_one_user`
/// test confirms the post-retry collision path and the DB-level invariant, but
/// SQLite serializes writers so it cannot reproduce the original race (two
/// transactions both reading "no user exists" from the same snapshot and both
/// attempting to commit distinct rows). This test runs the same scenario
/// against a real PostgreSQL backend when `VOUCH_TEST_POSTGRES_URL` is set,
/// exercising true snapshot isolation where the deterministic-ID collision is
/// the only thing preventing duplicate accounts.
///
/// To run:
///   VOUCH_TEST_POSTGRES_URL="postgres://user:pass@localhost/db" \
///     cargo test -p vouch-server --all-features --lib -- \
///     test_create_scim_user_concurrent_same_email_produces_one_user_postgres --nocapture
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[expect(
    clippy::print_stderr,
    reason = "skip notice when no Postgres is configured"
)]
async fn test_create_scim_user_concurrent_same_email_produces_one_user_postgres() {
    use crate::db::documents::user::UserDoc;
    use crate::db::pool::{Pool, PoolConfig};

    let url = match std::env::var("VOUCH_TEST_POSTGRES_URL") {
        Ok(u) if !u.is_empty() => u,
        _ => {
            eprintln!("skipping Postgres snapshot-isolation test: VOUCH_TEST_POSTGRES_URL not set");
            return;
        }
    };

    let pool = Pool::connect(&url, &PoolConfig::default())
        .await
        .expect("connect to Postgres test DB");
    let crate::db::pool::Pool::Postgres(p) = &pool else {
        panic!("VOUCH_TEST_POSTGRES_URL must point to a Postgres database");
    };

    // Apply the real Postgres migrations rather than an inline schema copy,
    // so schema drift breaks this test instead of silently passing. Two
    // vanilla-PostgreSQL adaptations: the files target Aurora DSQL, whose
    // `CREATE INDEX ASYNC` syntax vanilla Postgres rejects, and a reused
    // test database needs idempotent DDL (`IF NOT EXISTS`).
    let migrations_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/migrations/postgres");
    let mut migration_files: Vec<_> = std::fs::read_dir(migrations_dir)
        .expect("read migrations/postgres")
        .map(|entry| entry.expect("read migration entry").path())
        .collect();
    migration_files.sort();
    for file in migration_files {
        let sql = std::fs::read_to_string(&file)
            .expect("read migration file")
            .replace("CREATE INDEX ASYNC ", "CREATE INDEX IF NOT EXISTS ")
            .replace("CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ");
        // Migration files are repo-owned trusted content, not user input.
        sqlx::raw_sql(sqlx::AssertSqlSafe(sql))
            .execute(p)
            .await
            .unwrap_or_else(|e| panic!("apply Postgres migration {}: {e}", file.display()));
    }

    let crypto: std::sync::Arc<dyn crate::crypto::document_crypto::DocumentCrypto> =
        std::sync::Arc::new(crate::crypto::document_crypto::PlaintextDocumentCrypto);
    let store = crate::db::store::DocumentStore::new(pool.clone(), crypto.clone());

    // Seed the org doc that `create_scim_user`'s in-transaction
    // domain-ownership check reads. `pg-test-org` owns `example.com`.
    {
        use crate::db::documents::organization::OrganizationDoc;
        let org_doc = test_org_doc("example.com");
        // Clean up any leftover org from a previous run before inserting.
        if let Some(existing) = store
            .get::<OrganizationDoc>("pg-test-org")
            .await
            .expect("org lookup before test")
        {
            store
                .delete(&existing.id)
                .await
                .expect("delete leftover org");
        }
        store
            .insert_with_id("pg-test-org", &org_doc)
            .await
            .expect("seed pg-test-org");
    }

    let email = "pg-race@example.com";

    // Clean up any leftover row from a previous run.
    if let Some(existing) = store
        .find_one::<UserDoc>("email", email)
        .await
        .expect("find_one before test")
    {
        store.delete(&existing.id).await.expect("delete leftover");
    }

    let store = std::sync::Arc::new(store);
    let num_tasks = 20;
    let mut handles = Vec::with_capacity(num_tasks);
    for _ in 0..num_tasks {
        let s = std::sync::Arc::clone(&store);
        handles.push(tokio::spawn(async move {
            create_scim_user(&s, Some("pg-test-org"), email, Some("Racer"), None, true).await
        }));
    }

    let mut successes = 0u32;
    let mut unique_errors = 0u32;
    let mut other_errors = Vec::new();
    for handle in handles {
        let result = handle.await.expect("task should not panic");
        match result {
            Ok(_) => successes += 1,
            Err(ref e) if e.to_string().contains("UNIQUE") => unique_errors += 1,
            Err(ref e) => other_errors.push(format!("{e:#}")),
        }
    }

    assert!(
        other_errors.is_empty(),
        "unexpected non-UNIQUE errors: {other_errors:?}"
    );
    assert_eq!(
        successes, 1,
        "exactly one concurrent create should succeed on Postgres; got {successes}"
    );
    assert_eq!(
        unique_errors,
        u32::try_from(num_tasks - 1).expect("num_tasks - 1 fits in u32"),
        "every other concurrent create should be rejected with a UNIQUE error on Postgres"
    );

    // Verify at the DB level: exactly one user row for the email.
    let all_for_email = store
        .find_all::<UserDoc>("email", email)
        .await
        .expect("find_all by email");
    assert_eq!(
        all_for_email.len(),
        1,
        "exactly one user row must exist for the email on Postgres; got {}",
        all_for_email.len()
    );
    assert!(
        uuid::Uuid::try_parse(&all_for_email[0].id).is_ok(),
        "the winning user's ID must be a valid UUID; got {}",
        all_for_email[0].id
    );

    // Clean up.
    store
        .delete(&all_for_email[0].id)
        .await
        .expect("cleanup after test");
}
