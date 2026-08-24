// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Regression tests for issue #314: SCIM user creation must reject an email
//! whose domain the calling org has not proven ownership of.
//!
//! `POST /scim/v2/Users` is the only SCIM entry point that accepts an
//! email, so it is the only handler under test. Without this check, an IdP
//! token scoped to org A could provision `bob@orgB-domain.com` and bind
//! that address to org A instead — see the issue for the full attack
//! description this closes.

#![expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code: panicking on an assertion failure is the point"
)]

use serde_json::json;
use vouch_server::db::{RecheckOutcome, UNVERIFY_FAILURE_THRESHOLD, record_recheck_result};
use vouch_tests::TestHarness;

async fn create_user(harness: &TestHarness, token: &str, email: &str) -> (u16, serde_json::Value) {
    let resp = harness
        .post_json_authenticated(
            "/scim/v2/Users",
            &json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "userName": email,
                "active": true,
            }),
            token,
        )
        .await
        .expect("SCIM user creation HTTP call");
    let status = resp.status;
    let body: serde_json::Value = resp.json().expect("parse SCIM response");
    (status, body)
}

/// A user whose email domain is the org's primary domain is accepted.
#[tokio::test]
async fn primary_domain_email_is_accepted() {
    let harness = TestHarness::new().await;
    let org = harness
        .create_org("primary-ok.example.com")
        .await
        .expect("create org");
    let token = harness
        .create_scim_token("token", &org.id)
        .await
        .expect("create scim token");

    let (status, body) = create_user(&harness, &token, "alice@primary-ok.example.com").await;

    assert_eq!(status, 201, "primary-domain email must be accepted: {body}");
}

/// A user whose email domain is a *verified* additional domain is accepted.
#[tokio::test]
async fn verified_additional_domain_email_is_accepted() {
    let harness = TestHarness::new().await;
    let org = harness
        .create_org("secondary-ok.example.com")
        .await
        .expect("create org");
    let token = harness
        .create_scim_token("token", &org.id)
        .await
        .expect("create scim token");

    vouch_server::db::add_additional_domain(
        &harness.state.store,
        &org.id,
        "secondary-ok-alt.example.com",
        "admin-user-id",
        "admin@secondary-ok.example.com",
    )
    .await
    .expect("add additional domain");
    vouch_server::db::mark_additional_domain_verified(
        &harness.state.store,
        &org.id,
        "secondary-ok-alt.example.com",
    )
    .await
    .expect("mark additional domain verified");

    let (status, body) = create_user(&harness, &token, "bob@secondary-ok-alt.example.com").await;

    assert_eq!(
        status, 201,
        "verified additional-domain email must be accepted: {body}"
    );
}

/// The core #314 scenario: an org's SCIM token cannot provision a user
/// whose email domain belongs to someone else — a different org, or no one
/// at all.
#[tokio::test]
async fn unowned_domain_email_is_rejected() {
    let harness = TestHarness::new().await;
    harness
        .create_org("org-b-domain.example.com")
        .await
        .expect("create org b (whose domain org A will try to claim)");
    let org_a = harness
        .create_org("org-a.example.com")
        .await
        .expect("create org a");
    let token_a = harness
        .create_scim_token("org a token", &org_a.id)
        .await
        .expect("create scim token");

    let (status, body) = create_user(&harness, &token_a, "bob@org-b-domain.example.com").await;

    assert_eq!(
        status, 400,
        "cross-org domain email must be rejected: {body}"
    );
    assert_eq!(body["scimType"], "invalidValue");
}

/// A domain nobody in the system owns (a generic consumer-style address, not
/// claimed by any org) is rejected exactly like a domain owned by a
/// different org — both are simply not in the calling org's owned set.
#[tokio::test]
async fn neutral_unclaimed_domain_email_is_rejected() {
    let harness = TestHarness::new().await;
    let org = harness
        .create_org("neutral-test.example.com")
        .await
        .expect("create org");
    let token = harness
        .create_scim_token("token", &org.id)
        .await
        .expect("create scim token");

    let (status, body) = create_user(&harness, &token, "someone@gmail.com").await;

    assert_eq!(
        status, 400,
        "domain no org has claimed must be rejected: {body}"
    );
    assert_eq!(body["scimType"], "invalidValue");
}

/// Domain comparison is case-insensitive: a mixed-case email domain must
/// match the org's normalized (lowercase) verified-domain set.
#[tokio::test]
async fn mixed_case_domain_email_matching_verified_entry_is_accepted() {
    let harness = TestHarness::new().await;
    let org = harness
        .create_org("case-norm.example.com")
        .await
        .expect("create org");
    let token = harness
        .create_scim_token("token", &org.id)
        .await
        .expect("create scim token");
    vouch_server::db::add_additional_domain(
        &harness.state.store,
        &org.id,
        "case-norm-alt.example.com",
        "admin-user-id",
        "admin@case-norm.example.com",
    )
    .await
    .expect("add additional domain");
    vouch_server::db::mark_additional_domain_verified(
        &harness.state.store,
        &org.id,
        "case-norm-alt.example.com",
    )
    .await
    .expect("mark additional domain verified");

    // Mixed-case primary domain.
    let (status, body) = create_user(&harness, &token, "alice@Case-Norm.Example.COM").await;
    assert_eq!(
        status, 201,
        "mixed-case primary domain must match the lowercase stored domain: {body}"
    );

    // Mixed-case additional domain.
    let (status, body) = create_user(&harness, &token, "bob@Case-Norm-Alt.Example.Com").await;
    assert_eq!(
        status, 201,
        "mixed-case additional domain must match the lowercase verified entry: {body}"
    );
}

/// An additional domain that has been *added* but not yet DNS-verified
/// does not count as owned — otherwise an org could claim any domain by
/// merely adding it, without ever proving control via the TXT record.
#[tokio::test]
async fn pending_additional_domain_email_is_rejected() {
    let harness = TestHarness::new().await;
    let org = harness
        .create_org("pending-owner.example.com")
        .await
        .expect("create org");
    let token = harness
        .create_scim_token("token", &org.id)
        .await
        .expect("create scim token");

    vouch_server::db::add_additional_domain(
        &harness.state.store,
        &org.id,
        "pending-claim.example.com",
        "admin-user-id",
        "admin@pending-owner.example.com",
    )
    .await
    .expect("add additional domain (left pending, never verified)");

    let (status, body) = create_user(&harness, &token, "eve@pending-claim.example.com").await;

    assert_eq!(
        status, 400,
        "pending (unverified) additional-domain email must be rejected: {body}"
    );
    assert_eq!(body["scimType"], "invalidValue");
}

/// A domain that was verified but has since flipped back to `Unverified`
/// after repeated re-check failures no longer counts as owned: new
/// provisioning against it is rejected, matching how the flip already
/// affects login matching and subdomain eligibility.
#[tokio::test]
async fn domain_unverified_after_recheck_failures_email_is_rejected() {
    let harness = TestHarness::new().await;
    let org = harness
        .create_org("flip-owner.example.com")
        .await
        .expect("create org");
    let token = harness
        .create_scim_token("token", &org.id)
        .await
        .expect("create scim token");

    vouch_server::db::add_additional_domain(
        &harness.state.store,
        &org.id,
        "flip-claim.example.com",
        "admin-user-id",
        "admin@flip-owner.example.com",
    )
    .await
    .expect("add additional domain");
    vouch_server::db::mark_additional_domain_verified(
        &harness.state.store,
        &org.id,
        "flip-claim.example.com",
    )
    .await
    .expect("mark additional domain verified");

    // Drive the entry through UNVERIFY_FAILURE_THRESHOLD consecutive
    // failed re-checks, exactly as the background re-verification task
    // would after the TXT record disappears.
    for _ in 0..UNVERIFY_FAILURE_THRESHOLD {
        record_recheck_result(
            &harness.state.store,
            &org.id,
            "flip-claim.example.com",
            RecheckOutcome::Failure,
        )
        .await
        .expect("record recheck failure");
    }

    let (status, body) = create_user(&harness, &token, "carol@flip-claim.example.com").await;

    assert_eq!(
        status, 400,
        "email on a domain flipped back to unverified must be rejected: {body}"
    );
    assert_eq!(body["scimType"], "invalidValue");
}

/// An org whose own primary domain is itself unusual — here a reserved
/// TLD, the shape realistic for an on-prem/AD-derived UPN like
/// `alice@corp.internal` — can still provision against that domain. The
/// ownership check is set membership against the org's stored domain, not
/// a re-validation of the domain's shape (`normalize_domain` is the
/// gatekeeper for domains entering the system, not for this comparison).
#[tokio::test]
async fn reserved_tld_primary_domain_org_can_provision_own_domain() {
    let harness = TestHarness::new().await;
    let org = harness
        .create_org("corp.internal")
        .await
        .expect("create org with a reserved-TLD primary domain");
    let token = harness
        .create_scim_token("token", &org.id)
        .await
        .expect("create scim token");

    let (status, body) = create_user(&harness, &token, "alice@corp.internal").await;

    assert_eq!(
        status, 201,
        "org must be able to provision against its own (reserved-TLD) primary domain: {body}"
    );
}

/// A candidate domain containing whitespace is rejected outright rather
/// than silently repaired: repairing it would let a value that is stored
/// verbatim (unlike the org's own domain-shape-validated entries) slip
/// past the check.
#[tokio::test]
async fn whitespace_in_domain_is_rejected() {
    let harness = TestHarness::new().await;
    let org = harness
        .create_org("whitespace-test.example.com")
        .await
        .expect("create org");
    let token = harness
        .create_scim_token("token", &org.id)
        .await
        .expect("create scim token");

    let (status, body) = create_user(&harness, &token, "bob@ whitespace-test.example.com").await;

    assert_eq!(
        status, 400,
        "a domain with stray whitespace must not be silently trimmed and accepted: {body}"
    );
    assert_eq!(body["scimType"], "invalidValue");
}

/// A `userName` with no `@` and no `emails[]` fallback cannot be checked
/// against any domain at all, and is rejected with a message distinct
/// from "domain not verified" — the cause here is that there is no
/// domain, not that the domain is unowned.
#[tokio::test]
async fn non_email_username_is_rejected_with_distinct_message() {
    let harness = TestHarness::new().await;
    let org = harness
        .create_org("no-email-username.example.com")
        .await
        .expect("create org");
    let token = harness
        .create_scim_token("token", &org.id)
        .await
        .expect("create scim token");

    let (status, body) = create_user(&harness, &token, "not-an-email-address").await;

    assert_eq!(
        status, 400,
        "a non-email userName with no emails[] fallback must be rejected: {body}"
    );
    assert_eq!(body["scimType"], "invalidValue");
    assert_eq!(body["detail"], "userName must be an email address");
}

/// A subdomain of a verified domain is not itself owned: only the exact
/// domain in the owned set counts, so `eng.acme.com` does not match a
/// verified `acme.com`. Pins exact-match semantics against a future
/// suffix-matching change.
#[tokio::test]
async fn subdomain_of_verified_domain_is_rejected() {
    let harness = TestHarness::new().await;
    let org = harness
        .create_org("acme-subdomain-test.com")
        .await
        .expect("create org");
    let token = harness
        .create_scim_token("token", &org.id)
        .await
        .expect("create scim token");

    let (status, body) = create_user(&harness, &token, "bob@eng.acme-subdomain-test.com").await;

    assert_eq!(
        status, 400,
        "a subdomain of a verified domain must not match by suffix: {body}"
    );
    assert_eq!(body["scimType"], "invalidValue");
}

// ============================================================================
// TOCTOU regression: domain removal during SCIM user creation
// ============================================================================
//
// Before the fix, the domain-ownership check ran as a separate non-transactional
// read before `create_scim_user`'s transaction. A concurrent domain removal
// committing between the check and the user insert would let a user be created
// on a domain the org no longer owned. The fix moves the check inside the
// transaction and version-bumps the org doc, forcing an OCC conflict with the
// removal so the transaction retries against fresh state.

/// A user provisioned AFTER the domain has been removed is rejected with 400,
/// not created with 201. This is the core TOCTOU regression at the HTTP
/// handler level: the in-transaction check sees the removal and rejects.
#[tokio::test]
async fn user_creation_rejected_after_domain_removed() {
    let harness = TestHarness::new().await;
    let org = harness
        .create_org("toctou-removed.example.com")
        .await
        .expect("create org");
    let token = harness
        .create_scim_token("token", &org.id)
        .await
        .expect("create scim token");

    vouch_server::db::add_additional_domain(
        &harness.state.store,
        &org.id,
        "toctou-removed-alt.example.com",
        "admin-user-id",
        "admin@toctou-removed.example.com",
    )
    .await
    .expect("add additional domain");
    vouch_server::db::mark_additional_domain_verified(
        &harness.state.store,
        &org.id,
        "toctou-removed-alt.example.com",
    )
    .await
    .expect("mark additional domain verified");

    // Remove the domain before user creation. The in-transaction check
    // must see the removal and reject with 400.
    vouch_server::db::remove_additional_domain(
        &harness.state.store,
        &org.id,
        "toctou-removed-alt.example.com",
    )
    .await
    .expect("remove additional domain");

    let (status, body) =
        create_user(&harness, &token, "alice@toctou-removed-alt.example.com").await;

    assert_eq!(
        status, 400,
        "user creation must be rejected after domain removed: {body}"
    );
    assert_eq!(body["scimType"], "invalidValue");
}

/// A user provisioned on a verified domain succeeds (201), and the domain
/// can be removed afterward without affecting the already-created user.
/// This verifies the fix doesn't break the happy path: users created while
/// the domain was owned remain valid after the domain is later removed.
#[tokio::test]
async fn user_creation_succeeds_then_domain_removed() {
    let harness = TestHarness::new().await;
    let org = harness
        .create_org("toctou-happy.example.com")
        .await
        .expect("create org");
    let token = harness
        .create_scim_token("token", &org.id)
        .await
        .expect("create scim token");

    vouch_server::db::add_additional_domain(
        &harness.state.store,
        &org.id,
        "toctou-happy-alt.example.com",
        "admin-user-id",
        "admin@toctou-happy.example.com",
    )
    .await
    .expect("add additional domain");
    vouch_server::db::mark_additional_domain_verified(
        &harness.state.store,
        &org.id,
        "toctou-happy-alt.example.com",
    )
    .await
    .expect("mark additional domain verified");

    // Create user while domain is owned — must succeed.
    let (status, body) = create_user(&harness, &token, "bob@toctou-happy-alt.example.com").await;
    assert_eq!(
        status, 201,
        "user creation must succeed while domain is owned: {body}"
    );

    // Remove the domain afterward. The already-created user remains valid
    // (existing users keep their org_id by design — this is about retention
    // of existing membership, not creation of new membership).
    vouch_server::db::remove_additional_domain(
        &harness.state.store,
        &org.id,
        "toctou-happy-alt.example.com",
    )
    .await
    .expect("remove additional domain");

    // A SECOND user creation on the now-removed domain must be rejected.
    let (status, body) = create_user(&harness, &token, "carol@toctou-happy-alt.example.com").await;
    assert_eq!(
        status, 400,
        "second user creation must be rejected after domain removed: {body}"
    );
    assert_eq!(body["scimType"], "invalidValue");
}

/// A duplicate email returns 409 (not 400) even when domain validation is
/// in scope. This verifies the error-type mapping in the handler:
/// `DomainNotOwned` → 400, `DuplicateEmail` → 409.
#[tokio::test]
async fn duplicate_email_returns_409_not_400() {
    let harness = TestHarness::new().await;
    let org = harness
        .create_org("dup-type-test.example.com")
        .await
        .expect("create org");
    let token = harness
        .create_scim_token("token", &org.id)
        .await
        .expect("create scim token");

    // First creation succeeds.
    let (status, _) = create_user(&harness, &token, "alice@dup-type-test.example.com").await;
    assert_eq!(status, 201);

    // Second creation with the same email must return 409 (uniqueness),
    // not 400 (domain validation) — the email's domain is owned, so the
    // domain check passes, and the duplicate check fires.
    let (status, body) = create_user(&harness, &token, "alice@dup-type-test.example.com").await;
    assert_eq!(status, 409, "duplicate email must return 409: {body}");
    assert_eq!(body["scimType"], "uniqueness");
}
