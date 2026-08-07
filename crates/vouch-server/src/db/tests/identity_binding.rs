// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Upstream (issuer, subject) identity binding and account matching.
#![expect(
    clippy::expect_used,
    clippy::panic,
    reason = "test code: panic on assertion failure is acceptable; cast bounds are obvious in test fixtures"
)]

use super::*;

// ========================================================================
// Upstream identity binding: (issuer, subject) account matching
// ========================================================================

// A (issuer, subject) match must win over the email, and the stored
// account email must never be rewritten from the assertion: email is
// mutable profile data upstream, the binding is the identity.
#[tokio::test]
async fn test_enroll_identity_binding_wins_over_email() {
    use crate::db::documents::user::UserDoc;
    use crate::db::{UpstreamLogin, enroll_user_with_org};

    let (store, _audit) = test_db().await;
    let domain = "bind-wins.example";
    let upstream = UpstreamLogin {
        issuer: "https://idp.bind-wins.example".to_string(),
        durable_subject: Some("subject-1".to_string()),
    };

    let first = enroll_user_with_org(
        &store,
        "old-address@bind-wins.example",
        None,
        Some(domain),
        Some(&upstream),
    )
    .await
    .expect("first enrollment");
    assert!(
        !first.newly_bound,
        "a newly created user carries its binding from creation, not a lazy bind"
    );

    // Same upstream person, email changed at the IdP.
    let second = enroll_user_with_org(
        &store,
        "new-address@bind-wins.example",
        None,
        Some(domain),
        Some(&upstream),
    )
    .await
    .expect("re-enrollment after upstream email change");

    assert_eq!(
        second.id, first.id,
        "(issuer, subject) must match the account"
    );
    assert_eq!(
        second.email, "old-address@bind-wins.example",
        "the stored account email must not be rewritten from the assertion"
    );

    let doc = store
        .get::<UserDoc>(&first.id)
        .await
        .expect("get user")
        .expect("user exists");
    assert_eq!(
        doc.data.idp_identities.len(),
        1,
        "binding must not duplicate"
    );
}

// An email match against an account bound to a DIFFERENT subject at the
// same issuer is the account-takeover shape (upstream address reassigned
// to a new person) and must be refused, leaving the account untouched.
#[tokio::test]
async fn test_enroll_same_issuer_different_subject_refused() {
    use crate::db::documents::user::UserDoc;
    use crate::db::{EnrollUserError, IdpIdentity, UpstreamLogin, enroll_user_with_org};

    let (store, _audit) = test_db().await;
    let domain = "reassigned.example";
    let issuer = "https://idp.reassigned.example";

    let victim = enroll_user_with_org(
        &store,
        "shared@reassigned.example",
        None,
        Some(domain),
        Some(&UpstreamLogin {
            issuer: issuer.to_string(),
            durable_subject: Some("victim-subject".to_string()),
        }),
    )
    .await
    .expect("victim enrollment");

    // The address was reassigned upstream: same email, new subject.
    let result = enroll_user_with_org(
        &store,
        "shared@reassigned.example",
        None,
        Some(domain),
        Some(&UpstreamLogin {
            issuer: issuer.to_string(),
            durable_subject: Some("attacker-subject".to_string()),
        }),
    )
    .await;

    match result {
        Err(EnrollUserError::IdentityConflict { user_id, issuer: i }) => {
            assert_eq!(user_id, victim.id);
            assert_eq!(i, issuer);
        }
        other => panic!("expected IdentityConflict, got {other:?}"),
    }

    let doc = store
        .get::<UserDoc>(&victim.id)
        .await
        .expect("get user")
        .expect("user exists");
    assert_eq!(
        doc.data.idp_identities,
        vec![IdpIdentity {
            issuer: issuer.to_string(),
            subject: "victim-subject".to_string(),
        }],
        "the refused login must not mutate the account's bindings"
    );
}

// A login through an issuer the account has no binding for, but which
// carries no durable subject (e.g. a non-persistent SAML NameID format),
// must succeed via the email match alone and must never create a
// binding — otherwise a legitimately rotating NameID would still trip
// the #837 lockout the persistent-only allowlist exists to prevent.
#[tokio::test]
async fn test_enroll_non_durable_login_matches_email_without_binding() {
    use crate::db::documents::user::UserDoc;
    use crate::db::{UpstreamLogin, enroll_user_with_org};

    let (store, _audit) = test_db().await;
    let domain = "non-durable.example";
    let issuer = "https://idp.non-durable.example";

    let first = enroll_user_with_org(
        &store,
        "alice@non-durable.example",
        None,
        Some(domain),
        Some(&UpstreamLogin {
            issuer: issuer.to_string(),
            durable_subject: None,
        }),
    )
    .await
    .expect("first login with no durable subject");
    assert!(!first.newly_bound);

    // A second login through the same issuer, again with no durable
    // subject (simulating a rotating NameID) — must still succeed, and
    // still create no binding.
    let second = enroll_user_with_org(
        &store,
        "alice@non-durable.example",
        None,
        Some(domain),
        Some(&UpstreamLogin {
            issuer: issuer.to_string(),
            durable_subject: None,
        }),
    )
    .await
    .expect("second non-durable login must not be refused");
    assert_eq!(second.id, first.id);
    assert!(!second.newly_bound);

    let doc = store
        .get::<UserDoc>(&first.id)
        .await
        .expect("get user")
        .expect("user exists");
    assert!(
        doc.data.idp_identities.is_empty(),
        "a non-durable login must never create a binding"
    );
}

// Bugbot finding on PR #837: once an account is bound to a durable
// (issuer, subject), a later login through that SAME issuer that cannot
// reassert a durable subject must be refused — not silently downgraded
// to an email-only match. Restricting binding *creation* to
// persistent-format NameIDs must not let a different-format login walk
// past a binding that already exists.
#[tokio::test]
async fn test_enroll_non_durable_login_refused_once_issuer_is_bound() {
    use crate::db::documents::user::UserDoc;
    use crate::db::{EnrollUserError, IdpIdentity, UpstreamLogin, enroll_user_with_org};

    let (store, _audit) = test_db().await;
    let domain = "downgrade.example";
    let issuer = "https://idp.downgrade.example";

    let victim = enroll_user_with_org(
        &store,
        "shared@downgrade.example",
        None,
        Some(domain),
        Some(&UpstreamLogin {
            issuer: issuer.to_string(),
            durable_subject: Some("victim-subject".to_string()),
        }),
    )
    .await
    .expect("victim binds via a durable-format login");

    // Same email, same issuer, but this login carries no durable subject
    // (e.g. the IdP sent a non-persistent NameID this time).
    let result = enroll_user_with_org(
        &store,
        "shared@downgrade.example",
        None,
        Some(domain),
        Some(&UpstreamLogin {
            issuer: issuer.to_string(),
            durable_subject: None,
        }),
    )
    .await;

    match result {
        Err(EnrollUserError::IdentityConflict { user_id, issuer: i }) => {
            assert_eq!(user_id, victim.id);
            assert_eq!(i, issuer);
        }
        other => panic!("expected IdentityConflict, got {other:?}"),
    }

    let doc = store
        .get::<UserDoc>(&victim.id)
        .await
        .expect("get user")
        .expect("user exists");
    assert_eq!(
        doc.data.idp_identities,
        vec![IdpIdentity {
            issuer: issuer.to_string(),
            subject: "victim-subject".to_string(),
        }],
        "the refused login must not mutate the account's bindings"
    );
}

// A binding is scoped per-issuer: an account already bound for issuer A
// must not have that binding gate a login through unrelated issuer B. A
// non-durable login through B still matches on email and succeeds,
// because B itself has no binding to satisfy or conflict with.
#[tokio::test]
async fn test_enroll_non_durable_login_matches_email_when_bound_only_for_other_issuer() {
    use crate::db::documents::user::UserDoc;
    use crate::db::{IdpIdentity, UpstreamLogin, enroll_user_with_org};

    let (store, _audit) = test_db().await;
    let domain = "other-issuer.example";
    let bound_issuer = "https://idp-a.other-issuer.example";
    let other_issuer = "https://idp-b.other-issuer.example";

    let user = enroll_user_with_org(
        &store,
        "alice@other-issuer.example",
        None,
        Some(domain),
        Some(&UpstreamLogin {
            issuer: bound_issuer.to_string(),
            durable_subject: Some("alice-subject-a".to_string()),
        }),
    )
    .await
    .expect("bind via issuer A");

    // A login through issuer B, with no durable subject, must still
    // match on email — the account has no binding for issuer B.
    let second = enroll_user_with_org(
        &store,
        "alice@other-issuer.example",
        None,
        Some(domain),
        Some(&UpstreamLogin {
            issuer: other_issuer.to_string(),
            durable_subject: None,
        }),
    )
    .await
    .expect("email match through an unrelated issuer must not be refused");
    assert_eq!(second.id, user.id);
    assert!(!second.newly_bound);

    let doc = store
        .get::<UserDoc>(&user.id)
        .await
        .expect("get user")
        .expect("user exists");
    assert_eq!(
        doc.data.idp_identities,
        vec![IdpIdentity {
            issuer: bound_issuer.to_string(),
            subject: "alice-subject-a".to_string(),
        }],
        "a non-durable login through a different issuer must not touch bindings"
    );
}

// Accounts that predate identity binding (no bindings stored) bind
// lazily on their first IdP login; a second, different issuer adds a
// second binding rather than conflicting.
#[tokio::test]
async fn test_enroll_lazy_binds_legacy_account() {
    use crate::db::documents::user::UserDoc;
    use crate::db::{IdpIdentity, UpstreamLogin, enroll_user_with_org};

    let (store, _audit) = test_db().await;
    let domain = "legacy-bind.example";

    // Legacy account: enrolled before identity binding existed.
    let legacy = enroll_user_with_org(
        &store,
        "legacy@legacy-bind.example",
        None,
        Some(domain),
        None,
    )
    .await
    .expect("legacy enrollment");

    let idp_a = UpstreamLogin {
        issuer: "https://idp-a.legacy-bind.example".to_string(),
        durable_subject: Some("legacy-subject-a".to_string()),
    };
    let bound = enroll_user_with_org(
        &store,
        "legacy@legacy-bind.example",
        None,
        Some(domain),
        Some(&idp_a),
    )
    .await
    .expect("lazy-bind login");
    assert_eq!(bound.id, legacy.id);
    assert!(bound.newly_bound, "first IdP login must lazily bind");

    // A later login resolves via the binding even with a changed email.
    let via_binding = enroll_user_with_org(
        &store,
        "renamed@legacy-bind.example",
        None,
        Some(domain),
        Some(&idp_a),
    )
    .await
    .expect("binding lookup");
    assert_eq!(via_binding.id, legacy.id);
    assert!(!via_binding.newly_bound);

    // A second issuer (org adds another IdP) binds alongside, no conflict.
    let idp_b = UpstreamLogin {
        issuer: "https://idp-b.legacy-bind.example".to_string(),
        durable_subject: Some("legacy-subject-b".to_string()),
    };
    let second = enroll_user_with_org(
        &store,
        "legacy@legacy-bind.example",
        None,
        Some(domain),
        Some(&idp_b),
    )
    .await
    .expect("second-issuer login");
    assert_eq!(second.id, legacy.id);
    assert!(second.newly_bound);

    let doc = store
        .get::<UserDoc>(&legacy.id)
        .await
        .expect("get user")
        .expect("user exists");
    assert_eq!(
        doc.data.idp_identities,
        vec![
            IdpIdentity {
                issuer: idp_a.issuer,
                subject: "legacy-subject-a".to_string(),
            },
            IdpIdentity {
                issuer: idp_b.issuer,
                subject: "legacy-subject-b".to_string(),
            },
        ],
        "one binding per issuer, in bind order"
    );
}

// A SCIM-provisioned account (deterministic email-derived ID, no
// bindings) must be found by email on the first IdP login — any casing —
// and bind without creating a duplicate user.
#[tokio::test]
async fn test_enroll_scim_user_binds_on_first_idp_login() {
    use crate::db::documents::user::UserDoc;
    use crate::db::{UpstreamLogin, create_scim_user, enroll_user_with_org};

    let (store, _audit) = test_db().await;
    seed_test_org(&store).await;

    let scim_user = create_scim_user(
        &store,
        Some(TEST_ORG_ID),
        "Provisioned@Example.com",
        Some("Provisioned"),
        Some("ext-42"),
        true,
    )
    .await
    .expect("SCIM create");

    let upstream = UpstreamLogin {
        issuer: "https://idp.example.com".to_string(),
        durable_subject: Some("scim-subject".to_string()),
    };
    // First IdP login for the SCIM-provisioned account, email in a
    // different casing than SCIM stored — must find by email and bind.
    let enrolled = enroll_user_with_org(
        &store,
        "PROVISIONED@example.com",
        None,
        None,
        Some(&upstream),
    )
    .await
    .expect("first IdP login");

    assert_eq!(enrolled.id, scim_user.id, "no duplicate user row");
    assert!(enrolled.newly_bound);

    let count = store
        .count::<UserDoc>("email", "provisioned@example.com")
        .await
        .expect("count users");
    assert_eq!(count, 1);
}
