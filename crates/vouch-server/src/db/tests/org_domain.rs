// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `UserDoc.org_domain`: populated at creation by both production writers
//! (`enroll_user_with_org`, `create_scim_user`), read back via
//! `get_user_org_domain`, and lazily backfilled onto docs written before
//! the field existed.
#![expect(
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]

use super::*;
use crate::db::documents::organization::{
    AdditionalDomain, AdditionalDomainState, OrganizationDoc,
};
use crate::db::documents::user::UserDoc;
use secrecy::SecretString;

/// A `UserDoc` with `org_id` set but `org_domain` absent, as every doc
/// written before this field existed looks on disk.
fn legacy_org_user_doc(email: &str, org_id: &str) -> UserDoc {
    UserDoc {
        email: crate::email::Email::new(email),
        name: None,
        org_id: Some(org_id.to_string()),
        org_domain: None,
        is_org_admin: false,
        active: true,
        external_id: None,
        github_id: None,
        github_login: None,
        github_refresh_token: None,
        idp_identities: Vec::new(),
    }
}

#[tokio::test]
async fn test_enroll_user_with_org_stores_org_domain() {
    let (store, _audit) = test_db().await;
    let domain = "org-enroll.example";

    let user = enroll_user_with_org(&store, &format!("alice@{domain}"), None, Some(domain), None)
        .await
        .expect("enrollment");

    assert_eq!(
        user.org_domain.as_deref(),
        Some(domain),
        "EnrolledUser must carry the domain it just wrote"
    );

    let doc = store
        .get::<UserDoc>(&user.id)
        .await
        .expect("get user")
        .expect("user exists");
    assert_eq!(
        doc.data.org_domain.as_deref(),
        Some(domain),
        "org_domain must be persisted on the doc, not just returned"
    );
}

// The "domain" index covers the whole verified set, so an enrollment under
// a verified *additional* domain resolves to the owning org. The doc must
// be stamped with that org's primary domain — the tenant-scoping value —
// not the enrollment input.
#[tokio::test]
async fn test_enroll_via_verified_additional_domain_stores_primary_domain() {
    let (store, _audit) = test_db().await;

    let org = store
        .insert(&OrganizationDoc {
            domain: "primary.example".to_string(),
            name: None,
            created_by_user_id: None,
            additional_domains: vec![AdditionalDomain {
                domain: "added.example".to_string(),
                verification_token: SecretString::from("txt-token"),
                added_at: jiff::Timestamp::now(),
                added_by_user_id: "admin".to_string(),
                added_by_email: "admin@primary.example".to_string(),
                consecutive_failures: 0,
                state: AdditionalDomainState::Verified {
                    verified_at: jiff::Timestamp::now(),
                    last_checked_at: None,
                },
            }],
            subdomain: None,
        })
        .await
        .expect("insert org");

    let user = enroll_user_with_org(
        &store,
        "bob@added.example",
        None,
        Some("added.example"),
        None,
    )
    .await
    .expect("enrollment");

    assert_eq!(
        user.org_id.as_deref(),
        Some(org.id.as_str()),
        "enrollment under a verified additional domain must join the owning org"
    );
    assert_eq!(
        user.org_domain.as_deref(),
        Some("primary.example"),
        "the doc must carry the org's primary domain, not the enrollment input"
    );
}

#[tokio::test]
async fn test_enroll_individual_user_has_no_org_domain() {
    let (store, _audit) = test_db().await;

    let user = enroll_user_with_org(&store, "solo@personal.example", None, None, None)
        .await
        .expect("enrollment");

    assert_eq!(
        user.org_id, None,
        "an org-less enrollment must not gain an org_id"
    );
    assert_eq!(
        user.org_domain, None,
        "an org-less user must never carry an org_domain"
    );
}

#[tokio::test]
async fn test_create_scim_user_stores_org_domain() {
    let (store, _audit) = test_db().await;
    seed_test_org(&store).await;

    let record = create_scim_user(
        &store,
        Some(TEST_ORG_ID),
        "scim-store@example.com",
        Some("SCIM User"),
        None,
        true,
    )
    .await
    .expect("scim user creation");

    let doc = store
        .get::<UserDoc>(&record.id)
        .await
        .expect("get user")
        .expect("user exists");
    assert_eq!(
        doc.data.org_domain.as_deref(),
        Some(TEST_ORG_DOMAIN),
        "create_scim_user must store the org's domain alongside org_id"
    );
}

#[tokio::test]
async fn test_create_scim_user_without_org_has_no_org_domain() {
    let (store, _audit) = test_db().await;

    // `org_id: None` is the certification test path — no org to validate
    // or copy a domain from.
    let record = create_scim_user(&store, None, "cert-path@example.com", None, None, true)
        .await
        .expect("scim user creation");

    let doc = store
        .get::<UserDoc>(&record.id)
        .await
        .expect("get user")
        .expect("user exists");
    assert_eq!(doc.data.org_domain, None);
}

#[tokio::test]
async fn test_get_user_org_domain_falls_back_and_backfills_legacy_doc() {
    let (store, _audit) = test_db().await;
    seed_test_org(&store).await;

    let inserted = store
        .insert(&legacy_org_user_doc("legacy@example.com", TEST_ORG_ID))
        .await
        .expect("insert legacy user");

    // No cached value: falls back to a live lookup of the org row.
    let resolved = get_user_org_domain(&store, &inserted.id, TEST_ORG_ID, None)
        .await
        .expect("resolve org domain");
    assert_eq!(resolved.as_deref(), Some(TEST_ORG_DOMAIN));

    // The fallback must have persisted the result on the user doc.
    let refreshed = store
        .get::<UserDoc>(&inserted.id)
        .await
        .expect("get user")
        .expect("user exists");
    assert_eq!(
        refreshed.data.org_domain.as_deref(),
        Some(TEST_ORG_DOMAIN),
        "a resolved fallback must be backfilled onto the doc"
    );

    // A second call with the now-cached value must return the same domain
    // without touching the org row — pass a nonexistent org_id to prove the
    // cached branch is taken instead of a live lookup.
    let cached = get_user_org_domain(
        &store,
        &inserted.id,
        "nonexistent-org",
        refreshed.data.org_domain.as_deref(),
    )
    .await
    .expect("resolve org domain from cache");
    assert_eq!(cached.as_deref(), Some(TEST_ORG_DOMAIN));
}

#[tokio::test]
async fn test_get_user_org_domain_cached_and_fallback_paths_agree() {
    let (store, _audit) = test_db().await;
    seed_test_org(&store).await;

    let inserted = store
        .insert(&legacy_org_user_doc("parity@example.com", TEST_ORG_ID))
        .await
        .expect("insert legacy user");

    let via_fallback = get_user_org_domain(&store, &inserted.id, TEST_ORG_ID, None)
        .await
        .expect("fallback resolution");
    let via_cache = get_user_org_domain(&store, &inserted.id, TEST_ORG_ID, Some(TEST_ORG_DOMAIN))
        .await
        .expect("cached resolution");

    assert_eq!(
        via_fallback, via_cache,
        "the cached and fallback paths must resolve to the same domain"
    );
}

#[tokio::test]
async fn test_get_user_org_domain_org_row_absent_returns_none_and_caches_nothing() {
    let (store, _audit) = test_db().await;

    let inserted = store
        .insert(&legacy_org_user_doc(
            "orphan@example.com",
            "nonexistent-org",
        ))
        .await
        .expect("insert legacy user");

    let resolved = get_user_org_domain(&store, &inserted.id, "nonexistent-org", None)
        .await
        .expect("resolve org domain");
    assert_eq!(resolved, None);

    // A miss must not be written back: org_domain stays unset so a later
    // read retries the lookup instead of trusting a cached negative.
    let after = store
        .get::<UserDoc>(&inserted.id)
        .await
        .expect("get user")
        .expect("user exists");
    assert_eq!(after.data.org_domain, None);
}

#[tokio::test]
async fn test_get_user_org_domain_backfill_missing_user_does_not_fail_the_caller() {
    let (store, _audit) = test_db().await;
    seed_test_org(&store).await;

    // The user doc doesn't exist, so the backfill `store.modify` call finds
    // nothing to update — the live-looked-up domain must still be returned.
    let resolved = get_user_org_domain(&store, "nonexistent-user", TEST_ORG_ID, None)
        .await
        .expect("resolve org domain despite missing user doc");
    assert_eq!(resolved.as_deref(), Some(TEST_ORG_DOMAIN));
}

#[tokio::test]
async fn test_get_user_org_domain_backfill_write_error_does_not_fail_the_caller() {
    let (store, _audit) = test_db().await;
    seed_test_org(&store).await;

    let inserted = store
        .insert(&legacy_org_user_doc("hooked@example.com", TEST_ORG_ID))
        .await
        .expect("insert legacy user");

    // Land a conflicting write inside every OCC window so the backfill's
    // `store.modify` exhausts its retry budget and returns an error.
    let writer = store.clone();
    let mut hooked = store.clone();
    hooked.set_modify_test_hook(Arc::new(move |doc_id: &str, _attempt: u32| {
        let writer = writer.clone();
        let doc_id = doc_id.to_string();
        Box::pin(async move {
            writer
                .modify::<UserDoc, _>(&doc_id, |data| {
                    data.name = Some("conflicting write".to_string());
                })
                .await
                .expect("conflicting write must not error");
        })
    }));

    let resolved = get_user_org_domain(&hooked, &inserted.id, TEST_ORG_ID, None)
        .await
        .expect("resolve org domain despite failed backfill write");
    assert_eq!(resolved.as_deref(), Some(TEST_ORG_DOMAIN));

    // The backfill lost every race, so the doc keeps whatever the
    // conflicting writer left — org_domain stays unset.
    let after = store
        .get::<UserDoc>(&inserted.id)
        .await
        .expect("get user")
        .expect("user exists");
    assert_eq!(after.data.org_domain, None);
}
