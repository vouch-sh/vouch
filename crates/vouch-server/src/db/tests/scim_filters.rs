// SPDX-License-Identifier: Apache-2.0 OR MIT
//! SCIM list filter types (which attributes and operators are evaluated) and
//! application-side co/sw matching. Expression parsing is tested in
//! `crate::scim_filter`.
#![expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable; cast bounds are obvious in test fixtures"
)]

use super::*;

// ========================================================================
// SCIM filter parsing — co / sw operators and error path
// ========================================================================

#[tokio::test]
async fn test_scim_user_list_filter_co_operator() {
    let (store, _audit) = test_db().await;
    seed_test_org(&store).await;

    create_scim_user(
        &store,
        Some(TEST_ORG_ID),
        "alice@example.com",
        None,
        None,
        true,
    )
    .await
    .expect("create alice");
    create_scim_user(
        &store,
        Some(TEST_ORG_ID),
        "bob@example.com",
        None,
        None,
        true,
    )
    .await
    .expect("create bob");
    create_scim_user(
        &store,
        Some(TEST_ORG_ID),
        "alicia@example.com",
        None,
        None,
        true,
    )
    .await
    .expect("create alicia");

    // "userName co \"alic\"" should match alice and alicia
    let (results, _) = list_scim_users(
        &store,
        TEST_ORG_ID,
        Some(&user_filter(r#"userName co "alic""#)),
        1,
        100,
    )
    .await
    .expect("list_scim_users failed");
    assert_eq!(
        results.len(),
        2,
        "co filter should match two users; got {}",
        results.len()
    );
    let emails: Vec<&str> = results.iter().map(|u| u.email.as_str()).collect();
    assert!(emails.contains(&"alice@example.com"));
    assert!(emails.contains(&"alicia@example.com"));
}

#[tokio::test]
async fn test_scim_user_list_filter_sw_operator() {
    let (store, _audit) = test_db().await;
    seed_test_org(&store).await;

    create_scim_user(
        &store,
        Some(TEST_ORG_ID),
        "zara@example.com",
        None,
        None,
        true,
    )
    .await
    .expect("create zara");
    create_scim_user(
        &store,
        Some(TEST_ORG_ID),
        "zebra@example.com",
        None,
        None,
        true,
    )
    .await
    .expect("create zebra");
    create_scim_user(
        &store,
        Some(TEST_ORG_ID),
        "anna@example.com",
        None,
        None,
        true,
    )
    .await
    .expect("create anna");

    // "userName sw \"ze\"" should match zara? no — "ze" prefix: zebra matches, zara does not.
    let (results, _) = list_scim_users(
        &store,
        TEST_ORG_ID,
        Some(&user_filter(r#"userName sw "ze""#)),
        1,
        100,
    )
    .await
    .expect("list_scim_users failed");
    assert_eq!(results.len(), 1, "sw filter should match zebra only");
    assert_eq!(results[0].email, "zebra@example.com");
}

// ========================================================================
// SCIM filter — multibyte / CJK character handling
// ========================================================================

#[tokio::test]
async fn test_scim_groups_externalid_eq_value_containing_attr_name_finds_group() {
    // The reported repro: a group whose `externalId` value contains the
    // `displayName` attribute name followed by two tokens. Pre-fix this
    // returned `Err(unsupported filter operator 'reviewers')` (HTTP 400).
    let (store, _audit) = test_db().await;
    seed_test_org(&store).await;
    create_scim_group(
        &store,
        TEST_ORG_ID,
        "Engineering",
        Some("displayName Reviewers Team"),
        &[],
    )
    .await
    .expect("create group");
    create_scim_group(&store, TEST_ORG_ID, "Marketing", Some("ext-marketing"), &[])
        .await
        .expect("create decoy group");

    let (results, total) = list_scim_groups(
        &store,
        TEST_ORG_ID,
        Some(&group_filter(
            r#"externalId eq "displayName Reviewers Team""#,
        )),
        1,
        100,
    )
    .await
    .expect("indexed externalId eq lookup must not return a 400-equivalent error");

    assert_eq!(total, 1, "exactly one group matches the externalId filter");
    assert_eq!(results.len(), 1, "one result on the page");
    assert_eq!(results[0].display_name, "Engineering");
    assert_eq!(
        results[0].external_id.as_deref(),
        Some("displayName Reviewers Team")
    );
}

#[tokio::test]
async fn test_scim_users_externalid_eq_value_containing_attr_name_finds_user() {
    // Users try `userName` then `email` then `externalId`. A value containing
    // `username` followed by two tokens must reach the `externalId` branch.
    // Pre-fix this returned `Err(unsupported filter operator 'alice')`.
    let (store, _audit) = test_db().await;
    seed_test_org(&store).await;
    create_scim_user(
        &store,
        Some(TEST_ORG_ID),
        "alice@example.com",
        None,
        Some("userName alice smith"),
        true,
    )
    .await
    .expect("create alice");
    create_scim_user(
        &store,
        Some(TEST_ORG_ID),
        "bob@example.com",
        None,
        Some("ext-bob"),
        true,
    )
    .await
    .expect("create bob");

    let (results, total) = list_scim_users(
        &store,
        TEST_ORG_ID,
        Some(&user_filter(r#"externalId eq "userName alice smith""#)),
        1,
        100,
    )
    .await
    .expect("indexed externalId eq lookup must not return a 400-equivalent error");

    assert_eq!(total, 1, "exactly one user matches the externalId filter");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].email, "alice@example.com");
    assert_eq!(
        results[0].external_id.as_deref(),
        Some("userName alice smith")
    );
}

// RFC 7644 §3.12 Table 9: `invalidFilter` when "the specified attribute and
// filter comparison combination is not supported". An attribute or operator
// the list filters do not evaluate is declined, never read as "no filter".
#[test]
fn test_list_filters_decline_unsupported_attributes_and_operators() {
    use crate::db::{GroupListFilter, UserListFilter};
    use crate::scim_filter::parse;

    const USER: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
    const GROUP: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
    for filter in [
        r#"id eq "u1""#,
        r#"emails.value eq "a@example.com""#,
        r#"userNamefoo eq "a""#,
        r#"title eq "x""#,
        r#"userName ne "a""#,
        r#"userName ew "a""#,
        r#"userName gt "a""#,
        "userName eq 5",
        "externalId eq true",
    ] {
        let exp = parse(filter, USER).expect("well-formed");
        assert!(UserListFilter::try_from(exp).is_err(), "{filter}");
    }
    for filter in [
        r#"id eq "g1""#,
        r#"members.value eq "u1""#,
        r#"displayName le "a""#,
    ] {
        let exp = parse(filter, GROUP).expect("well-formed");
        assert!(GroupListFilter::try_from(exp).is_err(), "{filter}");
    }
}

// `email` is accepted as an alias of `userName` (both address the stored
// email), and a core-URN-qualified attribute is the same attribute.
#[test]
fn test_list_filters_accept_supported_attributes() {
    use crate::db::{GroupListFilter, UserListFilter};
    use crate::scim_filter::parse;

    const USER: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
    const GROUP: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
    for filter in [
        r#"userName eq "a""#,
        r#"email co "a""#,
        r#"urn:ietf:params:scim:schemas:core:2.0:User:externalId sw "e""#,
    ] {
        let exp = parse(filter, USER).expect("well-formed");
        assert!(UserListFilter::try_from(exp).is_ok(), "{filter}");
    }
    for filter in [r#"displayName eq "a""#, r#"EXTERNALID co "e""#] {
        let exp = parse(filter, GROUP).expect("well-formed");
        assert!(GroupListFilter::try_from(exp).is_ok(), "{filter}");
    }
}
