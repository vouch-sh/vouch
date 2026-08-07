// SPDX-License-Identifier: Apache-2.0 OR MIT
//! SCIM filter parsing and application-side co/sw matching, including multibyte input.
#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable; cast bounds are obvious in test fixtures"
)]

use super::*;

// ========================================================================
// SCIM filter parsing — co / sw operators and error path
// ========================================================================

#[test]
fn test_scim_filter_parse_co_operator() {
    use crate::db::scim::{ScimFilterOp, parse_scim_filter};

    let result =
        parse_scim_filter(r#"userName co "smith""#, "userName").expect("parse should succeed");
    let filter = result.expect("filter should be present");
    assert_eq!(filter.op, ScimFilterOp::Co);
    assert_eq!(filter.value, "smith");
}

#[test]
fn test_scim_filter_parse_sw_operator() {
    use crate::db::scim::{ScimFilterOp, parse_scim_filter};

    let result =
        parse_scim_filter(r#"userName sw "alice""#, "userName").expect("parse should succeed");
    let filter = result.expect("filter should be present");
    assert_eq!(filter.op, ScimFilterOp::Sw);
    assert_eq!(filter.value, "alice");
}

#[test]
fn test_scim_filter_parse_unsupported_operator_returns_error() {
    use crate::db::scim::parse_scim_filter;

    let result = parse_scim_filter(r#"userName gt "alice""#, "userName");
    assert!(result.is_err(), "Unsupported operator should return Err");
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("gt"),
        "Error should mention the unsupported operator"
    );
}

#[test]
fn test_scim_filter_parse_no_match_for_other_attribute() {
    use crate::db::scim::parse_scim_filter;

    let result =
        parse_scim_filter(r#"externalId eq "ext-1""#, "userName").expect("parse should not error");
    assert!(
        result.is_none(),
        "Filter for different attribute should return None"
    );
}

// ========================================================================
// SCIM list — co / sw filter operators applied in app code
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
    let (results, _) = list_scim_users(&store, TEST_ORG_ID, Some(r#"userName co "alic""#), 1, 100)
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
    let (results, _) = list_scim_users(&store, TEST_ORG_ID, Some(r#"userName sw "ze""#), 1, 100)
        .await
        .expect("list_scim_users failed");
    assert_eq!(results.len(), 1, "sw filter should match zebra only");
    assert_eq!(results[0].email, "zebra@example.com");
}

// ========================================================================
// SCIM filter — multibyte / CJK character handling
// ========================================================================

#[test]
fn test_scim_filter_parse_cjk_value() {
    use crate::db::scim::{ScimFilterOp, parse_scim_filter};

    let result = parse_scim_filter(r#"displayName eq "山田太郎""#, "displayName")
        .expect("parse should succeed");
    let filter = result.expect("filter should be present");
    assert_eq!(filter.op, ScimFilterOp::Eq);
    assert_eq!(filter.value, "山田太郎");
}

#[test]
fn test_scim_filter_parse_cjk_co_operator() {
    use crate::db::scim::{ScimFilterOp, parse_scim_filter};

    let result =
        parse_scim_filter(r#"displayName co "田中""#, "displayName").expect("parse should succeed");
    let filter = result.expect("filter should be present");
    assert_eq!(filter.op, ScimFilterOp::Co);
    assert_eq!(filter.value, "田中");
}

#[test]
fn test_scim_filter_parse_emoji_value() {
    use crate::db::scim::{ScimFilterOp, parse_scim_filter};

    let result = parse_scim_filter(r#"displayName eq "Test 🔑 Key""#, "displayName")
        .expect("parse should succeed");
    let filter = result.expect("filter should be present");
    assert_eq!(filter.op, ScimFilterOp::Eq);
    assert_eq!(filter.value, "Test 🔑 Key");
}
