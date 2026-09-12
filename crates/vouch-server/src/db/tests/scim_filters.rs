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

// ========================================================================
// SCIM filter — attribute name anchored to start (not matched inside value)
//
// Pins the fix for the unanchored-substring bug in `parse_scim_filter`: the
// attribute name must be matched at the start of the filter expression, not
// as a bare substring, so a quoted value containing an earlier-tried
// attribute name is no longer misparsed. The parser must return `Ok(None)`
// for a non-matching attribute (so the caller's try-each-attribute loop
// proceeds) and `Ok(Some(..))` for the matching one.
// ========================================================================

#[test]
fn test_scim_filter_parse_returns_none_when_value_contains_attr_name() {
    // Groups try `displayName` before `externalId`. The quoted value
    // `displayName Reviewers Team` contains the `displayName` attribute name
    // followed by two tokens; the pre-fix unanchored `find` matched it and
    // returned `Err(UnsupportedOperator("reviewers"))`. It must return
    // `Ok(None)` so `externalId` is tried next.
    use crate::db::scim::parse_scim_filter;

    let result = parse_scim_filter(
        r#"externalId eq "displayName Reviewers Team""#,
        "displayName",
    )
    .expect("parsing a different-attribute filter must not error");
    assert!(
        result.is_none(),
        "displayName branch must not match an externalId filter whose value contains \
         'displayName'; got {result:?}"
    );
}

#[test]
fn test_scim_filter_parse_rejects_longer_token_with_attr_prefix() {
    // `userNamefoo` starts with `userName` but is a different attribute name.
    // The whitespace boundary after the attribute name must reject it
    // (`Ok(None)`) rather than reading `foo` as the operator.
    use crate::db::scim::parse_scim_filter;

    let result = parse_scim_filter(r#"userNamefoo eq "x""#, "userName")
        .expect("parsing a different-attribute filter must not error");
    assert!(
        result.is_none(),
        "a longer token starting with the attribute name must not match; got {result:?}"
    );
}

#[test]
fn test_scim_filter_parse_finds_externalid_when_value_contains_attr_name() {
    // Positive counterpart: the same filter must parse cleanly against the
    // correct attribute (`externalId`), preserving the value's case exactly
    // as written in the original filter.
    use crate::db::scim::{ScimFilterOp, parse_scim_filter};

    let result = parse_scim_filter(
        r#"externalId eq "displayName Reviewers Team""#,
        "externalId",
    )
    .expect("parsing the matching-attribute filter must succeed");
    let filter = result.expect("externalId branch must match");
    assert_eq!(filter.op, ScimFilterOp::Eq);
    assert_eq!(filter.value, "displayName Reviewers Team");
}

#[test]
fn test_scim_filter_parse_preserves_unsupported_operator_error() {
    // A genuinely unsupported operator on the *matching* attribute must still
    // return `Err(UnsupportedOperator)`. The anchored lookup must not turn
    // real operator errors into a silent `Ok(None)`.
    use crate::db::scim::parse_scim_filter;

    let result = parse_scim_filter(r#"userName gt "alice""#, "userName");
    assert!(
        result.is_err(),
        "unsupported operator on matching attribute must error"
    );
    assert!(
        result.unwrap_err().to_string().contains("gt"),
        "error must mention the unsupported operator"
    );
}

// ========================================================================
// SCIM list — externalId filter whose value contains an earlier-tried attr
//
// End-to-end through `list_scim_groups` / `list_scim_users`. The indexed `eq`
// path tries earlier-tried attributes first and propagates the first `Err`
// via `?`, so a misparse in an earlier branch aborts before the correct one
// is reached. Both group and user paths must locate the matching resource
// instead of surfacing a 400 `invalidFilter`.
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
    )
    .await
    .expect("create group");
    create_scim_group(&store, TEST_ORG_ID, "Marketing", Some("ext-marketing"))
        .await
        .expect("create decoy group");

    let (results, total) = list_scim_groups(
        &store,
        TEST_ORG_ID,
        Some(r#"externalId eq "displayName Reviewers Team""#),
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
        Some(r#"externalId eq "userName alice smith""#),
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
