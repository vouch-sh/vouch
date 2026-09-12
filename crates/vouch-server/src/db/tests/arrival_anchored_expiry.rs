// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Request-deciding expiry comparisons are judged against the caller's
//! instant, not a clock the helper stamps itself.
#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable; cast bounds are obvious in test fixtures"
)]

use super::*;

// ========================================================================
// Every helper below decides whether a request succeeds by comparing a
// stored `expires_at` against an instant. That instant is the request's
// `ArrivalTime`, threaded in by the caller, because the same decision is
// made by several comparisons and they must all read one clock.
//
// A helper that stamped its own clock would read an instant strictly later
// than arrival, so a record still live when the request arrived could be
// rejected if it expired during the intervening awaits — a spurious
// rejection at the tail of every lifetime.
//
// Each test seeds a record that is ALREADY EXPIRED against the wall clock
// and passes an instant from before that expiry. The helper must accept.
// That can only pass if the comparison reads the parameter, so an ambient
// clock reintroduced into any of these helpers fails the test outright
// rather than flaking on a second boundary.
// ========================================================================

/// An instant comfortably in the past, and a record expiring just after it.
/// Both are far enough from "now" that no scheduling delay can blur them.
fn arrival_and_expiry() -> (jiff::Timestamp, jiff::Timestamp) {
    let arrival: jiff::Timestamp = "2020-01-01T00:00:00Z".parse().unwrap();
    let expires_at: jiff::Timestamp = "2020-01-01T00:01:00Z".parse().unwrap();
    (arrival, expires_at)
}

#[tokio::test]
async fn authorization_code_consume_reads_the_callers_instant() {
    let (store, _audit) = test_db().await;
    let (arrival, expires_at) = arrival_and_expiry();

    store_authorization_code(
        &store,
        "arrival-code-hash",
        "client-arrival",
        "user-arrival",
        expires_at,
        None,
    )
    .await
    .expect("seed authorization code");

    let _claim = try_consume_authorization_code(&store, "arrival-code-hash", arrival)
        .await
        .expect("a code live at the caller's instant must be consumable");
}

#[tokio::test]
async fn authorization_code_consume_still_rejects_a_code_expired_at_that_instant() {
    use crate::db::claim::ClaimError;
    let (store, _audit) = test_db().await;
    let (_, expires_at) = arrival_and_expiry();

    store_authorization_code(
        &store,
        "arrival-stale-hash",
        "client-arrival",
        "user-arrival",
        expires_at,
        None,
    )
    .await
    .expect("seed authorization code");

    // One second past the record's expiry: the parameter decides both ways,
    // so threading it cannot have turned the check off.
    let after = expires_at
        .checked_add(jiff::SignedDuration::from_secs(1))
        .unwrap();
    let err = try_consume_authorization_code(&store, "arrival-stale-hash", after)
        .await
        .expect_err("a code expired at the caller's instant must be rejected");
    assert!(
        matches!(err, ClaimError::AlreadyConsumed),
        "expired code must report AlreadyConsumed, got: {err:?}"
    );
}

#[tokio::test]
async fn pending_oauth_lookup_reads_the_callers_instant() {
    let (store, _audit) = test_db().await;

    // `create_pending_oauth_authorization` stamps a 10-minute expiry from the
    // wall clock. The record is therefore live now and expired at any instant
    // past that window, so the two lookups below can only disagree if the
    // comparison reads the instant it is given.
    let id = create_pending_oauth_authorization(
        &store,
        CreatePendingOAuthParams {
            client_id: "client-arrival",
            redirect_uri: "https://example.com/cb",
            response_type: "code",
            state: None,
            scope: None,
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            resource: None,
            acr_values: None,
            max_age: None,
            prompt: None,
            dpop_jkt: None,
            authorization_details: None,
            response_mode: crate::db::documents::oauth::ResponseMode::Query,
            par_request_uri: None,
        },
    )
    .await
    .expect("seed pending oauth authorization");

    assert!(
        get_pending_oauth_authorization(&store, &id, jiff::Timestamp::now())
            .await
            .expect("lookup must not error")
            .is_some(),
        "the record is live at the current instant"
    );

    let past_window: jiff::Timestamp = "2099-12-31T23:59:59Z".parse().unwrap();
    assert!(
        get_pending_oauth_authorization(&store, &id, past_window)
            .await
            .expect("lookup must not error")
            .is_none(),
        "the same record must read as expired at an instant past its window, \
         which is only possible if the comparison uses the caller's instant"
    );
}

#[tokio::test]
async fn scim_token_lookup_reads_the_callers_instant() {
    let (store, _audit) = test_db().await;
    let (arrival, expires_at) = arrival_and_expiry();
    seed_test_org(&store).await;

    let token = create_scim_token(
        &store,
        &CreateScimTokenParams {
            org_id: TEST_ORG_ID,
            token_hash: "arrival-scim-hash",
            description: Some("arrival token"),
            expires_at: Some(expires_at),
            scope: ScimScopeSet::default(),
        },
    )
    .await
    .expect("seed scim token");
    assert!(!token.is_empty(), "token id returned");

    assert!(
        get_scim_token_by_hash(&store, "arrival-scim-hash", arrival)
            .await
            .expect("lookup must not error")
            .is_some(),
        "a token live at the caller's instant must authenticate"
    );
    assert!(
        get_scim_token_by_hash(&store, "arrival-scim-hash", jiff::Timestamp::now())
            .await
            .expect("lookup must not error")
            .is_none(),
        "the same token must read as expired at the current instant"
    );
}

#[tokio::test]
async fn dpop_nonce_consume_reads_the_callers_instant() {
    use crate::db::claim::ClaimError;
    let (store, _audit) = test_db().await;

    // The nonce's expiry is stamped from the wall clock at generation, so it
    // is live now and expired at any instant past that 300-second window.
    let nonce = generate_dpop_nonce(&store, 300).await.expect("seed nonce");
    let past_window: jiff::Timestamp = "2099-12-31T23:59:59Z".parse().unwrap();

    let err = validate_and_consume_dpop_nonce(&store, &nonce, &past_window)
        .await
        .expect_err("a nonce expired at the caller's instant must be rejected");
    assert!(
        matches!(err, ClaimError::AlreadyConsumed),
        "an expired nonce must report AlreadyConsumed, got: {err:?}"
    );

    // The rejected attempt must not have consumed the row: the same nonce
    // still works when judged against an instant inside its window. This is
    // the direction that matters — an ambient clock here would be later than
    // the request's arrival and could reject a nonce that was still live.
    validate_and_consume_dpop_nonce(&store, &nonce, &jiff::Timestamp::now())
        .await
        .expect("a nonce live at the caller's instant must be consumable");
}
