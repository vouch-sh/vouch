// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `store_session` must not let a previous session's cached credentials
//! survive into a replacement session owned by a different identity.
//!
//! The credential-cache key is not user-specific (it is built from
//! role/provider parameters, never the Vouch user's email), so two distinct
//! Vouch identities who can both assume the same role produce the same key.
//! Without a credential drop on the replace path, a second identity logging
//! in on the same OS account would inherit the first user's still-valid cached
//! credentials, authenticating the second user as the first user's principal
//! until the cached entries' TTL elapsed.
//!
//! These tests pin the fix: a cross-identity `store_session` clears the cache,
//! a same-identity re-login (token refresh) keeps it, and the explicit-logout
//! path (`clear_session`) still clears it.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code: panicking on an assertion failure is the point"
)]

use vouch_agent::state::{AgentState, CachedCredential, Session};

use jiff::Timestamp;
use secrecy::SecretString;

/// A timestamp `seconds` in the future.
fn future_timestamp(seconds: i64) -> Timestamp {
    Timestamp::from_second(Timestamp::now().as_second().saturating_add(seconds)).unwrap()
}

/// A timestamp `seconds` in the past.
fn past_timestamp(seconds: i64) -> Timestamp {
    Timestamp::from_second(Timestamp::now().as_second().saturating_sub(seconds)).unwrap()
}

/// Build a live session for `email` with a 1 h expiry.
fn make_session(email: &str) -> Session {
    Session::new(
        SecretString::from("test_jwt_token"),
        email.to_string(),
        future_timestamp(3600),
    )
}

/// An AWS-role-shaped cached credential carrying `key`/`secret`, valid 1 h.
fn aws_credential(key: &str, secret: &str) -> CachedCredential {
    CachedCredential::new(
        serde_json::json!({
            "AccessKeyId": key,
            "SecretAccessKey": secret,
        }),
        future_timestamp(3600),
    )
}

/// Replacing the session with a different identity drops the previous session's
/// cached credentials — the cross-identity leak the bug report describes.
#[tokio::test]
async fn store_session_replacement_clears_prior_session_cached_credentials() {
    let state = AgentState::new();

    // User A logs in and caches AWS role credentials.
    state
        .store_session(
            make_session("user-A@example.com"),
            Some("https://server-A.com".to_string()),
        )
        .await;
    let aws_role = "aws:arn:aws:iam::123456789012:role/Example".to_string();
    state
        .cache_credential(aws_role.clone(), aws_credential("AKIA_A", "secretA"))
        .await;
    assert!(state.get_cached_credential(&aws_role).await.is_some());

    // User B logs in, replacing the identity.
    state
        .store_session(
            make_session("user-B@example.com"),
            Some("https://server-B.com".to_string()),
        )
        .await;

    // The new session is B's.
    assert_eq!(
        state.get_session().await.unwrap().user_email(),
        "user-B@example.com"
    );

    // A's cached credential must not be served under B's session. Before the
    // fix this returned Some, leaking A's AccessKeyId/SecretAccessKey to B.
    assert!(
        state.get_cached_credential(&aws_role).await.is_none(),
        "cross-identity replacement must not leak the prior session's cached credential"
    );
    assert_eq!(
        state.get_ssh_server_url().await.as_deref(),
        Some("https://server-B.com"),
        "the new session's server URL replaces the old one"
    );
}

/// Multiple cached entries from the prior identity are all dropped on a
/// cross-identity replacement, not just the one the new user happens to request
/// next. Each cache key is shared across identities, so any survivor leaks.
#[tokio::test]
async fn store_session_replacement_clears_all_cached_credentials() {
    let state = AgentState::new();
    state
        .store_session(make_session("alice@example.com"), None)
        .await;

    state
        .cache_credential("aws:role1".to_string(), aws_credential("ak1", "s1"))
        .await;
    state
        .cache_credential("aws:role2".to_string(), aws_credential("ak2", "s2"))
        .await;
    state
        .cache_credential("github:org".to_string(), aws_credential("ghs_a", "x"))
        .await;
    assert!(state.get_cached_credential("aws:role1").await.is_some());
    assert!(state.get_cached_credential("aws:role2").await.is_some());
    assert!(state.get_cached_credential("github:org").await.is_some());

    state
        .store_session(make_session("bob@example.com"), None)
        .await;

    assert!(state.get_cached_credential("aws:role1").await.is_none());
    assert!(state.get_cached_credential("aws:role2").await.is_none());
    assert!(state.get_cached_credential("github:org").await.is_none());
}

/// The new identity can cache and fetch its own credentials after the
/// replacement — the cleared cache is writeable, and a fresh entry is served.
#[tokio::test]
async fn store_session_replacement_lets_new_identity_cache_fresh_credentials() {
    let state = AgentState::new();
    state
        .store_session(make_session("alice@example.com"), None)
        .await;
    state
        .cache_credential("aws:role".to_string(), aws_credential("AKIA_A", "secretA"))
        .await;

    state
        .store_session(make_session("bob@example.com"), None)
        .await;
    // Cache is empty immediately after the replacement.
    assert!(state.get_cached_credential("aws:role").await.is_none());

    // Bob caches his own credentials for the same role and gets them back.
    state
        .cache_credential("aws:role".to_string(), aws_credential("AKIA_B", "secretB"))
        .await;
    let cached = state
        .get_cached_credential("aws:role")
        .await
        .expect("Bob's freshly cached credential should be served");
    let data = cached.data();
    assert_eq!(
        data.get("AccessKeyId").and_then(|v| v.as_str()),
        Some("AKIA_B")
    );
    assert_eq!(
        data.get("SecretAccessKey").and_then(|v| v.as_str()),
        Some("secretB")
    );
}

/// A same-identity re-login (token refresh) keeps the cache: those entries were
/// authorized by the same user's prior token and remain TTL-bounded, and
/// dropping them would cost an extra round-trip per previously cached role.
#[tokio::test]
async fn store_session_same_identity_keeps_cached_credentials() {
    let state = AgentState::new();
    state
        .store_session(make_session("alice@example.com"), None)
        .await;
    let role = "aws:arn:aws:iam::123456789012:role/Example".to_string();
    state
        .cache_credential(role.clone(), aws_credential("AKIA_A", "secretA"))
        .await;

    // Alice re-logs in (token refresh) — same identity.
    state
        .store_session(make_session("alice@example.com"), None)
        .await;
    assert_eq!(
        state.get_session().await.unwrap().user_email(),
        "alice@example.com"
    );
    let cached = state
        .get_cached_credential(&role)
        .await
        .expect("same-identity refresh should keep the cached credential");
    let data = cached.data();
    assert_eq!(
        data.get("AccessKeyId").and_then(|v| v.as_str()),
        Some("AKIA_A")
    );
}

/// A re-login after the prior session expired by time still clears the cache
/// when the identity changes — the no-logout-then-relogin-after-expiry path
/// that the expiry monitor documents as a supported flow. The expiry monitor
/// only notifies on expiry; it never clears the cache, so `store_session` must.
#[tokio::test]
async fn store_session_replacement_after_expiry_clears_cache_on_identity_change() {
    let state = AgentState::new();
    // Alice's session, already expired (simulating elapsed session lifetime).
    state
        .store_session(
            Session::new(
                SecretString::from("tokenA"),
                "alice@example.com".to_string(),
                past_timestamp(1),
            ),
            None,
        )
        .await;
    let role = "aws:arn:aws:iam::123456789012:role/Example".to_string();
    state
        .cache_credential(role.clone(), aws_credential("AKIA_A", "secretA"))
        .await;
    // The cache serves valid (unexpired) credentials even though the session
    // is expired — the cache has no session gate.
    assert!(state.get_cached_credential(&role).await.is_some());

    // Bob logs in, replacing the expired Alice session.
    state
        .store_session(make_session("bob@example.com"), None)
        .await;
    assert_eq!(
        state.get_session().await.unwrap().user_email(),
        "bob@example.com"
    );
    assert!(
        state.get_cached_credential(&role).await.is_none(),
        "replacing an expired session with a new identity must still clear the cache"
    );
}

/// The explicit-logout path (`clear_session`) still clears the cache — the
/// asymmetry that originally left the cache readable only on the replace path
/// must not regress in the other direction. This mirrors the pre-existing
/// `test_clear_session_also_clears_credential_cache` in `state.rs`.
#[tokio::test]
async fn clear_session_still_clears_cache() {
    let state = AgentState::new();
    state
        .store_session(make_session("user@example.com"), None)
        .await;
    state
        .cache_credential("aws:role".to_string(), aws_credential("AK", "s"))
        .await;
    assert!(state.get_cached_credential("aws:role").await.is_some());
    assert!(state.get_session().await.is_some());

    state.clear_session().await;

    assert!(state.get_session().await.is_none());
    assert!(state.get_cached_credential("aws:role").await.is_none());
}

/// `cache_credential` has no session gate (unlike `store_ssh_credentials`,
/// which refuses without a live session). A cache entry can therefore exist
/// with no session at all — which is exactly why the store_session clear is
/// necessary: the cache cannot rely on a session check to scope entries.
#[tokio::test]
async fn cache_credential_stores_without_session() {
    let state = AgentState::new();
    assert!(state.get_session().await.is_none());

    assert!(
        state
            .cache_credential("aws:role".to_string(), aws_credential("AK", "s"))
            .await,
        "cache_credential accepts an entry with no live session"
    );
    let cached = state
        .get_cached_credential("aws:role")
        .await
        .expect("the entry is served despite there being no session");
    assert_eq!(
        cached.data().get("AccessKeyId").and_then(|v| v.as_str()),
        Some("AK")
    );
}
