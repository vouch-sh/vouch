// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Integration tests for per-org OIDC issuer signing-key rotation (issue #626).
//!
//! The rotation model matches Auth0's: a pre-staged Next key is always
//! published alongside the Current signer, an operator rotate promotes it
//! (demoting the old signer to a verify-only Previous key), and an operator
//! revoke deletes the Previous key after the token-drain window. Nothing
//! transitions on a timer.
//!
//! All tests use `test_app_state_encrypted()` so the document store encrypts
//! at rest and per-org keys are actually created — under the default
//! plaintext state the feature falls back to the shared key.
//!
//! The invariant proptest at the bottom drives a synchronous model of the
//! state machine rather than generated async interleavings: concurrency is
//! covered by the explicit `tokio::spawn` test, and `proptest` has no tokio
//! integration worth the harness cost.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code: panicking on an assertion failure is the point"
)]

use std::sync::Arc;

use jiff::{Span, Timestamp};
use proptest::prelude::*;
use vouch_server::crypto::alg::JwsAlgorithm;
use vouch_server::crypto::keys::Jwk;
use vouch_server::db::{AuditEventFilter, SigningKeyState};
use vouch_server::services::oidc::{
    Operator, RevokeOutcome, RotateOutcome, emergency_rotate_org_keys, org_jwks, resolve_org_keys,
    revoke_org_previous_keys, rotate_org_keys,
};
use vouch_server::{db, test_utils};

const ADMIN: Operator<'static> = Operator {
    user_id: Some("test-admin-user-id"),
    email: Some("admin@acme.com"),
};

// ============================================================================
// Setup helpers
// ============================================================================

/// Create an encrypted `AppState`, an org (`"acme.com"`), and claim the
/// `"acme-com"` subdomain (derived from the registrable apex `acme.com`).
/// Each call creates a fresh in-memory SQLite so tests are fully isolated.
async fn setup_org() -> (Arc<vouch_server::AppState>, vouch_server::db::Organization) {
    let state = test_utils::test_app_state_encrypted().await;
    let org = test_utils::create_test_org(&state.store, "acme.com").await;
    db::claim_subdomain(&state.store, &org.id, "acme-com")
        .await
        .unwrap();
    // Reload the org so the subdomain field is populated.
    let org = db::get_organization(&state.store, &org.id)
        .await
        .unwrap()
        .unwrap();
    (state, org)
}

/// Bootstrap the org's key set (Current + Next per algorithm) and return the
/// Current ES256 kid for later comparisons.
async fn bootstrap(
    state: &Arc<vouch_server::AppState>,
    org: &vouch_server::db::Organization,
) -> String {
    let snap = resolve_org_keys(state, Some(org))
        .await
        .expect("resolve_org_keys")
        .expect("keys must exist on an encrypted store with a subdomain");
    snap.signers.es256.key_id().to_string()
}

/// Rewrite a key's publish/demotion timestamp so gate tests don't sleep.
async fn backdate(
    state: &vouch_server::AppState,
    org_id: &str,
    alg: JwsAlgorithm,
    key_state: SigningKeyState,
    hours: i64,
) {
    let id = db::deterministic_org_key_id(org_id, alg, key_state);
    let doc = state
        .store
        .get::<db::OrgSigningKeyDoc>(&id)
        .await
        .unwrap()
        .expect("key to backdate must exist");
    let past = Timestamp::now()
        .checked_sub(Span::new().hours(hours))
        .unwrap();
    let mut data = doc.data;
    match key_state {
        SigningKeyState::Next => data.staged_at = Some(past),
        SigningKeyState::Previous => data.demoted_at = Some(past),
        SigningKeyState::Current => panic!("current keys have no timestamp to backdate"),
    }
    state.store.update(&id, &data).await.unwrap();
}

/// Age both algorithms' Next keys past the publish window.
async fn age_next_keys(state: &vouch_server::AppState, org_id: &str) {
    for alg in [JwsAlgorithm::Es256, JwsAlgorithm::Rs256] {
        backdate(state, org_id, alg, SigningKeyState::Next, 25).await;
    }
}

/// Age both algorithms' Previous keys past the token-drain window.
async fn age_previous_keys(state: &vouch_server::AppState, org_id: &str) {
    for alg in [JwsAlgorithm::Es256, JwsAlgorithm::Rs256] {
        backdate(state, org_id, alg, SigningKeyState::Previous, 30).await;
    }
}

/// Extract all `kid` values from a JWKS response.
fn kids(jwks: &[Jwk]) -> Vec<String> {
    jwks.iter()
        .map(|j| match j {
            Jwk::Rsa(rsa) => rsa.kid.clone(),
            Jwk::Ec(ec) => ec.kid.clone(),
        })
        .collect()
}

/// Query audit events of one type.
async fn audit_events(
    state: &vouch_server::AppState,
    event_type: &str,
) -> Vec<vouch_server::db::AuditEvent> {
    state
        .audit
        .query_events(&AuditEventFilter {
            event_types: Some(vec![event_type.to_string()]),
            ..AuditEventFilter::default()
        })
        .await
        .expect("query audit events")
}

// ============================================================================
// First use: the always-staged invariant
// ============================================================================

#[tokio::test]
async fn first_use_publishes_current_and_next_for_both_algorithms() {
    let (state, org) = setup_org().await;
    bootstrap(&state, &org).await;

    let jwks = org_jwks(&state, &org).await.unwrap();
    assert_eq!(
        jwks.keys.len(),
        4,
        "Current + Next for both algorithms from day one"
    );

    // RS256 keys precede ES256 keys (OIDC Core §3.1.3.7), kids are distinct.
    let mut saw_ec = false;
    for jwk in &jwks.keys {
        match jwk {
            Jwk::Rsa(_) => assert!(!saw_ec, "RSA JWK after an EC JWK"),
            Jwk::Ec(_) => saw_ec = true,
        }
    }
    let all = kids(&jwks.keys);
    let unique: std::collections::HashSet<&String> = all.iter().collect();
    assert_eq!(all.len(), unique.len(), "duplicate kids in JWKS: {all:?}");

    for alg in [JwsAlgorithm::Es256, JwsAlgorithm::Rs256] {
        let next = db::get_org_signing_key(&state.store, &org.id, alg, SigningKeyState::Next)
            .await
            .unwrap()
            .expect("next key must exist after first use");
        assert!(next.data.staged_at.is_some());
    }
}

// ============================================================================
// Rotate
// ============================================================================

#[tokio::test]
async fn rotate_switches_signing_and_keeps_the_old_key_verifiable() {
    let (state, org) = setup_org().await;
    let old_es256_kid = bootstrap(&state, &org).await;
    age_next_keys(&state, &org.id).await;

    let outcome = rotate_org_keys(&state, &org.id, ADMIN).await.unwrap();
    let RotateOutcome::Rotated { es256, rs256 } = outcome else {
        panic!("expected Rotated, got {outcome:?}");
    };
    assert_eq!(es256.old_kid, old_es256_kid);

    // The promoted key signs; the demoted key stays published for
    // verification; a fresh Next is already staged for the next rotation.
    let snap = resolve_org_keys(&state, Some(&org)).await.unwrap().unwrap();
    assert_eq!(snap.signers.es256.key_id(), es256.new_kid);
    assert_eq!(snap.signers.rs256.key_id(), rs256.new_kid);

    let jwks = org_jwks(&state, &org).await.unwrap();
    let published = kids(&jwks.keys);
    assert_eq!(
        published.len(),
        6,
        "Current + Next + Previous per algorithm"
    );
    assert!(
        published.contains(&old_es256_kid),
        "old kid must stay published while its tokens drain"
    );

    // One audit event per algorithm, carrying the operator identity and the
    // exact kids involved.
    let events = audit_events(&state, "org_issuer_key_rotated").await;
    assert_eq!(events.len(), 2, "one rotate event per algorithm");
    for event in &events {
        assert_eq!(event.user_id.as_deref(), Some("test-admin-user-id"));
        assert_eq!(event.email_domain.as_deref(), Some("acme.com"));
        let data: serde_json::Value = serde_json::from_str(&event.data).unwrap();
        let (expected_old, expected_new) = if data["alg"] == "ES256" {
            (&es256.old_kid, &es256.new_kid)
        } else {
            (&rs256.old_kid, &rs256.new_kid)
        };
        assert_eq!(data["old_kid"].as_str(), Some(expected_old.as_str()));
        assert_eq!(data["new_kid"].as_str(), Some(expected_new.as_str()));
    }
}

#[tokio::test]
async fn rotate_is_rejected_until_gates_clear() {
    let (state, org) = setup_org().await;
    bootstrap(&state, &org).await;

    // Freshly staged Next keys: publish window still open.
    let outcome = rotate_org_keys(&state, &org.id, ADMIN).await.unwrap();
    assert!(
        matches!(outcome, RotateOutcome::NextNotReady { .. }),
        "expected NextNotReady, got {outcome:?}"
    );
    // A rejected rotate writes nothing and emits no audit events.
    assert!(
        audit_events(&state, "org_issuer_key_rotated")
            .await
            .is_empty()
    );

    age_next_keys(&state, &org.id).await;
    let outcome = rotate_org_keys(&state, &org.id, ADMIN).await.unwrap();
    assert!(matches!(outcome, RotateOutcome::Rotated { .. }));

    // A second rotate is blocked by the unrevoked Previous keys, even after
    // the freshly restaged Next keys age past the publish window.
    age_next_keys(&state, &org.id).await;
    let outcome = rotate_org_keys(&state, &org.id, ADMIN).await.unwrap();
    assert_eq!(outcome, RotateOutcome::PreviousUnrevoked);
}

#[tokio::test]
async fn concurrent_rotates_promote_exactly_once() {
    let (state, org) = setup_org().await;
    bootstrap(&state, &org).await;
    age_next_keys(&state, &org.id).await;

    let mut handles = Vec::new();
    for _ in 0..8 {
        let state = Arc::clone(&state);
        let org_id = org.id.clone();
        handles.push(tokio::spawn(async move {
            rotate_org_keys(&state, &org_id, ADMIN).await
        }));
    }
    let mut rotated = 0;
    for handle in handles {
        match handle.await.unwrap() {
            Ok(RotateOutcome::Rotated { .. }) => rotated += 1,
            // Losers see the winner's state: a fresh (young) Next key or the
            // Previous key the winner wrote. Neither is an error.
            Ok(RotateOutcome::PreviousUnrevoked | RotateOutcome::NextNotReady { .. }) => {}
            other => panic!("unexpected concurrent rotate result: {other:?}"),
        }
    }
    assert_eq!(rotated, 1, "exactly one concurrent rotate must win");

    // Exactly one Current signer per algorithm afterwards.
    for alg in [JwsAlgorithm::Es256, JwsAlgorithm::Rs256] {
        let current = db::get_org_signing_key(&state.store, &org.id, alg, SigningKeyState::Current)
            .await
            .unwrap();
        assert!(current.is_some(), "{alg:?}: current key must exist");
    }
    let events = audit_events(&state, "org_issuer_key_rotated").await;
    assert_eq!(events.len(), 2, "only the winner emits audit events");
}

// ============================================================================
// Revoke
// ============================================================================

#[tokio::test]
async fn revoke_deletes_previous_keys_after_the_drain_window() {
    let (state, org) = setup_org().await;
    let old_es256_kid = bootstrap(&state, &org).await;
    age_next_keys(&state, &org.id).await;
    let rotate_outcome = rotate_org_keys(&state, &org.id, ADMIN).await.unwrap();
    let RotateOutcome::Rotated { rs256, .. } = rotate_outcome else {
        panic!("expected Rotated, got {rotate_outcome:?}");
    };

    // Directly after the rotate the drain window is open: tokens signed by
    // the old key may still be live.
    let outcome = revoke_org_previous_keys(&state, &org.id, ADMIN)
        .await
        .unwrap();
    assert!(
        matches!(outcome, RevokeOutcome::NotReady { .. }),
        "expected NotReady, got {outcome:?}"
    );

    age_previous_keys(&state, &org.id).await;
    let outcome = revoke_org_previous_keys(&state, &org.id, ADMIN)
        .await
        .unwrap();
    let RevokeOutcome::Revoked {
        es256_kid,
        rs256_kid,
    } = outcome
    else {
        panic!("expected Revoked, got {outcome:?}");
    };
    assert_eq!(es256_kid.as_deref(), Some(old_es256_kid.as_str()));
    assert_eq!(rs256_kid.as_deref(), Some(rs256.old_kid.as_str()));

    // The revoked kid is gone from the JWKS; Current + Next remain.
    let jwks = org_jwks(&state, &org).await.unwrap();
    let published = kids(&jwks.keys);
    assert_eq!(published.len(), 4);
    assert!(!published.contains(&old_es256_kid));

    let events = audit_events(&state, "org_issuer_key_revoked").await;
    assert_eq!(events.len(), 2, "one revoke event per algorithm");
    for event in &events {
        assert_eq!(event.user_id.as_deref(), Some("test-admin-user-id"));
        assert_eq!(event.email_domain.as_deref(), Some("acme.com"));
        let data: serde_json::Value = serde_json::from_str(&event.data).unwrap();
        if data["alg"] == "ES256" {
            assert_eq!(data["kid"].as_str(), Some(old_es256_kid.as_str()));
        }
    }

    // Idempotent from the operator's point of view: nothing left to revoke.
    let outcome = revoke_org_previous_keys(&state, &org.id, ADMIN)
        .await
        .unwrap();
    assert_eq!(outcome, RevokeOutcome::NothingToRevoke);
}

#[tokio::test]
async fn concurrent_revokes_delete_and_audit_exactly_once() {
    let (state, org) = setup_org().await;
    bootstrap(&state, &org).await;
    age_next_keys(&state, &org.id).await;
    rotate_org_keys(&state, &org.id, ADMIN).await.unwrap();
    age_previous_keys(&state, &org.id).await;

    let mut handles = Vec::new();
    for _ in 0..8 {
        let state = Arc::clone(&state);
        let org_id = org.id.clone();
        handles.push(tokio::spawn(async move {
            revoke_org_previous_keys(&state, &org_id, ADMIN).await
        }));
    }
    let mut revoked = 0;
    for handle in handles {
        match handle.await.unwrap() {
            Ok(RevokeOutcome::Revoked { .. }) => revoked += 1,
            Ok(RevokeOutcome::NothingToRevoke) => {}
            other => panic!("unexpected concurrent revoke result: {other:?}"),
        }
    }
    assert_eq!(revoked, 1, "exactly one concurrent revoke must win");

    let events = audit_events(&state, "org_issuer_key_revoked").await;
    assert_eq!(events.len(), 2, "only the winner emits audit events");
}

// ============================================================================
// Emergency
// ============================================================================

#[tokio::test]
async fn emergency_replaces_the_entire_key_set_immediately() {
    let (state, org) = setup_org().await;
    bootstrap(&state, &org).await;
    // Leave a Previous key around so the emergency provably clears it.
    age_next_keys(&state, &org.id).await;
    rotate_org_keys(&state, &org.id, ADMIN).await.unwrap();

    let before = kids(&org_jwks(&state, &org).await.unwrap().keys);

    emergency_rotate_org_keys(&state, &org.id, ADMIN)
        .await
        .unwrap();

    // Every key that existed before the emergency is gone from the JWKS —
    // Current, Next, and Previous alike.
    let after = kids(&org_jwks(&state, &org).await.unwrap().keys);
    assert_eq!(after.len(), 4, "fresh Current + Next per algorithm");
    for old in &before {
        assert!(
            !after.contains(old),
            "pre-incident kid {old} must not survive an emergency"
        );
    }
    for alg in [JwsAlgorithm::Es256, JwsAlgorithm::Rs256] {
        assert!(
            db::get_org_signing_key(&state.store, &org.id, alg, SigningKeyState::Previous)
                .await
                .unwrap()
                .is_none(),
            "{alg:?}: previous key must be deleted outright"
        );
    }

    let events = audit_events(&state, "org_issuer_key_emergency_rotation").await;
    assert_eq!(events.len(), 2, "one emergency event per algorithm");
    for event in &events {
        assert_eq!(event.user_id.as_deref(), Some("test-admin-user-id"));
        assert_eq!(event.email_domain.as_deref(), Some("acme.com"));
    }
}

// ============================================================================
// Subdomain release / reclaim
// ============================================================================

#[tokio::test]
async fn release_cancels_rotation_state_and_reclaim_restages_fresh() {
    let (state, org) = setup_org().await;
    bootstrap(&state, &org).await;
    age_next_keys(&state, &org.id).await;
    rotate_org_keys(&state, &org.id, ADMIN).await.unwrap();
    let current_before = db::get_org_signing_key(
        &state.store,
        &org.id,
        JwsAlgorithm::Es256,
        SigningKeyState::Current,
    )
    .await
    .unwrap()
    .unwrap();

    db::release_subdomain(&state.store, &org.id).await.unwrap();

    // Release keeps the Current signer but drops Next and Previous: the
    // publish window is void while the issuer host is unclaimed, and a
    // reclaim must not inherit a stale successor.
    for alg in [JwsAlgorithm::Es256, JwsAlgorithm::Rs256] {
        for key_state in [SigningKeyState::Next, SigningKeyState::Previous] {
            assert!(
                db::get_org_signing_key(&state.store, &org.id, alg, key_state)
                    .await
                    .unwrap()
                    .is_none(),
                "{alg:?} {key_state:?} key must be deleted on release"
            );
        }
    }

    // While released, a resolve returns nothing and purges the cached
    // snapshot, so the reclaim below cannot see pre-release keys.
    let released_org = db::get_organization(&state.store, &org.id)
        .await
        .unwrap()
        .unwrap();
    assert!(
        resolve_org_keys(&state, Some(&released_org))
            .await
            .unwrap()
            .is_none(),
        "a released org resolves to no per-org keys"
    );

    // Same-org reclaim: the Current key carries over (same org, same trust),
    // and the first use restages a fresh Next with a fresh publish window.
    db::claim_subdomain(&state.store, &org.id, "acme-com")
        .await
        .unwrap();
    let org = db::get_organization(&state.store, &org.id)
        .await
        .unwrap()
        .unwrap();
    let snap = resolve_org_keys(&state, Some(&org)).await.unwrap().unwrap();
    assert_eq!(
        snap.signers.es256.key_id(),
        current_before.data.kid,
        "reclaim must not change the signing key"
    );
    let next = db::get_org_signing_key(
        &state.store,
        &org.id,
        JwsAlgorithm::Es256,
        SigningKeyState::Next,
    )
    .await
    .unwrap()
    .expect("fresh next key after reclaim");
    let staged_at = next.data.staged_at.unwrap();
    let age = Timestamp::now().since(staged_at).unwrap();
    assert!(
        age.get_hours() < 1,
        "restaged next key must have a fresh publish window"
    );

    // The fresh Next gates rotation for a full publish window again.
    let outcome = rotate_org_keys(&state, &org.id, ADMIN).await.unwrap();
    assert!(matches!(outcome, RotateOutcome::NextNotReady { .. }));
}

#[tokio::test]
async fn auto_release_via_domain_removal_cancels_rotation_state() {
    // The subdomain here is backed by an additional verified domain; removing
    // that domain auto-releases the subdomain, which must also drop the Next
    // and Previous keys (same rule as a manual release).
    let state = test_utils::test_app_state_encrypted().await;
    let org = test_utils::create_test_org(&state.store, "acme.com").await;
    let added = db::add_additional_domain(
        &state.store,
        &org.id,
        "beta.org",
        "test-admin-user-id",
        "admin@acme.com",
    )
    .await
    .unwrap();
    db::mark_additional_domain_verified(&state.store, &org.id, &added.domain)
        .await
        .unwrap();
    db::claim_subdomain(&state.store, &org.id, "beta-org")
        .await
        .unwrap();
    let org = db::get_organization(&state.store, &org.id)
        .await
        .unwrap()
        .unwrap();
    bootstrap(&state, &org).await;
    age_next_keys(&state, &org.id).await;
    rotate_org_keys(&state, &org.id, ADMIN).await.unwrap();

    db::remove_additional_domain(&state.store, &org.id, "beta.org")
        .await
        .unwrap();

    let org = db::get_organization(&state.store, &org.id)
        .await
        .unwrap()
        .unwrap();
    assert!(org.subdomain.is_none(), "subdomain must be auto-released");
    for alg in [JwsAlgorithm::Es256, JwsAlgorithm::Rs256] {
        for key_state in [SigningKeyState::Next, SigningKeyState::Previous] {
            assert!(
                db::get_org_signing_key(&state.store, &org.id, alg, key_state)
                    .await
                    .unwrap()
                    .is_none(),
                "{alg:?} {key_state:?} key must be deleted on auto-release"
            );
        }
        assert!(
            db::get_org_signing_key(&state.store, &org.id, alg, SigningKeyState::Current)
                .await
                .unwrap()
                .is_some(),
            "{alg:?} current key survives auto-release"
        );
    }
}

#[tokio::test]
async fn jwks_orders_all_three_states_per_algorithm() {
    let (state, org) = setup_org().await;
    bootstrap(&state, &org).await;
    age_next_keys(&state, &org.id).await;
    rotate_org_keys(&state, &org.id, ADMIN).await.unwrap();

    // Map each kid to its (alg, state) from the store.
    let docs = db::list_org_signing_keys(&state.store, &org.id)
        .await
        .unwrap();
    let lookup: std::collections::HashMap<String, (JwsAlgorithm, SigningKeyState)> = docs
        .into_iter()
        .map(|d| (d.data.kid.clone(), (d.data.alg, d.data.state)))
        .collect();

    let jwks = org_jwks(&state, &org).await.unwrap();
    let ordered: Vec<(JwsAlgorithm, SigningKeyState)> =
        kids(&jwks.keys).iter().map(|kid| lookup[kid]).collect();
    let expected = vec![
        (JwsAlgorithm::Rs256, SigningKeyState::Current),
        (JwsAlgorithm::Rs256, SigningKeyState::Next),
        (JwsAlgorithm::Rs256, SigningKeyState::Previous),
        (JwsAlgorithm::Es256, SigningKeyState::Current),
        (JwsAlgorithm::Es256, SigningKeyState::Next),
        (JwsAlgorithm::Es256, SigningKeyState::Previous),
    ];
    assert_eq!(
        ordered, expected,
        "RS256 before ES256, Current > Next > Previous"
    );
}

// ============================================================================
// State-machine invariants (synchronous model)
// ============================================================================

/// Abstract model of one algorithm's key set, mirroring the service rules.
#[derive(Clone, Debug, Default)]
struct KeySetModel {
    current: Option<u32>,
    next: Option<u32>,
    previous: Option<u32>,
    counter: u32,
}

#[derive(Clone, Copy, Debug)]
enum Op {
    /// First use: create Current and Next if missing.
    Bootstrap,
    /// Operator rotate; `aged` says whether the Next key's publish window has
    /// elapsed — an un-aged rotate must be rejected without changing state.
    Rotate { aged: bool },
    /// Operator revoke past the drain window.
    Revoke,
    /// Compromise response: replace everything.
    Emergency,
}

impl KeySetModel {
    fn fresh_id(&mut self) -> u32 {
        self.counter = self.counter.saturating_add(1);
        self.counter
    }

    fn apply(&mut self, op: Op) {
        match op {
            Op::Bootstrap => {
                if self.current.is_none() {
                    self.current = Some(self.fresh_id());
                }
                if self.next.is_none() {
                    self.next = Some(self.fresh_id());
                }
            }
            Op::Rotate { aged } => {
                // Gated: needs a bootstrapped set, an aged Next key, and no
                // unrevoked previous.
                let (Some(current), Some(next)) = (self.current, self.next) else {
                    return;
                };
                if !aged || self.previous.is_some() {
                    return;
                }
                self.current = Some(next);
                self.previous = Some(current);
                self.next = Some(self.fresh_id());
            }
            Op::Revoke => {
                self.previous = None;
            }
            Op::Emergency => {
                if self.current.is_none() {
                    return;
                }
                self.current = Some(self.fresh_id());
                self.next = Some(self.fresh_id());
                self.previous = None;
            }
        }
    }
}

proptest! {
    /// Over any operation sequence, once bootstrapped: a Current signer and a
    /// staged Next always exist, at most one Previous exists, and the three
    /// never alias each other.
    #[test]
    fn key_set_invariants_hold_over_any_operation_sequence(
        ops in proptest::collection::vec(
            prop_oneof![
                Just(Op::Bootstrap),
                Just(Op::Rotate { aged: true }),
                Just(Op::Rotate { aged: false }),
                Just(Op::Revoke),
                Just(Op::Emergency),
            ],
            0..25,
        )
    ) {
        let mut model = KeySetModel::default();
        let mut bootstrapped = false;
        for op in ops {
            model.apply(op);
            if matches!(op, Op::Bootstrap) {
                bootstrapped = true;
            }
            if bootstrapped {
                prop_assert!(model.current.is_some(), "current must always exist");
                prop_assert!(model.next.is_some(), "next must always exist");
            }
            let mut live: Vec<u32> = [model.current, model.next, model.previous]
                .into_iter()
                .flatten()
                .collect();
            let before = live.len();
            live.sort_unstable();
            live.dedup();
            prop_assert_eq!(live.len(), before, "key ids must never alias");
        }
    }
}
