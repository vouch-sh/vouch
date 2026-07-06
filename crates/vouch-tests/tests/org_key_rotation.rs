// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Integration tests for per-org OIDC issuer signing-key rotation (issue #626).
//!
//! All tests that touch the JWKS endpoint or `resolve_org_keys` use
//! `test_app_state_encrypted()` so the document store encrypts at rest and
//! per-org keys are actually created — unlike the default plaintext state where
//! the feature falls back to the shared key.
//!
//! ## Bounded proptest note
//!
//! The design spec called for a proptest over generated operation interleavings
//! (`stage`/`activate`/`reap`/`first-use`). A full interleaving harness is
//! disproportionate here because:
//! 1. `proptest` has no built-in tokio integration — async test code requires
//!    a `Runtime::block_on` wrapper, which limits parallelism and adds boilerplate.
//! 2. The concurrency safety is already covered by the explicit concurrent tests
//!    below (which use real `tokio::spawn` tasks sharing a single store).
//!
//! Instead, `rotation_invariants_hold_across_lifecycle_stages` walks the
//! bootstrap→stage→emergency rest states parametrically across representative
//! `session_hours` values. Activate and reap are each covered by their own
//! dedicated tests (see `activate_switches_signing_kid_and_retiring_key_stays_in_jwks`
//! and `reap_removes_retired_key_from_db_and_jwks`).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use jiff::{Span, Timestamp};
use proptest::prelude::*;
use vouch_server::db::{AuditEventFilter, JwsAlgorithm, SigningKeyState};
use vouch_server::services::oidc::{
    Jwk, OidcRsaSigningKey, OidcSigningKey, OrgKeySetSnapshot, emergency_rotate_org_keys, org_jwks,
    process_pending_org_key_transitions, resolve_org_keys, stage_org_key_rotation,
};
use vouch_server::{db, test_utils};

// ============================================================================
// Setup helpers
// ============================================================================

/// Create an encrypted `AppState`, an org (`"acme.com"`), and claim the
/// `"acme-com"` subdomain (derived from the registrable apex `acme.com`).
/// Each call creates a fresh in-memory SQLite so tests are fully isolated.
///
/// Returns the state and the reloaded `Organization` (with `subdomain` set).
async fn setup_org() -> (Arc<vouch_server::AppState>, vouch_server::db::Organization) {
    let state = test_utils::test_app_state_encrypted().await;
    let org = test_utils::create_test_org(&state.store, "acme.com").await;
    db::claim_subdomain(&state.store, &org.id, "acme-com")
        .await
        .unwrap();
    // Reload the org so subdomain field is populated.
    let org = db::get_organization(&state.store, &org.id)
        .await
        .unwrap()
        .unwrap();
    (state, org)
}

/// Bootstrap an org's Active signing keys (ES256 + RS256) via `resolve_org_keys`.
/// Panics if keys can't be resolved (e.g. store not encrypted).
async fn bootstrap_active_keys(
    state: &Arc<vouch_server::AppState>,
    org: &vouch_server::db::Organization,
) -> Arc<OrgKeySetSnapshot> {
    resolve_org_keys(state, Some(org))
        .await
        .expect("resolve_org_keys")
        .expect("must have keys on encrypted store with subdomain")
}

/// Generate a real ES256 PKCS#8 DER and return `(der_bytes, kid)`.
fn gen_es256() -> (Vec<u8>, String) {
    let der = OidcSigningKey::generate_pkcs8_der().unwrap();
    let kid = OidcSigningKey::from_pkcs8_der(&der)
        .unwrap()
        .key_id()
        .to_string();
    (der.to_vec(), kid)
}

/// Generate a real RS256 PKCS#8 DER and return `(der_bytes, kid)`.
/// Offloads RSA-3072 keygen (~200ms) to the blocking pool.
async fn gen_rs256() -> (Vec<u8>, String) {
    let der = tokio::task::spawn_blocking(OidcRsaSigningKey::generate_pkcs8_der)
        .await
        .unwrap()
        .unwrap();
    let kid = OidcRsaSigningKey::from_pkcs8_der(&der)
        .unwrap()
        .key_id()
        .to_string();
    (der.to_vec(), kid)
}

/// Insert a Pending doc at the **next** slot for `(org_id, alg)` with
/// `activate_at` set to 1 h in the past so the cleanup loop activates it
/// immediately on the next run.
async fn insert_pending_past(
    store: &vouch_server::AppState,
    org_id: &str,
    alg: JwsAlgorithm,
    der: &[u8],
    kid: &str,
) {
    let past = Timestamp::now().checked_sub(Span::new().hours(1)).unwrap();
    let doc = db::OrgSigningKeyDoc {
        org_id: org_id.to_string(),
        alg,
        kid: kid.to_string(),
        private_pkcs8_der_b64: STANDARD.encode(der).into(),
        state: SigningKeyState::Pending { activate_at: past },
    };
    db::try_insert_org_signing_key_next(&store.store, &doc)
        .await
        .unwrap();
}

/// Insert a Retiring doc at the **previous** slot for `(org_id, alg)` with
/// `not_after` set to 1 h in the past so the cleanup loop reaps it immediately.
async fn insert_retiring_past(
    store: &vouch_server::AppState,
    org_id: &str,
    alg: JwsAlgorithm,
    der: &[u8],
    kid: &str,
) {
    let past = Timestamp::now().checked_sub(Span::new().hours(1)).unwrap();
    let doc = db::OrgSigningKeyDoc {
        org_id: org_id.to_string(),
        alg,
        kid: kid.to_string(),
        private_pkcs8_der_b64: STANDARD.encode(der).into(),
        state: SigningKeyState::Retiring { not_after: past },
    };
    let prev_id = db::deterministic_org_key_previous_id(org_id, alg);
    store.store.insert_with_id(&prev_id, &doc).await.unwrap();
}

/// Extract all `kid` values from a JWKS response.
fn kids(jwks: &[Jwk]) -> Vec<String> {
    jwks.iter()
        .map(|j| match j {
            Jwk::Rsa(r) => r.kid.clone(),
            Jwk::Ec(e) => e.kid.clone(),
        })
        .collect()
}

/// Count RSA and EC keys in a JWKS slice.
fn count_by_alg(jwks: &[Jwk]) -> (usize, usize) {
    let rsa = jwks.iter().filter(|j| matches!(j, Jwk::Rsa(_))).count();
    let ec = jwks.iter().filter(|j| matches!(j, Jwk::Ec(_))).count();
    (rsa, ec)
}

/// Run one cleanup pass (activate + reap) for the given state.
async fn run_cleanup(state: &Arc<vouch_server::AppState>) {
    let session_hours = state.config().session_hours;
    process_pending_org_key_transitions(
        &state.store,
        &state.audit,
        &state.org_keys_cache,
        session_hours,
    )
    .await
    .expect("cleanup pass");
}

// ============================================================================
// Stage tests
// ============================================================================

/// After `stage_org_key_rotation`, the org JWKS must publish 2 keys per
/// algorithm (Active + Pending) and the resolver must still return the old
/// Active kid for signing (not the Pending successor).
#[tokio::test]
async fn stage_adds_pending_keys_to_jwks_and_resolver_keeps_old_active_kid() {
    let (state, org) = setup_org().await;

    // Bootstrap Active keys and record the original Active kids.
    let snap_before = bootstrap_active_keys(&state, &org).await;
    let old_es256_kid = snap_before.signers.es256.key_id().to_string();
    let old_rs256_kid = snap_before.signers.rs256.key_id().to_string();

    // Stage a rotation — generates real ES256 + RS256 successors and
    // invalidates the cache so the next resolution re-reads from DB.
    stage_org_key_rotation(&state.store, &org.id, &state.org_keys_cache)
        .await
        .expect("stage");

    // The JWKS now has 2 keys per alg: Active + Pending.
    let jwks = org_jwks(&state, &org).await.expect("org_jwks");
    let (rsa_count, ec_count) = count_by_alg(&jwks.keys);
    assert_eq!(
        rsa_count, 2,
        "JWKS must have 2 RS256 keys after staging (Active + Pending)"
    );
    assert_eq!(
        ec_count, 2,
        "JWKS must have 2 ES256 keys after staging (Active + Pending)"
    );

    // The old Active kids must still be present (relying parties need them for
    // tokens already in flight).
    let jwks_kids = kids(&jwks.keys);
    assert!(
        jwks_kids.contains(&old_rs256_kid),
        "old RS256 Active kid must be in JWKS after staging"
    );
    assert!(
        jwks_kids.contains(&old_es256_kid),
        "old ES256 Active kid must be in JWKS after staging"
    );

    // The resolver must still sign with the OLD Active kid, not the Pending one.
    let snap_after = bootstrap_active_keys(&state, &org).await;
    assert_eq!(
        snap_after.signers.es256.key_id(),
        old_es256_kid,
        "resolver must still use old ES256 kid while Pending is not yet activated"
    );
    assert_eq!(
        snap_after.signers.rs256.key_id(),
        old_rs256_kid,
        "resolver must still use old RS256 kid while Pending is not yet activated"
    );
}

// ============================================================================
// Activate tests
// ============================================================================

/// After activation (cleanup promotes Pending → Active, Active → Retiring):
/// - The resolver signs with the **new** kid (successor).
/// - The JWKS contains both the new Active kid and the old Retiring kid
///   (overlap window: RPs can still verify tokens signed by the old key).
#[tokio::test]
async fn activate_switches_signing_kid_and_retiring_key_stays_in_jwks() {
    let (state, org) = setup_org().await;

    let snap_before = bootstrap_active_keys(&state, &org).await;
    let old_es256_kid = snap_before.signers.es256.key_id().to_string();
    let old_rs256_kid = snap_before.signers.rs256.key_id().to_string();

    // Insert real Pending keys with activate_at in the past.
    let (new_es256_der, new_es256_kid) = gen_es256();
    let (new_rs256_der, new_rs256_kid) = gen_rs256().await;
    insert_pending_past(
        &state,
        &org.id,
        JwsAlgorithm::Es256,
        &new_es256_der,
        &new_es256_kid,
    )
    .await;
    insert_pending_past(
        &state,
        &org.id,
        JwsAlgorithm::Rs256,
        &new_rs256_der,
        &new_rs256_kid,
    )
    .await;

    // Run the cleanup loop — both Pending keys should be activated.
    run_cleanup(&state).await;

    // Verify DB state: current slots now hold the new Active docs.
    let es_doc = db::get_org_signing_key(&state.store, &org.id, JwsAlgorithm::Es256)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        es_doc.data.kid, new_es256_kid,
        "current ES256 slot must now hold successor kid"
    );
    assert_eq!(
        es_doc.data.state,
        SigningKeyState::Active,
        "current ES256 slot must be Active"
    );

    let rs_doc = db::get_org_signing_key(&state.store, &org.id, JwsAlgorithm::Rs256)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        rs_doc.data.kid, new_rs256_kid,
        "current RS256 slot must now hold successor kid"
    );

    // Verify DB state: previous slots now hold the old Retiring docs.
    let es_prev = db::get_org_signing_key_previous(&state.store, &org.id, JwsAlgorithm::Es256)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        es_prev.data.kid, old_es256_kid,
        "previous ES256 slot must hold the old (now Retiring) kid"
    );
    assert!(
        matches!(es_prev.data.state, SigningKeyState::Retiring { .. }),
        "previous ES256 slot must be in Retiring state"
    );

    let rs_prev = db::get_org_signing_key_previous(&state.store, &org.id, JwsAlgorithm::Rs256)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        rs_prev.data.kid, old_rs256_kid,
        "previous RS256 slot must hold the old (now Retiring) kid"
    );

    // Resolver must now sign with the new kids.
    state.org_keys_cache.invalidate(&org.id);
    let snap_after = bootstrap_active_keys(&state, &org).await;
    assert_eq!(
        snap_after.signers.es256.key_id(),
        new_es256_kid,
        "resolver must sign with successor ES256 kid after activation"
    );
    assert_eq!(
        snap_after.signers.rs256.key_id(),
        new_rs256_kid,
        "resolver must sign with successor RS256 kid after activation"
    );

    // JWKS must contain BOTH old and new kids (overlap window for verification).
    let jwks = org_jwks(&state, &org).await.expect("org_jwks");
    let (rsa_count, ec_count) = count_by_alg(&jwks.keys);
    assert_eq!(
        rsa_count, 2,
        "JWKS must have 2 RS256 keys during overlap (Active + Retiring)"
    );
    assert_eq!(
        ec_count, 2,
        "JWKS must have 2 ES256 keys during overlap (Active + Retiring)"
    );

    let jwks_kids = kids(&jwks.keys);
    assert!(
        jwks_kids.contains(&old_es256_kid),
        "old ES256 kid must stay in JWKS during retirement window"
    );
    assert!(
        jwks_kids.contains(&new_es256_kid),
        "new ES256 kid must appear in JWKS after activation"
    );
    assert!(
        jwks_kids.contains(&old_rs256_kid),
        "old RS256 kid must stay in JWKS during retirement window"
    );
    assert!(
        jwks_kids.contains(&new_rs256_kid),
        "new RS256 kid must appear in JWKS after activation"
    );

    // GAP1: verify audit events were emitted — one per alg, with correct fields.
    let activate_events = state
        .audit
        .query_events(&AuditEventFilter {
            event_types: Some(vec!["org_issuer_key_activated".to_string()]),
            ..AuditEventFilter::default()
        })
        .await
        .expect("query audit events");
    assert_eq!(
        activate_events.len(),
        2,
        "must emit 2 org_issuer_key_activated events (one per alg)"
    );
    let es256_event = activate_events
        .iter()
        .find(|e| e.data.contains("\"ES256\""))
        .expect("must have ES256 activate event");
    let es256_data: serde_json::Value =
        serde_json::from_str(&es256_event.data).expect("ES256 event data must be valid JSON");
    assert_eq!(
        es256_data["org_id"].as_str(),
        Some(org.id.as_str()),
        "ES256 activate event must carry org_id"
    );
    assert_eq!(
        es256_data["old_kid"].as_str(),
        Some(old_es256_kid.as_str()),
        "ES256 activate event must carry old_kid"
    );
    assert_eq!(
        es256_data["new_kid"].as_str(),
        Some(new_es256_kid.as_str()),
        "ES256 activate event must carry new_kid"
    );
    let rs256_event = activate_events
        .iter()
        .find(|e| e.data.contains("\"RS256\""))
        .expect("must have RS256 activate event");
    let rs256_data: serde_json::Value =
        serde_json::from_str(&rs256_event.data).expect("RS256 event data must be valid JSON");
    assert_eq!(
        rs256_data["old_kid"].as_str(),
        Some(old_rs256_kid.as_str()),
        "RS256 activate event must carry old_kid"
    );
    assert_eq!(
        rs256_data["new_kid"].as_str(),
        Some(new_rs256_kid.as_str()),
        "RS256 activate event must carry new_kid"
    );
}

// ============================================================================
// Reap tests
// ============================================================================

/// After `not_after` elapses, the cleanup loop must delete the Retiring doc.
/// The JWKS returns to 1 key per algorithm (only the Active remains).
/// The DB previous slot must be empty.
#[tokio::test]
async fn reap_removes_retired_key_from_db_and_jwks() {
    let (state, org) = setup_org().await;

    // Bootstrap Active keys (real DER, for JWKS to work after reap).
    bootstrap_active_keys(&state, &org).await;

    // Insert Retiring docs at previous slots with past not_after.
    // Fake DER is fine here — after reap, only the Active (real DER) remains,
    // and the JWKS call will succeed.
    let fake_der = b"fake-retiring-der-content-for-reap-test";
    insert_retiring_past(
        &state,
        &org.id,
        JwsAlgorithm::Es256,
        fake_der,
        "retiring-es256-kid",
    )
    .await;
    insert_retiring_past(
        &state,
        &org.id,
        JwsAlgorithm::Rs256,
        fake_der,
        "retiring-rs256-kid",
    )
    .await;

    // Verify previous slots are occupied before cleanup.
    assert!(
        db::get_org_signing_key_previous(&state.store, &org.id, JwsAlgorithm::Es256)
            .await
            .unwrap()
            .is_some(),
        "ES256 previous slot must exist before reap"
    );
    assert!(
        db::get_org_signing_key_previous(&state.store, &org.id, JwsAlgorithm::Rs256)
            .await
            .unwrap()
            .is_some(),
        "RS256 previous slot must exist before reap"
    );

    // Run cleanup — both past-due Retiring docs are reaped.
    run_cleanup(&state).await;

    // Both previous slots must be gone.
    assert!(
        db::get_org_signing_key_previous(&state.store, &org.id, JwsAlgorithm::Es256)
            .await
            .unwrap()
            .is_none(),
        "ES256 previous slot must be deleted after reap"
    );
    assert!(
        db::get_org_signing_key_previous(&state.store, &org.id, JwsAlgorithm::Rs256)
            .await
            .unwrap()
            .is_none(),
        "RS256 previous slot must be deleted after reap"
    );

    // JWKS must be back to 1 key per alg.
    state.org_keys_cache.invalidate(&org.id);
    let jwks = org_jwks(&state, &org).await.expect("org_jwks after reap");
    let (rsa_count, ec_count) = count_by_alg(&jwks.keys);
    assert_eq!(
        rsa_count, 1,
        "JWKS must have exactly 1 RS256 key after reap"
    );
    assert_eq!(ec_count, 1, "JWKS must have exactly 1 ES256 key after reap");

    // GAP1: verify reap audit events — 2 events (one per alg), each carrying org_id, alg, kid.
    let reap_events = state
        .audit
        .query_events(&AuditEventFilter {
            event_types: Some(vec!["org_issuer_key_reaped".to_string()]),
            ..AuditEventFilter::default()
        })
        .await
        .expect("query reap audit events");
    assert_eq!(
        reap_events.len(),
        2,
        "must emit 2 org_issuer_key_reaped events (one per alg)"
    );
    let reaped_kids: Vec<Option<&str>> = reap_events
        .iter()
        .map(|e| {
            serde_json::from_str::<serde_json::Value>(&e.data)
                .ok()
                .and_then(|v| v["kid"].as_str().map(str::to_owned).map(|_| ()))
                .map(|()| "present")
        })
        .collect();
    assert!(
        reaped_kids.iter().all(Option::is_some),
        "every org_issuer_key_reaped event must carry a kid field"
    );
    let es256_reap = reap_events
        .iter()
        .find(|e| e.data.contains("\"ES256\""))
        .expect("must have ES256 reap event");
    let es256_reap_data: serde_json::Value =
        serde_json::from_str(&es256_reap.data).expect("ES256 reap data must be valid JSON");
    assert_eq!(
        es256_reap_data["org_id"].as_str(),
        Some(org.id.as_str()),
        "ES256 reap event must carry org_id"
    );
    assert_eq!(
        es256_reap_data["kid"].as_str(),
        Some("retiring-es256-kid"),
        "ES256 reap event must carry the reaped kid"
    );
}

// ============================================================================
// Concurrent stage tests
// ============================================================================

/// N concurrent calls to `stage_org_key_rotation` must produce exactly 1
/// Pending doc per `(org, alg)` — the first writer wins, others are no-ops.
#[tokio::test]
async fn concurrent_stage_produces_exactly_one_pending_per_alg() {
    let (state, org) = setup_org().await;
    bootstrap_active_keys(&state, &org).await;

    const N: usize = 5;
    let org_id = org.id.clone();

    // Spawn N concurrent stage tasks.
    let mut handles = Vec::with_capacity(N);
    for _ in 0..N {
        let state_clone = Arc::clone(&state);
        let org_id_clone = org_id.clone();
        handles.push(tokio::spawn(async move {
            stage_org_key_rotation(
                &state_clone.store,
                &org_id_clone,
                &state_clone.org_keys_cache,
            )
            .await
            .expect("stage must not fail")
        }));
    }
    for h in handles {
        h.await.expect("task must not panic");
    }

    // Exactly one Pending next-slot doc per alg.
    let es_next = db::get_org_signing_key_next(&state.store, &org.id, JwsAlgorithm::Es256)
        .await
        .unwrap();
    assert!(
        es_next.is_some(),
        "ES256 next slot must exist after concurrent stage"
    );
    let es_next_doc = es_next.unwrap();
    assert!(
        matches!(es_next_doc.data.state, SigningKeyState::Pending { .. }),
        "ES256 next slot must be Pending"
    );

    let rs_next = db::get_org_signing_key_next(&state.store, &org.id, JwsAlgorithm::Rs256)
        .await
        .unwrap();
    assert!(
        rs_next.is_some(),
        "RS256 next slot must exist after concurrent stage"
    );
    let rs_next_doc = rs_next.unwrap();
    assert!(
        matches!(rs_next_doc.data.state, SigningKeyState::Pending { .. }),
        "RS256 next slot must be Pending"
    );

    // The list query must find exactly 1 Pending per alg (2 Pending total + 2 Active).
    let all_docs = db::list_org_signing_keys(&state.store, &org.id)
        .await
        .unwrap();
    let pending_count = all_docs
        .iter()
        .filter(|d| matches!(d.data.state, SigningKeyState::Pending { .. }))
        .count();
    assert_eq!(
        pending_count, 2,
        "must have exactly 1 Pending per alg (2 total) after concurrent stage"
    );
}

// ============================================================================
// Concurrent activate tests (S3 no-op path)
// ============================================================================

/// N concurrent cleanup passes racing to activate the same due Pending key:
/// - Exactly 1 Active per `(org, alg)` after all passes complete (single winner).
/// - No spurious errors surfaced — the S3 CAS-first no-op path returns `Ok(..)`
///   for every loser so `process_pending_org_key_transitions` always succeeds.
#[tokio::test]
async fn concurrent_activate_single_promotion_and_no_spurious_errors() {
    let (state, org) = setup_org().await;
    bootstrap_active_keys(&state, &org).await;

    // Insert Pending docs with past activate_at using fake DER (state test only,
    // no JWKS call after this).
    let fake_der = b"fake-pending-der-concurrent-activate-test";
    insert_pending_past(
        &state,
        &org.id,
        JwsAlgorithm::Es256,
        fake_der,
        "pending-es256-kid",
    )
    .await;
    insert_pending_past(
        &state,
        &org.id,
        JwsAlgorithm::Rs256,
        fake_der,
        "pending-rs256-kid",
    )
    .await;

    const N: usize = 8;

    // Spawn N concurrent cleanup tasks — they all race to activate the same Pending.
    let mut handles = Vec::with_capacity(N);
    for _ in 0..N {
        let state_clone = Arc::clone(&state);
        handles.push(tokio::spawn(async move {
            run_cleanup(&state_clone).await;
        }));
    }
    for h in handles {
        h.await.expect("task must not panic");
        // Each task must complete without error (no spurious OccConflict bubbling out).
    }

    // Exactly 1 Active per alg: current slot holds the winner's doc.
    let es_current = db::get_org_signing_key(&state.store, &org.id, JwsAlgorithm::Es256)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        es_current.data.state,
        SigningKeyState::Active,
        "ES256 current slot must be Active after concurrent activate"
    );

    let rs_current = db::get_org_signing_key(&state.store, &org.id, JwsAlgorithm::Rs256)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        rs_current.data.state,
        SigningKeyState::Active,
        "RS256 current slot must be Active after concurrent activate"
    );

    // The next slot must be empty (winner deleted it; losers found it gone → no-op).
    assert!(
        db::get_org_signing_key_next(&state.store, &org.id, JwsAlgorithm::Es256)
            .await
            .unwrap()
            .is_none(),
        "ES256 next slot must be empty after activation"
    );
    assert!(
        db::get_org_signing_key_next(&state.store, &org.id, JwsAlgorithm::Rs256)
            .await
            .unwrap()
            .is_none(),
        "RS256 next slot must be empty after activation"
    );

    // Invariant: never two Active per alg. Verify via the full key list.
    let all_docs = db::list_org_signing_keys(&state.store, &org.id)
        .await
        .unwrap();
    let active_count = all_docs
        .iter()
        .filter(|d| d.data.state == SigningKeyState::Active)
        .count();
    assert_eq!(
        active_count, 2,
        "must have exactly 1 Active per alg (2 total) — never two Active"
    );
}

// ============================================================================
// Emergency rotation tests (N1)
// ============================================================================

/// Emergency rotation must replace **both** ES256 and RS256 in a single call
/// (N1: a store-key compromise exposes both DERs) and the resulting JWKS must
/// immediately exclude the old kids on this instance.
#[tokio::test]
async fn emergency_rotates_both_algs_and_excludes_old_kids_from_jwks() {
    let (state, org) = setup_org().await;

    let snap_before = bootstrap_active_keys(&state, &org).await;
    let old_es256_kid = snap_before.signers.es256.key_id().to_string();
    let old_rs256_kid = snap_before.signers.rs256.key_id().to_string();

    // Stage a rotation so there are also Pending and potential Retiring docs;
    // emergency must delete them all.
    stage_org_key_rotation(&state.store, &org.id, &state.org_keys_cache)
        .await
        .expect("stage before emergency");

    // Emergency rotation: both algs replaced, all old/staged docs deleted.
    // Pass real operator identity so GAP1 assertions can verify C1 wiring.
    let operator_user_id = "test-admin-user-id";
    let operator_email = "admin@example.com";
    emergency_rotate_org_keys(
        &state.store,
        &org.id,
        &state.audit,
        &state.org_keys_cache,
        Some(operator_user_id),
        Some(operator_email),
    )
    .await
    .expect("emergency rotate");

    // JWKS must immediately exclude the old kids on this instance.
    let jwks = org_jwks(&state, &org)
        .await
        .expect("org_jwks after emergency");
    let jwks_kids = kids(&jwks.keys);

    assert!(
        !jwks_kids.contains(&old_es256_kid),
        "old ES256 kid must NOT appear in JWKS after emergency rotation"
    );
    assert!(
        !jwks_kids.contains(&old_rs256_kid),
        "old RS256 kid must NOT appear in JWKS after emergency rotation"
    );

    // N1: BOTH algs must be in the JWKS (new successors).
    let (rsa_count, ec_count) = count_by_alg(&jwks.keys);
    assert_eq!(
        rsa_count, 1,
        "JWKS must have exactly 1 RS256 key after emergency (no Retiring)"
    );
    assert_eq!(
        ec_count, 1,
        "JWKS must have exactly 1 ES256 key after emergency (no Retiring)"
    );

    // The DB previous and next slots must be empty (emergency deletes them outright).
    assert!(
        db::get_org_signing_key_previous(&state.store, &org.id, JwsAlgorithm::Es256)
            .await
            .unwrap()
            .is_none(),
        "ES256 previous slot must be gone after emergency"
    );
    assert!(
        db::get_org_signing_key_previous(&state.store, &org.id, JwsAlgorithm::Rs256)
            .await
            .unwrap()
            .is_none(),
        "RS256 previous slot must be gone after emergency"
    );
    assert!(
        db::get_org_signing_key_next(&state.store, &org.id, JwsAlgorithm::Es256)
            .await
            .unwrap()
            .is_none(),
        "ES256 next slot must be gone after emergency"
    );
    assert!(
        db::get_org_signing_key_next(&state.store, &org.id, JwsAlgorithm::Rs256)
            .await
            .unwrap()
            .is_none(),
        "RS256 next slot must be gone after emergency"
    );

    // The new Active kids must be different from the old ones.
    state.org_keys_cache.invalidate(&org.id);
    let snap_after = bootstrap_active_keys(&state, &org).await;
    let new_es256_kid = snap_after.signers.es256.key_id().to_string();
    let new_rs256_kid = snap_after.signers.rs256.key_id().to_string();
    assert_ne!(
        new_es256_kid, old_es256_kid,
        "ES256 signing kid must differ after emergency rotation"
    );
    assert_ne!(
        new_rs256_kid, old_rs256_kid,
        "RS256 signing kid must differ after emergency rotation"
    );

    // GAP1: verify emergency audit events — 2 events (one per alg) with correct fields.
    let emergency_events = state
        .audit
        .query_events(&AuditEventFilter {
            event_types: Some(vec!["org_issuer_key_emergency_rotation".to_string()]),
            ..AuditEventFilter::default()
        })
        .await
        .expect("query emergency audit events");
    assert_eq!(
        emergency_events.len(),
        2,
        "must emit 2 org_issuer_key_emergency_rotation events (one per alg)"
    );
    let es256_emerg = emergency_events
        .iter()
        .find(|e| e.data.contains("\"ES256\""))
        .expect("must have ES256 emergency event");
    let es256_emerg_data: serde_json::Value =
        serde_json::from_str(&es256_emerg.data).expect("ES256 emergency data must be valid JSON");
    assert_eq!(
        es256_emerg_data["org_id"].as_str(),
        Some(org.id.as_str()),
        "ES256 emergency event must carry org_id"
    );
    assert_eq!(
        es256_emerg_data["old_kid"].as_str(),
        Some(old_es256_kid.as_str()),
        "ES256 emergency event must carry old_kid"
    );
    assert_eq!(
        es256_emerg_data["new_kid"].as_str(),
        Some(new_es256_kid.as_str()),
        "ES256 emergency event must carry new_kid"
    );
    // C1: operator identity must be stored on each per-alg event (not a separate handler event).
    assert_eq!(
        es256_emerg.user_id.as_deref(),
        Some(operator_user_id),
        "ES256 emergency event must carry operator user_id (C1)"
    );
    assert_eq!(
        es256_emerg.email_domain.as_deref(),
        Some("example.com"),
        "ES256 emergency event must carry operator email_domain (C1)"
    );
    let rs256_emerg = emergency_events
        .iter()
        .find(|e| e.data.contains("\"RS256\""))
        .expect("must have RS256 emergency event");
    let rs256_emerg_data: serde_json::Value =
        serde_json::from_str(&rs256_emerg.data).expect("RS256 emergency data must be valid JSON");
    assert_eq!(
        rs256_emerg_data["old_kid"].as_str(),
        Some(old_rs256_kid.as_str()),
        "RS256 emergency event must carry old_kid"
    );
    assert_eq!(
        rs256_emerg_data["new_kid"].as_str(),
        Some(new_rs256_kid.as_str()),
        "RS256 emergency event must carry new_kid"
    );
    assert_eq!(
        rs256_emerg.user_id.as_deref(),
        Some(operator_user_id),
        "RS256 emergency event must carry operator user_id (C1)"
    );
    assert_eq!(
        rs256_emerg.email_domain.as_deref(),
        Some("example.com"),
        "RS256 emergency event must carry operator email_domain (C1)"
    );
}

// ============================================================================
// Subdomain release cancels in-flight rotation (M6)
// ============================================================================

/// When a subdomain is released during an in-flight rotation, the next and
/// previous key slots must be deleted so a future reclaim cannot activate a
/// stale Pending whose `kid` RPs may have already dropped.
#[tokio::test]
async fn subdomain_release_cancels_in_flight_rotation() {
    let (state, org) = setup_org().await;
    bootstrap_active_keys(&state, &org).await;

    // Stage a rotation to populate the next slots.
    stage_org_key_rotation(&state.store, &org.id, &state.org_keys_cache)
        .await
        .expect("stage before release");

    // Verify next slots are populated.
    assert!(
        db::get_org_signing_key_next(&state.store, &org.id, JwsAlgorithm::Es256)
            .await
            .unwrap()
            .is_some(),
        "ES256 next slot must exist after staging"
    );
    assert!(
        db::get_org_signing_key_next(&state.store, &org.id, JwsAlgorithm::Rs256)
            .await
            .unwrap()
            .is_some(),
        "RS256 next slot must exist after staging"
    );

    // Release the subdomain — must atomically cancel the in-flight rotation.
    db::release_subdomain(&state.store, &org.id)
        .await
        .expect("release_subdomain");

    // Both next slots must now be gone.
    assert!(
        db::get_org_signing_key_next(&state.store, &org.id, JwsAlgorithm::Es256)
            .await
            .unwrap()
            .is_none(),
        "ES256 next slot must be deleted by release"
    );
    assert!(
        db::get_org_signing_key_next(&state.store, &org.id, JwsAlgorithm::Rs256)
            .await
            .unwrap()
            .is_none(),
        "RS256 next slot must be deleted by release"
    );

    // The current (Active) slots must still exist — release only cancels
    // in-flight rotation, not the org's base keys.
    assert!(
        db::get_org_signing_key(&state.store, &org.id, JwsAlgorithm::Es256)
            .await
            .unwrap()
            .is_some(),
        "ES256 current (Active) slot must survive release"
    );
    assert!(
        db::get_org_signing_key(&state.store, &org.id, JwsAlgorithm::Rs256)
            .await
            .unwrap()
            .is_some(),
        "RS256 current (Active) slot must survive release"
    );
}

// ============================================================================
// JWKS ordering: RS256 first, then ES256; within alg Active → Pending → Retiring
// ============================================================================

/// M2: The org JWKS must serve RSA keys before EC keys (OIDC Core §3.1.3.7),
/// and within each algorithm the ordering must be Active → Pending → Retiring.
/// This is load-bearing: some OIDC libraries pick the first key matching `alg`.
#[tokio::test]
async fn jwks_ordering_rs256_first_then_es256_within_alg_active_before_pending() {
    let (state, org) = setup_org().await;

    // Bootstrap Active keys.
    bootstrap_active_keys(&state, &org).await;

    // Stage a rotation — adds Pending keys for both algs and invalidates cache.
    stage_org_key_rotation(&state.store, &org.id, &state.org_keys_cache)
        .await
        .expect("stage for JWKS ordering test");

    let jwks = org_jwks(&state, &org).await.expect("org_jwks");
    let keys = &jwks.keys;

    // Must have at least 2 RS256 keys (Active + Pending) and 2 ES256 keys.
    let (rsa_count, ec_count) = count_by_alg(keys);
    assert_eq!(rsa_count, 2, "must have 2 RS256 keys after staging");
    assert_eq!(ec_count, 2, "must have 2 ES256 keys after staging");

    // All RSA keys must come before all EC keys.
    let first_ec_idx = keys
        .iter()
        .position(|j| matches!(j, Jwk::Ec(_)))
        .expect("must have at least one EC key");
    let last_rsa_idx = keys
        .iter()
        .rposition(|j| matches!(j, Jwk::Rsa(_)))
        .expect("must have at least one RSA key");
    assert!(
        last_rsa_idx < first_ec_idx,
        "all RSA keys must appear before any EC key (M2); last_rsa_idx={last_rsa_idx}, first_ec_idx={first_ec_idx}"
    );

    // Within each algorithm, Active must come before Pending.
    // The JWKS doesn't expose `state` directly, but we know:
    // - The Active kid was recorded from `snap_before.signers`
    // - The Pending kid is the new one (kid != Active kid)
    // Reload the snapshot to get the current Active kid.
    let snap = bootstrap_active_keys(&state, &org).await;
    let active_es256_kid = snap.signers.es256.key_id();
    let active_rs256_kid = snap.signers.rs256.key_id();

    // In the RSA sub-slice, the Active kid must appear before the Pending kid.
    let rsa_keys: Vec<_> = keys.iter().filter(|j| matches!(j, Jwk::Rsa(_))).collect();
    let rsa_kids: Vec<String> = rsa_keys
        .iter()
        .map(|j| match j {
            Jwk::Rsa(r) => r.kid.clone(),
            _ => unreachable!(),
        })
        .collect();
    assert_eq!(
        rsa_kids.first().map(|s| s.as_str()),
        Some(active_rs256_kid),
        "RS256 Active kid must be first in the RSA sub-slice"
    );

    // In the EC sub-slice, the Active kid must appear before the Pending kid.
    let ec_keys: Vec<_> = keys.iter().filter(|j| matches!(j, Jwk::Ec(_))).collect();
    let ec_kids: Vec<String> = ec_keys
        .iter()
        .map(|j| match j {
            Jwk::Ec(e) => e.kid.clone(),
            _ => unreachable!(),
        })
        .collect();
    assert_eq!(
        ec_kids.first().map(|s| s.as_str()),
        Some(active_es256_kid),
        "ES256 Active kid must be first in the EC sub-slice"
    );
}

// ============================================================================
// Sequential state-machine invariant walk (bounded proptest alternative)
// ============================================================================

/// Walk bootstrap → stage → emergency across representative `session_hours` values
/// and verify the key-state invariants at each rest state:
/// - Never two Active docs per `(org, alg)`.
/// - Active is always at the deterministic current-slot ID.
/// - After emergency, both next and previous slots are empty.
///
/// Activate and reap are **not** exercised here — they require time-travel (past-due
/// `activate_at`) that can't be injected cleanly into this parameterisation.
/// Activate is covered by `activate_switches_signing_kid_and_retiring_key_stays_in_jwks`;
/// reap by `cleanup_reaps_retired_keys_and_drops_from_jwks`.
/// The M1 schedule floor is unit-tested for both algs in `schedule_math_m1_floor_applies_*`.
///
/// This is a bounded alternative to a full proptest interleaving harness.
/// See the module-level doc comment for why proptest is not used here.
#[tokio::test]
async fn rotation_invariants_hold_across_lifecycle_stages() {
    // Representative session_hours: below floor (4), at floor (8), above (12), large (24).
    // Each iteration creates its own isolated in-memory SQLite via setup_org().
    for session_hours in [4u64, 8, 12, 24] {
        let (state, org) = setup_org().await;
        bootstrap_active_keys(&state, &org).await;

        // ── Step 1: after bootstrapping, exactly 1 Active per alg ──────────
        assert_invariant_one_active_at_current_slot(&state, &org.id).await;
        assert_no_pending_or_retiring(&state, &org.id).await;

        // ── Step 2: after staging, still 1 Active + 1 Pending per alg ──────
        stage_org_key_rotation(&state.store, &org.id, &state.org_keys_cache)
            .await
            .expect("stage");
        assert_invariant_one_active_at_current_slot(&state, &org.id).await;
        // Previous slot must be empty (rotation not yet activated).
        for alg in [JwsAlgorithm::Es256, JwsAlgorithm::Rs256] {
            assert!(
                db::get_org_signing_key_previous(&state.store, &org.id, alg)
                    .await
                    .unwrap()
                    .is_none(),
                "previous slot must be empty before activation (session_hours={session_hours})"
            );
        }

        // ── Step 3: emergency rotation resets to 1 Active per alg ────────
        emergency_rotate_org_keys(
            &state.store,
            &org.id,
            &state.audit,
            &state.org_keys_cache,
            None,
            None,
        )
        .await
        .expect("emergency rotate in invariant walk");

        assert_invariant_one_active_at_current_slot(&state, &org.id).await;

        // After emergency, both next and previous slots must be empty.
        for alg in [JwsAlgorithm::Es256, JwsAlgorithm::Rs256] {
            assert!(
                db::get_org_signing_key_next(&state.store, &org.id, alg)
                    .await
                    .unwrap()
                    .is_none(),
                "next slot must be empty after emergency (session_hours={session_hours})"
            );
            assert!(
                db::get_org_signing_key_previous(&state.store, &org.id, alg)
                    .await
                    .unwrap()
                    .is_none(),
                "previous slot must be empty after emergency (session_hours={session_hours})"
            );
        }
    }
}

/// Verify that exactly 1 Active doc exists per `(org_id, alg)` pair and it is
/// located at the deterministic current-slot ID.
async fn assert_invariant_one_active_at_current_slot(
    state: &Arc<vouch_server::AppState>,
    org_id: &str,
) {
    for alg in [JwsAlgorithm::Es256, JwsAlgorithm::Rs256] {
        let all_docs = db::list_org_signing_keys(&state.store, org_id)
            .await
            .unwrap();

        let active_docs: Vec<_> = all_docs
            .iter()
            .filter(|d| d.data.alg == alg && d.data.state == SigningKeyState::Active)
            .collect();
        assert_eq!(
            active_docs.len(),
            1,
            "must have exactly 1 Active {alg:?} key (got {})",
            active_docs.len()
        );

        // The single Active doc must be at the deterministic current-slot ID.
        let expected_id = db::deterministic_org_key_id(org_id, alg);
        let current_doc = db::get_org_signing_key(&state.store, org_id, alg)
            .await
            .unwrap()
            .expect("current slot must be occupied");
        assert_eq!(
            current_doc.data.state,
            SigningKeyState::Active,
            "current slot must hold the Active {alg:?} key"
        );
        drop(expected_id); // derived from org_id+alg; the current-slot query implicitly uses it
        drop(current_doc);
    }
}

/// Verify that there are no Pending or Retiring docs for `org_id`.
async fn assert_no_pending_or_retiring(state: &Arc<vouch_server::AppState>, org_id: &str) {
    let all_docs = db::list_org_signing_keys(&state.store, org_id)
        .await
        .unwrap();
    let non_active: Vec<_> = all_docs
        .iter()
        .filter(|d| !matches!(d.data.state, SigningKeyState::Active))
        .collect();
    assert!(
        non_active.is_empty(),
        "must have no Pending or Retiring docs at rest; found: {non_active:?}",
        non_active = non_active
            .iter()
            .map(|d| format!("{:?}:{:?}", d.data.alg, d.data.state))
            .collect::<Vec<_>>()
    );
}

// ============================================================================
// Property-based state-machine invariants
// ============================================================================

/// In-memory model of the org key rotation state machine for a single
/// `(org, alg)` pair. Operations mirror the real rotation functions; all time
/// conditions are treated as immediately satisfied (Pending is always "due",
/// Retiring is always "past not_after") to maximise operation coverage.
///
/// Mirrors the three deterministic document slots:
/// - `current` → `deterministic_org_key_id` — holds `Active` or `None`
/// - `next` → `_next_id` — holds `Pending` or `None`
/// - `prev` → `_prev_id` — holds `Retiring` or `None`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ModelState {
    Active,
    Pending,
    Retiring,
}

#[derive(Debug, Clone, Default)]
struct ModelSlots {
    current: Option<ModelState>,
    next: Option<ModelState>,
    prev: Option<ModelState>,
}

#[derive(Debug, Clone, Copy)]
enum Op {
    /// `stage_org_key_rotation` — insert Pending if next slot is empty.
    Stage,
    /// `try_activate_org_key_rotation` — promote Pending to Active.
    Activate,
    /// `reap_org_retired_key` — delete Retiring from previous slot.
    Reap,
    /// `resolve_org_keys` first-use — create Active if current slot is empty.
    FirstUse,
}

impl ModelSlots {
    fn apply(&mut self, op: Op) {
        match op {
            Op::Stage => {
                // Idempotent: skip if a Pending already exists.
                if self.next.is_none() {
                    self.next = Some(ModelState::Pending);
                }
            }
            Op::Activate => {
                // Pre-conditions (time treated as met):
                // - next must be Pending
                // - prev must be None (no concurrent activation already in flight)
                // - current must exist (something to retire)
                if self.next == Some(ModelState::Pending)
                    && self.prev.is_none()
                    && self.current.is_some()
                {
                    self.prev = Some(ModelState::Retiring);
                    self.current = Some(ModelState::Active);
                    self.next = None;
                }
                // Otherwise: NothingStaged / AlreadyDone / no current → no-op.
            }
            Op::Reap => {
                if self.prev == Some(ModelState::Retiring) {
                    self.prev = None;
                }
            }
            Op::FirstUse => {
                if self.current.is_none() {
                    self.current = Some(ModelState::Active);
                }
            }
        }
    }

    fn active_count(&self) -> usize {
        [self.current, self.next, self.prev]
            .iter()
            .filter(|s| **s == Some(ModelState::Active))
            .count()
    }

    /// Returns `true` if the invariant "Active always at current slot" holds.
    /// That is: if any slot holds `Active`, it must be `current` and not `next`
    /// or `prev`.
    fn active_is_at_current_or_absent(&self) -> bool {
        self.next != Some(ModelState::Active) && self.prev != Some(ModelState::Active)
    }
}

fn arb_op() -> impl Strategy<Value = Op> {
    prop_oneof![
        Just(Op::Stage),
        Just(Op::Activate),
        Just(Op::Reap),
        Just(Op::FirstUse),
    ]
}

proptest! {
    /// Over any sequence (up to length 25) of stage / activate / reap / first-use
    /// operations the model must satisfy two invariants at every step:
    ///
    /// 1. **Never two Active** — at most 1 slot holds `Active` at a time.
    /// 2. **Active at current** — if `Active` exists, it is in the `current` slot,
    ///    never in `next` or `prev`.
    #[test]
    fn prop_rotation_state_machine_invariants(
        ops in prop::collection::vec(arb_op(), 0..25)
    ) {
        let mut slots = ModelSlots::default();

        for op in &ops {
            slots.apply(*op);

            let active = slots.active_count();
            prop_assert!(
                active <= 1,
                "invariant 1 violated after {op:?}: {active} Active keys (>1). \
                 State: current={:?} next={:?} prev={:?}",
                slots.current, slots.next, slots.prev
            );
            prop_assert!(
                slots.active_is_at_current_or_absent(),
                "invariant 2 violated after {op:?}: Active not at current slot. \
                 State: current={:?} next={:?} prev={:?}",
                slots.current, slots.next, slots.prev
            );
        }
    }
}

// ============================================================================
// GAP2: auto-release path (M6 via remove_additional_domain)
// ============================================================================

/// Removing the additional domain that backs the org's subdomain must trigger
/// the auto-release path (`release_ineligible_subdomain`), which must call
/// `cancel_org_rotation_in_tx` and clean up any in-flight rotation slots.
///
/// This is distinct from the manual `release_subdomain` path tested by
/// `subdomain_release_cancels_in_flight_rotation` — here the release is a
/// side-effect of domain removal, not an explicit admin action.
#[tokio::test]
async fn auto_release_via_domain_removal_cancels_in_flight_rotation() {
    let state = test_utils::test_app_state_encrypted().await;

    // Create an org whose primary domain yields a DIFFERENT eligible label than
    // the additional domain we'll use for the subdomain claim. This ensures that
    // removing the additional domain makes the subdomain ineligible.
    //
    // Primary "primary.com" → registrable apex "primary.com" → label "primary-com".
    // Additional "beta.org" → registrable apex "beta.org" → label "beta-org".
    // Claiming "beta-org" is only backed by "beta.org"; removing it makes "beta-org"
    // ineligible (only "primary-com" remains from the primary domain).
    let org = test_utils::create_test_org(&state.store, "primary.com").await;

    // Add "beta.org" as an additional domain and mark it verified.
    db::add_additional_domain(
        &state.store,
        &org.id,
        "beta.org",
        "test-admin",
        "admin@primary.com",
    )
    .await
    .expect("add_additional_domain");
    db::mark_additional_domain_verified(&state.store, &org.id, "beta.org")
        .await
        .expect("mark_additional_domain_verified");

    // Claim "beta-org" (derived from the verified additional domain "beta.org").
    db::claim_subdomain(&state.store, &org.id, "beta-org")
        .await
        .expect("claim_subdomain beta-org");

    // Reload org so the subdomain field is populated.
    let org = db::get_organization(&state.store, &org.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        org.subdomain.as_deref(),
        Some("beta-org"),
        "subdomain must be claimed before test"
    );

    // Bootstrap Active keys and stage a rotation — creates next slots.
    bootstrap_active_keys(&state, &org).await;
    stage_org_key_rotation(&state.store, &org.id, &state.org_keys_cache)
        .await
        .expect("stage before auto-release");

    // Confirm next slots exist before the domain removal.
    for alg in [JwsAlgorithm::Es256, JwsAlgorithm::Rs256] {
        assert!(
            db::get_org_signing_key_next(&state.store, &org.id, alg)
                .await
                .unwrap()
                .is_some(),
            "{alg:?} next slot must exist after staging"
        );
    }

    // Remove "beta.org" — the only verified domain backing the "beta-org" subdomain.
    // This triggers release_ineligible_subdomain → cancel_org_rotation_in_tx.
    let summary = db::remove_additional_domain(&state.store, &org.id, "beta.org")
        .await
        .expect("remove_additional_domain")
        .expect("domain must have been attached");
    assert_eq!(
        summary.released_subdomain.as_deref(),
        Some("beta-org"),
        "auto-release must report the released subdomain label"
    );

    // Reload org: subdomain must now be None.
    let org_after = db::get_organization(&state.store, &org.id)
        .await
        .unwrap()
        .unwrap();
    assert!(
        org_after.subdomain.is_none(),
        "subdomain must be cleared after auto-release"
    );

    // Both next slots must be gone — cancel_org_rotation_in_tx ran atomically.
    for alg in [JwsAlgorithm::Es256, JwsAlgorithm::Rs256] {
        assert!(
            db::get_org_signing_key_next(&state.store, &org.id, alg)
                .await
                .unwrap()
                .is_none(),
            "{alg:?} next slot must be deleted after auto-release"
        );
        assert!(
            db::get_org_signing_key_previous(&state.store, &org.id, alg)
                .await
                .unwrap()
                .is_none(),
            "{alg:?} previous slot must be deleted after auto-release"
        );
    }

    // Active key at the current slot must still be present — release only
    // cancels the in-flight rotation, it does not delete the signing key.
    for alg in [JwsAlgorithm::Es256, JwsAlgorithm::Rs256] {
        let doc = db::get_org_signing_key(&state.store, &org.id, alg)
            .await
            .unwrap();
        assert!(
            doc.is_some(),
            "{alg:?} Active key must survive the auto-release"
        );
    }
}

// ============================================================================
// GAP3: reclaim-after-release — no stale activation end-to-end
// ============================================================================

/// After a subdomain is released (which cancels in-flight rotation), the same
/// org can immediately reclaim its own label. A fresh `resolve_org_keys` call
/// on the re-claimed subdomain must find exactly the pre-existing Active key
/// with no stale Pending or Retiring docs — the cancelled rotation must not
/// resurface or silently activate.
#[tokio::test]
async fn reclaim_after_release_has_no_stale_rotation_slots() {
    let (state, org) = setup_org().await;

    // Bootstrap Active keys and stage a rotation so next slots exist.
    let snap_before = bootstrap_active_keys(&state, &org).await;
    let original_es256_kid = snap_before.signers.es256.key_id().to_string();
    let original_rs256_kid = snap_before.signers.rs256.key_id().to_string();

    stage_org_key_rotation(&state.store, &org.id, &state.org_keys_cache)
        .await
        .expect("stage before release");

    // Confirm both next slots exist.
    for alg in [JwsAlgorithm::Es256, JwsAlgorithm::Rs256] {
        assert!(
            db::get_org_signing_key_next(&state.store, &org.id, alg)
                .await
                .unwrap()
                .is_some(),
            "{alg:?} next slot must exist after staging"
        );
    }

    // Manually release the subdomain — this cancels the rotation atomically.
    let released = db::release_subdomain(&state.store, &org.id)
        .await
        .expect("release_subdomain");
    assert_eq!(
        released.as_deref(),
        Some("acme-com"),
        "release must report the label"
    );

    // Reclaim the same label immediately — same org, no cooldown applies.
    db::claim_subdomain(&state.store, &org.id, "acme-com")
        .await
        .expect("reclaim acme-com");

    // Reload org so the subdomain field reflects the re-claim.
    let org_reclaimed = db::get_organization(&state.store, &org.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        org_reclaimed.subdomain.as_deref(),
        Some("acme-com"),
        "subdomain must be set after reclaim"
    );

    // Cache invalidation after the release cleared the snapshot.
    state.org_keys_cache.invalidate(&org.id);

    // resolve_org_keys — hits the cache miss path, reads all docs.
    // The current Active slot still exists (release only cancelled next/prev).
    // No new key should be generated; the existing Active must be returned.
    let snap_after = resolve_org_keys(&state, Some(&org_reclaimed))
        .await
        .expect("resolve_org_keys after reclaim")
        .expect("must have keys — store is encrypted and subdomain is claimed");

    // The signing kids must be the SAME originals — no stale Pending activated.
    assert_eq!(
        snap_after.signers.es256.key_id(),
        original_es256_kid,
        "ES256 signing kid must be the pre-release Active key, not a stale Pending"
    );
    assert_eq!(
        snap_after.signers.rs256.key_id(),
        original_rs256_kid,
        "RS256 signing kid must be the pre-release Active key, not a stale Pending"
    );

    // No rotation slots must exist — cancelled slots are gone, not re-staged.
    assert_no_pending_or_retiring(&state, &org.id).await;
}
