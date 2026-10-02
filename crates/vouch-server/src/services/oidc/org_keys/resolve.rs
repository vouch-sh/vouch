// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Hot read path for per-org issuer keys: TTL-cached resolution of an org's
//! active signing keys, and the per-org JWKS document.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use jiff::Timestamp;

use super::{KeyMaterial, OrgKeySetSnapshot, build_snapshot, generate_key_material};
use crate::AppState;
use crate::crypto::alg::JwsAlgorithm;
use crate::db::documents::organization::{OrgSigningKeyDoc, OrganizationDoc, SigningKeyState};
use crate::db::pool::{self, CasError};
use crate::db::store::DocumentStore;
use crate::db::{self, Organization};
use crate::error::ServiceError;
use crate::services::oidc::discovery::{JwksResponse, build_jwks};

/// How long a resolved key set may be served from [`OrgKeysCache`].
const ORG_KEYS_CACHE_TTL: Duration = Duration::from_mins(1);

/// Inner map type for `OrgKeysCache`: org ID → (insert time, snapshot).
type OrgKeysCacheMap = HashMap<String, (Instant, Arc<OrgKeySetSnapshot>)>;

/// Cache of resolved per-org key set snapshots, keyed by org ID.
///
/// Every rotation transition must call `invalidate(org_id)` so the next
/// request after a state change rebuilds from the DB rather than serving a
/// stale snapshot.
#[derive(Default)]
pub struct OrgKeysCache {
    entries: Arc<Mutex<OrgKeysCacheMap>>,
}

impl OrgKeysCache {
    /// Return a cached snapshot for `org_id`, if present and not expired.
    fn get(&self, org_id: &str) -> Option<Arc<OrgKeySetSnapshot>> {
        let Ok(map) = self.entries.lock() else {
            return None;
        };
        map.get(org_id)
            .filter(|(inserted_at, _)| inserted_at.elapsed() < ORG_KEYS_CACHE_TTL)
            .map(|(_, snap)| Arc::clone(snap))
    }

    /// Cache `snapshot`, pruning expired entries so deleted orgs don't accumulate.
    fn insert(&self, org_id: &str, snapshot: Arc<OrgKeySetSnapshot>) {
        let Ok(mut map) = self.entries.lock() else {
            return;
        };
        map.retain(|_, (inserted_at, _)| inserted_at.elapsed() < ORG_KEYS_CACHE_TTL);
        map.insert(org_id.to_string(), (Instant::now(), snapshot));
    }

    /// Evict the cached snapshot for `org_id`.
    ///
    /// Called after every rotation transition (rotate, revoke, emergency) so
    /// the next request rebuilds from the DB immediately rather than serving
    /// a now-stale snapshot.
    pub fn invalidate(&self, org_id: &str) {
        if let Ok(mut map) = self.entries.lock() {
            map.remove(org_id);
        }
    }
}

/// Resolve an org's own signing key set, creating it on first use.
///
/// Returns `None` when the org has no claimed subdomain, or when the document
/// store doesn't encrypt at rest — the caller then falls back to the common
/// platform key. Resolutions are served from a per-org cache for
/// [`ORG_KEYS_CACHE_TTL`], so the token hot paths don't re-read and unseal key
/// rows on every request.
///
/// The returned snapshot also contains the ordered public-JWK list for all live
/// keys (Current + Next + Previous) which [`org_jwks`] uses directly.
///
/// # Errors
/// Returns an error if key creation or loading fails.
pub async fn resolve_org_keys(
    state: &Arc<AppState>,
    org: Option<&Organization>,
) -> Result<Option<Arc<OrgKeySetSnapshot>>> {
    let Some(org) = org else { return Ok(None) };
    if org.subdomain.is_none() {
        // Self-heal: release cancels rotation keys in the DB, but the release
        // paths live in the db layer and cannot reach this cache. Purging on
        // the first resolve for a released org keeps a quick reclaim from
        // resurrecting a pre-release snapshot. Advisory only — the caller's
        // `org` snapshot can be stale, so the transactional creation path
        // below re-checks the subdomain against the DB authoritatively.
        state.org_keys_cache.invalidate(&org.id);
        return Ok(None);
    }
    if !state.store.is_encrypted() {
        return Ok(None);
    }
    if let Some(snap) = state.org_keys_cache.get(&org.id) {
        return Ok(Some(snap));
    }
    let store = &state.store;

    // Single list_all call to check which keys already exist (avoids
    // serial round-trips by discovering the full doc set upfront). The Auth0
    // invariant is that a claimed org always has a Current signer AND a
    // pre-staged Next successor per algorithm, so both are created here.
    let docs = db::list_org_signing_keys(store, &org.id).await?;
    let has = |alg: JwsAlgorithm, state: SigningKeyState| {
        docs.iter()
            .any(|d| d.data.alg == alg && d.data.state == state)
    };

    // Pre-generate material for every missing (alg, state) outside any
    // transaction. RSA keygen is expensive and must not hold a DB transaction
    // open while it runs — mirrors `rotate_org_keys`, which generates its
    // fresh Next material once, before its retry loop, and reuses it on a
    // retry instead of regenerating.
    let mut pending: Vec<(JwsAlgorithm, SigningKeyState, KeyMaterial)> = Vec::new();
    for alg in [JwsAlgorithm::Es256, JwsAlgorithm::Rs256] {
        for state in [SigningKeyState::Current, SigningKeyState::Next] {
            if !has(alg, state) {
                pending.push((alg, state, generate_key_material(alg).await?));
            }
        }
    }

    // Re-read only when we just generated new keys; otherwise build from the
    // already-loaded list (saves the extra round-trip in the common case).
    let docs = if pending.is_empty() {
        docs
    } else {
        // Guarded creation: re-check the org's subdomain inside a transaction
        // anchored by a CAS on the org document, so a subdomain release that
        // races the resolve (between the caller's org read and this point)
        // cannot resurrect a Next key the release just deleted. Mirrors
        // `guard_subdomain_claimed_in_tx` in `rotation.rs`.
        if !ensure_keys_guarded(store, &org.id, &pending).await? {
            // The org was released (or vanished) between the caller's org
            // read and the transaction. Do not bootstrap keys for a released
            // org; purge the cache and fall back to the common platform key,
            // exactly as the `subdomain.is_none()` fast path does for a
            // non-stale snapshot.
            state.org_keys_cache.invalidate(&org.id);
            return Ok(None);
        }
        db::list_org_signing_keys(store, &org.id).await?
    };

    let Some(snap) = build_snapshot(&docs)? else {
        return Ok(None);
    };
    let snap = Arc::new(snap);
    state.org_keys_cache.insert(&org.id, Arc::clone(&snap));
    Ok(Some(snap))
}

/// Re-check the org's claimed subdomain inside a transaction and create any
/// missing signing keys the pre-read found, anchoring the subdomain check
/// with a CAS on the org document so a racing `release_subdomain` — which
/// also CAS-writes the org doc in the same transaction that deletes the
/// rotation keys — collides here instead of interleaving with the key
/// inserts. Mirrors `guard_subdomain_claimed_in_tx` in `rotation.rs`.
///
/// Returns `true` when the org was still claimed and the missing keys were
/// created (or already existed); `false` when the org was released (or
/// vanished) so the caller skips key creation and falls back to the common
/// platform key. OCC version conflicts on the org doc retry the whole
/// transaction via `with_dsql_retry!`.
#[expect(
    clippy::disallowed_methods,
    reason = "stamps a newly created signing key's staged_at, like `ensure_key`"
)]
async fn ensure_keys_guarded(
    store: &DocumentStore,
    org_id: &str,
    pending: &[(JwsAlgorithm, SigningKeyState, KeyMaterial)],
) -> Result<bool, CasError> {
    let result: Result<bool, CasError> = crate::with_dsql_retry!(async {
        let mut tx = store.begin().await?;
        let Some(org_doc) = tx.get::<OrganizationDoc>(org_id).await? else {
            // The org vanished between the caller's read and this
            // transaction; there is nothing to bootstrap.
            return Ok(false);
        };
        if org_doc.data.subdomain.is_none() {
            // A release committed between the caller's read and this
            // transaction: the org no longer holds its subdomain, so its
            // Next/Previous keys were deleted by `release_subdomain`. Do not
            // resurrect them.
            return Ok(false);
        }
        // Bump the org doc version so a concurrent release (which clears the
        // subdomain and writes the org doc in the same transaction that
        // deletes the rotation keys) collides with this transaction on every
        // backend instead of interleaving with the key inserts below. The
        // data is unchanged; only the version moves, exactly as
        // `guard_subdomain_claimed_in_tx` does for `rotate_org_keys`.
        if !tx
            .compare_and_update(org_id, org_doc.version, &org_doc.data)
            .await?
        {
            return Err(CasError::OccConflict);
        }
        for (alg, state, mat) in pending {
            let id = db::deterministic_org_key_id(org_id, *alg, *state);
            // A concurrent resolve (or a prior retry of this loop) may already
            // have created this key; the deterministic id makes the insert
            // idempotent, and the in-tx re-check skips the redundant write.
            if tx.get::<OrgSigningKeyDoc>(&id).await?.is_some() {
                continue;
            }
            let doc = OrgSigningKeyDoc {
                staged_at: (*state == SigningKeyState::Next).then(Timestamp::now),
                ..mat.doc(org_id, *alg, *state)
            };
            match tx.insert_with_id(&id, &doc).await {
                Ok(_) => {}
                Err(e) if pool::is_unique_violation(&e) => {}
                Err(e) => return Err(CasError::Other(e)),
            }
        }
        tx.commit().await?;
        Ok(true)
    });
    result
}

/// Build the JWKS served on `org`'s issuer-subdomain host: the org's own keys,
/// or the common keys when the org has none (dev / not-yet-encrypted). RSA
/// first (OIDC Core §3.1.3.7), then EC; within each alg: Current → Next →
/// Previous.
///
/// Uses the unified cache snapshot so signing and JWKS are always consistent
/// within an instance.
///
/// # Errors
/// Returns `ServiceError` if a key cannot be resolved or exported.
pub async fn org_jwks(
    state: &Arc<AppState>,
    org: &Organization,
) -> Result<JwksResponse, ServiceError> {
    let Some(snap) = resolve_org_keys(state, Some(org))
        .await
        .map_err(|e| ServiceError::Internal(format!("resolve org keys: {e}")))?
    else {
        return build_jwks(state);
    };
    Ok(JwksResponse {
        keys: snap.jwks.clone(),
    })
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;
    use crate::crypto::jwk::Jwk;
    use crate::db::get_org_signing_key;
    use crate::services::oidc::org_keys::test_support::setup;

    #[tokio::test]
    async fn first_use_creates_current_and_next_and_signs_with_current() {
        let (state, org_id, org) = setup().await;

        let snap = resolve_org_keys(&state, Some(&org)).await.unwrap().unwrap();
        // Two algorithms x (Current + Next) published from day one.
        assert_eq!(snap.jwks.len(), 4, "expected Current+Next for both algs");

        // The signer is the Current key, not the staged Next.
        let current = get_org_signing_key(
            &state.store,
            &org_id,
            JwsAlgorithm::Es256,
            SigningKeyState::Current,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(snap.signers.es256.key_id(), current.data.kid);

        let next = get_org_signing_key(
            &state.store,
            &org_id,
            JwsAlgorithm::Es256,
            SigningKeyState::Next,
        )
        .await
        .unwrap()
        .unwrap();
        assert!(next.data.staged_at.is_some(), "next key records staged_at");
        assert_ne!(next.data.kid, current.data.kid);
    }

    #[tokio::test]
    async fn jwks_lists_rsa_first_with_distinct_kids() {
        let (state, _org_id, org) = setup().await;
        let snap = resolve_org_keys(&state, Some(&org)).await.unwrap().unwrap();

        let mut saw_ec = false;
        for jwk in &snap.jwks {
            match jwk {
                Jwk::Rsa(_) => assert!(!saw_ec, "RSA JWK after an EC JWK"),
                Jwk::Ec(_) => saw_ec = true,
                // `Jwk` also models the OKP keys Vouch verifies DPoP proofs
                // with. It signs with none, so no `for_jwks` constructor
                // builds one and a published set cannot contain one.
                Jwk::Okp(_) => panic!("Vouch publishes no OKP signing key"),
            }
        }
        assert!(saw_ec, "at least one EC JWK must be present");

        let kids: Vec<&str> = snap
            .jwks
            .iter()
            .map(|jwk| match jwk {
                Jwk::Rsa(rsa) => rsa.kid(),
                Jwk::Ec(ec) => ec.kid(),
                Jwk::Okp(_) => panic!("Vouch publishes no OKP signing key"),
            })
            // `for_jwks` is the only constructor and it always sets `kid`, so
            // this doubles as an assertion of that guarantee.
            .map(|kid| kid.expect("a published JWK carries a kid"))
            .collect();
        let unique: std::collections::HashSet<&str> = kids.iter().copied().collect();
        assert_eq!(kids.len(), unique.len(), "duplicate kids: {kids:?}");
    }
}
