// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Hot read path for per-org issuer keys: TTL-cached resolution of an org's
//! active signing keys, and the per-org JWKS document.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;

use super::{OrgKeySetSnapshot, build_snapshot, ensure_key};
use crate::AppState;
use crate::db::documents::oauth::JwsAlgorithm;
use crate::db::documents::organization::SigningKeyState;
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
        // resurrecting a pre-release snapshot.
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
    let mut created = false;
    for alg in [JwsAlgorithm::Es256, JwsAlgorithm::Rs256] {
        for state in [SigningKeyState::Current, SigningKeyState::Next] {
            if !has(alg, state) {
                ensure_key(store, &org.id, alg, state).await?;
                created = true;
            }
        }
    }

    // Re-read only when we just generated new keys; otherwise build from the
    // already-loaded list (saves the extra round-trip in the common case).
    let docs = if created {
        db::list_org_signing_keys(store, &org.id).await?
    } else {
        docs
    };

    let Some(snap) = build_snapshot(&docs)? else {
        return Ok(None);
    };
    let snap = Arc::new(snap);
    state.org_keys_cache.insert(&org.id, Arc::clone(&snap));
    Ok(Some(snap))
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
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::super::test_support::setup;
    use super::*;
    use crate::crypto::keys::Jwk;
    use crate::db::get_org_signing_key;

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
            }
        }
        assert!(saw_ec, "at least one EC JWK must be present");

        let kids: Vec<&str> = snap
            .jwks
            .iter()
            .map(|jwk| match jwk {
                Jwk::Rsa(rsa) => rsa.kid.as_str(),
                Jwk::Ec(ec) => ec.kid.as_str(),
            })
            .collect();
        let unique: std::collections::HashSet<&str> = kids.iter().copied().collect();
        assert_eq!(kids.len(), unique.len(), "duplicate kids: {kids:?}");
    }
}
