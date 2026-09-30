// SPDX-License-Identifier: Apache-2.0 OR MIT
//! JWKS resolution and caching for RFC 7523.
//!
//! Handles resolving client public keys from inline JWKS or remote JWKS URIs,
//! with database-backed caching for multi-instance deployments.

use super::validate::JwtAssertionHeader;
use crate::db::documents::jwks_cache::JwksCacheDoc;
use crate::db::store::DocumentStore;
use crate::db::{self, JwkSet, UnusableJwk};
use crate::error::{OAuthErrorCode, ServiceError, ServiceResult};
use crate::infra::jwks;
use crate::infra::jwks::JwksOrigin;

/// Resolve the JWKS for a client — from an inline key set or a fetched
/// `jwks_uri`. The two are exclusive (RFC 7591 §2), so there is no precedence
/// between them: at most one is ever `Some`.
///
/// For `jwks_uri` clients, uses database-backed caching with stale-while-revalidate.
///
/// Also returns [`JwksOrigin`] so the caller's kid-miss force-refresh can gate a
/// second fetch on whether resolution already fetched in this request — the
/// same within-request bound the mTLS self-signed path applies
/// (`services::oidc::token`). Inline keys never fetch, so they report
/// [`JwksOrigin::NoFetch`].
pub async fn resolve_client_jwks(
    store: &DocumentStore,
    client_id: &str,
    jwks: Option<&JwkSet>,
    jwks_uri: Option<&str>,
    jwks_cache: Option<&JwksCacheDoc>,
    allow_loopback: bool,
    http_client: &reqwest::Client,
) -> ServiceResult<(JwkSet, JwksOrigin)> {
    // An inline key set is already parsed — it arrives typed and needs no fetch.
    if let Some(jwks) = jwks {
        return Ok((jwks.clone(), JwksOrigin::NoFetch));
    }

    // JWKS URI with caching
    if let Some(uri) = jwks_uri {
        return resolve_jwks_uri(
            store,
            client_id,
            uri,
            jwks_cache,
            allow_loopback,
            http_client,
        )
        .await;
    }

    Err(ServiceError::oauth(
        OAuthErrorCode::InvalidClient,
        "Client has no JWKS or JWKS URI configured",
    ))
}

/// Fetch JWKS from a URI with caching.
///
/// Fetching, cache freshness, and stale-while-revalidate live in
/// [`crate::infra::jwks`] so the RFC 9421 signature path applies the same rules.
async fn resolve_jwks_uri(
    store: &DocumentStore,
    parent_id: &str,
    uri: &str,
    cached: Option<&JwksCacheDoc>,
    allow_loopback: bool,
    http_client: &reqwest::Client,
) -> ServiceResult<(JwkSet, JwksOrigin)> {
    // Keep `origin` so the RFC 7523 kid-miss force-refresh path can gate a
    // second fetch on it — the same within-request bound the mTLS self-signed
    // path applies (`services::oidc::token`). With the compressed
    // `REQUEST_TIMEOUT` (10s) and a 5s per-fetch cap, a second fetch in this
    // request could race the router's innermost `TimeoutLayer` and surface as
    // a bare 408 instead of the structured 401 `invalid_client` this path
    // returns. Resolution already fetched → the kid is missing from a fresh
    // set → fetching again would only repeat it.
    let (value, origin) =
        jwks::resolve_cached_jwks(store, parent_id, uri, cached, allow_loopback, http_client)
            .await?;
    parse_jwks_value(&value).map(|jwks| (jwks, origin))
}

/// Parse a JWKS from a `serde_json::Value`.
fn parse_jwks_value(value: &serde_json::Value) -> ServiceResult<JwkSet> {
    db::parse_jwks_set(value).map_err(|e| {
        tracing::debug!("Failed to parse JWKS value: {e}");
        ServiceError::oauth(OAuthErrorCode::InvalidClient, "Invalid JWKS format")
    })
}

/// Find a matching key in a JWKS for the given JWT header.
///
/// The candidates are the keys whose `kid` equals the header's, or every key
/// when the header has none. Each is tried with
/// [`JwkEntry::decoding_key_for`], the rule write-time checks also use, and
/// the first that builds is returned. A candidate that is not selectable for
/// the algorithm is skipped; one that is selectable but malformed is skipped
/// too, so an unbuildable key earlier in the set does not mask a usable one
/// later (RFC 7517 §4.5 makes `kid` uniqueness a SHOULD). When none builds,
/// the first malformed candidate's reason is returned.
pub fn find_matching_key(
    jwks: &JwkSet,
    header: &JwtAssertionHeader,
) -> ServiceResult<jsonwebtoken::DecodingKey> {
    let mut first_unusable = None;
    for key in &jwks.keys {
        if header.kid.is_some() && key.kid != header.kid {
            continue;
        }
        match key.decoding_key_for(header.alg) {
            Ok(decoding_key) => return Ok(decoding_key),
            Err(UnusableJwk::NotSelectable) => {}
            Err(reason) => {
                first_unusable.get_or_insert(reason);
            }
        }
    }
    if let Some(ref kid) = header.kid {
        tracing::debug!("No usable key with kid '{kid}' found in JWKS");
    }
    let reason = first_unusable.unwrap_or(UnusableJwk::NotSelectable);
    Err(ServiceError::oauth(
        OAuthErrorCode::InvalidClient,
        reason.to_string(),
    ))
}

/// Minimum interval between JWKS URI force-refreshes (seconds).
const JWKS_FORCE_REFRESH_MIN_INTERVAL_SECONDS: i64 = 10;

/// Find a matching key for a client, force-refreshing the JWKS URI on kid-miss.
///
/// On initial key miss, if the client has a `jwks_uri` and it hasn't been refreshed
/// in the last 10 seconds, fetches a fresh JWKS and retries. This handles key rotation
/// where a client starts signing with a new key before the server's cache has expired.
#[expect(
    clippy::too_many_arguments,
    reason = "store/client/uri/cache/loopback-flag/http-client/jwks/header/origin are all distinct inputs"
)]
pub async fn find_matching_key_with_refresh_client(
    store: &DocumentStore,
    client_id: &str,
    jwks_uri: Option<&str>,
    // Load once before calling resolve_client_jwks; pre-refresh timestamp matches prior behavior.
    jwks_cache: Option<&JwksCacheDoc>,
    allow_loopback: bool,
    http_client: &reqwest::Client,
    jwks: &JwkSet,
    header: &JwtAssertionHeader,
    origin: JwksOrigin,
) -> ServiceResult<jsonwebtoken::DecodingKey> {
    // Try initial match first
    if let Ok(key) = find_matching_key(jwks, header) {
        return Ok(key);
    }

    // On miss, force-refresh if we have a URI and haven't refreshed recently
    let Some(uri) = jwks_uri else {
        return find_matching_key(jwks, header);
    };

    // Within-request gate: if `resolve_client_jwks` already fetched in this
    // request (`JwksOrigin::Fetched`), the kid is missing from a freshly
    // fetched set, so a second `fetch_and_cache` would only repeat it. This
    // bounds every auth attempt to at most one network fetch — the same gate
    // the mTLS self-signed path applies at `services::oidc::token`. Under the
    // 10s `REQUEST_TIMEOUT` with a 5s per-fetch cap, a second fetch here could
    // race the router's innermost `TimeoutLayer` and surface as a bare 408
    // instead of the structured 401 `invalid_client` this function returns.
    //
    // The cross-request 10s throttle below cannot substitute: the
    // `jwks_cache` snapshot is loaded once before resolution, so for a
    // freshly-registered client it is `None` (the `if let Some(cache)` guard
    // is skipped) and for a stale-cache client it already predates the 10s
    // window by construction.
    if matches!(origin, JwksOrigin::Fetched) {
        tracing::debug!(
            "Skipping JWKS force-refresh for client {client_id}: JWKS already fetched in this request"
        );
        return find_matching_key(jwks, header);
    }

    // Rate-limit: skip force-refresh if cached within the last 10 seconds.
    if let Some(cache) = jwks_cache
        && cache.is_fresh(JWKS_FORCE_REFRESH_MIN_INTERVAL_SECONDS)
    {
        tracing::debug!(
            "Skipping JWKS force-refresh for client {client_id}: refreshed {}s ago",
            cache.age_seconds()
        );
        return find_matching_key(jwks, header);
    }

    tracing::debug!("Key not found in JWKS cache for client {client_id}; force-refreshing");
    // Deliberately the unconditional fetch, not `resolve_cached_jwks`: this path
    // has already decided the cache is not to be trusted (the kid is missing
    // from it), so the TTL and the stale fallback must both be bypassed.
    //
    // The 10-second limit above reads `cached_at`, which only a successful
    // fetch advances, so it bounds refetches of a working `jwks_uri` alone.
    // While the URI is failing, every kid-miss assertion costs one fetch: the
    // within-request gate above caps each auth attempt at one, and nothing
    // throttles across requests beyond the per-client auth rate limiter. The
    // mTLS certificate-miss refetch in `services::oidc::token` has the same
    // bound.
    match jwks::fetch_and_cache(store, client_id, uri, allow_loopback, http_client).await {
        Ok(jwks_value) => match parse_jwks_value(&jwks_value) {
            Ok(fresh_jwks) => find_matching_key(&fresh_jwks, header),
            Err(e) => {
                tracing::warn!("Force-refreshed JWKS for client {client_id} did not parse: {e}");
                find_matching_key(jwks, header)
            }
        },
        Err(e) => {
            tracing::warn!("JWKS force-refresh failed for client {client_id}: {e}");
            find_matching_key(jwks, header)
        }
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;
    use crate::crypto::alg::JwsAlgorithm;
    use crate::crypto::jwk::EcJwk;
    use crate::db::{JwkEntry, KeyType};
    use crate::test_utils;
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    // -----------------------------------------------------------------------
    // Well-known test vectors for JWK components
    // -----------------------------------------------------------------------

    /// P-256 EC key x-coordinate (base64url, from RFC 7517-style test vectors).
    const EC_X: &str = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU";
    /// P-256 EC key y-coordinate (base64url).
    const EC_Y: &str = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0";

    /// RSA modulus (base64url, from RFC 7517 Appendix A.1).
    const RSA_N: &str = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt\
        VT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9y\
        BXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgd\
        AZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksI\
        NHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";
    /// RSA public exponent (base64url).
    const RSA_E: &str = "AQAB";

    // -----------------------------------------------------------------------
    // Helper: build a JwkEntry directly (avoids JSON round-trip for matching tests)
    // -----------------------------------------------------------------------

    fn ec_jwk_entry(kid: Option<&str>, alg: Option<&str>, use_: Option<&str>) -> JwkEntry {
        JwkEntry {
            kty: KeyType::Ec,
            kid: kid.map(String::from),
            alg: alg.map(String::from),
            use_: use_.map(String::from),
            crv: Some("P-256".to_string()),
            x: Some(EC_X.to_string()),
            y: Some(EC_Y.to_string()),
            n: None,
            e: None,
            x5c: None,
        }
    }

    fn rsa_jwk_entry(kid: Option<&str>, alg: Option<&str>, use_: Option<&str>) -> JwkEntry {
        JwkEntry {
            kty: KeyType::Rsa,
            kid: kid.map(String::from),
            alg: alg.map(String::from),
            use_: use_.map(String::from),
            crv: None,
            x: None,
            y: None,
            n: Some(RSA_N.to_string()),
            e: Some(RSA_E.to_string()),
            x5c: None,
        }
    }

    /// An RSA key with no `n`/`e` components — metadata-complete (right `kty`,
    /// absent `use`/`alg`) but unbuildable. `is_usable_for` does not check
    /// component presence for RSA, so this passes write-time validation and
    /// reaches the runtime matcher, reproducing the production scenario a
    /// single malformed key ahead of a valid one creates.
    fn malformed_rsa_jwk_entry(
        kid: Option<&str>,
        alg: Option<&str>,
        use_: Option<&str>,
    ) -> JwkEntry {
        JwkEntry {
            n: None,
            e: None,
            ..rsa_jwk_entry(kid, alg, use_)
        }
    }

    /// Ed25519 public key x-coordinate (base64url, 32 bytes of zeros for testing).
    const OKP_X: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn okp_jwk_entry(kid: Option<&str>, alg: Option<&str>, use_: Option<&str>) -> JwkEntry {
        JwkEntry {
            kty: KeyType::Okp,
            kid: kid.map(String::from),
            alg: alg.map(String::from),
            use_: use_.map(String::from),
            crv: Some("Ed25519".to_string()),
            x: Some(OKP_X.to_string()),
            y: None,
            n: None,
            e: None,
            x5c: None,
        }
    }

    fn header(alg: JwsAlgorithm, kid: Option<&str>) -> JwtAssertionHeader {
        JwtAssertionHeader {
            alg,
            kid: kid.map(String::from),
        }
    }

    // =======================================================================
    // find_matching_key tests
    // =======================================================================

    // RFC 7517 §4: kid identifies a key within a set.
    #[test]
    fn test_find_matching_key_by_kid() {
        let jwks = JwkSet {
            keys: vec![
                ec_jwk_entry(Some("key-1"), None, None),
                ec_jwk_entry(Some("key-2"), None, None),
            ],
        };
        let hdr = header(JwsAlgorithm::Es256, Some("key-2"));

        // Should succeed and select the second key (kid="key-2")
        let result = find_matching_key(&jwks, &hdr);
        assert!(result.is_ok(), "should find key with kid=key-2");
    }

    // RFC 7517 §5: a kid absent from the set resolves no key.
    #[test]
    fn test_find_matching_key_kid_not_found() {
        let jwks = JwkSet {
            keys: vec![
                ec_jwk_entry(Some("key-1"), None, None),
                ec_jwk_entry(Some("key-2"), None, None),
            ],
        };
        let hdr = header(JwsAlgorithm::Es256, Some("missing"));

        let result = find_matching_key(&jwks, &hdr);
        let err = result.unwrap_err();
        assert!(
            matches!(&err, ServiceError::OAuth { code, .. } if *code == OAuthErrorCode::InvalidClient)
        );
        assert!(
            matches!(&err, ServiceError::OAuth { description, .. } if description == "No matching key found in JWKS")
        );
    }

    // RFC 7517 §4: kty narrows candidate keys when kid is absent.
    #[test]
    fn test_find_matching_key_algorithm_fallback_ec() {
        let jwks = JwkSet {
            keys: vec![ec_jwk_entry(None, None, None)],
        };
        // No kid in header — should fall back to kty matching
        let hdr = header(JwsAlgorithm::Es256, None);

        let result = find_matching_key(&jwks, &hdr);
        assert!(result.is_ok(), "should match EC key by algorithm fallback");
    }

    // RFC 7517 §4: kty narrows candidate keys when kid is absent.
    #[test]
    fn test_find_matching_key_algorithm_fallback_rsa() {
        let jwks = JwkSet {
            keys: vec![rsa_jwk_entry(None, None, None)],
        };
        let hdr = header(JwsAlgorithm::Rs256, None);

        let result = find_matching_key(&jwks, &hdr);
        assert!(result.is_ok(), "should match RSA key by algorithm fallback");
    }

    // RFC 7517 §4: a key whose use is enc is not a signature verification key.
    #[test]
    fn test_find_matching_key_skips_enc_use() {
        // Key has use="enc" (encryption), should be skipped for signing
        let jwks = JwkSet {
            keys: vec![ec_jwk_entry(None, None, Some("enc"))],
        };
        let hdr = header(JwsAlgorithm::Es256, None);

        let result = find_matching_key(&jwks, &hdr);
        let err = result.unwrap_err();
        assert!(
            matches!(&err, ServiceError::OAuth { code, .. } if *code == OAuthErrorCode::InvalidClient)
        );
        assert!(
            matches!(&err, ServiceError::OAuth { description, .. } if description == "No matching key found in JWKS")
        );
    }

    // RFC 7517 §4: a key whose use is sig verifies signatures.
    #[test]
    fn test_find_matching_key_allows_sig_use() {
        // Key with use="sig" should be accepted
        let jwks = JwkSet {
            keys: vec![ec_jwk_entry(None, None, Some("sig"))],
        };
        let hdr = header(JwsAlgorithm::Es256, None);

        let result = find_matching_key(&jwks, &hdr);
        assert!(result.is_ok(), "should accept key with use=sig");
    }

    // RFC 7517 §4: alg restricts the key to one algorithm.
    #[test]
    fn test_find_matching_key_skips_wrong_alg_field() {
        // Key has alg="ES384" but header wants ES256 — should skip
        let jwks = JwkSet {
            keys: vec![ec_jwk_entry(None, Some("ES384"), None)],
        };
        let hdr = header(JwsAlgorithm::Es256, None);

        let result = find_matching_key(&jwks, &hdr);
        let err = result.unwrap_err();
        assert!(
            matches!(&err, ServiceError::OAuth { code, .. } if *code == OAuthErrorCode::InvalidClient)
        );
        assert!(
            matches!(&err, ServiceError::OAuth { description, .. } if description == "No matching key found in JWKS")
        );
    }

    // RFC 7517 §4: a key whose alg matches is used.
    #[test]
    fn test_find_matching_key_accepts_matching_alg_field() {
        // Key with alg="ES256" matching header alg should be accepted
        let jwks = JwkSet {
            keys: vec![ec_jwk_entry(None, Some("ES256"), None)],
        };
        let hdr = header(JwsAlgorithm::Es256, None);

        let result = find_matching_key(&jwks, &hdr);
        assert!(result.is_ok(), "should accept key with matching alg");
    }

    // RFC 7517 §4: an algorithm the key cannot carry resolves no key.
    //
    // `KeyType::for_alg` maps RS256 to an RSA key, so an EC-only key set has
    // nothing selectable. An `alg` outside `JwsAlgorithm` cannot be tested
    // here at all — `HeaderAlg` refuses it before a `JwtAssertionHeader`
    // exists (`test_structural_algorithm_gate_matches_client_assertion_allowed`).
    #[test]
    fn test_find_matching_key_algorithm_without_matching_key_type() {
        let jwks = JwkSet {
            keys: vec![ec_jwk_entry(None, None, None)],
        };
        let hdr = header(JwsAlgorithm::Rs256, None);

        let result = find_matching_key(&jwks, &hdr);
        let err = result.unwrap_err();
        assert!(
            matches!(&err, ServiceError::OAuth { code, .. } if *code == OAuthErrorCode::InvalidClient)
        );
    }

    // RFC 7517 §5: an empty key set resolves no key.
    #[test]
    fn test_find_matching_key_empty_jwks() {
        let jwks = JwkSet { keys: vec![] };
        let hdr = header(JwsAlgorithm::Es256, None);

        let result = find_matching_key(&jwks, &hdr);
        assert!(result.is_err(), "empty JWKS should produce error");
    }

    // RFC 7517 §4: kid is the primary selector.
    #[test]
    fn test_find_matching_key_kid_match_ignores_kty() {
        // When kid matches, the function uses that key regardless of kty filtering.
        // Here kid matches an RSA key but header says ES256 — the function will
        // attempt to build an EC decoding key from RSA components and fail.
        let jwks = JwkSet {
            keys: vec![rsa_jwk_entry(Some("rsa-key"), None, None)],
        };
        let hdr = header(JwsAlgorithm::Es256, Some("rsa-key"));

        // kid match causes JwkEntry::decoding_key_for("RSA", "ES256") which is
        // an unsupported combination and returns an error.
        let result = find_matching_key(&jwks, &hdr);
        assert!(
            result.is_err(),
            "RSA key with ES256 alg should fail to build"
        );
    }

    // RFC 7517 §4: use still disqualifies a kid-matched key.
    #[test]
    fn test_find_matching_key_kid_match_skips_enc_use() {
        // A key with use="enc" must not be selected for signature verification,
        // even when its kid matches the header. This mirrors the SAML KeyDescriptor
        // behavior (encryption-only keys are skipped) and the algorithm-fallback path.
        let jwks = JwkSet {
            keys: vec![ec_jwk_entry(Some("key-1"), None, Some("enc"))],
        };
        let hdr = header(JwsAlgorithm::Es256, Some("key-1"));

        let result = find_matching_key(&jwks, &hdr);
        let err = result.unwrap_err();
        assert!(
            matches!(&err, ServiceError::OAuth { code, .. } if *code == OAuthErrorCode::InvalidClient)
        );
        assert!(
            matches!(&err, ServiceError::OAuth { description, .. } if description == "No matching key found in JWKS")
        );
    }

    // RFC 7517 §4: alg still disqualifies a kid-matched key.
    #[test]
    fn test_find_matching_key_kid_match_skips_wrong_alg_field() {
        // A key whose declared alg differs from the header alg must not be selected,
        // even when its kid matches. This prevents a key declared for PS256 from
        // being used to verify an RS256 JWT (and vice versa).
        let jwks = JwkSet {
            keys: vec![rsa_jwk_entry(Some("key-1"), Some("PS256"), None)],
        };
        let hdr = header(JwsAlgorithm::Rs256, Some("key-1"));

        let result = find_matching_key(&jwks, &hdr);
        let err = result.unwrap_err();
        assert!(
            matches!(&err, ServiceError::OAuth { code, .. } if *code == OAuthErrorCode::InvalidClient)
        );
        assert!(
            matches!(&err, ServiceError::OAuth { description, .. } if description == "No matching key found in JWKS")
        );
    }

    // RFC 7517 §4: use and alg are optional.
    #[test]
    fn test_find_matching_key_kid_match_allows_absent_use_and_alg() {
        // A key with no use and no alg fields (both absent) should be accepted
        // when kid matches — absence means the key is valid for any use/alg.
        // This is the common case (e.g. vouch-cli's PublicEcJwk emits no use/alg).
        let jwks = JwkSet {
            keys: vec![ec_jwk_entry(Some("key-1"), None, None)],
        };
        let hdr = header(JwsAlgorithm::Es256, Some("key-1"));

        let result = find_matching_key(&jwks, &hdr);
        assert!(
            result.is_ok(),
            "key with absent use/alg and matching kid should be accepted"
        );
    }

    // RFC 7517 §4: kid takes precedence over a type match.
    #[test]
    fn test_find_matching_key_prefers_kid_over_kty() {
        // Two keys: EC key-1 and EC key-2. Header has kid=key-2.
        // Should specifically pick key-2 even though key-1 also matches by kty.
        let jwks = JwkSet {
            keys: vec![
                ec_jwk_entry(Some("key-1"), None, None),
                ec_jwk_entry(Some("key-2"), None, None),
            ],
        };
        let hdr = header(JwsAlgorithm::Es256, Some("key-2"));

        let result = find_matching_key(&jwks, &hdr);
        assert!(result.is_ok());
    }

    // =======================================================================
    // find_matching_key: skip unbuildable candidates (short-circuit fix)
    //
    // A key that matches the selector (by `kid` or by `kty`) but cannot be
    // built into a `DecodingKey` — wrong `kty` for the algorithm, or
    // missing/invalid `x`/`y`/`n`/`e`/`crv` components — is "not usable for
    // this assertion," the same category as the `use`/`alg` metadata
    // mismatches the loops already `continue` past. The search must skip it
    // and try later candidates, returning an error only when none are usable.
    // =======================================================================

    // RFC 7517 §4: a `kty`-matched key that cannot be built is skipped, and a
    // later key of the same `kty` satisfies the assertion. The algorithm
    // fallback is reached whenever the JWS header carries no `kid`, so a
    // single malformed key ahead of a valid one is reachable without any
    // duplicate-`kid` precondition.
    #[test]
    fn test_find_matching_key_alg_fallback_skips_malformed_rsa() {
        let jwks = JwkSet {
            keys: vec![
                malformed_rsa_jwk_entry(None, None, None), // kty=Rsa, missing n/e
                rsa_jwk_entry(None, None, None),           // valid RSA
            ],
        };
        let hdr = header(JwsAlgorithm::Rs256, None);

        let result = find_matching_key(&jwks, &hdr);
        assert!(
            result.is_ok(),
            "should skip the malformed first key and build the valid RSA key"
        );
    }

    // RFC 7517 §4.5 makes `kid` uniqueness a SHOULD, not a MUST, and the
    // write-time gates do not reject duplicate `kid`s. When two keys share a
    // `kid` and the first is the wrong `kty` for the header's algorithm (RSA
    // vs an ES256 header — the wrong-`kty`-for-`alg` arm of
    // `JwkEntry::decoding_key_for`), the search must skip it and use the
    // later, buildable sibling carrying the same `kid`.
    #[test]
    fn test_find_matching_key_kid_match_skips_unbuildable_sibling() {
        // First key: RSA with kid="dup", wrong kty for ES256.
        // Second key: EC with kid="dup", valid for ES256.
        let jwks = JwkSet {
            keys: vec![
                rsa_jwk_entry(Some("dup"), None, None),
                ec_jwk_entry(Some("dup"), None, None),
            ],
        };
        let hdr = header(JwsAlgorithm::Es256, Some("dup"));

        let result = find_matching_key(&jwks, &hdr);
        assert!(
            result.is_ok(),
            "should skip the unbuildable RSA key and build the valid EC sibling"
        );
    }

    // RFC 7517 §4: a single algorithm-fallback candidate that is unbuildable
    // reports the build error (not the generic "no matching key"), matching
    // the pre-fix behavior for a one-key set so error reporting is unchanged.
    #[test]
    fn test_find_matching_key_alg_fallback_single_unbuildable_returns_build_error() {
        let jwks = JwkSet {
            keys: vec![malformed_rsa_jwk_entry(None, None, None)],
        };
        let hdr = header(JwsAlgorithm::Rs256, None);

        let err = find_matching_key(&jwks, &hdr).unwrap_err();
        assert!(
            matches!(&err, ServiceError::OAuth { code, .. } if *code == OAuthErrorCode::InvalidClient)
        );
        assert!(
            matches!(&err, ServiceError::OAuth { description, .. } if description == "RSA key missing n component")
        );
    }

    // RFC 7517 §4: when every algorithm-fallback candidate is unbuildable,
    // the FIRST candidate's build error is returned (not the last's, and not
    // the generic "no matching key" fallback) — keeping error reporting
    // identical to the single-key case the pre-fix code produced.
    #[test]
    fn test_find_matching_key_alg_fallback_all_unbuildable_returns_first_error() {
        // First: missing `n` -> "RSA key missing n component".
        // Second: has `n` but missing `e` -> "RSA key missing e component".
        let first = JwkEntry {
            n: None,
            e: None,
            ..rsa_jwk_entry(None, None, None)
        };
        let second = JwkEntry {
            e: None,
            ..rsa_jwk_entry(None, None, None)
        };
        let jwks = JwkSet {
            keys: vec![first, second],
        };
        let hdr = header(JwsAlgorithm::Rs256, None);

        let err = find_matching_key(&jwks, &hdr).unwrap_err();
        assert!(
            matches!(&err, ServiceError::OAuth { code, .. } if *code == OAuthErrorCode::InvalidClient)
        );
        assert!(
            matches!(&err, ServiceError::OAuth { description, .. } if description == "RSA key missing n component"),
            "all-candidates-fail must return the FIRST build error, not the last's"
        );
    }

    // =======================================================================
    // JwkEntry::decoding_key_for tests
    // =======================================================================

    // RFC 7517 §4: an EC key is built from its crv, x and y parameters.
    #[test]
    fn test_build_decoding_key_ec_valid() {
        let key = ec_jwk_entry(None, None, None);
        let result = key.decoding_key_for(JwsAlgorithm::Es256);
        assert!(result.is_ok(), "should build valid EC decoding key");
    }

    // RFC 7518 §6.2.1.2: "The length of this octet string MUST be the full
    // size of a coordinate for the curve specified in the "crv" parameter."
    // For P-256 that is 32 octets. A coordinate one octet short names a
    // different point (or none at all), so a signature made with the real key
    // does not verify under it — checked end to end, because the length is
    // enforced by the ECDSA verification, not at key construction.
    #[tokio::test]
    async fn test_ec_coordinate_shorter_than_the_curve_size_does_not_verify() {
        let (token, jwk) = es256_token_and_jwk().await;

        // The full-size coordinates verify the token: the control case, without
        // which a truncated coordinate failing would prove nothing.
        let full = ec_entry_from_coordinates(jwk.x(), jwk.y());
        let key = full
            .decoding_key_for(JwsAlgorithm::Es256)
            .expect("full-size EC key builds");
        assert!(
            verify_es256(&token, &key),
            "a P-256 key with full-size coordinates must verify its own token"
        );

        // Drop the last octet of x: 31 octets where the curve requires 32.
        let short_x = URL_SAFE_NO_PAD.encode(
            URL_SAFE_NO_PAD
                .decode(jwk.x())
                .expect("x is base64url")
                .get(..31)
                .expect("P-256 x is 32 octets"),
        );
        let truncated = ec_entry_from_coordinates(&short_x, jwk.y());

        let verified = truncated
            .decoding_key_for(JwsAlgorithm::Es256)
            .is_ok_and(|key| verify_es256(&token, &key));
        assert!(
            !verified,
            "a coordinate shorter than the full curve size must not verify a signature"
        );
    }

    /// Sign an ES256 JWT and return it with the public JWK that verifies it.
    async fn es256_token_and_jwk() -> (String, EcJwk) {
        let key = test_utils::make_test_oidc_key();
        let token = key
            .sign_jwt(&serde_json::json!({ "sub": "subject", "exp": 9_999_999_999i64 }))
            .await
            .expect("sign ES256 JWT");
        let jwk = key.public_key_jwk().expect("public JWK");
        (token, jwk)
    }

    /// A P-256 `JwkEntry` carrying the given base64url coordinates.
    fn ec_entry_from_coordinates(x: &str, y: &str) -> JwkEntry {
        JwkEntry {
            x: Some(x.to_string()),
            y: Some(y.to_string()),
            ..ec_jwk_entry(None, None, None)
        }
    }

    /// Whether `token` verifies as ES256 under `key`.
    fn verify_es256(token: &str, key: &jsonwebtoken::DecodingKey) -> bool {
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
        validation.validate_aud = false;
        jsonwebtoken::decode::<serde_json::Value>(token, key, &validation).is_ok()
    }

    // RFC 7518 §6.2.1: "The following members MUST be present for all
    // Elliptic Curve public keys: o "crv" o "x"". A client's registered JWKS
    // is attacker-influenced input via RFC 7591 dynamic registration, so an
    // EC key missing `x` has to be refused rather than defaulted.
    #[test]
    fn test_build_decoding_key_ec_missing_x() {
        let mut key = ec_jwk_entry(None, None, None);
        key.x = None;

        let result = key.decoding_key_for(JwsAlgorithm::Es256);
        let err = result.unwrap_err();
        assert!(err.to_string() == "EC key missing x component");
    }

    // RFC 7518 §6.2.1: "The following member MUST also be present for
    // Elliptic Curve public keys for the three curves defined in the following
    // section: o "y"". P-256 is one of those three, so `y` is required for
    // every EC key Vouch can verify with.
    #[test]
    fn test_build_decoding_key_ec_missing_y() {
        let mut key = ec_jwk_entry(None, None, None);
        key.y = None;

        let result = key.decoding_key_for(JwsAlgorithm::Es256);
        let err = result.unwrap_err();
        assert!(err.to_string() == "EC key missing y component");
    }

    // RFC 7517 §4: EC parameters are base64url encoded.
    #[test]
    fn test_build_decoding_key_ec_invalid_components() {
        let mut key = ec_jwk_entry(None, None, None);
        key.x = Some("not-valid-base64url!!!".to_string());

        let result = key.decoding_key_for(JwsAlgorithm::Es256);
        let err = result.unwrap_err();
        assert!(err.to_string() == "Invalid key in JWKS");
    }

    // RFC 7518 §6.3.1: "The following members MUST be present for RSA public
    // keys" — the modulus `n` and the exponent `e`.
    #[test]
    fn test_build_decoding_key_rsa_valid() {
        let key = rsa_jwk_entry(None, None, None);
        let result = key.decoding_key_for(JwsAlgorithm::Rs256);
        assert!(result.is_ok(), "should build valid RSA decoding key");
    }

    // RFC 7518 §6.3.1.1: the "n" (modulus) parameter is one of the members
    // that MUST be present for an RSA public key (§6.3.1).
    #[test]
    fn test_build_decoding_key_rsa_missing_n() {
        let mut key = rsa_jwk_entry(None, None, None);
        key.n = None;

        let result = key.decoding_key_for(JwsAlgorithm::Rs256);
        let err = result.unwrap_err();
        assert!(err.to_string() == "RSA key missing n component");
    }

    // RFC 7518 §6.3.1.2: the "e" (exponent) parameter is one of the members
    // that MUST be present for an RSA public key (§6.3.1).
    #[test]
    fn test_build_decoding_key_rsa_missing_e() {
        let mut key = rsa_jwk_entry(None, None, None);
        key.e = None;

        let result = key.decoding_key_for(JwsAlgorithm::Rs256);
        let err = result.unwrap_err();
        assert!(err.to_string() == "RSA key missing e component");
    }

    // RFC 7517 §4: RSA parameters are base64url encoded.
    #[test]
    fn test_build_decoding_key_rsa_invalid_components() {
        let mut key = rsa_jwk_entry(None, None, None);
        key.n = Some("not-valid!!!".to_string());

        let result = key.decoding_key_for(JwsAlgorithm::Rs256);
        let err = result.unwrap_err();
        assert!(err.to_string() == "Invalid key in JWKS");
    }

    // RFC 7517 §4: kty and alg must agree.
    #[test]
    fn test_build_decoding_key_unsupported_kty_alg_combination() {
        // EC key with RS256 algorithm — unsupported combination
        let key = ec_jwk_entry(None, None, None);
        let result = key.decoding_key_for(JwsAlgorithm::Rs256);
        let err = result.unwrap_err();
        assert!(err.to_string() == "No matching key found in JWKS");
    }

    // RFC 7517 §4: kty and alg must agree.
    #[test]
    fn test_build_decoding_key_rsa_key_with_ec_alg() {
        // RSA key with ES256 algorithm — unsupported combination
        let key = rsa_jwk_entry(None, None, None);
        let result = key.decoding_key_for(JwsAlgorithm::Es256);
        assert!(result.is_err());
    }

    // RFC 7517 §4: an alg that does not match the key's kty builds no key.
    #[test]
    fn test_build_decoding_key_algorithm_kty_mismatch() {
        let key = ec_jwk_entry(None, None, None);
        let result = key.decoding_key_for(JwsAlgorithm::Rs256);
        assert!(result.is_err());
    }

    // ====================================================================
    // PS256 support (RFC 9101 / FAPI 2.0)
    // ====================================================================

    // RFC 7517 §4: kty narrows candidate keys when kid is absent.
    #[test]
    fn test_find_matching_key_algorithm_fallback_ps256() {
        let jwks = JwkSet {
            keys: vec![rsa_jwk_entry(None, None, None)],
        };
        let hdr = header(JwsAlgorithm::Ps256, None);

        let result = find_matching_key(&jwks, &hdr);
        assert!(
            result.is_ok(),
            "should match RSA key by algorithm fallback for PS256"
        );
    }

    // RFC 7517 §4: an RSA key serves PS256 as well as RS256.
    #[test]
    fn test_build_decoding_key_rsa_ps256_valid() {
        let key = rsa_jwk_entry(None, None, None);
        let result = key.decoding_key_for(JwsAlgorithm::Ps256);
        assert!(
            result.is_ok(),
            "PS256 with valid RSA key should produce a decoding key"
        );
    }

    // ====================================================================
    // EdDSA / OKP support
    // ====================================================================

    // RFC 7517 §4: kty narrows candidate keys when kid is absent.
    #[test]
    fn test_find_matching_key_algorithm_fallback_eddsa() {
        let jwks = JwkSet {
            keys: vec![okp_jwk_entry(None, None, None)],
        };
        let hdr = header(JwsAlgorithm::EdDsa, None);

        let result = find_matching_key(&jwks, &hdr);
        assert!(
            result.is_ok(),
            "should match OKP key by algorithm fallback for EdDSA"
        );
    }

    // RFC 7517 §4: an OKP key is built from its crv and x parameters.
    #[test]
    fn test_build_decoding_key_okp_eddsa_valid() {
        let key = okp_jwk_entry(None, None, None);
        let result = key.decoding_key_for(JwsAlgorithm::EdDsa);
        assert!(
            result.is_ok(),
            "EdDSA with valid OKP key should produce a decoding key"
        );
    }

    // RFC 7517 §4: an OKP key without x is incomplete.
    #[test]
    fn test_build_decoding_key_okp_missing_x() {
        let mut key = okp_jwk_entry(None, None, None);
        key.x = None;

        let result = key.decoding_key_for(JwsAlgorithm::EdDsa);
        let err = result.unwrap_err();
        assert!(err.to_string() == "OKP key missing x component");
    }

    // RFC 7517 §4: an OKP key without crv is incomplete.
    #[test]
    fn test_build_decoding_key_okp_missing_crv() {
        let mut key = okp_jwk_entry(None, None, None);
        key.crv = None;

        let result = key.decoding_key_for(JwsAlgorithm::EdDsa);
        let err = result.unwrap_err();
        assert!(err.to_string() == "OKP key missing crv component");
    }

    // RFC 7517 §4: crv must name the curve the algorithm uses.
    #[test]
    fn test_build_decoding_key_okp_wrong_curve() {
        let mut key = okp_jwk_entry(None, None, None);
        key.crv = Some("Ed448".to_string());

        let result = key.decoding_key_for(JwsAlgorithm::EdDsa);
        let err = result.unwrap_err();
        assert!(err.to_string() == "EdDSA requires OKP key with Ed25519 curve");
    }

    // =======================================================================
    // find_matching_key_with_refresh_client tests
    // =======================================================================

    #[tokio::test]
    async fn test_find_matching_key_with_refresh_no_uri_returns_error_on_miss() {
        // When no JWKS URI is configured, a kid-miss must return an error without
        // any network call.
        let state = test_utils::test_app_state().await;
        let http_client = reqwest::Client::new();
        let jwks = JwkSet { keys: vec![] }; // empty — no matching key
        let hdr = header(JwsAlgorithm::Es256, Some("unknown-kid"));

        let result = find_matching_key_with_refresh_client(
            &state.store,
            "client-abc",
            None, // no JWKS URI
            None,
            false,
            &http_client,
            &jwks,
            &hdr,
            // No URI → the function returns before the origin gate, so the
            // value is irrelevant; `NoFetch` is the honest report.
            JwksOrigin::NoFetch,
        )
        .await;

        assert!(
            result.is_err(),
            "kid-miss with no JWKS URI must return error"
        );
    }

    #[tokio::test]
    async fn test_find_matching_key_with_refresh_rate_limited_skip() {
        // When cached_at is within the 10-second rate-limit window, force-refresh
        // is skipped and the original error is returned without any network call.
        use jiff::Timestamp;
        let state = test_utils::test_app_state().await;
        let http_client = reqwest::Client::new();
        let jwks = JwkSet { keys: vec![] };
        let hdr = header(JwsAlgorithm::Es256, Some("missing-kid"));

        // cached_at = now (0 seconds ago) — within the 10-second rate limit window
        let recent = JwksCacheDoc {
            value: serde_json::json!({"keys": []}),
            cached_at: Timestamp::now(),
        };

        // Port 1 is unreachable; if the HTTP client is called the test would hang/error.
        let result = find_matching_key_with_refresh_client(
            &state.store,
            "client-rate-limited",
            Some("https://127.0.0.1:1/jwks"),
            Some(&recent),
            false,
            &http_client,
            &jwks,
            &hdr,
            // `NoFetch`: the origin gate must NOT fire here, so the 10s
            // rate-limit gate below it is what this test exercises.
            JwksOrigin::NoFetch,
        )
        .await;

        assert!(
            result.is_err(),
            "rate-limited refresh must propagate the original kid-miss error"
        );
    }

    #[tokio::test]
    async fn test_find_matching_key_with_refresh_attempts_fetch_on_stale_cache() {
        // When cached_at is stale (older than the rate-limit window) and a kid-miss
        // occurs, the function must attempt a force-refresh. Since fetch_and_parse_jwks
        // enforces HTTPS and wiremock serves HTTP, the fetch fails gracefully and the
        // function falls back to the original error. This test verifies the refresh
        // attempt path is entered (not the rate-limit skip path).
        let state = test_utils::test_app_state().await;
        let http_client = reqwest::Client::new();
        let stale_jwks = JwkSet { keys: vec![] };
        let hdr = header(JwsAlgorithm::Es256, Some("fresh-kid"));

        // cached_at 60 seconds ago — well outside the 10-second rate-limit window
        let old_cache = JwksCacheDoc {
            value: serde_json::json!({"keys": []}),
            cached_at: jiff::Timestamp::now() - jiff::SignedDuration::from_secs(60),
        };

        // Use an http URI (wiremock) so fetch_and_parse_jwks rejects it with an HTTPS error.
        // The wrapper logs a warning and falls back to the stale JWKS → kid not found → error.
        let result = find_matching_key_with_refresh_client(
            &state.store,
            "client-fetch-test",
            Some("http://127.0.0.1:1/jwks"),
            Some(&old_cache),
            false,
            &http_client,
            &stale_jwks,
            &hdr,
            // `NoFetch`: the origin gate must NOT fire here, so the
            // force-refresh attempt path below is what this test exercises.
            JwksOrigin::NoFetch,
        )
        .await;

        // Fetch fails (http URI rejected by HTTPS check) → fallback → kid not found → error
        assert!(
            result.is_err(),
            "kid-miss with stale cache: fallback error expected when fetch fails"
        );
    }

    // =======================================================================
    // resolve_client_jwks — JwksOrigin reporting
    //
    // Mirrors the mTLS self-signed path's `resolve_self_signed_jwks` origin
    // tests in `services::oidc::token::tests`: the `JwksOrigin` a URI-backed
    // resolution reports is the signal the kid-miss force-refresh gate reads,
    // so it must be `NoFetch` for a fresh cache and `Fetched` once a fetch is
    // attempted (success or stale-while-revalidate fallback). An unreachable
    // `https://` URI stands in for the fetch without a real network server:
    // the SSRF guard permits loopback in the test default (no TLS configured),
    // the connection is dialed, and it fails on connection-refused.
    // =======================================================================

    /// Directly seed a `JwksCacheDoc` at a given age — `db::upsert_jwks_cache`
    /// always stamps `cached_at: now`, so a TTL-boundary test needs this.
    /// Mirrors `services::oidc::token::tests::seed_jwks_cache`.
    async fn seed_jwks_cache(
        store: &DocumentStore,
        parent_id: &str,
        value: serde_json::Value,
        age_seconds: i64,
    ) {
        let doc = JwksCacheDoc {
            value,
            cached_at: jiff::Timestamp::now()
                .checked_sub(jiff::SignedDuration::from_secs(age_seconds))
                .expect("cache age must be representable"),
        };
        store
            .upsert(&format!("jwks_cache:{parent_id}"), &doc)
            .await
            .expect("seed jwks cache");
    }

    /// A URI the SSRF guard permits (loopback, allowed in the test default
    /// where TLS is not configured) but nothing listens on, so a fetch
    /// attempt fails fast on connection-refused.
    const UNREACHABLE_JWKS_URI: &str = "https://127.0.0.1:1/jwks.json";

    #[tokio::test]
    async fn resolve_client_jwks_reports_no_fetch_for_inline_jwks() {
        // An inline key set never fetches, so the RFC 7523 path's kid-miss
        // gate reads `NoFetch` — moot for inline clients (no URI to
        // force-refresh from), but the value must be correct so the gate
        // never misfires for an inline-configured client.
        let state = test_utils::test_app_state().await;
        let inline = JwkSet {
            keys: vec![ec_jwk_entry(Some("inline-kid"), None, None)],
        };

        let (resolved, origin) = resolve_client_jwks(
            &state.store,
            "inline-client",
            Some(&inline),
            None,
            None,
            false,
            &state.http_client,
        )
        .await
        .expect("inline jwks must resolve");

        assert_eq!(resolved, inline);
        assert!(
            matches!(origin, JwksOrigin::NoFetch),
            "an inline key set never fetches"
        );
    }

    #[tokio::test]
    async fn resolve_client_jwks_reports_no_fetch_for_fresh_cache() {
        // A cache within the 1h TTL is served without a fetch — the signal the
        // kid-miss force-refresh gate relies on to know it may still fetch
        // once this request. The unreachable URI would fail if dialed, so a
        // success proves no fetch happened.
        let state = test_utils::test_app_state().await;
        let value = serde_json::json!({"keys":[]});
        seed_jwks_cache(&state.store, "client-fresh-origin", value.clone(), 60).await;
        let cached = db::get_jwks_cache(&state.store, "client-fresh-origin")
            .await
            .expect("cache read")
            .expect("cache seeded");

        let (resolved, origin) = resolve_client_jwks(
            &state.store,
            "client-fresh-origin",
            None,
            Some(UNREACHABLE_JWKS_URI),
            Some(&cached),
            true,
            &state.http_client,
        )
        .await
        .expect("a fresh cache must resolve without a fetch");

        assert_eq!(resolved, db::parse_jwks_set(&value).expect("parse jwks"));
        assert!(
            matches!(origin, JwksOrigin::NoFetch),
            "a cache within the TTL must not fetch"
        );
    }

    #[tokio::test]
    async fn resolve_client_jwks_reports_fetched_for_stale_cache() {
        // Past the 1h TTL but within the 24h stale window: resolution attempts
        // a fetch (fails against the unreachable URI) and falls back to the
        // stale cache — `JwksOrigin::Fetched`. This is the origin the kid-miss
        // gate must read to skip a second fetch in the same request.
        let state = test_utils::test_app_state().await;
        let value = serde_json::json!({"keys":[]});
        seed_jwks_cache(&state.store, "client-stale-origin", value.clone(), 7200).await;
        let cached = db::get_jwks_cache(&state.store, "client-stale-origin")
            .await
            .expect("cache read")
            .expect("cache seeded");

        let (resolved, origin) = resolve_client_jwks(
            &state.store,
            "client-stale-origin",
            None,
            Some(UNREACHABLE_JWKS_URI),
            Some(&cached),
            true,
            &state.http_client,
        )
        .await
        .expect("a failed fetch within the stale window must fall back to the cache");

        assert_eq!(resolved, db::parse_jwks_set(&value).expect("parse jwks"));
        assert!(
            matches!(origin, JwksOrigin::Fetched),
            "a cache past the TTL must attempt a fetch"
        );
    }

    // =======================================================================
    // find_matching_key_with_refresh_client — within-request origin gate
    // =======================================================================

    #[tokio::test]
    async fn find_matching_key_with_refresh_skips_when_origin_is_fetched() {
        // When `resolve_client_jwks` already fetched in this request
        // (`JwksOrigin::Fetched`), the kid-miss force-refresh must be skipped
        // — bounding the auth attempt to at most one network fetch. This
        // mirrors the mTLS self-signed path's gate
        // (`test_authenticate_client_mtls_self_signed_skips_retry_when_resolution_already_fetched`).
        //
        // Structural coverage, not a mutation-killing assertion for the gate:
        // a skipped refresh and an attempted-then-failed refresh both fall
        // back to the same kid-miss error text by design, so this test alone
        // cannot distinguish them. The mutation-killing assertion — that the
        // skipped path performs exactly one network fetch, not two — lives in
        // `client_auth::tests::resolve_client_decoding_key_bounded_to_one_jwks_fetch`
        // (a network-call-counting harness). This test pins the gate's
        // observable contract: `Fetched` returns a clean `invalid_client`,
        // never a panic, hang, or a leaked network-error message.
        let state = test_utils::test_app_state().await;
        let http_client = reqwest::Client::new();
        let jwks = JwkSet { keys: vec![] };
        let hdr = header(JwsAlgorithm::Es256, Some("missing-kid"));

        // Stale cache (2h old) — past the 10s rate-limit window, so the
        // cross-request throttle does NOT skip; the within-request origin
        // gate is the only thing that prevents the fetch.
        let stale = JwksCacheDoc {
            value: serde_json::json!({"keys": []}),
            cached_at: jiff::Timestamp::now() - jiff::SignedDuration::from_secs(7200),
        };

        let result = find_matching_key_with_refresh_client(
            &state.store,
            "client-already-fetched",
            Some(UNREACHABLE_JWKS_URI),
            Some(&stale),
            true,
            &http_client,
            &jwks,
            &hdr,
            JwksOrigin::Fetched,
        )
        .await;

        let err = result.expect_err("already-fetched must skip the force-refresh");
        assert!(
            matches!(&err, ServiceError::OAuth { code, .. } if *code == OAuthErrorCode::InvalidClient),
            "already-fetched must resolve to invalid_client: {err:?}"
        );
        assert!(
            matches!(&err, ServiceError::OAuth { description, .. } if description == "No matching key found in JWKS"),
            "already-fetched must fall back to the original kid-miss, not a leaked fetch error: {err:?}"
        );
    }
}
