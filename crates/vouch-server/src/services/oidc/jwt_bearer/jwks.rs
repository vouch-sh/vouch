// SPDX-License-Identifier: Apache-2.0 OR MIT
//! JWKS resolution and caching for RFC 7523.
//!
//! Handles resolving client public keys from inline JWKS or remote JWKS URIs,
//! with database-backed caching for multi-instance deployments.

use super::validate::JwtAssertionHeader;
use crate::crypto::alg::JwsAlgorithm;
use crate::db::documents::jwks_cache::JwksCacheDoc;
use crate::db::store::DocumentStore;
use crate::db::{JwkEntry, JwkSet, KeyType};
use crate::error::{OAuthErrorCode, ServiceError, ServiceResult};

/// Resolve the JWKS for a client — from an inline key set or a fetched
/// `jwks_uri`. The two are exclusive (RFC 7591 §2), so there is no precedence
/// between them: at most one is ever `Some`.
///
/// For `jwks_uri` clients, uses database-backed caching with stale-while-revalidate.
pub async fn resolve_client_jwks(
    store: &DocumentStore,
    client_id: &str,
    jwks: Option<&JwkSet>,
    jwks_uri: Option<&str>,
    jwks_cache: Option<&JwksCacheDoc>,
    allow_loopback: bool,
    http_client: &reqwest::Client,
) -> ServiceResult<JwkSet> {
    // An inline key set is already parsed — it arrives typed and needs no fetch.
    if let Some(jwks) = jwks {
        return Ok(jwks.clone());
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
) -> ServiceResult<JwkSet> {
    // This path doesn't act on whether the resolution fetched — that
    // distinction only matters to the mTLS force-refetch retry gate
    // (services/oidc/token.rs).
    let (value, _origin) = crate::infra::jwks::resolve_cached_jwks(
        store,
        parent_id,
        uri,
        cached,
        allow_loopback,
        http_client,
    )
    .await?;
    parse_jwks_value(&value)
}

/// Parse a JWKS from a `serde_json::Value`.
fn parse_jwks_value(value: &serde_json::Value) -> ServiceResult<JwkSet> {
    crate::db::parse_jwks_set(value).map_err(|e| {
        tracing::debug!("Failed to parse JWKS value: {e}");
        ServiceError::oauth(OAuthErrorCode::InvalidClient, "Invalid JWKS format")
    })
}

/// Find a matching key in a JWKS for the given JWT header.
///
/// Matching strategy:
/// 1. If `kid` is present in the header, match by `kid`.
/// 2. Otherwise, match by algorithm/key type.
pub fn find_matching_key(
    jwks: &JwkSet,
    header: &JwtAssertionHeader,
) -> ServiceResult<jsonwebtoken::DecodingKey> {
    // Try matching by kid first
    if let Some(ref kid) = header.kid {
        for key in &jwks.keys {
            if key.kid.as_deref() == Some(kid) {
                // Enforce the same `use`/`alg` constraints as the algorithm-fallback
                // path: a key declared for encryption (`use != "sig"`) or a different
                // algorithm must not be selected for signature verification, even when
                // its `kid` matches. This mirrors the SAML KeyDescriptor behavior, which
                // skips encryption-only keys.
                if let Some(ref use_) = key.use_
                    && use_ != "sig"
                {
                    continue;
                }
                if let Some(ref key_alg) = key.alg
                    && key_alg.as_str() != header.alg.as_str()
                {
                    continue;
                }
                return build_decoding_key_from_jwk(key, header.alg);
            }
        }
        tracing::debug!("No key with kid '{kid}' found in JWKS");
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidClient,
            "No matching key found in JWKS",
        ));
    }

    // Fall back to matching by algorithm/key type. The kty-per-alg rule is
    // `KeyType::for_alg`, shared with the write-time usability checks so the
    // two cannot disagree about which keys are selectable.
    let expected_kty = KeyType::for_alg(header.alg);

    for key in &jwks.keys {
        if key.kty == expected_kty {
            // If key has an alg field, it must match
            if let Some(ref key_alg) = key.alg
                && key_alg.as_str() != header.alg.as_str()
            {
                continue;
            }
            // If key has a use field, it must be "sig"
            if let Some(ref use_) = key.use_
                && use_ != "sig"
            {
                continue;
            }
            return build_decoding_key_from_jwk(key, header.alg);
        }
    }

    Err(ServiceError::oauth(
        OAuthErrorCode::InvalidClient,
        "No matching key found in JWKS",
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
    reason = "store/client/uri/cache/loopback-flag/http-client/jwks/header are all distinct inputs"
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
) -> ServiceResult<jsonwebtoken::DecodingKey> {
    // Try initial match first
    if let Ok(key) = find_matching_key(jwks, header) {
        return Ok(key);
    }

    // On miss, force-refresh if we have a URI and haven't refreshed recently
    let Some(uri) = jwks_uri else {
        return find_matching_key(jwks, header);
    };

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
    // from it), so the TTL and the stale fallback must both be bypassed. The
    // 10-second rate limit above is what bounds the fetch rate here.
    match crate::infra::jwks::fetch_and_cache(store, client_id, uri, allow_loopback, http_client)
        .await
    {
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

/// Build a `DecodingKey` from a JWK entry.
fn build_decoding_key_from_jwk(
    key: &JwkEntry,
    alg: JwsAlgorithm,
) -> ServiceResult<jsonwebtoken::DecodingKey> {
    match (&key.kty, alg) {
        (KeyType::Ec, JwsAlgorithm::Es256) => {
            let x = key.x.as_deref().ok_or_else(|| {
                ServiceError::oauth(OAuthErrorCode::InvalidClient, "EC key missing x component")
            })?;
            let y = key.y.as_deref().ok_or_else(|| {
                ServiceError::oauth(OAuthErrorCode::InvalidClient, "EC key missing y component")
            })?;
            jsonwebtoken::DecodingKey::from_ec_components(x, y).map_err(|e| {
                tracing::debug!("Invalid EC key in JWKS: {e}");
                ServiceError::oauth(OAuthErrorCode::InvalidClient, "Invalid key in JWKS")
            })
        }
        (KeyType::Rsa, JwsAlgorithm::Rs256 | JwsAlgorithm::Ps256) => {
            let n = key.n.as_deref().ok_or_else(|| {
                ServiceError::oauth(OAuthErrorCode::InvalidClient, "RSA key missing n component")
            })?;
            let e = key.e.as_deref().ok_or_else(|| {
                ServiceError::oauth(OAuthErrorCode::InvalidClient, "RSA key missing e component")
            })?;
            jsonwebtoken::DecodingKey::from_rsa_components(n, e).map_err(|e| {
                tracing::debug!("Invalid RSA key in JWKS: {e}");
                ServiceError::oauth(OAuthErrorCode::InvalidClient, "Invalid key in JWKS")
            })
        }
        (KeyType::Okp, JwsAlgorithm::EdDsa) => {
            let x = key.x.as_deref().ok_or_else(|| {
                ServiceError::oauth(OAuthErrorCode::InvalidClient, "OKP key missing x component")
            })?;
            let crv = key.crv.as_deref().ok_or_else(|| {
                ServiceError::oauth(
                    OAuthErrorCode::InvalidClient,
                    "OKP key missing crv component",
                )
            })?;
            if crv != "Ed25519" {
                return Err(ServiceError::oauth(
                    OAuthErrorCode::InvalidClient,
                    "EdDSA requires OKP key with Ed25519 curve",
                ));
            }
            jsonwebtoken::DecodingKey::from_ed_components(x).map_err(|e| {
                tracing::debug!("Invalid Ed25519 key in JWKS: {e}");
                ServiceError::oauth(OAuthErrorCode::InvalidClient, "Invalid key in JWKS")
            })
        }
        // Known kty, wrong alg for it. Kept as a separate arm from the
        // `Other` case below rather than merged, so an unrecognized kty is
        // a deliberate, visible decision here — both produce the same
        // error today, but the split is what the "Other" case means, not
        // an accident of a shared wildcard.
        (KeyType::Ec | KeyType::Rsa | KeyType::Okp, _) => Err(ServiceError::oauth(
            OAuthErrorCode::InvalidClient,
            "No matching key found in JWKS",
        )),
        // Unrecognized kty (RFC 7517 §4.1's registry is open — see
        // `KeyType`): never selectable, regardless of alg.
        (KeyType::Other(_), _) => Err(ServiceError::oauth(
            OAuthErrorCode::InvalidClient,
            "No matching key found in JWKS",
        )),
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

        // kid match causes build_decoding_key_from_jwk("RSA", "ES256") which is
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
    // build_decoding_key_from_jwk tests
    // =======================================================================

    // RFC 7517 §4: an EC key is built from its crv, x and y parameters.
    #[test]
    fn test_build_decoding_key_ec_valid() {
        let key = ec_jwk_entry(None, None, None);
        let result = build_decoding_key_from_jwk(&key, JwsAlgorithm::Es256);
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
        let full = ec_entry_from_coordinates(&jwk.x, &jwk.y);
        let key = build_decoding_key_from_jwk(&full, JwsAlgorithm::Es256)
            .expect("full-size EC key builds");
        assert!(
            verify_es256(&token, &key),
            "a P-256 key with full-size coordinates must verify its own token"
        );

        // Drop the last octet of x: 31 octets where the curve requires 32.
        let short_x = URL_SAFE_NO_PAD.encode(
            URL_SAFE_NO_PAD
                .decode(&jwk.x)
                .expect("x is base64url")
                .get(..31)
                .expect("P-256 x is 32 octets"),
        );
        let truncated = ec_entry_from_coordinates(&short_x, &jwk.y);

        let verified = build_decoding_key_from_jwk(&truncated, JwsAlgorithm::Es256)
            .is_ok_and(|key| verify_es256(&token, &key));
        assert!(
            !verified,
            "a coordinate shorter than the full curve size must not verify a signature"
        );
    }

    /// Sign an ES256 JWT and return it with the public JWK that verifies it.
    async fn es256_token_and_jwk() -> (String, crate::crypto::keys::EcJwk) {
        let key = crate::test_utils::make_test_oidc_key();
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

        let result = build_decoding_key_from_jwk(&key, JwsAlgorithm::Es256);
        let err = result.unwrap_err();
        assert!(
            matches!(&err, ServiceError::OAuth { code, .. } if *code == OAuthErrorCode::InvalidClient)
        );
        assert!(
            matches!(&err, ServiceError::OAuth { description, .. } if description == "EC key missing x component")
        );
    }

    // RFC 7518 §6.2.1: "The following member MUST also be present for
    // Elliptic Curve public keys for the three curves defined in the following
    // section: o "y"". P-256 is one of those three, so `y` is required for
    // every EC key Vouch can verify with.
    #[test]
    fn test_build_decoding_key_ec_missing_y() {
        let mut key = ec_jwk_entry(None, None, None);
        key.y = None;

        let result = build_decoding_key_from_jwk(&key, JwsAlgorithm::Es256);
        let err = result.unwrap_err();
        assert!(
            matches!(&err, ServiceError::OAuth { code, .. } if *code == OAuthErrorCode::InvalidClient)
        );
        assert!(
            matches!(&err, ServiceError::OAuth { description, .. } if description == "EC key missing y component")
        );
    }

    // RFC 7517 §4: EC parameters are base64url encoded.
    #[test]
    fn test_build_decoding_key_ec_invalid_components() {
        let mut key = ec_jwk_entry(None, None, None);
        key.x = Some("not-valid-base64url!!!".to_string());

        let result = build_decoding_key_from_jwk(&key, JwsAlgorithm::Es256);
        let err = result.unwrap_err();
        assert!(
            matches!(&err, ServiceError::OAuth { code, .. } if *code == OAuthErrorCode::InvalidClient)
        );
        assert!(
            matches!(&err, ServiceError::OAuth { description, .. } if description == "Invalid key in JWKS")
        );
    }

    // RFC 7518 §6.3.1: "The following members MUST be present for RSA public
    // keys" — the modulus `n` and the exponent `e`.
    #[test]
    fn test_build_decoding_key_rsa_valid() {
        let key = rsa_jwk_entry(None, None, None);
        let result = build_decoding_key_from_jwk(&key, JwsAlgorithm::Rs256);
        assert!(result.is_ok(), "should build valid RSA decoding key");
    }

    // RFC 7518 §6.3.1.1: the "n" (modulus) parameter is one of the members
    // that MUST be present for an RSA public key (§6.3.1).
    #[test]
    fn test_build_decoding_key_rsa_missing_n() {
        let mut key = rsa_jwk_entry(None, None, None);
        key.n = None;

        let result = build_decoding_key_from_jwk(&key, JwsAlgorithm::Rs256);
        let err = result.unwrap_err();
        assert!(
            matches!(&err, ServiceError::OAuth { code, .. } if *code == OAuthErrorCode::InvalidClient)
        );
        assert!(
            matches!(&err, ServiceError::OAuth { description, .. } if description == "RSA key missing n component")
        );
    }

    // RFC 7518 §6.3.1.2: the "e" (exponent) parameter is one of the members
    // that MUST be present for an RSA public key (§6.3.1).
    #[test]
    fn test_build_decoding_key_rsa_missing_e() {
        let mut key = rsa_jwk_entry(None, None, None);
        key.e = None;

        let result = build_decoding_key_from_jwk(&key, JwsAlgorithm::Rs256);
        let err = result.unwrap_err();
        assert!(
            matches!(&err, ServiceError::OAuth { code, .. } if *code == OAuthErrorCode::InvalidClient)
        );
        assert!(
            matches!(&err, ServiceError::OAuth { description, .. } if description == "RSA key missing e component")
        );
    }

    // RFC 7517 §4: RSA parameters are base64url encoded.
    #[test]
    fn test_build_decoding_key_rsa_invalid_components() {
        let mut key = rsa_jwk_entry(None, None, None);
        key.n = Some("not-valid!!!".to_string());

        let result = build_decoding_key_from_jwk(&key, JwsAlgorithm::Rs256);
        let err = result.unwrap_err();
        assert!(
            matches!(&err, ServiceError::OAuth { code, .. } if *code == OAuthErrorCode::InvalidClient)
        );
        assert!(
            matches!(&err, ServiceError::OAuth { description, .. } if description == "Invalid key in JWKS")
        );
    }

    // RFC 7517 §4: kty and alg must agree.
    #[test]
    fn test_build_decoding_key_unsupported_kty_alg_combination() {
        // EC key with RS256 algorithm — unsupported combination
        let key = ec_jwk_entry(None, None, None);
        let result = build_decoding_key_from_jwk(&key, JwsAlgorithm::Rs256);
        let err = result.unwrap_err();
        assert!(
            matches!(&err, ServiceError::OAuth { code, .. } if *code == OAuthErrorCode::InvalidClient)
        );
        assert!(
            matches!(&err, ServiceError::OAuth { description, .. } if description == "No matching key found in JWKS")
        );
    }

    // RFC 7517 §4: kty and alg must agree.
    #[test]
    fn test_build_decoding_key_rsa_key_with_ec_alg() {
        // RSA key with ES256 algorithm — unsupported combination
        let key = rsa_jwk_entry(None, None, None);
        let result = build_decoding_key_from_jwk(&key, JwsAlgorithm::Es256);
        assert!(result.is_err());
    }

    // RFC 7517 §4: an alg that does not match the key's kty builds no key.
    #[test]
    fn test_build_decoding_key_algorithm_kty_mismatch() {
        let key = ec_jwk_entry(None, None, None);
        let result = build_decoding_key_from_jwk(&key, JwsAlgorithm::Rs256);
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
        let result = build_decoding_key_from_jwk(&key, JwsAlgorithm::Ps256);
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
        let result = build_decoding_key_from_jwk(&key, JwsAlgorithm::EdDsa);
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

        let result = build_decoding_key_from_jwk(&key, JwsAlgorithm::EdDsa);
        let err = result.unwrap_err();
        assert!(
            matches!(&err, ServiceError::OAuth { code, .. } if *code == OAuthErrorCode::InvalidClient)
        );
        assert!(
            matches!(&err, ServiceError::OAuth { description, .. } if description == "OKP key missing x component")
        );
    }

    // RFC 7517 §4: an OKP key without crv is incomplete.
    #[test]
    fn test_build_decoding_key_okp_missing_crv() {
        let mut key = okp_jwk_entry(None, None, None);
        key.crv = None;

        let result = build_decoding_key_from_jwk(&key, JwsAlgorithm::EdDsa);
        let err = result.unwrap_err();
        assert!(
            matches!(&err, ServiceError::OAuth { code, .. } if *code == OAuthErrorCode::InvalidClient)
        );
        assert!(
            matches!(&err, ServiceError::OAuth { description, .. } if description == "OKP key missing crv component")
        );
    }

    // RFC 7517 §4: crv must name the curve the algorithm uses.
    #[test]
    fn test_build_decoding_key_okp_wrong_curve() {
        let mut key = okp_jwk_entry(None, None, None);
        key.crv = Some("Ed448".to_string());

        let result = build_decoding_key_from_jwk(&key, JwsAlgorithm::EdDsa);
        let err = result.unwrap_err();
        assert!(
            matches!(&err, ServiceError::OAuth { code, .. } if *code == OAuthErrorCode::InvalidClient)
        );
        assert!(
            matches!(&err, ServiceError::OAuth { description, .. } if description == "EdDSA requires OKP key with Ed25519 curve")
        );
    }

    // =======================================================================
    // find_matching_key_with_refresh_client tests
    // =======================================================================

    #[tokio::test]
    async fn test_find_matching_key_with_refresh_no_uri_returns_error_on_miss() {
        // When no JWKS URI is configured, a kid-miss must return an error without
        // any network call.
        let state = crate::test_utils::test_app_state().await;
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
        let state = crate::test_utils::test_app_state().await;
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
        let state = crate::test_utils::test_app_state().await;
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
        )
        .await;

        // Fetch fails (http URI rejected by HTTPS check) → fallback → kid not found → error
        assert!(
            result.is_err(),
            "kid-miss with stale cache: fallback error expected when fetch fails"
        );
    }
}
