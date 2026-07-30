// SPDX-License-Identifier: Apache-2.0 OR MIT
//! JWKS resolution and caching for RFC 7523.
//!
//! Handles resolving client public keys from inline JWKS or remote JWKS URIs,
//! with database-backed caching for multi-instance deployments.

use super::validate::JwtAssertionHeader;
use crate::db::documents::jwks_cache::JwksCacheDoc;
use crate::db::store::DocumentStore;
use crate::error::{OAuthErrorCode, ServiceError, ServiceResult};
use serde::Deserialize;

/// A JSON Web Key Set (RFC 7517 Section 5).
#[derive(Debug, Deserialize)]
pub struct JwkSet {
    /// The keys in the set.
    pub keys: Vec<JwkEntry>,
}

/// A single JWK entry in a JWKS.
#[derive(Debug, Deserialize)]
pub struct JwkEntry {
    /// Key type (e.g., "EC", "RSA", "OKP").
    pub kty: String,
    /// Key ID (optional).
    #[serde(default)]
    pub kid: Option<String>,
    /// Algorithm (optional).
    #[serde(default)]
    pub alg: Option<String>,
    /// Key use (optional, e.g., "sig").
    #[serde(rename = "use", default)]
    pub use_: Option<String>,

    // EC key components
    #[serde(default)]
    pub crv: Option<String>,
    #[serde(default)]
    pub x: Option<String>,
    #[serde(default)]
    pub y: Option<String>,

    // RSA key components
    #[serde(default)]
    pub n: Option<String>,
    #[serde(default)]
    pub e: Option<String>,

    /// X.509 certificate chain (RFC 7517 Section 4.7).
    /// Each entry is base64-encoded (standard, NOT base64url) DER.
    #[serde(default)]
    pub x5c: Option<Vec<String>>,
}

/// Resolve the JWKS for a client — from inline `jwks` or fetched `jwks_uri`.
///
/// For `jwks_uri` clients, uses database-backed caching with stale-while-revalidate.
pub async fn resolve_client_jwks(
    store: &DocumentStore,
    client_id: &str,
    jwks: Option<&serde_json::Value>,
    jwks_uri: Option<&str>,
    jwks_cache: Option<&JwksCacheDoc>,
    allow_loopback: bool,
    http_client: &reqwest::Client,
) -> ServiceResult<JwkSet> {
    // Inline JWKS takes priority
    if let Some(jwks_value) = jwks {
        return parse_jwks_value(jwks_value);
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
    let value = crate::infra::jwks::resolve_cached_jwks(
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

/// Parse a JWKS JSON string.
#[cfg(test)]
fn parse_jwks(json: &str) -> ServiceResult<JwkSet> {
    serde_json::from_str(json).map_err(|e| {
        tracing::debug!("Failed to parse JWKS: {e}");
        ServiceError::oauth(OAuthErrorCode::InvalidClient, "Invalid JWKS format")
    })
}

/// Parse a JWKS from a `serde_json::Value`.
fn parse_jwks_value(value: &serde_json::Value) -> ServiceResult<JwkSet> {
    serde_json::from_value(value.clone()).map_err(|e| {
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
                    && key_alg != &header.alg
                {
                    continue;
                }
                return build_decoding_key_from_jwk(key, &header.alg);
            }
        }
        tracing::debug!("No key with kid '{kid}' found in JWKS");
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidClient,
            "No matching key found in JWKS",
        ));
    }

    // Fall back to matching by algorithm/key type
    let expected_kty = match header.alg.as_str() {
        "ES256" => "EC",
        "RS256" | "PS256" => "RSA",
        "EdDSA" => "OKP",
        _ => {
            return Err(ServiceError::oauth(
                OAuthErrorCode::InvalidClient,
                format!("Unsupported algorithm: {}", header.alg),
            ));
        }
    };

    for key in &jwks.keys {
        if key.kty == expected_kty {
            // If key has an alg field, it must match
            if let Some(ref key_alg) = key.alg
                && key_alg != &header.alg
            {
                continue;
            }
            // If key has a use field, it must be "sig"
            if let Some(ref use_) = key.use_
                && use_ != "sig"
            {
                continue;
            }
            return build_decoding_key_from_jwk(key, &header.alg);
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
    alg: &str,
) -> ServiceResult<jsonwebtoken::DecodingKey> {
    match (key.kty.as_str(), alg) {
        ("EC", "ES256") => {
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
        ("RSA", "RS256") | ("RSA", "PS256") => {
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
        ("OKP", "EdDSA") => {
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
        _ => Err(ServiceError::oauth(
            OAuthErrorCode::InvalidClient,
            "No matching key found in JWKS",
        )),
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

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
            kty: "EC".to_string(),
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
            kty: "RSA".to_string(),
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
            kty: "OKP".to_string(),
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

    fn header(alg: &str, kid: Option<&str>) -> JwtAssertionHeader {
        JwtAssertionHeader {
            alg: alg.to_string(),
            kid: kid.map(String::from),
        }
    }

    // =======================================================================
    // parse_jwks tests
    // =======================================================================

    #[test]
    fn test_parse_jwks_valid_ec_key() {
        let json =
            format!(r#"{{"keys":[{{"kty":"EC","crv":"P-256","x":"{EC_X}","y":"{EC_Y}"}}]}}"#,);
        let jwks = parse_jwks(&json).expect("should parse valid EC JWKS");
        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(jwks.keys[0].kty, "EC");
        assert_eq!(jwks.keys[0].crv.as_deref(), Some("P-256"));
        assert_eq!(jwks.keys[0].x.as_deref(), Some(EC_X));
        assert_eq!(jwks.keys[0].y.as_deref(), Some(EC_Y));
    }

    #[test]
    fn test_parse_jwks_valid_rsa_key() {
        let json = format!(r#"{{"keys":[{{"kty":"RSA","n":"{RSA_N}","e":"{RSA_E}"}}]}}"#,);
        let jwks = parse_jwks(&json).expect("should parse valid RSA JWKS");
        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(jwks.keys[0].kty, "RSA");
        assert_eq!(jwks.keys[0].n.as_deref(), Some(RSA_N));
        assert_eq!(jwks.keys[0].e.as_deref(), Some(RSA_E));
    }

    #[test]
    fn test_parse_jwks_empty_keys_array() {
        let json = r#"{"keys":[]}"#;
        let jwks = parse_jwks(json).expect("should parse empty JWKS");
        assert!(jwks.keys.is_empty());
    }

    #[test]
    fn test_parse_jwks_invalid_json() {
        let result = parse_jwks("not json");
        let err = result.unwrap_err();
        assert!(
            matches!(&err, ServiceError::OAuth { code, .. } if *code == OAuthErrorCode::InvalidClient)
        );
        assert!(
            matches!(&err, ServiceError::OAuth { description, .. } if description == "Invalid JWKS format")
        );
    }

    #[test]
    fn test_parse_jwks_missing_keys_field() {
        let result = parse_jwks(r#"{"not_keys": []}"#);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_jwks_multiple_keys() {
        let json = format!(
            r#"{{"keys":[
                {{"kty":"EC","crv":"P-256","x":"{EC_X}","y":"{EC_Y}","kid":"ec-1"}},
                {{"kty":"RSA","n":"{RSA_N}","e":"{RSA_E}","kid":"rsa-1"}}
            ]}}"#,
        );
        let jwks = parse_jwks(&json).expect("should parse multi-key JWKS");
        assert_eq!(jwks.keys.len(), 2);
        assert_eq!(jwks.keys[0].kid.as_deref(), Some("ec-1"));
        assert_eq!(jwks.keys[1].kid.as_deref(), Some("rsa-1"));
    }

    #[test]
    fn test_parse_jwks_preserves_optional_fields() {
        let json = format!(
            r#"{{"keys":[{{"kty":"EC","crv":"P-256","x":"{EC_X}","y":"{EC_Y}",
                "kid":"key-1","alg":"ES256","use":"sig"}}]}}"#,
        );
        let jwks = parse_jwks(&json).expect("should parse JWKS with optional fields");
        let key = &jwks.keys[0];
        assert_eq!(key.kid.as_deref(), Some("key-1"));
        assert_eq!(key.alg.as_deref(), Some("ES256"));
        assert_eq!(key.use_.as_deref(), Some("sig"));
    }

    // =======================================================================
    // find_matching_key tests
    // =======================================================================

    #[test]
    fn test_find_matching_key_by_kid() {
        let jwks = JwkSet {
            keys: vec![
                ec_jwk_entry(Some("key-1"), None, None),
                ec_jwk_entry(Some("key-2"), None, None),
            ],
        };
        let hdr = header("ES256", Some("key-2"));

        // Should succeed and select the second key (kid="key-2")
        let result = find_matching_key(&jwks, &hdr);
        assert!(result.is_ok(), "should find key with kid=key-2");
    }

    #[test]
    fn test_find_matching_key_kid_not_found() {
        let jwks = JwkSet {
            keys: vec![
                ec_jwk_entry(Some("key-1"), None, None),
                ec_jwk_entry(Some("key-2"), None, None),
            ],
        };
        let hdr = header("ES256", Some("missing"));

        let result = find_matching_key(&jwks, &hdr);
        let err = result.unwrap_err();
        assert!(
            matches!(&err, ServiceError::OAuth { code, .. } if *code == OAuthErrorCode::InvalidClient)
        );
        assert!(
            matches!(&err, ServiceError::OAuth { description, .. } if description == "No matching key found in JWKS")
        );
    }

    #[test]
    fn test_find_matching_key_algorithm_fallback_ec() {
        let jwks = JwkSet {
            keys: vec![ec_jwk_entry(None, None, None)],
        };
        // No kid in header — should fall back to kty matching
        let hdr = header("ES256", None);

        let result = find_matching_key(&jwks, &hdr);
        assert!(result.is_ok(), "should match EC key by algorithm fallback");
    }

    #[test]
    fn test_find_matching_key_algorithm_fallback_rsa() {
        let jwks = JwkSet {
            keys: vec![rsa_jwk_entry(None, None, None)],
        };
        let hdr = header("RS256", None);

        let result = find_matching_key(&jwks, &hdr);
        assert!(result.is_ok(), "should match RSA key by algorithm fallback");
    }

    #[test]
    fn test_find_matching_key_skips_enc_use() {
        // Key has use="enc" (encryption), should be skipped for signing
        let jwks = JwkSet {
            keys: vec![ec_jwk_entry(None, None, Some("enc"))],
        };
        let hdr = header("ES256", None);

        let result = find_matching_key(&jwks, &hdr);
        let err = result.unwrap_err();
        assert!(
            matches!(&err, ServiceError::OAuth { code, .. } if *code == OAuthErrorCode::InvalidClient)
        );
        assert!(
            matches!(&err, ServiceError::OAuth { description, .. } if description == "No matching key found in JWKS")
        );
    }

    #[test]
    fn test_find_matching_key_allows_sig_use() {
        // Key with use="sig" should be accepted
        let jwks = JwkSet {
            keys: vec![ec_jwk_entry(None, None, Some("sig"))],
        };
        let hdr = header("ES256", None);

        let result = find_matching_key(&jwks, &hdr);
        assert!(result.is_ok(), "should accept key with use=sig");
    }

    #[test]
    fn test_find_matching_key_skips_wrong_alg_field() {
        // Key has alg="ES384" but header wants ES256 — should skip
        let jwks = JwkSet {
            keys: vec![ec_jwk_entry(None, Some("ES384"), None)],
        };
        let hdr = header("ES256", None);

        let result = find_matching_key(&jwks, &hdr);
        let err = result.unwrap_err();
        assert!(
            matches!(&err, ServiceError::OAuth { code, .. } if *code == OAuthErrorCode::InvalidClient)
        );
        assert!(
            matches!(&err, ServiceError::OAuth { description, .. } if description == "No matching key found in JWKS")
        );
    }

    #[test]
    fn test_find_matching_key_accepts_matching_alg_field() {
        // Key with alg="ES256" matching header alg should be accepted
        let jwks = JwkSet {
            keys: vec![ec_jwk_entry(None, Some("ES256"), None)],
        };
        let hdr = header("ES256", None);

        let result = find_matching_key(&jwks, &hdr);
        assert!(result.is_ok(), "should accept key with matching alg");
    }

    #[test]
    fn test_find_matching_key_unsupported_algorithm() {
        // No kid in header, unsupported algorithm should error
        let jwks = JwkSet {
            keys: vec![ec_jwk_entry(None, None, None)],
        };
        let hdr = header("ES384", None);

        let result = find_matching_key(&jwks, &hdr);
        let err = result.unwrap_err();
        assert!(
            matches!(&err, ServiceError::OAuth { code, .. } if *code == OAuthErrorCode::InvalidClient)
        );
        assert!(
            matches!(&err, ServiceError::OAuth { description, .. } if description.contains("Unsupported algorithm"))
        );
    }

    #[test]
    fn test_find_matching_key_empty_jwks() {
        let jwks = JwkSet { keys: vec![] };
        let hdr = header("ES256", None);

        let result = find_matching_key(&jwks, &hdr);
        assert!(result.is_err(), "empty JWKS should produce error");
    }

    #[test]
    fn test_find_matching_key_kid_match_ignores_kty() {
        // When kid matches, the function uses that key regardless of kty filtering.
        // Here kid matches an RSA key but header says ES256 — the function will
        // attempt to build an EC decoding key from RSA components and fail.
        let jwks = JwkSet {
            keys: vec![rsa_jwk_entry(Some("rsa-key"), None, None)],
        };
        let hdr = header("ES256", Some("rsa-key"));

        // kid match causes build_decoding_key_from_jwk("RSA", "ES256") which is
        // an unsupported combination and returns an error.
        let result = find_matching_key(&jwks, &hdr);
        assert!(
            result.is_err(),
            "RSA key with ES256 alg should fail to build"
        );
    }

    #[test]
    fn test_find_matching_key_kid_match_skips_enc_use() {
        // A key with use="enc" must not be selected for signature verification,
        // even when its kid matches the header. This mirrors the SAML KeyDescriptor
        // behavior (encryption-only keys are skipped) and the algorithm-fallback path.
        let jwks = JwkSet {
            keys: vec![ec_jwk_entry(Some("key-1"), None, Some("enc"))],
        };
        let hdr = header("ES256", Some("key-1"));

        let result = find_matching_key(&jwks, &hdr);
        let err = result.unwrap_err();
        assert!(
            matches!(&err, ServiceError::OAuth { code, .. } if *code == OAuthErrorCode::InvalidClient)
        );
        assert!(
            matches!(&err, ServiceError::OAuth { description, .. } if description == "No matching key found in JWKS")
        );
    }

    #[test]
    fn test_find_matching_key_kid_match_skips_wrong_alg_field() {
        // A key whose declared alg differs from the header alg must not be selected,
        // even when its kid matches. This prevents a key declared for PS256 from
        // being used to verify an RS256 JWT (and vice versa).
        let jwks = JwkSet {
            keys: vec![rsa_jwk_entry(Some("key-1"), Some("PS256"), None)],
        };
        let hdr = header("RS256", Some("key-1"));

        let result = find_matching_key(&jwks, &hdr);
        let err = result.unwrap_err();
        assert!(
            matches!(&err, ServiceError::OAuth { code, .. } if *code == OAuthErrorCode::InvalidClient)
        );
        assert!(
            matches!(&err, ServiceError::OAuth { description, .. } if description == "No matching key found in JWKS")
        );
    }

    #[test]
    fn test_find_matching_key_kid_match_allows_absent_use_and_alg() {
        // A key with no use and no alg fields (both absent) should be accepted
        // when kid matches — absence means the key is valid for any use/alg.
        // This is the common case (e.g. vouch-cli's PublicEcJwk emits no use/alg).
        let jwks = JwkSet {
            keys: vec![ec_jwk_entry(Some("key-1"), None, None)],
        };
        let hdr = header("ES256", Some("key-1"));

        let result = find_matching_key(&jwks, &hdr);
        assert!(
            result.is_ok(),
            "key with absent use/alg and matching kid should be accepted"
        );
    }

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
        let hdr = header("ES256", Some("key-2"));

        let result = find_matching_key(&jwks, &hdr);
        assert!(result.is_ok());
    }

    // =======================================================================
    // build_decoding_key_from_jwk tests
    // =======================================================================

    #[test]
    fn test_build_decoding_key_ec_valid() {
        let key = ec_jwk_entry(None, None, None);
        let result = build_decoding_key_from_jwk(&key, "ES256");
        assert!(result.is_ok(), "should build valid EC decoding key");
    }

    #[test]
    fn test_build_decoding_key_ec_missing_x() {
        let mut key = ec_jwk_entry(None, None, None);
        key.x = None;

        let result = build_decoding_key_from_jwk(&key, "ES256");
        let err = result.unwrap_err();
        assert!(
            matches!(&err, ServiceError::OAuth { code, .. } if *code == OAuthErrorCode::InvalidClient)
        );
        assert!(
            matches!(&err, ServiceError::OAuth { description, .. } if description == "EC key missing x component")
        );
    }

    #[test]
    fn test_build_decoding_key_ec_missing_y() {
        let mut key = ec_jwk_entry(None, None, None);
        key.y = None;

        let result = build_decoding_key_from_jwk(&key, "ES256");
        let err = result.unwrap_err();
        assert!(
            matches!(&err, ServiceError::OAuth { code, .. } if *code == OAuthErrorCode::InvalidClient)
        );
        assert!(
            matches!(&err, ServiceError::OAuth { description, .. } if description == "EC key missing y component")
        );
    }

    #[test]
    fn test_build_decoding_key_ec_invalid_components() {
        let mut key = ec_jwk_entry(None, None, None);
        key.x = Some("not-valid-base64url!!!".to_string());

        let result = build_decoding_key_from_jwk(&key, "ES256");
        let err = result.unwrap_err();
        assert!(
            matches!(&err, ServiceError::OAuth { code, .. } if *code == OAuthErrorCode::InvalidClient)
        );
        assert!(
            matches!(&err, ServiceError::OAuth { description, .. } if description == "Invalid key in JWKS")
        );
    }

    #[test]
    fn test_build_decoding_key_rsa_valid() {
        let key = rsa_jwk_entry(None, None, None);
        let result = build_decoding_key_from_jwk(&key, "RS256");
        assert!(result.is_ok(), "should build valid RSA decoding key");
    }

    #[test]
    fn test_build_decoding_key_rsa_missing_n() {
        let mut key = rsa_jwk_entry(None, None, None);
        key.n = None;

        let result = build_decoding_key_from_jwk(&key, "RS256");
        let err = result.unwrap_err();
        assert!(
            matches!(&err, ServiceError::OAuth { code, .. } if *code == OAuthErrorCode::InvalidClient)
        );
        assert!(
            matches!(&err, ServiceError::OAuth { description, .. } if description == "RSA key missing n component")
        );
    }

    #[test]
    fn test_build_decoding_key_rsa_missing_e() {
        let mut key = rsa_jwk_entry(None, None, None);
        key.e = None;

        let result = build_decoding_key_from_jwk(&key, "RS256");
        let err = result.unwrap_err();
        assert!(
            matches!(&err, ServiceError::OAuth { code, .. } if *code == OAuthErrorCode::InvalidClient)
        );
        assert!(
            matches!(&err, ServiceError::OAuth { description, .. } if description == "RSA key missing e component")
        );
    }

    #[test]
    fn test_build_decoding_key_rsa_invalid_components() {
        let mut key = rsa_jwk_entry(None, None, None);
        key.n = Some("not-valid!!!".to_string());

        let result = build_decoding_key_from_jwk(&key, "RS256");
        let err = result.unwrap_err();
        assert!(
            matches!(&err, ServiceError::OAuth { code, .. } if *code == OAuthErrorCode::InvalidClient)
        );
        assert!(
            matches!(&err, ServiceError::OAuth { description, .. } if description == "Invalid key in JWKS")
        );
    }

    #[test]
    fn test_build_decoding_key_unsupported_kty_alg_combination() {
        // EC key with RS256 algorithm — unsupported combination
        let key = ec_jwk_entry(None, None, None);
        let result = build_decoding_key_from_jwk(&key, "RS256");
        let err = result.unwrap_err();
        assert!(
            matches!(&err, ServiceError::OAuth { code, .. } if *code == OAuthErrorCode::InvalidClient)
        );
        assert!(
            matches!(&err, ServiceError::OAuth { description, .. } if description == "No matching key found in JWKS")
        );
    }

    #[test]
    fn test_build_decoding_key_rsa_key_with_ec_alg() {
        // RSA key with ES256 algorithm — unsupported combination
        let key = rsa_jwk_entry(None, None, None);
        let result = build_decoding_key_from_jwk(&key, "ES256");
        assert!(result.is_err());
    }

    #[test]
    fn test_build_decoding_key_unknown_algorithm() {
        let key = ec_jwk_entry(None, None, None);
        let result = build_decoding_key_from_jwk(&key, "ES384");
        assert!(result.is_err());
    }

    // ====================================================================
    // x5c field parsing (RFC 7517 Section 4.7)
    // ====================================================================

    #[test]
    fn test_parse_jwks_with_x5c() {
        // x5c uses standard base64 (not base64url) per RFC 7517 §4.7
        let x5c_val = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA";
        let json = format!(
            r#"{{"keys":[{{"kty":"EC","crv":"P-256","x":"{EC_X}","y":"{EC_Y}",
                "x5c":["{x5c_val}"]}}]}}"#,
        );
        let jwks = parse_jwks(&json).expect("should parse JWKS with x5c");
        let key = jwks.keys.first().expect("one key");
        let x5c = key.x5c.as_ref().expect("x5c should be present");
        assert_eq!(x5c.len(), 1);
        assert_eq!(x5c.first().map(String::as_str), Some(x5c_val));
    }

    #[test]
    fn test_parse_jwks_without_x5c_defaults_to_none() {
        let json =
            format!(r#"{{"keys":[{{"kty":"EC","crv":"P-256","x":"{EC_X}","y":"{EC_Y}"}}]}}"#);
        let jwks = parse_jwks(&json).expect("should parse JWKS without x5c");
        let key = jwks.keys.first().expect("one key");
        assert!(
            key.x5c.is_none(),
            "x5c should default to None when absent from JSON"
        );
    }

    // ====================================================================
    // PS256 support (RFC 9101 / FAPI 2.0)
    // ====================================================================

    #[test]
    fn test_find_matching_key_algorithm_fallback_ps256() {
        let jwks = JwkSet {
            keys: vec![rsa_jwk_entry(None, None, None)],
        };
        let hdr = header("PS256", None);

        let result = find_matching_key(&jwks, &hdr);
        assert!(
            result.is_ok(),
            "should match RSA key by algorithm fallback for PS256"
        );
    }

    #[test]
    fn test_build_decoding_key_rsa_ps256_valid() {
        let key = rsa_jwk_entry(None, None, None);
        let result = build_decoding_key_from_jwk(&key, "PS256");
        assert!(
            result.is_ok(),
            "PS256 with valid RSA key should produce a decoding key"
        );
    }

    // ====================================================================
    // EdDSA / OKP support
    // ====================================================================

    #[test]
    fn test_find_matching_key_algorithm_fallback_eddsa() {
        let jwks = JwkSet {
            keys: vec![okp_jwk_entry(None, None, None)],
        };
        let hdr = header("EdDSA", None);

        let result = find_matching_key(&jwks, &hdr);
        assert!(
            result.is_ok(),
            "should match OKP key by algorithm fallback for EdDSA"
        );
    }

    #[test]
    fn test_build_decoding_key_okp_eddsa_valid() {
        let key = okp_jwk_entry(None, None, None);
        let result = build_decoding_key_from_jwk(&key, "EdDSA");
        assert!(
            result.is_ok(),
            "EdDSA with valid OKP key should produce a decoding key"
        );
    }

    #[test]
    fn test_build_decoding_key_okp_missing_x() {
        let mut key = okp_jwk_entry(None, None, None);
        key.x = None;

        let result = build_decoding_key_from_jwk(&key, "EdDSA");
        let err = result.unwrap_err();
        assert!(
            matches!(&err, ServiceError::OAuth { code, .. } if *code == OAuthErrorCode::InvalidClient)
        );
        assert!(
            matches!(&err, ServiceError::OAuth { description, .. } if description == "OKP key missing x component")
        );
    }

    #[test]
    fn test_build_decoding_key_okp_missing_crv() {
        let mut key = okp_jwk_entry(None, None, None);
        key.crv = None;

        let result = build_decoding_key_from_jwk(&key, "EdDSA");
        let err = result.unwrap_err();
        assert!(
            matches!(&err, ServiceError::OAuth { code, .. } if *code == OAuthErrorCode::InvalidClient)
        );
        assert!(
            matches!(&err, ServiceError::OAuth { description, .. } if description == "OKP key missing crv component")
        );
    }

    #[test]
    fn test_build_decoding_key_okp_wrong_curve() {
        let mut key = okp_jwk_entry(None, None, None);
        key.crv = Some("Ed448".to_string());

        let result = build_decoding_key_from_jwk(&key, "EdDSA");
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
        let hdr = header("ES256", Some("unknown-kid"));

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
        let hdr = header("ES256", Some("missing-kid"));

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
        let hdr = header("ES256", Some("fresh-kid"));

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
