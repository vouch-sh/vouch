// SPDX-License-Identifier: Apache-2.0 OR MIT
//! JWKS resolution and caching for RFC 7523.
//!
//! Handles resolving client public keys from inline JWKS or remote JWKS URIs,
//! with database-backed caching for multi-instance deployments.

use super::validate::JwtAssertionHeader;
use crate::db::{self, store::DocumentStore};
use crate::services::{OAuthErrorCode, ServiceError, ServiceResult};
use jiff::Timestamp;
use serde::Deserialize;

/// Maximum JWKS response size (256KB).
const MAX_JWKS_RESPONSE_SIZE: usize = 256 * 1024;

/// JWKS URI cache TTL in seconds (1 hour).
const JWKS_CACHE_TTL_SECONDS: i64 = 3600;

/// Maximum age for stale JWKS cache before rejecting (24 hours).
/// Prevents indefinite use of revoked keys on persistent fetch failures.
const JWKS_STALE_MAX_AGE_SECONDS: i64 = 86400;

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
    jwks_uri_cache: Option<&serde_json::Value>,
    jwks_uri_cached_at: Option<&str>,
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
            jwks_uri_cache,
            jwks_uri_cached_at,
            http_client,
        )
        .await;
    }

    Err(ServiceError::oauth(
        OAuthErrorCode::InvalidClient,
        "Client has no JWKS or JWKS URI configured",
    ))
}

/// Resolve the JWKS for a trusted issuer.
pub async fn resolve_issuer_jwks(
    store: &DocumentStore,
    issuer_id: &str,
    jwks_uri: &str,
    jwks_cache: Option<&serde_json::Value>,
    jwks_cached_at: Option<&str>,
    http_client: &reqwest::Client,
) -> ServiceResult<JwkSet> {
    resolve_jwks_uri_for_issuer(
        store,
        issuer_id,
        jwks_uri,
        jwks_cache,
        jwks_cached_at,
        http_client,
    )
    .await
}

/// Fetch JWKS from a URI with caching (for clients).
async fn resolve_jwks_uri(
    store: &DocumentStore,
    client_id: &str,
    uri: &str,
    cached_jwks: Option<&serde_json::Value>,
    cached_at: Option<&str>,
    http_client: &reqwest::Client,
) -> ServiceResult<JwkSet> {
    // Check cache freshness
    if let (Some(cache), Some(cached_at)) = (cached_jwks, cached_at)
        && let Ok(ts) = cached_at.parse::<Timestamp>()
    {
        let cache_age = Timestamp::now().as_second() - ts.as_second();
        if cache_age < JWKS_CACHE_TTL_SECONDS {
            return parse_jwks_value(cache);
        }
    }

    // Cache is stale or missing — attempt fetch
    match fetch_and_parse_jwks(uri, http_client).await {
        Ok((jwks_value, jwks_set)) => {
            // Update cache in database
            if let Err(e) = db::update_client_jwks_cache(store, client_id, &jwks_value).await {
                tracing::warn!("Failed to update JWKS cache for client {client_id}: {e}");
            }
            Ok(jwks_set)
        }
        Err(e) => {
            // Stale-while-revalidate: use stale cache on fetch failure (with max age cap)
            if let (Some(cache), Some(cached_at)) = (cached_jwks, cached_at)
                && let Ok(ts) = cached_at.parse::<Timestamp>()
            {
                let stale_age = Timestamp::now().as_second() - ts.as_second();
                if stale_age < JWKS_STALE_MAX_AGE_SECONDS {
                    tracing::warn!("JWKS fetch failed, using stale cache: {e}");
                    return parse_jwks_value(cache);
                }
                tracing::warn!("JWKS fetch failed and stale cache too old ({stale_age}s)");
            }
            Err(e)
        }
    }
}

/// Fetch JWKS from a URI with caching (for issuers).
async fn resolve_jwks_uri_for_issuer(
    store: &DocumentStore,
    issuer_id: &str,
    uri: &str,
    cached_jwks: Option<&serde_json::Value>,
    cached_at: Option<&str>,
    http_client: &reqwest::Client,
) -> ServiceResult<JwkSet> {
    // Check cache freshness
    if let (Some(cache), Some(cached_at)) = (cached_jwks, cached_at)
        && let Ok(ts) = cached_at.parse::<Timestamp>()
    {
        let cache_age = Timestamp::now().as_second() - ts.as_second();
        if cache_age < JWKS_CACHE_TTL_SECONDS {
            return parse_jwks_value(cache);
        }
    }

    // Cache is stale or missing — attempt fetch
    match fetch_and_parse_jwks(uri, http_client).await {
        Ok((jwks_value, jwks_set)) => {
            if let Err(e) = db::update_issuer_jwks_cache(store, issuer_id, &jwks_value).await {
                tracing::warn!("Failed to update JWKS cache for issuer {issuer_id}: {e}");
            }
            Ok(jwks_set)
        }
        Err(e) => {
            // Stale-while-revalidate: use stale cache on fetch failure (with max age cap)
            if let (Some(cache), Some(cached_at)) = (cached_jwks, cached_at)
                && let Ok(ts) = cached_at.parse::<Timestamp>()
            {
                let stale_age = Timestamp::now().as_second() - ts.as_second();
                if stale_age < JWKS_STALE_MAX_AGE_SECONDS {
                    tracing::warn!("JWKS fetch failed, using stale cache: {e}");
                    return parse_jwks_value(cache);
                }
                tracing::warn!("JWKS fetch failed and stale cache too old ({stale_age}s)");
            }
            Err(e)
        }
    }
}

/// Fetch JWKS from a remote URI.
///
/// Enforces HTTPS-only and response size cap.
async fn fetch_jwks(uri: &str, http_client: &reqwest::Client) -> ServiceResult<String> {
    // HTTPS-only
    if !uri.starts_with("https://") {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidClient,
            "JWKS URI must use HTTPS",
        ));
    }

    let response = http_client.get(uri).send().await.map_err(|e| {
        tracing::warn!("Failed to fetch JWKS from {uri}: {e}");
        ServiceError::oauth(
            OAuthErrorCode::InvalidClient,
            "Failed to fetch JWKS from URI",
        )
    })?;

    if !response.status().is_success() {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidClient,
            "JWKS URI request failed",
        ));
    }

    // Check content length before reading body
    if let Some(len) = response.content_length()
        && len > MAX_JWKS_RESPONSE_SIZE as u64
    {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidClient,
            "JWKS response exceeds maximum size (256KB)",
        ));
    }

    let body = response.bytes().await.map_err(|e| {
        ServiceError::oauth(
            OAuthErrorCode::InvalidClient,
            format!("Failed to read JWKS response: {e}"),
        )
    })?;

    if body.len() > MAX_JWKS_RESPONSE_SIZE {
        return Err(ServiceError::oauth(
            OAuthErrorCode::InvalidClient,
            "JWKS response exceeds maximum size (256KB)",
        ));
    }

    String::from_utf8(body.to_vec()).map_err(|_| {
        ServiceError::oauth(
            OAuthErrorCode::InvalidClient,
            "JWKS response is not valid UTF-8",
        )
    })
}

/// Fetch JWKS from a URI and parse into both a `Value` (for caching) and a `JwkSet`.
async fn fetch_and_parse_jwks(
    uri: &str,
    http_client: &reqwest::Client,
) -> ServiceResult<(serde_json::Value, JwkSet)> {
    let jwks_json = fetch_jwks(uri, http_client).await?;
    let jwks_value: serde_json::Value = serde_json::from_str(&jwks_json).map_err(|e| {
        tracing::debug!("Failed to parse JWKS as JSON value: {e}");
        ServiceError::oauth(OAuthErrorCode::InvalidClient, "Invalid JWKS format")
    })?;
    let jwks_set = parse_jwks_value(&jwks_value)?;
    Ok((jwks_value, jwks_set))
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
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
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

    // =======================================================================
    // fetch_jwks HTTPS enforcement test
    // =======================================================================

    #[tokio::test]
    async fn test_fetch_jwks_rejects_http_url() {
        let client = reqwest::Client::new();
        let result = fetch_jwks("http://example.com/jwks", &client).await;
        let err = result.unwrap_err();
        assert!(
            matches!(&err, ServiceError::OAuth { code, .. } if *code == OAuthErrorCode::InvalidClient)
        );
        assert!(
            matches!(&err, ServiceError::OAuth { description, .. } if description == "JWKS URI must use HTTPS")
        );
    }

    #[tokio::test]
    async fn test_fetch_jwks_rejects_ftp_url() {
        let client = reqwest::Client::new();
        let result = fetch_jwks("ftp://example.com/jwks", &client).await;
        let err = result.unwrap_err();
        assert!(
            matches!(&err, ServiceError::OAuth { code, .. } if *code == OAuthErrorCode::InvalidClient)
        );
        assert!(
            matches!(&err, ServiceError::OAuth { description, .. } if description == "JWKS URI must use HTTPS")
        );
    }

    #[tokio::test]
    async fn test_fetch_jwks_rejects_empty_uri() {
        let client = reqwest::Client::new();
        let result = fetch_jwks("", &client).await;
        let err = result.unwrap_err();
        assert!(
            matches!(&err, ServiceError::OAuth { code, .. } if *code == OAuthErrorCode::InvalidClient)
        );
        assert!(
            matches!(&err, ServiceError::OAuth { description, .. } if description == "JWKS URI must use HTTPS")
        );
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
}
