// SPDX-License-Identifier: Apache-2.0 OR MIT
//! OIDC discovery client for upstream identity providers.
//!
//! Fetches and caches the OpenID Connect discovery document (RFC 8414)
//! at startup to discover authorization, token, and JWKS endpoints.

use serde::Deserialize;
use url::Url;

use super::IdentityResult;

/// Cached OIDC discovery endpoints (RFC 8414).
#[derive(Debug)]
pub struct OidcProvider {
    /// The issuer identifier (must match the configured issuer).
    pub issuer: String,
    /// The authorization endpoint URL.
    pub authorization_endpoint: Url,
    /// The token endpoint URL.
    pub token_endpoint: Url,
    /// The JWKS endpoint URL (for ID token signature verification).
    pub jwks_uri: Url,
}

#[derive(Deserialize)]
struct DiscoveryDocument {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
}

/// Raw OIDC ID token claims (deserialization target, not exposed).
#[derive(Debug, Deserialize)]
struct IdTokenClaims {
    email: String,
    #[serde(default)]
    email_verified: bool,
    nonce: Option<String>,
    /// Google Workspace hosted domain claim.
    hd: Option<String>,
}

/// Fetch discovery from `{issuer}/.well-known/openid-configuration`.
///
/// # Errors
///
/// Returns error if fetch fails, JSON is invalid, required fields missing,
/// endpoints aren't valid URLs, or discovered issuer doesn't match configured.
pub async fn fetch_discovery(
    http_client: &reqwest::Client,
    issuer_url: &str,
) -> Result<OidcProvider, anyhow::Error> {
    let issuer = issuer_url.trim_end_matches('/');

    // Reject non-HTTPS issuers (except localhost for development)
    if let Ok(parsed) = Url::parse(issuer)
        && parsed.scheme() != "https"
        && !is_localhost(&parsed)
    {
        anyhow::bail!(
            "OIDC issuer must use HTTPS (got {issuer}). \
             HTTP is only allowed for localhost development."
        );
    }

    let discovery_url = format!("{issuer}/.well-known/openid-configuration");

    let response = http_client.get(&discovery_url).send().await.map_err(|e| {
        anyhow::anyhow!("Failed to fetch discovery document from {discovery_url}: {e}")
    })?;

    if !response.status().is_success() {
        anyhow::bail!(
            "Discovery endpoint returned HTTP {}: {discovery_url}",
            response.status()
        );
    }

    let doc: DiscoveryDocument = response
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to parse discovery document: {e}"))?;

    // RFC 8414 Section 3.3: The issuer in the discovery document MUST match
    // the configured issuer. This prevents SSRF and issuer confusion attacks.
    let discovered_issuer = doc.issuer.trim_end_matches('/');
    if discovered_issuer != issuer {
        anyhow::bail!(
            "Issuer mismatch: configured '{issuer}' but discovery \
             document reports '{discovered_issuer}'"
        );
    }

    let authorization_endpoint = Url::parse(&doc.authorization_endpoint).map_err(|e| {
        anyhow::anyhow!(
            "Invalid authorization_endpoint '{}': {e}",
            doc.authorization_endpoint
        )
    })?;

    let token_endpoint = Url::parse(&doc.token_endpoint)
        .map_err(|e| anyhow::anyhow!("Invalid token_endpoint '{}': {e}", doc.token_endpoint))?;

    let jwks_uri = Url::parse(&doc.jwks_uri)
        .map_err(|e| anyhow::anyhow!("Invalid jwks_uri '{}': {e}", doc.jwks_uri))?;

    Ok(OidcProvider {
        issuer: doc.issuer,
        authorization_endpoint,
        token_endpoint,
        jwks_uri,
    })
}

/// Verify an ID token from the upstream IdP and return a protocol-agnostic
/// [`IdentityResult`].
///
/// Fetches the JWKS from the provider's `jwks_uri`, verifies the JWT
/// signature, validates `iss`/`aud`/`exp`/`nonce` claims, checks
/// `email_verified`, and extracts the hosted domain (`hd`) claim.
///
/// # Errors
///
/// Returns error if JWKS fetch fails, no matching key is found,
/// signature is invalid, claims validation fails, nonce mismatches,
/// or the email is not verified.
pub async fn verify_id_token(
    http_client: &reqwest::Client,
    provider: &OidcProvider,
    id_token: &str,
    expected_client_id: &str,
    expected_nonce: &str,
) -> Result<IdentityResult, anyhow::Error> {
    // Decode the JWT header to determine algorithm and key ID
    let header = jsonwebtoken::decode_header(id_token)
        .map_err(|e| anyhow::anyhow!("Invalid ID token header: {e}"))?;

    let alg = header.alg;

    // Fetch JWKS from the upstream IdP
    let jwks_response = http_client
        .get(provider.jwks_uri.as_str())
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to fetch JWKS from {}: {e}", provider.jwks_uri))?;

    if !jwks_response.status().is_success() {
        anyhow::bail!(
            "JWKS endpoint returned HTTP {}: {}",
            jwks_response.status(),
            provider.jwks_uri,
        );
    }

    let jwks: jsonwebtoken::jwk::JwkSet = jwks_response
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to parse JWKS: {e}"))?;

    // Find matching key by kid, then by algorithm
    let decoding_key = find_decoding_key(&jwks, header.kid.as_deref(), alg)?;

    // Validate the token: signature, exp, iss, aud
    let mut validation = jsonwebtoken::Validation::new(alg);
    validation.set_issuer(&[&provider.issuer]);
    validation.set_audience(&[expected_client_id]);

    let token_data = jsonwebtoken::decode::<IdTokenClaims>(id_token, &decoding_key, &validation)
        .map_err(|e| anyhow::anyhow!("ID token verification failed: {e}"))?;

    let claims = token_data.claims;

    // OIDC Core Section 3.1.3.7: Verify nonce matches the value sent
    // in the authentication request to prevent replay attacks.
    // Empty nonce is only valid for device-code flow where no nonce is sent.
    if !expected_nonce.is_empty() {
        match &claims.nonce {
            Some(nonce) if nonce == expected_nonce => {}
            Some(nonce) => {
                anyhow::bail!(
                    "ID token nonce mismatch: expected '{expected_nonce}', \
                     got '{nonce}'"
                );
            }
            None => {
                anyhow::bail!("ID token missing nonce claim (expected '{expected_nonce}')");
            }
        }
    }

    if !claims.email_verified {
        anyhow::bail!("Email address is not verified by the identity provider");
    }

    Ok(IdentityResult {
        email: claims.email,
        domain: claims.hd,
    })
}

/// Find a `DecodingKey` from a JWKS matching the given `kid` and algorithm.
fn find_decoding_key(
    jwks: &jsonwebtoken::jwk::JwkSet,
    kid: Option<&str>,
    alg: jsonwebtoken::Algorithm,
) -> Result<jsonwebtoken::DecodingKey, anyhow::Error> {
    let expected_key_alg = algorithm_to_key_algorithm(alg);

    // Try matching by kid first
    if let Some(kid) = kid {
        for jwk in &jwks.keys {
            if jwk.common.key_id.as_deref() == Some(kid) {
                return jsonwebtoken::DecodingKey::from_jwk(jwk)
                    .map_err(|e| anyhow::anyhow!("Failed to build key from JWK (kid={kid}): {e}"));
            }
        }
        anyhow::bail!("No key with kid '{kid}' found in upstream JWKS");
    }

    // Fall back to matching by algorithm
    if let Some(expected) = expected_key_alg {
        for jwk in &jwks.keys {
            if jwk.common.key_algorithm == Some(expected) {
                return jsonwebtoken::DecodingKey::from_jwk(jwk)
                    .map_err(|e| anyhow::anyhow!("Failed to build key from JWK: {e}"));
            }
        }
    }

    // Last resort: try the first key (no kid/algorithm matched)
    tracing::warn!("No JWK matched by kid or algorithm, falling back to first key in JWKS");
    jwks.keys.first().map_or_else(
        || Err(anyhow::anyhow!("Upstream JWKS is empty")),
        |jwk| {
            jsonwebtoken::DecodingKey::from_jwk(jwk)
                .map_err(|e| anyhow::anyhow!("Failed to build key from JWK: {e}"))
        },
    )
}

/// Convert a `jsonwebtoken::Algorithm` to its `jwk::KeyAlgorithm` equivalent.
fn algorithm_to_key_algorithm(
    alg: jsonwebtoken::Algorithm,
) -> Option<jsonwebtoken::jwk::KeyAlgorithm> {
    use jsonwebtoken::Algorithm;
    use jsonwebtoken::jwk::KeyAlgorithm;
    match alg {
        Algorithm::ES256 => Some(KeyAlgorithm::ES256),
        Algorithm::ES384 => Some(KeyAlgorithm::ES384),
        Algorithm::RS256 => Some(KeyAlgorithm::RS256),
        Algorithm::RS384 => Some(KeyAlgorithm::RS384),
        Algorithm::RS512 => Some(KeyAlgorithm::RS512),
        Algorithm::PS256 => Some(KeyAlgorithm::PS256),
        Algorithm::PS384 => Some(KeyAlgorithm::PS384),
        Algorithm::PS512 => Some(KeyAlgorithm::PS512),
        Algorithm::EdDSA => Some(KeyAlgorithm::EdDSA),
        _ => None,
    }
}

/// Check if a URL points to localhost.
fn is_localhost(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(d)) => d == "localhost",
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )]

    use super::*;

    // ── Test helpers for verify_id_token ────────────────────────────────────

    /// Build an `OidcProvider` that points all endpoints at the given mock server.
    fn make_test_provider(base_url: &str) -> OidcProvider {
        OidcProvider {
            issuer: base_url.to_string(),
            authorization_endpoint: Url::parse(&format!("{base_url}/authorize")).unwrap(),
            token_endpoint: Url::parse(&format!("{base_url}/token")).unwrap(),
            jwks_uri: Url::parse(&format!("{base_url}/jwks")).unwrap(),
        }
    }

    /// Build a JWKS JSON payload from an EC P-256 signing key.
    ///
    /// Constructs a `{"keys": [...]}` object compatible with the
    /// `jsonwebtoken::jwk::JwkSet` deserializer. The EC key coordinates
    /// (x, y) and kid are taken directly from the signing key so that
    /// the JWKS matches the signature on JWTs the same key produces.
    fn make_ec_jwks_json(signing_key: &crate::services::oidc::OidcSigningKey) -> String {
        let jwk = signing_key
            .public_key_jwk()
            .expect("public_key_jwk should succeed");

        serde_json::json!({
            "keys": [{
                "kty": jwk.kty,
                "crv": jwk.crv,
                "alg": jwk.alg,
                "kid": jwk.kid,
                "use": jwk.key_use,
                "x": jwk.x,
                "y": jwk.y,
            }]
        })
        .to_string()
    }

    /// Sign a JWT with the given custom claims using ES256.
    ///
    /// Claims must include the standard registered claims `iss`, `aud`, `exp`,
    /// and `iat`; the caller also sets `email`, `email_verified`, `nonce`, and
    /// `hd` as required by `verify_id_token`.
    async fn sign_test_jwt(
        key: &crate::services::oidc::OidcSigningKey,
        claims: serde_json::Value,
    ) -> String {
        key.sign_jwt(&claims)
            .await
            .expect("sign_jwt should succeed")
    }

    /// Mount a JWKS endpoint on the mock server and return the signing key.
    async fn mount_jwks(
        server: &wiremock::MockServer,
        key: &crate::services::oidc::OidcSigningKey,
    ) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let jwks_json = make_ec_jwks_json(key);
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_string(jwks_json))
            .mount(server)
            .await;
    }

    /// Build a minimal valid claims object for verify_id_token.
    ///
    /// `iss` is set to `issuer`, `aud` to `client_id`, `exp` far in the
    /// future, `email_verified` to `true`, and nonce/hd are left to the
    /// caller.
    fn base_claims(issuer: &str, client_id: &str) -> serde_json::Value {
        serde_json::json!({
            "iss": issuer,
            "aud": client_id,
            "sub": "user-123",
            "exp": 9_999_999_999_i64,
            "iat": 1_000_000_000_i64,
            "email": "alice@example.com",
            "email_verified": true,
        })
    }

    fn parse_discovery_json(json: &str) -> DiscoveryDocument {
        serde_json::from_str(json).expect("valid JSON")
    }

    #[test]
    fn parse_google_discovery() {
        let json = r#"{
            "issuer": "https://accounts.google.com",
            "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
            "token_endpoint": "https://oauth2.googleapis.com/token",
            "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs"
        }"#;
        let doc = parse_discovery_json(json);
        assert_eq!(doc.issuer, "https://accounts.google.com");
        assert_eq!(
            doc.authorization_endpoint,
            "https://accounts.google.com/o/oauth2/v2/auth"
        );
        assert_eq!(doc.token_endpoint, "https://oauth2.googleapis.com/token");
        assert_eq!(doc.jwks_uri, "https://www.googleapis.com/oauth2/v3/certs");
    }

    #[test]
    fn parse_okta_discovery() {
        let json = r#"{
            "issuer": "https://dev-123456.okta.com",
            "authorization_endpoint": "https://dev-123456.okta.com/oauth2/v1/authorize",
            "token_endpoint": "https://dev-123456.okta.com/oauth2/v1/token",
            "jwks_uri": "https://dev-123456.okta.com/oauth2/v1/keys"
        }"#;
        let doc = parse_discovery_json(json);
        assert_eq!(doc.issuer, "https://dev-123456.okta.com");
    }

    #[test]
    fn parse_azure_ad_discovery() {
        let json = r#"{
            "issuer": "https://login.microsoftonline.com/tenant-id/v2.0",
            "authorization_endpoint": "https://login.microsoftonline.com/tenant-id/oauth2/v2.0/authorize",
            "token_endpoint": "https://login.microsoftonline.com/tenant-id/oauth2/v2.0/token",
            "jwks_uri": "https://login.microsoftonline.com/tenant-id/discovery/v2.0/keys"
        }"#;
        let doc = parse_discovery_json(json);
        assert_eq!(
            doc.issuer,
            "https://login.microsoftonline.com/tenant-id/v2.0"
        );
    }

    #[test]
    fn reject_missing_required_fields() {
        // Missing token_endpoint and jwks_uri
        let json = r#"{"issuer": "https://example.com", "authorization_endpoint": "https://example.com/auth"}"#;
        let result: Result<DiscoveryDocument, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn reject_http_issuer() {
        let url = Url::parse("http://evil.example.com").unwrap();
        assert!(!is_localhost(&url));
    }

    #[test]
    fn allow_http_localhost() {
        let url = Url::parse("http://localhost:8080").unwrap();
        assert!(is_localhost(&url));
    }

    #[test]
    fn allow_http_ipv6_localhost() {
        let url = Url::parse("http://[::1]:8080").unwrap();
        assert!(is_localhost(&url));
    }

    #[test]
    fn issuer_mismatch_detection() {
        let configured = "https://accounts.google.com";
        let discovered = "https://evil.example.com";
        assert_ne!(
            configured.trim_end_matches('/'),
            discovered.trim_end_matches('/')
        );
    }

    // ── wiremock integration tests for fetch_discovery ──────────────────

    fn discovery_json(issuer: &str) -> String {
        serde_json::json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/authorize"),
            "token_endpoint": format!("{issuer}/token"),
            "jwks_uri": format!("{issuer}/jwks"),
        })
        .to_string()
    }

    #[tokio::test]
    async fn fetch_discovery_happy_path() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let issuer = server.uri();

        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_string(discovery_json(&issuer)))
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        let provider = fetch_discovery(&client, &issuer).await.unwrap();

        assert_eq!(provider.issuer, issuer);
        assert_eq!(
            provider.authorization_endpoint.as_str(),
            format!("{issuer}/authorize"),
        );
        assert_eq!(provider.token_endpoint.as_str(), format!("{issuer}/token"),);
        assert_eq!(provider.jwks_uri.as_str(), format!("{issuer}/jwks"),);
    }

    #[tokio::test]
    async fn fetch_discovery_preserves_canonical_issuer_from_document() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let configured_issuer = server.uri();
        let canonical_issuer = format!("{configured_issuer}/");

        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(discovery_json(&canonical_issuer)),
            )
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        let provider = fetch_discovery(&client, &configured_issuer).await.unwrap();

        assert_eq!(provider.issuer, canonical_issuer);
    }

    #[tokio::test]
    async fn fetch_discovery_issuer_mismatch() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let issuer = server.uri();

        // Discovery doc reports a different issuer
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(discovery_json("https://evil.example.com")),
            )
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        let err = fetch_discovery(&client, &issuer).await.unwrap_err();

        assert!(
            err.to_string().contains("Issuer mismatch"),
            "expected issuer mismatch error, got: {err}",
        );
    }

    #[tokio::test]
    async fn fetch_discovery_non_200() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        let err = fetch_discovery(&client, &server.uri()).await.unwrap_err();

        assert!(
            err.to_string().contains("HTTP 404"),
            "expected HTTP 404 error, got: {err}",
        );
    }

    #[tokio::test]
    async fn fetch_discovery_invalid_json() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        let err = fetch_discovery(&client, &server.uri()).await.unwrap_err();

        assert!(
            err.to_string().contains("parse discovery"),
            "expected parse error, got: {err}",
        );
    }

    #[tokio::test]
    async fn fetch_discovery_rejects_http_non_localhost() {
        let client = reqwest::Client::new();
        let err = fetch_discovery(&client, "http://evil.example.com")
            .await
            .unwrap_err();

        assert!(
            err.to_string().contains("HTTPS"),
            "expected HTTPS error, got: {err}",
        );
    }

    // ── verify_id_token tests ───────────────────────────────────────────────

    /// Happy path: valid ES256 JWT with all required claims returns correct
    /// `IdentityResult`.
    #[tokio::test]
    async fn verify_id_token_happy_path() {
        use wiremock::MockServer;

        let server = MockServer::start().await;
        let issuer = server.uri();
        let client_id = "test-client";
        let nonce = "test-nonce-abc";

        let key = crate::services::oidc::OidcSigningKey::generate().unwrap();
        mount_jwks(&server, &key).await;

        let mut claims = base_claims(&issuer, client_id);
        claims["nonce"] = serde_json::json!(nonce);
        claims["hd"] = serde_json::json!("example.com");

        let token = sign_test_jwt(&key, claims).await;
        let provider = make_test_provider(&issuer);
        let client = reqwest::Client::new();

        let result = verify_id_token(&client, &provider, &token, client_id, nonce)
            .await
            .unwrap();

        assert_eq!(result.email, "alice@example.com");
        assert_eq!(result.domain, Some("example.com".to_string()));
    }

    /// Nonce mismatch: JWT has a nonce that differs from expected → error
    /// message must contain "nonce mismatch".
    #[tokio::test]
    async fn verify_id_token_nonce_mismatch() {
        use wiremock::MockServer;

        let server = MockServer::start().await;
        let issuer = server.uri();
        let client_id = "test-client";

        let key = crate::services::oidc::OidcSigningKey::generate().unwrap();
        mount_jwks(&server, &key).await;

        let mut claims = base_claims(&issuer, client_id);
        claims["nonce"] = serde_json::json!("actual-nonce");

        let token = sign_test_jwt(&key, claims).await;
        let provider = make_test_provider(&issuer);
        let client = reqwest::Client::new();

        let err = verify_id_token(&client, &provider, &token, client_id, "expected-nonce")
            .await
            .unwrap_err();

        assert!(
            err.to_string().contains("nonce mismatch"),
            "expected 'nonce mismatch' in error, got: {err}",
        );
    }

    /// Missing nonce: JWT has no nonce claim but caller expects one → error
    /// message must contain "missing nonce".
    #[tokio::test]
    async fn verify_id_token_missing_nonce() {
        use wiremock::MockServer;

        let server = MockServer::start().await;
        let issuer = server.uri();
        let client_id = "test-client";

        let key = crate::services::oidc::OidcSigningKey::generate().unwrap();
        mount_jwks(&server, &key).await;

        // No nonce claim in the token
        let claims = base_claims(&issuer, client_id);
        let token = sign_test_jwt(&key, claims).await;
        let provider = make_test_provider(&issuer);
        let client = reqwest::Client::new();

        let err = verify_id_token(&client, &provider, &token, client_id, "expected-nonce")
            .await
            .unwrap_err();

        assert!(
            err.to_string().contains("missing nonce"),
            "expected 'missing nonce' in error, got: {err}",
        );
    }

    /// Empty nonce bypass: device-code flow sends expected_nonce="" and the
    /// token has no nonce claim → should succeed (nonce check is skipped).
    #[tokio::test]
    async fn verify_id_token_empty_nonce_bypass() {
        use wiremock::MockServer;

        let server = MockServer::start().await;
        let issuer = server.uri();
        let client_id = "test-client";

        let key = crate::services::oidc::OidcSigningKey::generate().unwrap();
        mount_jwks(&server, &key).await;

        // No nonce in token; empty expected_nonce signals device-code flow
        let claims = base_claims(&issuer, client_id);
        let token = sign_test_jwt(&key, claims).await;
        let provider = make_test_provider(&issuer);
        let client = reqwest::Client::new();

        let result = verify_id_token(&client, &provider, &token, client_id, "")
            .await
            .unwrap();

        assert_eq!(result.email, "alice@example.com");
    }

    /// Email not verified: JWT has email_verified=false → error message must
    /// contain "not verified".
    #[tokio::test]
    async fn verify_id_token_email_not_verified() {
        use wiremock::MockServer;

        let server = MockServer::start().await;
        let issuer = server.uri();
        let client_id = "test-client";
        let nonce = "test-nonce";

        let key = crate::services::oidc::OidcSigningKey::generate().unwrap();
        mount_jwks(&server, &key).await;

        let mut claims = base_claims(&issuer, client_id);
        claims["email_verified"] = serde_json::json!(false);
        claims["nonce"] = serde_json::json!(nonce);

        let token = sign_test_jwt(&key, claims).await;
        let provider = make_test_provider(&issuer);
        let client = reqwest::Client::new();

        let err = verify_id_token(&client, &provider, &token, client_id, nonce)
            .await
            .unwrap_err();

        assert!(
            err.to_string().contains("not verified"),
            "expected 'not verified' in error, got: {err}",
        );
    }

    /// Domain from hd claim: when `hd` is present, `IdentityResult.domain`
    /// reflects that value.
    #[tokio::test]
    async fn verify_id_token_domain_from_hd_claim() {
        use wiremock::MockServer;

        let server = MockServer::start().await;
        let issuer = server.uri();
        let client_id = "test-client";
        let nonce = "test-nonce";

        let key = crate::services::oidc::OidcSigningKey::generate().unwrap();
        mount_jwks(&server, &key).await;

        let mut claims = base_claims(&issuer, client_id);
        claims["nonce"] = serde_json::json!(nonce);
        claims["hd"] = serde_json::json!("acme.com");

        let token = sign_test_jwt(&key, claims).await;
        let provider = make_test_provider(&issuer);
        let client = reqwest::Client::new();

        let result = verify_id_token(&client, &provider, &token, client_id, nonce)
            .await
            .unwrap();

        assert_eq!(
            result.domain,
            Some("acme.com".to_string()),
            "domain should come from hd claim"
        );
    }

    /// No hd claim: when `hd` is absent, `IdentityResult.domain` is `None`.
    #[tokio::test]
    async fn verify_id_token_no_hd_claim() {
        use wiremock::MockServer;

        let server = MockServer::start().await;
        let issuer = server.uri();
        let client_id = "test-client";
        let nonce = "test-nonce";

        let key = crate::services::oidc::OidcSigningKey::generate().unwrap();
        mount_jwks(&server, &key).await;

        let mut claims = base_claims(&issuer, client_id);
        claims["nonce"] = serde_json::json!(nonce);
        // Intentionally no "hd" claim

        let token = sign_test_jwt(&key, claims).await;
        let provider = make_test_provider(&issuer);
        let client = reqwest::Client::new();

        let result = verify_id_token(&client, &provider, &token, client_id, nonce)
            .await
            .unwrap();

        assert!(
            result.domain.is_none(),
            "domain should be None when hd claim is absent, got: {:?}",
            result.domain
        );
    }
}
