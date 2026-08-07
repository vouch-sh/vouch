// SPDX-License-Identifier: Apache-2.0 OR MIT
#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable"
)]

use super::*;
use jsonwebtoken::Algorithm;

// ── Issuer host matching (#425) ────────────────────────────────────────

#[test]
fn is_entra_host_matches_legitimate_endpoints() {
    assert!(is_entra_host(
        "https://login.microsoftonline.com/tenant-uuid/v2.0"
    ));
    assert!(is_entra_host(
        "https://login.microsoftonline.com/organizations/v2.0"
    ));
    assert!(is_entra_host(
        "https://login.microsoftonline.com/%7Btenantid%7D/v2.0"
    ));
}

/// Lookalike host with the target domain as a substring must be
/// rejected — the entire point of swapping `.contains()` for host-based
/// matching (#425).
#[test]
fn is_entra_host_rejects_lookalike_domain() {
    assert!(!is_entra_host(
        "https://login.microsoftonline.com.evil.com/tenant/v2.0"
    ));
    assert!(!is_entra_host(
        "https://evil.com/login.microsoftonline.com/v2.0"
    ));
}

#[test]
fn is_entra_host_rejects_malformed_url() {
    assert!(!is_entra_host("not a url"));
    assert!(!is_entra_host(""));
}

#[test]
fn is_google_host_matches_legitimate_endpoint() {
    assert!(is_google_host("https://accounts.google.com"));
    assert!(is_google_host("https://accounts.google.com/"));
}

#[test]
fn is_google_host_rejects_lookalike_domain() {
    assert!(!is_google_host("https://accounts.google.com.evil.com"));
    assert!(!is_google_host("https://evil.com/accounts.google.com"));
}

#[test]
fn is_google_host_rejects_malformed_url() {
    assert!(!is_google_host("not a url"));
    assert!(!is_google_host(""));
}

// ── Upstream JWKS key selection ─────────────────────────────────────────

/// RSA public key modulus from RFC 7638 Section 3.1.
const RFC7638_N: &str = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1\
    RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6\
    Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI\
    SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8aw\
    apJzKnqDKgw";

fn rsa_jwk(kid: &str) -> serde_json::Value {
    serde_json::json!({
        "kty": "RSA",
        "alg": "RS256",
        "use": "sig",
        "kid": kid,
        "n": RFC7638_N,
        "e": "AQAB",
    })
}

/// A key type `jsonwebtoken` has no decoder for, shaped like the ML-DSA
/// entry in RFC 9964 Appendix A.1.
fn unusable_jwk(kid: &str) -> serde_json::Value {
    serde_json::json!({
        "kty": "AKP",
        "use": "sig",
        "kid": kid,
        "pub": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    })
}

fn jwks_of(keys: Vec<serde_json::Value>) -> jsonwebtoken::jwk::JwkSet {
    serde_json::from_value(serde_json::json!({ "keys": keys })).expect("JWKS must deserialize")
}

#[test]
fn find_decoding_key_matches_by_kid() {
    let jwks = jwks_of(vec![rsa_jwk("other"), rsa_jwk("wanted")]);
    assert!(find_decoding_key(&jwks, Some("wanted"), Algorithm::RS256).is_ok());
}

#[test]
fn find_decoding_key_reports_missing_kid() {
    let jwks = jwks_of(vec![rsa_jwk("other")]);
    let err = find_decoding_key(&jwks, Some("wanted"), Algorithm::RS256)
        .expect_err("unknown kid must not resolve a key");
    assert!(err.to_string().contains("wanted"));
}

/// jsonwebtoken 11 keeps unrecognized `kty` values as
/// `AlgorithmParameters::Other` instead of failing the whole set, so a
/// JWKS that lists one first must still resolve the usable key behind it.
#[test]
fn find_decoding_key_skips_unusable_key_when_matching_by_algorithm() {
    let mut unusable = unusable_jwk("pq-1");
    unusable["alg"] = serde_json::json!("RS256");
    let jwks = jwks_of(vec![unusable, rsa_jwk("rsa-1")]);
    assert!(find_decoding_key(&jwks, None, Algorithm::RS256).is_ok());
}

#[test]
fn find_decoding_key_skips_unusable_key_in_last_resort_fallback() {
    // Neither key advertises `alg`, so selection falls through to the
    // first key the crate can actually build a `DecodingKey` from.
    let mut usable = rsa_jwk("rsa-1");
    usable.as_object_mut().expect("object").remove("alg");
    let jwks = jwks_of(vec![unusable_jwk("pq-1"), usable]);
    assert!(find_decoding_key(&jwks, None, Algorithm::RS256).is_ok());
}

#[test]
fn find_decoding_key_rejects_jwks_without_a_usable_key() {
    let jwks = jwks_of(vec![unusable_jwk("pq-1")]);
    assert!(find_decoding_key(&jwks, None, Algorithm::RS256).is_err());
    assert!(find_decoding_key(&jwks_of(vec![]), None, Algorithm::RS256).is_err());
}

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
fn make_ec_jwks_json(signing_key: &crate::crypto::keys::OidcSigningKey) -> String {
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
    key: &crate::crypto::keys::OidcSigningKey,
    claims: serde_json::Value,
) -> String {
    key.sign_jwt(&claims)
        .await
        .expect("sign_jwt should succeed")
}

/// Mount a JWKS endpoint on the mock server and return the signing key.
async fn mount_jwks(server: &wiremock::MockServer, key: &crate::crypto::keys::OidcSigningKey) {
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

// ── Entra /organizations/ issuer template tests ────────────────────────

#[test]
fn validate_discovered_issuer_exact_match() {
    assert!(
        validate_discovered_issuer("https://accounts.google.com", "https://accounts.google.com")
            .is_ok()
    );
}

#[test]
fn validate_discovered_issuer_mismatch_rejected() {
    assert!(
        validate_discovered_issuer("https://accounts.google.com", "https://evil.example.com")
            .is_err()
    );
}

#[test]
fn validate_discovered_issuer_entra_organizations_accepts_tenant_issuer() {
    // /organizations/ configured; discovered issuer is per-tenant
    assert!(
        validate_discovered_issuer(
            "https://login.microsoftonline.com/organizations/v2.0",
            "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0"
        )
        .is_ok()
    );
}

#[test]
fn validate_discovered_issuer_entra_organizations_accepts_literal_placeholder() {
    // Microsoft's discovery doc literally returns the `{tenantid}` placeholder.
    assert!(
        validate_discovered_issuer(
            "https://login.microsoftonline.com/organizations/v2.0",
            "https://login.microsoftonline.com/{tenantid}/v2.0"
        )
        .is_ok()
    );
}

#[test]
fn validate_discovered_issuer_entra_organizations_rejects_non_uuid_path_segment() {
    // The tightened check should reject arbitrary path segments that are
    // neither the literal placeholder nor a UUID.
    assert!(
        validate_discovered_issuer(
            "https://login.microsoftonline.com/organizations/v2.0",
            "https://login.microsoftonline.com/notauuid/v2.0"
        )
        .is_err()
    );
}

#[test]
fn validate_discovered_issuer_entra_specific_tenant_rejects_different_tenant() {
    // A tenant-specific configured issuer must match exactly
    assert!(
        validate_discovered_issuer(
            "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0",
            "https://login.microsoftonline.com/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/v2.0"
        )
        .is_err()
    );
}

// ── extract_entra_tenant_from_issuer tests ─────────────────────────────

#[test]
fn extract_tenant_from_specific_issuer() {
    let issuer = "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0";
    assert_eq!(
        extract_entra_tenant_from_issuer(issuer),
        Some("11111111-2222-3333-4444-555555555555")
    );
}

#[test]
fn extract_tenant_returns_none_for_organizations() {
    let issuer = "https://login.microsoftonline.com/organizations/v2.0";
    assert_eq!(extract_entra_tenant_from_issuer(issuer), None);
}

#[test]
fn extract_tenant_returns_none_for_common() {
    let issuer = "https://login.microsoftonline.com/common/v2.0";
    assert_eq!(extract_entra_tenant_from_issuer(issuer), None);
}

#[test]
fn extract_tenant_returns_none_for_google() {
    assert_eq!(
        extract_entra_tenant_from_issuer("https://accounts.google.com"),
        None
    );
}

// ── is_entra_common_issuer tests ───────────────────────────────────────

#[test]
fn is_entra_common_issuer_detects_common() {
    assert!(is_entra_common_issuer(
        "https://login.microsoftonline.com/common/v2.0"
    ));
    assert!(is_entra_common_issuer(
        "https://login.microsoftonline.com/common"
    ));
}

#[test]
fn is_entra_common_issuer_does_not_match_organizations() {
    assert!(!is_entra_common_issuer(
        "https://login.microsoftonline.com/organizations/v2.0"
    ));
}

#[test]
fn is_entra_common_issuer_does_not_match_google() {
    assert!(!is_entra_common_issuer("https://accounts.google.com"));
}

// ── lookalike-domain rejection tests (host-based matching) ─────────────

#[test]
fn is_entra_organizations_issuer_rejects_evil_subdomain() {
    // These URLs contain "login.microsoftonline.com" as a substring but the
    // host is NOT Microsoft. The previous `contains()` check would have
    // accepted these.
    assert!(!is_entra_organizations_issuer(
        "https://login.microsoftonline.com.evil.com/organizations/v2.0"
    ));
    assert!(!is_entra_organizations_issuer(
        "https://login.microsoftonline.com.attacker.org/organizations/v2.0"
    ));
    // Path-based spoof: host is attacker-controlled, microsoft string in path.
    assert!(!is_entra_organizations_issuer(
        "https://evil.com/login.microsoftonline.com/organizations/v2.0"
    ));
}

#[test]
fn is_entra_organizations_issuer_rejects_malformed_urls() {
    assert!(!is_entra_organizations_issuer("not a url"));
    assert!(!is_entra_organizations_issuer(""));
}

#[test]
fn is_entra_organizations_issuer_accepts_legitimate_microsoft() {
    assert!(is_entra_organizations_issuer(
        "https://login.microsoftonline.com/organizations/v2.0"
    ));
    assert!(is_entra_organizations_issuer(
        "https://login.microsoftonline.com/organizations"
    ));
}

#[test]
fn is_entra_common_issuer_rejects_evil_subdomain() {
    assert!(!is_entra_common_issuer(
        "https://login.microsoftonline.com.evil.com/common/v2.0"
    ));
    assert!(!is_entra_common_issuer(
        "https://evil.com/login.microsoftonline.com/common/v2.0"
    ));
}

#[test]
fn is_entra_tenant_template_issuer_rejects_evil_subdomain() {
    assert!(!is_entra_tenant_template_issuer(
        "https://login.microsoftonline.com.evil.com/{tenantid}/v2.0"
    ));
}

#[test]
fn validate_discovered_issuer_rejects_evil_subdomain_discovery_bypass() {
    // Configured issuer is on an attacker-controlled lookalike subdomain.
    // The discovered issuer is the real Microsoft URL. The Entra fallback
    // must NOT trigger here — the configured host must be Microsoft.
    assert!(
        validate_discovered_issuer(
            "https://login.microsoftonline.com.evil.com/organizations/v2.0",
            "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0",
        )
        .is_err()
    );
    // The reverse: configured is real Microsoft, but discovered host is
    // attacker-controlled. Tenant template / tenant extraction must reject.
    assert!(
        validate_discovered_issuer(
            "https://login.microsoftonline.com/organizations/v2.0",
            "https://login.microsoftonline.com.evil.com/{tenantid}/v2.0",
        )
        .is_err()
    );
    assert!(
        validate_discovered_issuer(
            "https://login.microsoftonline.com/organizations/v2.0",
            "https://login.microsoftonline.com.evil.com/00000000-0000-0000-0000-000000000000/v2.0",
        )
        .is_err()
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
        .respond_with(ResponseTemplate::new(200).set_body_string(discovery_json(&canonical_issuer)))
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
            ResponseTemplate::new(200).set_body_string(discovery_json("https://evil.example.com")),
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

    let key = crate::crypto::keys::OidcSigningKey::generate().unwrap();
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
    let upstream = result.upstream.expect("upstream identity must be set");
    assert_eq!(upstream.issuer, issuer);
    assert_eq!(upstream.durable_subject.as_deref(), Some("user-123"));
}

/// A token missing the required `sub` claim must fail verification
/// (fail-closed): without a stable subject there is nothing to bind
/// the account to, so email-only linking must not silently happen.
#[tokio::test]
async fn verify_id_token_missing_sub_rejected() {
    use wiremock::MockServer;

    let server = MockServer::start().await;
    let issuer = server.uri();
    let client_id = "test-client";
    let nonce = "test-nonce-abc";

    let key = crate::crypto::keys::OidcSigningKey::generate().unwrap();
    mount_jwks(&server, &key).await;

    let mut claims = base_claims(&issuer, client_id);
    claims["nonce"] = serde_json::json!(nonce);
    claims.as_object_mut().expect("claims object").remove("sub");

    let token = sign_test_jwt(&key, claims).await;
    let provider = make_test_provider(&issuer);
    let client = reqwest::Client::new();

    let err = verify_id_token(&client, &provider, &token, client_id, nonce)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("verification failed"),
        "expected verification failure for missing sub, got: {err}",
    );
}

/// Nonce mismatch: JWT has a nonce that differs from expected → error
/// message must contain "nonce mismatch".
#[tokio::test]
async fn verify_id_token_nonce_mismatch() {
    use wiremock::MockServer;

    let server = MockServer::start().await;
    let issuer = server.uri();
    let client_id = "test-client";

    let key = crate::crypto::keys::OidcSigningKey::generate().unwrap();
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

    let key = crate::crypto::keys::OidcSigningKey::generate().unwrap();
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

    let key = crate::crypto::keys::OidcSigningKey::generate().unwrap();
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

    let key = crate::crypto::keys::OidcSigningKey::generate().unwrap();
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
    // Google Workspace: hd claim is used for domain
    let google_issuer = "https://accounts.google.com";
    let client_id = "test-client";
    let nonce = "test-nonce";

    let key = crate::crypto::keys::OidcSigningKey::generate().unwrap();
    mount_jwks(&server, &key).await;

    let mut claims = base_claims(google_issuer, client_id);
    claims["nonce"] = serde_json::json!(nonce);
    claims["hd"] = serde_json::json!("acme.com");

    let token = sign_test_jwt(&key, claims).await;
    let mut provider = make_test_provider(google_issuer);
    provider.jwks_uri = url::Url::parse(&format!("{}/jwks", server.uri())).unwrap();
    let client = reqwest::Client::new();

    let result = verify_id_token(&client, &provider, &token, client_id, nonce)
        .await
        .unwrap();

    assert_eq!(
        result.domain,
        Some("acme.com".to_string()),
        "Google Workspace domain should come from hd claim"
    );
}

/// No hd claim: when `hd` is absent, `IdentityResult.domain` is `None`.
#[tokio::test]
async fn verify_id_token_no_hd_claim_non_google_falls_back_to_email() {
    use wiremock::MockServer;

    let server = MockServer::start().await;
    let issuer = server.uri(); // non-Google issuer
    let client_id = "test-client";
    let nonce = "test-nonce";

    let key = crate::crypto::keys::OidcSigningKey::generate().unwrap();
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

    // Non-Google issuers fall back to email domain when hd is absent
    assert_eq!(
        result.domain.as_deref(),
        Some("example.com"),
        "non-Google issuer should fall back to email domain"
    );
}

/// Regression: mixed-case `hd` claim must be lowercased so org lookups
/// (which match against the lowercase-stored primary/additional domain)
/// find the right org. Removing the `.to_ascii_lowercase()` call would
/// silently break login for IdPs that return uppercase domain parts.
#[tokio::test]
async fn verify_id_token_lowercases_mixed_case_hd_claim() {
    use wiremock::MockServer;

    let server = MockServer::start().await;
    let google_issuer = "https://accounts.google.com";
    let client_id = "test-client";
    let nonce = "test-nonce";

    let key = crate::crypto::keys::OidcSigningKey::generate().unwrap();
    mount_jwks(&server, &key).await;

    let mut claims = base_claims(google_issuer, client_id);
    claims["nonce"] = serde_json::json!(nonce);
    claims["hd"] = serde_json::json!("ACME.COM");

    let token = sign_test_jwt(&key, claims).await;
    let mut provider = make_test_provider(google_issuer);
    provider.jwks_uri = url::Url::parse(&format!("{}/jwks", server.uri())).unwrap();
    let client = reqwest::Client::new();

    let result = verify_id_token(&client, &provider, &token, client_id, nonce)
        .await
        .unwrap();

    assert_eq!(
        result.domain.as_deref(),
        Some("acme.com"),
        "uppercase hd claim must be normalized to lowercase",
    );
}

/// Regression: when falling back to the email domain for non-Google
/// issuers, the extracted domain must be lowercased.
#[tokio::test]
async fn verify_id_token_lowercases_email_domain_fallback() {
    use wiremock::MockServer;

    let server = MockServer::start().await;
    let issuer = server.uri();
    let client_id = "test-client";
    let nonce = "test-nonce";

    let key = crate::crypto::keys::OidcSigningKey::generate().unwrap();
    mount_jwks(&server, &key).await;

    let mut claims = base_claims(&issuer, client_id);
    claims["nonce"] = serde_json::json!(nonce);
    claims["email"] = serde_json::json!("Alice@CORP.Example.COM");

    let token = sign_test_jwt(&key, claims).await;
    let provider = make_test_provider(&issuer);
    let client = reqwest::Client::new();

    let result = verify_id_token(&client, &provider, &token, client_id, nonce)
        .await
        .unwrap();

    assert_eq!(
        result.domain.as_deref(),
        Some("corp.example.com"),
        "email-fallback domain must be normalized to lowercase",
    );
}

#[tokio::test]
async fn verify_id_token_google_consumer_no_hd_returns_none() {
    use wiremock::MockServer;

    let server = MockServer::start().await;
    // Use Google issuer — consumer accounts have no hd claim
    let google_issuer = "https://accounts.google.com";
    let client_id = "test-client";
    let nonce = "test-nonce";

    let key = crate::crypto::keys::OidcSigningKey::generate().unwrap();
    mount_jwks(&server, &key).await;

    let mut claims = base_claims(google_issuer, client_id);
    claims["nonce"] = serde_json::json!(nonce);
    // No "hd" claim — Google consumer account

    let token = sign_test_jwt(&key, claims).await;
    let mut provider = make_test_provider(google_issuer);
    // Point jwks_uri to our mock server
    provider.jwks_uri = url::Url::parse(&format!("{}/jwks", server.uri())).unwrap();
    let client = reqwest::Client::new();

    let result = verify_id_token(&client, &provider, &token, client_id, nonce)
        .await
        .unwrap();

    // Google consumer accounts: no hd → domain should be None
    assert!(
        result.domain.is_none(),
        "Google consumer should have domain=None, got: {:?}",
        result.domain
    );
}

// ── Entra tid claim validation ─────────────────────────────────────────

/// Token tid must match the tenant UUID in the issuer URL.
#[tokio::test]
async fn verify_id_token_entra_tid_mismatch_rejected() {
    use wiremock::MockServer;

    let server = MockServer::start().await;
    let issuer_tenant = "11111111-2222-3333-4444-555555555555";
    let other_tenant = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    let entra_issuer = format!("https://login.microsoftonline.com/{issuer_tenant}/v2.0");
    let client_id = "test-client";
    let nonce = "test-nonce";

    let key = crate::crypto::keys::OidcSigningKey::generate().unwrap();
    mount_jwks(&server, &key).await;

    let mut claims = base_claims(&entra_issuer, client_id);
    claims["nonce"] = serde_json::json!(nonce);
    // tid from a different tenant — cross-tenant injection attempt
    claims["tid"] = serde_json::json!(other_tenant);

    let token = sign_test_jwt(&key, claims).await;
    let mut provider = make_test_provider(&entra_issuer);
    provider.issuer = entra_issuer.clone();
    provider.jwks_uri = url::Url::parse(&format!("{}/jwks", server.uri())).unwrap();
    let client = reqwest::Client::new();

    let err = verify_id_token(&client, &provider, &token, client_id, nonce)
        .await
        .unwrap_err();

    assert!(
        err.to_string().contains("cross-tenant token injection"),
        "expected cross-tenant rejection, got: {err}"
    );
}

/// Token with matching tid succeeds (tenant-specific issuer in provider).
#[tokio::test]
async fn verify_id_token_entra_tid_matches_issuer_succeeds() {
    use wiremock::MockServer;

    let server = MockServer::start().await;
    let tenant_id = "11111111-2222-3333-4444-555555555555";
    let entra_issuer = format!("https://login.microsoftonline.com/{tenant_id}/v2.0");
    let client_id = "test-client";
    let nonce = "test-nonce";

    let key = crate::crypto::keys::OidcSigningKey::generate().unwrap();
    mount_jwks(&server, &key).await;

    let mut claims = base_claims(&entra_issuer, client_id);
    claims["nonce"] = serde_json::json!(nonce);
    claims["tid"] = serde_json::json!(tenant_id);

    let token = sign_test_jwt(&key, claims).await;
    let mut provider = make_test_provider(&entra_issuer);
    provider.issuer = entra_issuer.clone();
    provider.jwks_uri = url::Url::parse(&format!("{}/jwks", server.uri())).unwrap();
    let client = reqwest::Client::new();

    let result = verify_id_token(&client, &provider, &token, client_id, nonce)
        .await
        .unwrap();

    assert_eq!(result.email, "alice@example.com");
}

// ── {tenantid}-template provider.issuer with real per-tenant token iss ──
//
// After fetch_discovery() hits /common/v2.0/.well-known/openid-configuration
// or /organizations/v2.0/.well-known/openid-configuration, Microsoft returns
// the literal placeholder `https://login.microsoftonline.com/{tenantid}/v2.0`
// as the discovery document's `issuer`. That literal string is what gets
// stored in OidcProvider::issuer — these tests exercise that post-discovery
// state, not the configured /common/ or /organizations/ URL.

/// When provider.issuer is the literal `{tenantid}` template (the form
/// Microsoft returns from /common/ and /organizations/ discovery), the
/// library issuer check must be disabled. A token with a real per-tenant
/// iss and matching tid must succeed.
#[tokio::test]
async fn verify_id_token_entra_tenant_template_with_per_tenant_token_succeeds() {
    use wiremock::MockServer;

    let server = MockServer::start().await;
    let tenant_id = "11111111-2222-3333-4444-555555555555";
    // This is exactly what OidcProvider::issuer holds after fetch_discovery
    // from either /common/v2.0 or /organizations/v2.0.
    let template_issuer = "https://login.microsoftonline.com/{tenantid}/v2.0".to_string();
    // Real tokens have the per-tenant UUID in their iss claim
    let token_iss = format!("https://login.microsoftonline.com/{tenant_id}/v2.0");
    let client_id = "test-client";
    let nonce = "test-nonce";

    let key = crate::crypto::keys::OidcSigningKey::generate().unwrap();
    mount_jwks(&server, &key).await;

    // Token claims use the per-tenant issuer (as Entra actually issues them)
    let mut claims = base_claims(&token_iss, client_id);
    claims["nonce"] = serde_json::json!(nonce);
    claims["tid"] = serde_json::json!(tenant_id);

    let token = sign_test_jwt(&key, claims).await;

    // provider.issuer is the literal {tenantid} template (as stored after discovery)
    let mut provider = make_test_provider(&template_issuer);
    provider.issuer = template_issuer.clone();
    provider.jwks_uri = url::Url::parse(&format!("{}/jwks", server.uri())).unwrap();
    let client = reqwest::Client::new();

    let result = verify_id_token(&client, &provider, &token, client_id, nonce)
        .await
        .unwrap();

    assert_eq!(result.email, "alice@example.com");
    // The binding must pin the concrete per-tenant issuer from the
    // token, not the `{tenantid}` template stored in provider.issuer.
    let upstream = result.upstream.expect("upstream identity must be set");
    assert_eq!(upstream.issuer, token_iss);
    assert_eq!(upstream.durable_subject.as_deref(), Some("user-123"));
}

/// When provider.issuer is the `{tenantid}` template, a token whose tid
/// does not match the per-tenant UUID in its own iss claim must be
/// rejected as a cross-tenant injection attempt.
#[tokio::test]
async fn verify_id_token_entra_tenant_template_tid_mismatch_rejected() {
    use wiremock::MockServer;

    let server = MockServer::start().await;
    let token_tenant = "11111111-2222-3333-4444-555555555555";
    let other_tenant = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    let template_issuer = "https://login.microsoftonline.com/{tenantid}/v2.0".to_string();
    let token_iss = format!("https://login.microsoftonline.com/{token_tenant}/v2.0");
    let client_id = "test-client";
    let nonce = "test-nonce";

    let key = crate::crypto::keys::OidcSigningKey::generate().unwrap();
    mount_jwks(&server, &key).await;

    let mut claims = base_claims(&token_iss, client_id);
    claims["nonce"] = serde_json::json!(nonce);
    // tid from a different tenant — cross-tenant injection attempt
    claims["tid"] = serde_json::json!(other_tenant);

    let token = sign_test_jwt(&key, claims).await;

    let mut provider = make_test_provider(&template_issuer);
    provider.issuer = template_issuer.clone();
    provider.jwks_uri = url::Url::parse(&format!("{}/jwks", server.uri())).unwrap();
    let client = reqwest::Client::new();

    let err = verify_id_token(&client, &provider, &token, client_id, nonce)
        .await
        .unwrap_err();

    assert!(
        err.to_string().contains("cross-tenant token injection"),
        "expected cross-tenant rejection, got: {err}"
    );
}

/// Regression test for /common/ login `InvalidIssuer` failure: when
/// provider.issuer is the `{tenantid}` template, a token with an arbitrary
/// non-Entra issuer must be rejected with the manual Entra check (not pass
/// through silently because the library check was disabled).
#[tokio::test]
async fn verify_id_token_entra_tenant_template_rejects_non_entra_issuer() {
    use wiremock::MockServer;

    let server = MockServer::start().await;
    let template_issuer = "https://login.microsoftonline.com/{tenantid}/v2.0".to_string();
    let token_iss = "https://evil.example.com/".to_string();
    let client_id = "test-client";
    let nonce = "test-nonce";

    let key = crate::crypto::keys::OidcSigningKey::generate().unwrap();
    mount_jwks(&server, &key).await;

    let mut claims = base_claims(&token_iss, client_id);
    claims["nonce"] = serde_json::json!(nonce);

    let token = sign_test_jwt(&key, claims).await;

    let mut provider = make_test_provider(&template_issuer);
    provider.issuer = template_issuer.clone();
    provider.jwks_uri = url::Url::parse(&format!("{}/jwks", server.uri())).unwrap();
    let client = reqwest::Client::new();

    let err = verify_id_token(&client, &provider, &token, client_id, nonce)
        .await
        .unwrap_err();

    assert!(
        err.to_string().contains("not a valid per-tenant issuer"),
        "expected per-tenant issuer rejection, got: {err}"
    );
}

// ── /common/ is rejected at discovery time ─────────────────────────────

/// `fetch_discovery` must reject `/common/v2.0` outright, before any HTTP
/// fetch is attempted. Apps with personal-MSA support cannot emit
/// `xms_edov`, so vouch refuses to start with such an issuer.
#[tokio::test]
async fn fetch_discovery_rejects_entra_common_issuer() {
    let client = reqwest::Client::new();
    let err = fetch_discovery(&client, "https://login.microsoftonline.com/common/v2.0")
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("/common/") || msg.contains("not supported") || msg.contains("xms_edov"),
        "expected /common/ rejection message, got: {msg}"
    );
    assert!(
        msg.contains("organizations") || msg.contains("tenant"),
        "error must point operators at /organizations/ or single-tenant, got: {msg}"
    );
}

/// Entra tokens lack `email_verified` but include `xms_edov=true` when the
/// optional claim is configured. Verification must succeed.
#[tokio::test]
async fn verify_id_token_entra_xms_edov_true_accepted_without_email_verified() {
    use wiremock::MockServer;

    let server = MockServer::start().await;
    let tenant_id = "11111111-2222-3333-4444-555555555555";
    let template_issuer = "https://login.microsoftonline.com/{tenantid}/v2.0".to_string();
    let token_iss = format!("https://login.microsoftonline.com/{tenant_id}/v2.0");
    let client_id = "test-client";
    let nonce = "test-nonce";

    let key = crate::crypto::keys::OidcSigningKey::generate().unwrap();
    mount_jwks(&server, &key).await;

    let mut claims = base_claims(&token_iss, client_id);
    claims["nonce"] = serde_json::json!(nonce);
    claims["tid"] = serde_json::json!(tenant_id);
    // Entra never emits `email_verified` — explicitly remove it to
    // reproduce real production tokens.
    claims.as_object_mut().unwrap().remove("email_verified");
    claims["xms_edov"] = serde_json::json!(true);

    let token = sign_test_jwt(&key, claims).await;
    let mut provider = make_test_provider(&template_issuer);
    provider.issuer = template_issuer.clone();
    provider.jwks_uri = url::Url::parse(&format!("{}/jwks", server.uri())).unwrap();
    let client = reqwest::Client::new();

    let result = verify_id_token(&client, &provider, &token, client_id, nonce)
        .await
        .unwrap();

    assert_eq!(result.email, "alice@example.com");
}

/// Entra token with `xms_edov=false` (domain unverified) must be rejected
/// with an Entra-specific error message that points at the optional claim
/// configuration.
#[tokio::test]
async fn verify_id_token_entra_xms_edov_false_rejected_with_guidance() {
    use wiremock::MockServer;

    let server = MockServer::start().await;
    let tenant_id = "11111111-2222-3333-4444-555555555555";
    let template_issuer = "https://login.microsoftonline.com/{tenantid}/v2.0".to_string();
    let token_iss = format!("https://login.microsoftonline.com/{tenant_id}/v2.0");
    let client_id = "test-client";
    let nonce = "test-nonce";

    let key = crate::crypto::keys::OidcSigningKey::generate().unwrap();
    mount_jwks(&server, &key).await;

    let mut claims = base_claims(&token_iss, client_id);
    claims["nonce"] = serde_json::json!(nonce);
    claims["tid"] = serde_json::json!(tenant_id);
    claims.as_object_mut().unwrap().remove("email_verified");
    claims["xms_edov"] = serde_json::json!(false);

    let token = sign_test_jwt(&key, claims).await;
    let mut provider = make_test_provider(&template_issuer);
    provider.issuer = template_issuer.clone();
    provider.jwks_uri = url::Url::parse(&format!("{}/jwks", server.uri())).unwrap();
    let client = reqwest::Client::new();

    let err = verify_id_token(&client, &provider, &token, client_id, nonce)
        .await
        .unwrap_err();

    let msg = err.to_string();
    assert!(
        msg.contains("xms_edov"),
        "expected xms_edov guidance, got: {msg}"
    );
    assert!(
        msg.contains("not verified"),
        "expected 'not verified', got: {msg}"
    );
}

/// Entra token missing both `email_verified` and `xms_edov` (operator did
/// not configure the optional claim) must be rejected with guidance.
#[tokio::test]
async fn verify_id_token_entra_missing_xms_edov_rejected_with_guidance() {
    use wiremock::MockServer;

    let server = MockServer::start().await;
    let tenant_id = "11111111-2222-3333-4444-555555555555";
    let template_issuer = "https://login.microsoftonline.com/{tenantid}/v2.0".to_string();
    let token_iss = format!("https://login.microsoftonline.com/{tenant_id}/v2.0");
    let client_id = "test-client";
    let nonce = "test-nonce";

    let key = crate::crypto::keys::OidcSigningKey::generate().unwrap();
    mount_jwks(&server, &key).await;

    let mut claims = base_claims(&token_iss, client_id);
    claims["nonce"] = serde_json::json!(nonce);
    claims["tid"] = serde_json::json!(tenant_id);
    claims.as_object_mut().unwrap().remove("email_verified");
    // No xms_edov claim — operator forgot to configure it in Azure.

    let token = sign_test_jwt(&key, claims).await;
    let mut provider = make_test_provider(&template_issuer);
    provider.issuer = template_issuer.clone();
    provider.jwks_uri = url::Url::parse(&format!("{}/jwks", server.uri())).unwrap();
    let client = reqwest::Client::new();

    let err = verify_id_token(&client, &provider, &token, client_id, nonce)
        .await
        .unwrap_err();

    let msg = err.to_string();
    assert!(
        msg.contains("xms_edov"),
        "expected xms_edov guidance, got: {msg}"
    );
    assert!(
        msg.contains("Token configuration"),
        "expected Azure setup guidance, got: {msg}"
    );
}

/// `xms_edov` is an Entra-specific signal. A non-Entra token with
/// `xms_edov=true` and `email_verified=false` must still be rejected.
#[tokio::test]
async fn verify_id_token_non_entra_xms_edov_does_not_override_email_verified() {
    use wiremock::MockServer;

    let server = MockServer::start().await;
    let issuer = server.uri();
    let client_id = "test-client";
    let nonce = "test-nonce";

    let key = crate::crypto::keys::OidcSigningKey::generate().unwrap();
    mount_jwks(&server, &key).await;

    let mut claims = base_claims(&issuer, client_id);
    claims["nonce"] = serde_json::json!(nonce);
    claims["email_verified"] = serde_json::json!(false);
    claims["xms_edov"] = serde_json::json!(true);

    let token = sign_test_jwt(&key, claims).await;
    let provider = make_test_provider(&issuer);
    let client = reqwest::Client::new();

    let err = verify_id_token(&client, &provider, &token, client_id, nonce)
        .await
        .unwrap_err();

    let msg = err.to_string();
    assert!(
        msg.contains("not verified"),
        "expected 'not verified', got: {msg}"
    );
    // Non-Entra error message must not include Entra-specific guidance.
    assert!(
        !msg.contains("xms_edov"),
        "non-Entra error must not mention xms_edov, got: {msg}"
    );
}

#[test]
fn is_entra_tenant_template_issuer_detects_post_discovery_form() {
    // Both /v2.0 and bare tail variants of the literal placeholder
    assert!(is_entra_tenant_template_issuer(
        "https://login.microsoftonline.com/{tenantid}/v2.0"
    ));
    assert!(is_entra_tenant_template_issuer(
        "https://login.microsoftonline.com/{tenantid}"
    ));
    // Concrete per-tenant UUIDs and configured /common/ form must NOT match
    assert!(!is_entra_tenant_template_issuer(
        "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0"
    ));
    assert!(!is_entra_tenant_template_issuer(
        "https://login.microsoftonline.com/common/v2.0"
    ));
    assert!(!is_entra_tenant_template_issuer(
        "https://login.microsoftonline.com/organizations/v2.0"
    ));
    // Other hosts must not match even if they contain {tenantid}
    assert!(!is_entra_tenant_template_issuer(
        "https://evil.example.com/{tenantid}/v2.0"
    ));
}
