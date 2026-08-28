// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 9728 — OAuth 2.0 Protected Resource Metadata tests.
//!
//! Covers:
//! * §2 metadata document shape (every RFC-defined field).
//! * §3.1 path-insertion variants (`/.well-known/oauth-protected-resource/{*path}`).
//! * §3.2 content type and cache behaviour.
//! * §3.3 signed metadata JWT (verification via the resource JWKS).
//! * §4 identity rule (returned `resource` byte-identical to
//!   caller URL; unknown sub-paths → 404).
//! * §5.2 `WWW-Authenticate: resource_metadata=...` on 401s from
//!   protected-resource endpoints.
//! * Regression: the wildcard route MUST NOT shadow the AS discovery
//!   or JWKS routes.

use super::helpers::*;
use crate::infra::resource_metadata::WELL_KNOWN_SUFFIX;
use crate::services::oidc::protected_resource::{PROTECTED_RESOURCE_PREFIXES, SIGNED_METADATA_TYP};
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use std::collections::BTreeSet;

// Shared RFC 7235 `WWW-Authenticate` mini-parser. The full grammar is
// not needed — we only extract parameter values so tests can verify
// `error`, `resource_metadata`, etc. by exact equality rather than
// fragile substring checks.
fn parse_www_authenticate_params(header: &str) -> std::collections::HashMap<String, String> {
    let mut out = std::collections::HashMap::new();

    // Skip the auth-scheme ("Bearer", "DPoP", …) then iterate parameters.
    let (_scheme, rest) = header
        .split_once(char::is_whitespace)
        .unwrap_or((header, ""));

    let mut cursor = rest.trim_start();
    while !cursor.is_empty() {
        // Consume leading commas / whitespace between parameters.
        cursor = cursor.trim_start_matches(|c: char| c == ',' || c.is_whitespace());
        if cursor.is_empty() {
            break;
        }
        // Parameter name: up to `=`.
        let Some(eq_idx) = cursor.find('=') else {
            break;
        };
        let name = cursor[..eq_idx].trim().to_ascii_lowercase();
        cursor = &cursor[eq_idx + 1..];
        cursor = cursor.trim_start();

        // Parameter value: either a `quoted-string` or a bare token.
        let value = if let Some(remaining) = cursor.strip_prefix('"') {
            // Read until next unescaped `"` (we don't honour `\"` for simplicity).
            let end = remaining.find('"').unwrap_or(remaining.len());
            let v = remaining[..end].to_string();
            cursor = &remaining[end.min(remaining.len())..];
            if !cursor.is_empty() {
                cursor = &cursor[1..]; // consume closing quote
            }
            v
        } else {
            let end = cursor
                .find(|c: char| c == ',' || c.is_whitespace())
                .unwrap_or(cursor.len());
            let v = cursor[..end].to_string();
            cursor = &cursor[end..];
            v
        };

        out.insert(name, value);
    }
    out
}

// ============================================================================
// §3.2 — Content type and cache control
// ============================================================================

#[tokio::test]
async fn test_rfc9728_content_type_and_cache_control() {
    // RFC 9728 §3.2: Response is application/json with a 200 status.
    let (app, _state) = test_app().await;

    let response = http_get_full(&app, WELL_KNOWN_SUFFIX, &[]).await;
    assert_eq!(response.status, StatusCode::OK);

    let content_type = response
        .headers
        .get("content-type")
        .expect("must have Content-Type")
        .to_str()
        .expect("valid UTF-8");
    assert!(
        content_type.contains("application/json"),
        "Metadata must be application/json, got: {content_type}"
    );

    // We intentionally advertise a one-hour public cache to match
    // the AS discovery endpoint; verify the header is present.
    let cache_control = response
        .headers
        .get("cache-control")
        .expect("must have Cache-Control")
        .to_str()
        .expect("valid UTF-8");
    assert!(
        cache_control.contains("public") && cache_control.contains("max-age=3600"),
        "Cache-Control must be `public, max-age=3600`, got: {cache_control}"
    );
}

// ============================================================================
// §2 REQUIRED/OPTIONAL fields
// ============================================================================

#[tokio::test]
async fn test_rfc9728_required_fields_present() {
    // RFC 9728 §2: `resource` is REQUIRED. Other fields we populate
    // unconditionally are checked here; config-driven optional fields
    // are checked separately.
    let (app, state) = test_app().await;

    let (status, body) = http_get(&app, WELL_KNOWN_SUFFIX, &[]).await;
    assert_eq!(status, StatusCode::OK);
    let m: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");

    assert_eq!(
        m["resource"].as_str(),
        Some(state.config().base_url.as_str()),
        "resource MUST be exactly base_url"
    );

    let servers = m["authorization_servers"]
        .as_array()
        .expect("authorization_servers must be a JSON array");
    assert_eq!(servers.len(), 1, "Vouch is its own AS");
    assert_eq!(servers[0].as_str(), Some(state.config().base_url.as_str()));

    let expected_jwks = format!("{}/oauth/jwks", state.config().base_url);
    assert_eq!(m["jwks_uri"].as_str(), Some(expected_jwks.as_str()));

    // Scopes must match the AS discovery document.
    let expected_scopes: std::collections::HashSet<String> = m["scopes_supported"]
        .as_array()
        .expect("scopes_supported must be array")
        .iter()
        .filter_map(|s| s.as_str().map(str::to_string))
        .collect();
    assert!(
        expected_scopes.contains("openid"),
        "scopes_supported must include openid"
    );

    // bearer_methods_supported lists the token *locations* Vouch
    // accepts: `header` for every resource endpoint, `body` for the
    // RFC 6750 §2.2 POST form variant on `/oauth/userinfo`. `query`
    // is excluded (forbidden by FAPI 2.0).
    let methods = m["bearer_methods_supported"]
        .as_array()
        .expect("bearer_methods_supported must be array");
    let method_strs: std::collections::HashSet<&str> =
        methods.iter().filter_map(|v| v.as_str()).collect();
    // RFC 6750 §2.1 (Authorization header) is used by every resource
    // endpoint; RFC 6750 §2.2 (POST body access_token) is accepted by
    // the userinfo endpoint. RFC 6750 §2.3 (URI query) is forbidden
    // by FAPI 2.0 §5.3.2.1 and not supported.
    assert_eq!(
        method_strs,
        std::collections::HashSet::from(["header", "body"]),
        "Vouch accepts header and body tokens, not query, got: {method_strs:?}"
    );
    assert!(
        !method_strs.contains("query"),
        "FAPI 2.0 forbids query-string tokens"
    );

    // DPoP posture.
    assert_eq!(m["dpop_bound_access_tokens_required"], true);
    let dpop_algs = m["dpop_signing_alg_values_supported"]
        .as_array()
        .expect("dpop_signing_alg_values_supported must be array");
    let dpop_strs: Vec<&str> = dpop_algs.iter().filter_map(|v| v.as_str()).collect();
    assert!(dpop_strs.contains(&"ES256"));
    assert!(dpop_strs.contains(&"PS256"));
    assert!(dpop_strs.contains(&"EdDSA"));
    assert!(
        !dpop_strs.contains(&"RS256"),
        "FAPI 2.0 §5.4.1 excludes RS256 from DPoP"
    );

    // signed_metadata MUST be present (we always sign).
    assert!(
        m["signed_metadata"].as_str().is_some_and(|s| !s.is_empty()),
        "signed_metadata must be populated"
    );

    // tls_client_certificate_bound_access_tokens is always emitted
    // (boolean with no skip).
    assert!(
        m.get("tls_client_certificate_bound_access_tokens")
            .is_some()
    );
}

#[tokio::test]
async fn test_rfc9728_scopes_match_discovery() {
    // The AS discovery and RS protected-resource metadata documents
    // must advertise the same scope list (both sourced from
    // `OAuthScope::all()`).
    let (app, _state) = test_app().await;

    let (status, discovery_body) = http_get(&app, "/.well-known/openid-configuration", &[]).await;
    assert_eq!(status, StatusCode::OK);
    let discovery: serde_json::Value = serde_json::from_str(&discovery_body).expect("valid JSON");
    let discovery_scopes: std::collections::HashSet<&str> = discovery["scopes_supported"]
        .as_array()
        .expect("discovery scopes_supported")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();

    let (status, rs_body) = http_get(&app, WELL_KNOWN_SUFFIX, &[]).await;
    assert_eq!(status, StatusCode::OK);
    let rs: serde_json::Value = serde_json::from_str(&rs_body).expect("valid JSON");
    let rs_scopes: std::collections::HashSet<&str> = rs["scopes_supported"]
        .as_array()
        .expect("rs scopes_supported")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();

    assert_eq!(
        discovery_scopes, rs_scopes,
        "AS and RS must advertise the same scopes"
    );
}

#[tokio::test]
async fn test_rfc9728_authorization_servers_matches_discovery_issuer() {
    // `authorization_servers[0]` must be exactly the issuer the AS
    // discovery document advertises.
    let (app, _state) = test_app().await;

    let (status, d) = http_get(&app, "/.well-known/openid-configuration", &[]).await;
    assert_eq!(status, StatusCode::OK);
    let discovery: serde_json::Value = serde_json::from_str(&d).expect("valid JSON");
    let issuer = discovery["issuer"]
        .as_str()
        .expect("discovery.issuer must be string");

    let (status, r) = http_get(&app, WELL_KNOWN_SUFFIX, &[]).await;
    assert_eq!(status, StatusCode::OK);
    let rs: serde_json::Value = serde_json::from_str(&r).expect("valid JSON");

    let servers = rs["authorization_servers"]
        .as_array()
        .expect("authorization_servers array");
    assert_eq!(servers[0].as_str(), Some(issuer));
}

#[tokio::test]
async fn test_rfc9728_resource_signing_algs_match_available_keys() {
    // Without an RSA OIDC key (the default test harness), ES256 is
    // the only value. With one configured, RS256 is added as well.
    // This test exercises the default (no RSA key) branch.
    let (app, state) = test_app().await;
    assert!(
        state.oidc_rsa_key.is_none(),
        "test harness must not preload an RSA key"
    );

    let (status, body) = http_get(&app, WELL_KNOWN_SUFFIX, &[]).await;
    assert_eq!(status, StatusCode::OK);
    let m: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");

    let algs = m["resource_signing_alg_values_supported"]
        .as_array()
        .expect("resource_signing_alg_values_supported must be array");
    let alg_strs: Vec<&str> = algs.iter().filter_map(|v| v.as_str()).collect();
    assert_eq!(alg_strs, vec!["ES256"]);
}

/// Drift guard: the protected-resource metadata's `dpop_signing_alg_values_supported`
/// must exactly match `JwsAlgorithm::FAPI_ALLOWED`, the same source the AS discovery
/// document derives its `dpop_signing_alg_values_supported` from. Checks both
/// representations of the field — the plain JSON and the `signed_metadata` JWT
/// payload, which RFC 9728 §3.3 requires to mirror the outer JSON — since they
/// are built independently and could drift from each other. Same shape as
/// `test_dpop_signing_algs_match_supported_algorithms` in `tests/rfc9449.rs`.
#[tokio::test]
async fn test_rfc9728_dpop_signing_algs_match_fapi_allowed() {
    let (app, _state) = test_app().await;

    let (status, body) = http_get(&app, WELL_KNOWN_SUFFIX, &[]).await;
    assert_eq!(status, StatusCode::OK);
    let outer: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");

    let source: BTreeSet<String> = crate::crypto::alg::JwsAlgorithm::FAPI_ALLOWED
        .iter()
        .map(|alg| alg.as_str().to_string())
        .collect();

    let extract_algs = |doc: &serde_json::Value| -> BTreeSet<String> {
        doc["dpop_signing_alg_values_supported"]
            .as_array()
            .expect("dpop_signing_alg_values_supported must be array")
            .iter()
            .map(|v| v.as_str().expect("alg should be string").to_string())
            .collect()
    };

    let outer_algs = extract_algs(&outer);
    assert_eq!(
        outer_algs, source,
        "protected-resource dpop_signing_alg_values_supported must exactly match \
         JwsAlgorithm::FAPI_ALLOWED"
    );

    let jwt = outer["signed_metadata"]
        .as_str()
        .expect("signed_metadata must be string");
    let signed_algs = extract_algs(&decode_jwt_payload(jwt));
    assert_eq!(
        signed_algs, source,
        "signed_metadata.dpop_signing_alg_values_supported must exactly match \
         JwsAlgorithm::FAPI_ALLOWED"
    );

    for alg in &source {
        assert!(
            alg.parse::<crate::crypto::alg::JwsAlgorithm>().is_ok(),
            "FAPI_ALLOWED wire string does not round-trip through JwsAlgorithm parsing: {alg}"
        );
    }
}

#[tokio::test]
async fn test_rfc9728_descriptive_fields_have_defaults() {
    // The descriptive metadata fields have defaults and are present
    // in the metadata document without explicit configuration.
    let (app, state) = test_app().await;
    assert_eq!(state.config().resource_name.as_deref(), Some("Vouch"));
    assert_eq!(
        state.config().resource_documentation.as_deref(),
        Some("https://vouch.sh/docs/")
    );
    assert_eq!(
        state.config().resource_policy_uri.as_deref(),
        Some("https://vouch.sh/privacy/")
    );
    assert_eq!(
        state.config().resource_tos_uri.as_deref(),
        Some("https://vouch.sh/terms/")
    );

    let (status, body) = http_get(&app, WELL_KNOWN_SUFFIX, &[]).await;
    assert_eq!(status, StatusCode::OK);
    let m: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");

    assert_eq!(m["resource_name"].as_str(), Some("Vouch"));
    assert_eq!(
        m["resource_documentation"].as_str(),
        Some("https://vouch.sh/docs/")
    );
    assert_eq!(
        m["resource_policy_uri"].as_str(),
        Some("https://vouch.sh/privacy/")
    );
    assert_eq!(
        m["resource_tos_uri"].as_str(),
        Some("https://vouch.sh/terms/")
    );
}

#[tokio::test]
async fn test_rfc9728_tls_binding_mirrors_discovery_when_mtls_configured() {
    // RFC 8705 §3 + RFC 9728 §2: when the server is configured with
    // a TLS certificate (which enables mTLS client auth), the
    // `tls_client_certificate_bound_access_tokens` field flips to
    // `true` and matches the AS discovery document. The default test
    // harness has no TLS, so this test mutates the live ArcSwap
    // config (the builder re-snapshots per request).
    use std::sync::Arc;

    let (app, state) = test_app().await;

    // Default: no TLS → false in both documents.
    let (status, rs_body) = http_get(&app, WELL_KNOWN_SUFFIX, &[]).await;
    assert_eq!(status, StatusCode::OK);
    let rs: serde_json::Value = serde_json::from_str(&rs_body).expect("valid JSON");
    assert_eq!(
        rs["tls_client_certificate_bound_access_tokens"], false,
        "default test harness has no TLS"
    );

    // Flip TLS on by injecting placeholder cert and key. Advertising mTLS
    // requires full TLS configuration (`tls_configured()`, cert AND key) —
    // a partial config never starts the mTLS listener.
    let mut new_config = (**state.config()).clone();
    new_config.tls_cert = Some("/tmp/fake-cert.pem".to_string());
    new_config.tls_key = Some(secrecy::SecretString::from("/tmp/fake-key.pem".to_string()));
    state.config.store(Arc::new(new_config));

    let (status, rs_body) = http_get(&app, WELL_KNOWN_SUFFIX, &[]).await;
    assert_eq!(status, StatusCode::OK);
    let rs: serde_json::Value = serde_json::from_str(&rs_body).expect("valid JSON");
    assert_eq!(
        rs["tls_client_certificate_bound_access_tokens"], true,
        "with TLS configured, mTLS binding must be advertised"
    );

    let (status, as_body) = http_get(&app, "/.well-known/openid-configuration", &[]).await;
    assert_eq!(status, StatusCode::OK);
    let as_meta: serde_json::Value = serde_json::from_str(&as_body).expect("valid JSON");
    assert_eq!(
        rs["tls_client_certificate_bound_access_tokens"],
        as_meta["tls_client_certificate_bound_access_tokens"],
        "AS and RS must agree on mTLS binding"
    );
}

#[tokio::test]
async fn test_rfc9728_descriptive_fields_overridden_via_config() {
    // When the operator overrides descriptive URLs, the metadata
    // document echoes them verbatim. Mutates the live `ArcSwap`
    // config on an already-built router — exercises the hot-reload
    // path that the builder uses (it re-snapshots on every request).
    use std::sync::Arc;

    let (app, state) = test_app().await;

    let mut new_config = (**state.config()).clone();
    new_config.resource_name = Some("Vouch Test Deployment".to_string());
    new_config.resource_documentation = Some("https://docs.test/".to_string());
    new_config.resource_policy_uri = Some("https://policy.test/".to_string());
    new_config.resource_tos_uri = Some("https://tos.test/".to_string());
    state.config.store(Arc::new(new_config));

    let (status, body) = http_get(&app, WELL_KNOWN_SUFFIX, &[]).await;
    assert_eq!(status, StatusCode::OK);
    let m: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");

    assert_eq!(m["resource_name"].as_str(), Some("Vouch Test Deployment"));
    assert_eq!(
        m["resource_documentation"].as_str(),
        Some("https://docs.test/")
    );
    assert_eq!(
        m["resource_policy_uri"].as_str(),
        Some("https://policy.test/")
    );
    assert_eq!(m["resource_tos_uri"].as_str(), Some("https://tos.test/"));
}

// ============================================================================
// §4 — Identity rule and path-insertion variants
// ============================================================================

#[tokio::test]
async fn test_rfc9728_resource_identity_root() {
    // Root document: `resource == base_url`.
    let (app, state) = test_app().await;
    let (status, body) = http_get(&app, WELL_KNOWN_SUFFIX, &[]).await;
    assert_eq!(status, StatusCode::OK);
    let m: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(
        m["resource"].as_str(),
        Some(state.config().base_url.as_str())
    );
}

#[tokio::test]
async fn test_rfc9728_resource_identity_path_variants() {
    // For every known protected resource prefix, the path variant
    // echoes `base_url + "/" + prefix` verbatim.
    let (app, state) = test_app().await;

    for prefix in PROTECTED_RESOURCE_PREFIXES {
        let url = format!("{WELL_KNOWN_SUFFIX}/{prefix}");
        let (status, body) = http_get(&app, &url, &[]).await;
        assert_eq!(status, StatusCode::OK, "GET {url} should succeed");
        let m: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        let expected = format!("{}/{prefix}", state.config().base_url);
        assert_eq!(
            m["resource"].as_str(),
            Some(expected.as_str()),
            "resource must be byte-identical to {expected}"
        );
    }
}

#[tokio::test]
async fn test_rfc9728_resource_identity_deeper_path() {
    // Paths deeper than a registered prefix match (e.g. `scim/v2/Users/42`).
    // The returned `resource` echoes the entire sub-path.
    let (app, state) = test_app().await;

    let url = format!("{WELL_KNOWN_SUFFIX}/scim/v2/Users/42");
    let (status, body) = http_get(&app, &url, &[]).await;
    assert_eq!(status, StatusCode::OK);
    let m: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    let expected = format!("{}/scim/v2/Users/42", state.config().base_url);
    assert_eq!(m["resource"].as_str(), Some(expected.as_str()));
}

#[tokio::test]
async fn test_rfc9728_unknown_subpath_returns_404() {
    // RFC 9728 §4 prohibits echoing unrecognized resource identifiers,
    // so unknown sub-paths yield 404 rather than a fabricated document.
    let (app, _state) = test_app().await;

    let url = format!("{WELL_KNOWN_SUFFIX}/does/not/exist");
    let response = http_get_full(&app, &url, &[]).await;
    assert_eq!(response.status, StatusCode::NOT_FOUND);
}

/// Canonical, hand-maintained list of every URL prefix Vouch serves
/// as an OAuth 2.0 protected resource (i.e. requires a bearer/DPoP
/// access token). Mirrors the routes layered with
/// [`crate::infra::resource_metadata::layer`] in
/// [`crate::infra::router`]. The drift-detection test below cross-
/// checks this against [`PROTECTED_RESOURCE_PREFIXES`] in the service
/// layer; updates to either side must keep them in sync.
const KNOWN_PROTECTED_ENDPOINTS: &[&str] = &[
    "oauth/userinfo",
    "oauth/introspect",
    // RFC 7592 management endpoints — `/oauth/register/{client_id}`.
    // The bare `/oauth/register` POST is RFC 7591 dynamic registration
    // (unauthenticated) and is intentionally NOT a protected resource.
    "oauth/register",
    "v1/credentials/ssh",
    "v1/credentials/aws/token",
    "v1/credentials/github/token",
    "v1/keys",
    "api/v1/org",
    "api/v1/applications",
    "scim/v2",
];

#[tokio::test]
async fn test_rfc9728_allowlist_matches_protected_endpoints() {
    // Drift guard: any change to PROTECTED_RESOURCE_PREFIXES must be
    // mirrored in KNOWN_PROTECTED_ENDPOINTS, and vice versa. New
    // protected resource endpoints must be added to both lists. This
    // test catches the silent failure mode where a new resource
    // endpoint is added to the router without being advertised at
    // `/.well-known/oauth-protected-resource/{path}`.
    let allowlist: std::collections::HashSet<&str> =
        PROTECTED_RESOURCE_PREFIXES.iter().copied().collect();
    let known: std::collections::HashSet<&str> =
        KNOWN_PROTECTED_ENDPOINTS.iter().copied().collect();

    let missing_from_allowlist: Vec<&&str> = known.difference(&allowlist).collect();
    assert!(
        missing_from_allowlist.is_empty(),
        "Endpoints listed as protected but missing from PROTECTED_RESOURCE_PREFIXES: \
         {missing_from_allowlist:?}. Add them to the allowlist in \
         services/oidc/protected_resource.rs."
    );
    let extra_in_allowlist: Vec<&&str> = allowlist.difference(&known).collect();
    assert!(
        extra_in_allowlist.is_empty(),
        "Allowlist entries with no matching protected endpoint in this test: \
         {extra_in_allowlist:?}. Either remove the entry from \
         PROTECTED_RESOURCE_PREFIXES or add the route to \
         KNOWN_PROTECTED_ENDPOINTS in tests/rfc9728.rs."
    );
}

#[tokio::test]
async fn test_rfc9728_metadata_serves_every_known_prefix() {
    // For every known protected-endpoint prefix, the path-insertion
    // metadata variant must respond 200 and echo the requested
    // resource URL byte-identically. This is the contract clients
    // actually depend on — they fetch the metadata, not the resource
    // itself — and serves as a complementary drift guard: a change
    // to `PROTECTED_RESOURCE_PREFIXES` that breaks the §4 identity
    // rule for any known endpoint surfaces here.
    //
    // Note: we deliberately do *not* probe the resource endpoints
    // themselves, because some allowlist entries (e.g. `api/v1/org`)
    // are namespaces that have no GET handler at the bare prefix.
    let (app, state) = test_app().await;
    for prefix in KNOWN_PROTECTED_ENDPOINTS {
        let url = format!("{WELL_KNOWN_SUFFIX}/{prefix}");
        let (status, body) = http_get(&app, &url, &[]).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "metadata for {prefix} must be served"
        );
        let m: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        let expected = format!("{}/{prefix}", state.config().base_url);
        assert_eq!(
            m["resource"].as_str(),
            Some(expected.as_str()),
            "resource must echo the caller URL byte-identically"
        );
    }
}

// ============================================================================
// Wildcard route must not shadow siblings
// ============================================================================

#[tokio::test]
async fn test_rfc9728_wildcard_does_not_shadow_as_discovery() {
    // Regression test for axum route precedence: registering a
    // `/.well-known/oauth-protected-resource/{*path}` wildcard must
    // not affect the `openid-configuration` and
    // `oauth-authorization-server` well-known URLs.
    let (app, state) = test_app().await;

    for path in [
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
    ] {
        let response = http_get_full(&app, path, &[]).await;
        assert_eq!(response.status, StatusCode::OK, "{path} must return 200");
        let meta: serde_json::Value = serde_json::from_str(&response.body).expect("valid JSON");
        assert_eq!(
            meta["issuer"].as_str(),
            Some(state.config().base_url.as_str()),
            "{path} must still return AS metadata"
        );
    }
}

#[tokio::test]
async fn test_rfc9728_wildcard_does_not_shadow_jwks() {
    // The JWKS endpoint lives at `/oauth/jwks`, nowhere near the
    // wildcard, but we verify anyway as defense-in-depth.
    let (app, _state) = test_app().await;
    let response = http_get_full(&app, "/oauth/jwks", &[]).await;
    assert_eq!(response.status, StatusCode::OK);
}

// ============================================================================
// §3.3 — signed metadata
// ============================================================================

#[tokio::test]
async fn test_rfc9728_signed_metadata_typ_header() {
    // The JWS header must carry the RFC-defined media type so
    // clients can assert it before extracting claims.
    let (app, _state) = test_app().await;
    let (status, body) = http_get(&app, WELL_KNOWN_SUFFIX, &[]).await;
    assert_eq!(status, StatusCode::OK);
    let m: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");

    let jwt = m["signed_metadata"]
        .as_str()
        .expect("signed_metadata must be string");
    let header = jsonwebtoken::decode_header(jwt).expect("valid JWT header");
    assert_eq!(header.typ.as_deref(), Some(SIGNED_METADATA_TYP));
    assert_eq!(header.alg, jsonwebtoken::Algorithm::ES256);
}

#[tokio::test]
async fn test_rfc9728_signed_metadata_iss_iat_and_claims_match() {
    // RFC 9728 §3.3: `iss` MUST be present and identify the issuer.
    // Vouch adds `iat` for freshness and emits the same claim set
    // as the surrounding JSON (minus `signed_metadata`).
    let (app, state) = test_app().await;
    let (status, body) = http_get(&app, WELL_KNOWN_SUFFIX, &[]).await;
    assert_eq!(status, StatusCode::OK);
    let outer: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");

    let jwt = outer["signed_metadata"]
        .as_str()
        .expect("signed_metadata must be string");
    let signed_claims = decode_jwt_payload(jwt);

    assert_eq!(
        signed_claims["iss"].as_str(),
        Some(state.config().base_url.as_str()),
        "signed_metadata.iss MUST equal base_url (RFC 9728 §3.3)"
    );
    assert!(
        signed_claims["iat"].as_i64().is_some(),
        "signed_metadata.iat should be set (freshness hint)"
    );

    // Every non-signed_metadata field in the outer JSON must match
    // the signed claim with the same name.
    let outer_obj = outer.as_object().expect("outer JSON is object");
    for (k, v) in outer_obj {
        if k == "signed_metadata" {
            continue;
        }
        assert_eq!(
            signed_claims.get(k),
            Some(v),
            "signed_metadata claim `{k}` must match outer JSON"
        );
    }
}

#[tokio::test]
async fn test_rfc9728_signed_metadata_signature_verifies_with_jwks() {
    // RFC 9728 §3.3: signed_metadata is verifiable with keys
    // published at `jwks_uri`. Grab the EC JWK, reconstruct the
    // raw public key, and verify the ES256 signature.
    let (app, state) = test_app().await;

    let (status, body) = http_get(&app, WELL_KNOWN_SUFFIX, &[]).await;
    assert_eq!(status, StatusCode::OK);
    let outer: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    let jwt = outer["signed_metadata"]
        .as_str()
        .expect("signed_metadata must be string");

    // Pull the EC JWK out of the resource's advertised JWKS.
    let jwks_uri = outer["jwks_uri"].as_str().expect("jwks_uri").to_string();
    let jwks_path = jwks_uri
        .strip_prefix(state.config().base_url.as_str())
        .expect("jwks_uri begins with base_url")
        .to_string();
    let (status, jwks_body) = http_get(&app, &jwks_path, &[]).await;
    assert_eq!(status, StatusCode::OK);
    let jwks: serde_json::Value = serde_json::from_str(&jwks_body).expect("valid JSON");
    let keys = jwks["keys"].as_array().expect("keys array");
    let ec_key = keys
        .iter()
        .find(|k| k["kty"].as_str() == Some("EC"))
        .expect("EC key must be present in JWKS");

    let x_b64 = ec_key["x"].as_str().expect("EC.x");
    let y_b64 = ec_key["y"].as_str().expect("EC.y");
    let x = URL_SAFE_NO_PAD.decode(x_b64).expect("EC.x base64url");
    let y = URL_SAFE_NO_PAD.decode(y_b64).expect("EC.y base64url");
    assert_eq!(x.len(), 32);
    assert_eq!(y.len(), 32);

    // Uncompressed SEC1 form: 0x04 || X || Y.
    let mut raw_public_key = Vec::with_capacity(1 + 32 + 32);
    raw_public_key.push(0x04);
    raw_public_key.extend_from_slice(&x);
    raw_public_key.extend_from_slice(&y);

    // Build signing input and decode the raw ES256 signature.
    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3, "JWT has three parts");
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let signature = URL_SAFE_NO_PAD
        .decode(parts[2])
        .expect("signature base64url");
    assert_eq!(
        signature.len(),
        64,
        "ES256 signature is 64 bytes (r || s, P-256 fixed)"
    );

    let public_key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, raw_public_key);
    public_key
        .verify(signing_input.as_bytes(), &signature)
        .expect("signed_metadata signature must verify against JWKS");
}

#[tokio::test]
async fn test_rfc9728_signed_metadata_has_no_recursion() {
    // RFC 9728 §3.3 forbids `signed_metadata` inside the signed
    // claims. Verify absence.
    let (app, _state) = test_app().await;
    let (status, body) = http_get(&app, WELL_KNOWN_SUFFIX, &[]).await;
    assert_eq!(status, StatusCode::OK);
    let outer: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    let jwt = outer["signed_metadata"].as_str().expect("signed_metadata");
    let claims = decode_jwt_payload(jwt);
    assert!(
        claims.get("signed_metadata").is_none(),
        "signed_metadata claims must not recursively embed signed_metadata"
    );
}

// ============================================================================
// §5.2 — WWW-Authenticate resource_metadata injection
// ============================================================================

#[tokio::test]
async fn test_rfc9728_www_authenticate_on_userinfo_no_auth() {
    // RFC 9728 §5.2: a 401 from a protected resource SHOULD include
    // `resource_metadata`. Verify for the userinfo endpoint with no
    // Authorization header.
    let (app, state) = test_app().await;
    let response = http_get_full(&app, "/oauth/userinfo", &[]).await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);

    let header = response
        .headers
        .get("www-authenticate")
        .expect("401 must include WWW-Authenticate")
        .to_str()
        .expect("valid UTF-8");

    let params = parse_www_authenticate_params(header);
    let expected = format!("{}{WELL_KNOWN_SUFFIX}", state.config().base_url);
    assert_eq!(
        params.get("resource_metadata").map(String::as_str),
        Some(expected.as_str()),
        "resource_metadata must point at the metadata URL, header: {header}"
    );
}

#[tokio::test]
async fn test_rfc9728_www_authenticate_on_userinfo_invalid_token() {
    // Additional coverage: an invalid Bearer token still produces
    // `resource_metadata` alongside the `error=invalid_token` param.
    let (app, state) = test_app().await;
    let response = http_get_full(
        &app,
        "/oauth/userinfo",
        &[("Authorization", "Bearer not-a-real-token")],
    )
    .await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);

    let header = response
        .headers
        .get("www-authenticate")
        .expect("401 must include WWW-Authenticate")
        .to_str()
        .expect("valid UTF-8");
    let params = parse_www_authenticate_params(header);
    assert_eq!(
        params.get("error").map(String::as_str),
        Some("invalid_token")
    );
    let expected = format!("{}{WELL_KNOWN_SUFFIX}", state.config().base_url);
    assert_eq!(
        params.get("resource_metadata").map(String::as_str),
        Some(expected.as_str()),
        "resource_metadata must be present even with an invalid token"
    );
}

#[tokio::test]
async fn test_rfc9728_www_authenticate_preserves_step_up() {
    // The step-up challenge (RFC 9470) must keep its `error=
    // insufficient_user_authentication` and `max_age` parameters
    // while also advertising `resource_metadata`.
    let (app, state) = test_app().await;

    let user = create_test_user(&state.store, "stepup-rfc9728@example.com").await;
    let auth_id = create_test_authenticator(&state.store, &user.id).await;
    // A second authenticator so deletion doesn't fall through to
    // a different error.
    let auth_id2 = create_test_authenticator(&state.store, &user.id).await;

    let stale_iat = jiff::Timestamp::now().as_second() - 600;
    let token =
        create_test_session_with_iat(&state, &user.id, &user.email, &auth_id, stale_iat).await;

    let response = http_delete_full(
        &app,
        &format!("/v1/keys/{auth_id2}"),
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);

    let header = response
        .headers
        .get("www-authenticate")
        .expect("step-up 401 must include WWW-Authenticate")
        .to_str()
        .expect("valid UTF-8");
    let params = parse_www_authenticate_params(header);
    assert_eq!(
        params.get("error").map(String::as_str),
        Some("insufficient_user_authentication"),
        "step-up error must be preserved, header: {header}"
    );
    assert!(
        params.contains_key("max_age"),
        "max_age must be preserved, header: {header}"
    );
    let expected = format!("{}{WELL_KNOWN_SUFFIX}", state.config().base_url);
    assert_eq!(
        params.get("resource_metadata").map(String::as_str),
        Some(expected.as_str()),
        "resource_metadata must be injected alongside step-up parameters"
    );
}

#[tokio::test]
async fn test_rfc9728_www_authenticate_not_applied_to_as_metadata() {
    // AS metadata endpoints are not OAuth 2.0 protected resources —
    // they serve public metadata. Their 200 responses must not
    // carry `WWW-Authenticate`, and specifically not the
    // `resource_metadata` parameter.
    let (app, _state) = test_app().await;
    let resp = http_get_full(&app, "/.well-known/openid-configuration", &[]).await;
    assert_eq!(resp.status, StatusCode::OK);
    assert!(
        resp.headers.get("www-authenticate").is_none(),
        "AS discovery response must not include WWW-Authenticate"
    );
}

#[tokio::test]
async fn test_rfc9728_root_document_field_set_snapshot() {
    // Snapshot the *set of fields* present in the root document
    // (excluding values that vary per-test like `signed_metadata`,
    // descriptive URLs, the EC public key embedded in the signature,
    // and `iat`). Catches accidental field additions/removals from
    // `ProtectedResourceMetadata` in code review.
    let (app, _state) = test_app().await;
    let (status, body) = http_get(&app, WELL_KNOWN_SUFFIX, &[]).await;
    assert_eq!(status, StatusCode::OK);
    let m: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");

    let mut keys: Vec<&str> = m
        .as_object()
        .expect("metadata must be a JSON object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();

    // Adding a new RFC 9728 field requires updating this list — that
    // is intentional, the snapshot is the change-detection contract.
    let expected: Vec<&str> = vec![
        "authorization_servers",
        "bearer_methods_supported",
        "dpop_bound_access_tokens_required",
        "dpop_signing_alg_values_supported",
        "jwks_uri",
        "resource",
        "resource_documentation",
        "resource_name",
        "resource_policy_uri",
        "resource_signing_alg_values_supported",
        "resource_tos_uri",
        "scopes_supported",
        "signed_metadata",
        "tls_client_certificate_bound_access_tokens",
    ];

    assert_eq!(
        keys, expected,
        "Protected Resource Metadata field set drifted. \
         Update the snapshot or revisit field selection."
    );
}

#[tokio::test]
async fn test_rfc9728_www_authenticate_idempotent() {
    // Hitting userinfo twice without auth must yield a single
    // `resource_metadata` parameter — not two. Regression against
    // double-wrapping bugs.
    let (app, _state) = test_app().await;
    for _ in 0..2 {
        let response = http_get_full(&app, "/oauth/userinfo", &[]).await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED);
        let header = response
            .headers
            .get("www-authenticate")
            .expect("WWW-Authenticate")
            .to_str()
            .expect("UTF-8");
        let count = header.matches("resource_metadata=").count();
        assert_eq!(
            count, 1,
            "resource_metadata must appear exactly once, header: {header}"
        );
    }
}
