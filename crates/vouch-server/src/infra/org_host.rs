// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Org issuer-subdomain host detection and route gating.
//!
//! Organizations can claim a subdomain of the primary host as their OIDC
//! issuer for AWS workload identity federation (`acme.us.vouch.sh`). Those
//! hosts serve only what AWS IAM fetches when creating an OIDC identity
//! provider — the discovery document and the JWKS — plus health checks.
//! Every other route 404s on org hosts so cookies, WebAuthn origins, and
//! FAPI flows remain anchored to the primary host.
//!
//! The request `Host` header is attacker-controlled (the load balancer is
//! L4 passthrough), so it is used strictly as a lookup key after shape
//! validation. Issuer strings in responses and tokens are always built from
//! the stored label plus the configured `base_url`, never from the header.

use crate::AppState;
use crate::config::ServerConfig;
use crate::db::validate_subdomain_label;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode, Uri, header::HOST};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::sync::Arc;

/// Paths served on org-subdomain hosts. Everything else 404s there.
const ORG_HOST_ALLOWED_PATHS: &[&str] = &[
    "/.well-known/openid-configuration",
    "/oauth/jwks",
    "/health",
    "/health/ready",
];

/// Extract a validated org-subdomain label from the request host.
///
/// Returns `Some(label)` only when the request host is exactly
/// `{label}.{primary_host}` (after port stripping and lowercasing) and the
/// label passes [`validate_subdomain_label`]. Any other host — the primary
/// host itself, IP literals, NLB DNS names, multi-label prefixes — yields
/// `None`, which means "behave exactly as today".
pub(crate) fn org_label_from_request(
    headers: &HeaderMap,
    uri: &Uri,
    config: &ServerConfig,
) -> Option<String> {
    let primary_host = config.primary_host()?;

    // Prefer the Host header; fall back to the URI authority (HTTP/2 maps
    // `:authority` there). Non-ASCII or whitespace-bearing values are noise.
    let raw = headers
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .or_else(|| uri.host())?;
    let raw = raw.trim();
    if raw.is_empty() || !raw.is_ascii() || raw.contains(char::is_whitespace) {
        return None;
    }
    // Bracketed IPv6 literals can never be org hosts.
    if raw.starts_with('[') {
        return None;
    }
    // Strip an optional :port suffix.
    let host = raw.rsplit_once(':').map_or(raw, |(h, _)| h);
    let host = host.to_ascii_lowercase();

    let label = host.strip_suffix(&format!(".{primary_host}"))?;
    validate_subdomain_label(label).ok()
}

/// Middleware gating org-subdomain hosts to the WIF-only surface.
///
/// DB-free: only the host *shape* is checked here. Whether the label is
/// actually claimed is decided by the discovery handler; the JWKS content is
/// identical for every issuer host, so serving it for unclaimed labels is
/// harmless (public keys, no issuer assertion).
pub(crate) async fn org_host_gate(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    let is_org_host =
        org_label_from_request(request.headers(), request.uri(), &state.config()).is_some();
    if is_org_host && !ORG_HOST_ALLOWED_PATHS.contains(&request.uri().path()) {
        return StatusCode::NOT_FOUND.into_response();
    }
    next.run(request).await
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn config_with_base_url(base_url: &str) -> ServerConfig {
        let mut config = crate::test_utils::test_config();
        config.base_url = base_url.to_string();
        config
    }

    fn headers_with_host(host: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_str(host).unwrap());
        headers
    }

    fn label_for(base_url: &str, host: &str) -> Option<String> {
        let config = config_with_base_url(base_url);
        let uri = Uri::from_static("/");
        org_label_from_request(&headers_with_host(host), &uri, &config)
    }

    #[test]
    fn org_label_extracted_from_valid_subdomain() {
        assert_eq!(
            label_for("https://us.vouch.sh", "acme.us.vouch.sh"),
            Some("acme".to_string())
        );
    }

    #[test]
    fn org_label_strips_port_and_lowercases() {
        assert_eq!(
            label_for("https://us.vouch.sh", "ACME.US.Vouch.SH:443"),
            Some("acme".to_string())
        );
    }

    #[test]
    fn org_label_preserved_for_loopback_dev() {
        assert_eq!(
            label_for("http://localhost:3000", "acme.localhost:3000"),
            Some("acme".to_string())
        );
    }

    #[test]
    fn primary_host_is_not_an_org_host() {
        assert_eq!(label_for("https://us.vouch.sh", "us.vouch.sh"), None);
        assert_eq!(label_for("https://us.vouch.sh", "us.vouch.sh:443"), None);
    }

    #[test]
    fn foreign_and_malformed_hosts_are_ignored() {
        assert_eq!(label_for("https://us.vouch.sh", "example.com"), None);
        assert_eq!(label_for("https://us.vouch.sh", "10.1.2.3"), None);
        assert_eq!(label_for("https://us.vouch.sh", "[::1]:443"), None);
        // Multi-label prefixes are rejected (wildcard certs don't cover them
        // and no org can claim a dotted label).
        assert_eq!(label_for("https://us.vouch.sh", "a.b.us.vouch.sh"), None);
        // Suffix-embedding tricks must not match.
        assert_eq!(
            label_for("https://us.vouch.sh", "acme.us.vouch.sh.evil.com"),
            None
        );
    }

    #[test]
    fn reserved_labels_are_not_org_hosts() {
        assert_eq!(label_for("https://us.vouch.sh", "www.us.vouch.sh"), None);
        assert_eq!(label_for("https://us.vouch.sh", "mtls.us.vouch.sh"), None);
    }
}
