// SPDX-License-Identifier: Apache-2.0 OR MIT
//! HTTP request extractors for authentication context.

use std::net::IpAddr;
use std::sync::Arc;

use axum::extract::rejection::PathRejection;
use axum::extract::{FromRequestParts, Path};
use axum::http::{HeaderMap, StatusCode};
use http::request::Parts;
use ipnet::IpNet;
use serde::Deserialize;

use crate::AppState;
use crate::services::error::ServiceError;

/// A validated UUID string. Rejects during deserialization if not valid.
/// Derefs to `&str` so it can be passed directly to db functions.
/// Normalizes to lowercase (UUIDs are case-insensitive per RFC 9562).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidUuid(String);

impl std::ops::Deref for ValidUuid {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for ValidUuid {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ValidUuid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ValidUuid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let parsed = uuid::Uuid::try_parse(&s)
            .map_err(|_| serde::de::Error::custom("invalid UUID format"))?;
        Ok(Self(parsed.to_string()))
    }
}

/// Path extractor that converts `PathRejection` into `ServiceError`.
/// Use instead of `axum::extract::Path` when the handler returns `ServiceError`.
pub struct ValidPath<T>(pub T);

impl<T, S> FromRequestParts<S> for ValidPath<T>
where
    T: serde::de::DeserializeOwned + Send,
    S: Send + Sync,
{
    type Rejection = ServiceError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match Path::<T>::from_request_parts(parts, state).await {
            Ok(Path(value)) => Ok(Self(value)),
            Err(rejection) => {
                let message = match rejection {
                    PathRejection::FailedToDeserializePathParams(e) => e.body_text(),
                    PathRejection::MissingPathParams(_) => "Missing path parameters".to_string(),
                    _ => "Invalid path parameters".to_string(),
                };
                Err(ServiceError::api(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    message,
                ))
            }
        }
    }
}

/// Maximum length for hostname values (RFC 1035: 253 chars).
const MAX_HOSTNAME_LEN: usize = 253;
/// Maximum length for other client metadata header values.
const MAX_CLIENT_HEADER_LEN: usize = 256;

/// Client information extracted from the request.
///
/// `client_ip` comes from the TCP socket (`ConnectInfo<SocketAddr>`), not from
/// proxy headers. This prevents IP spoofing via `X-Forwarded-For` when the
/// server is exposed directly without a trusted reverse proxy.
#[derive(Debug, Clone, Default)]
pub struct ClientInfo {
    /// Client IP address from the TCP peer socket.
    pub client_ip: Option<IpAddr>,
    /// User-Agent header.
    pub user_agent: Option<String>,
    /// Client hostname (from `Vouch-Client-Hostname` header).
    pub client_hostname: Option<String>,
    /// Client OS (from `Vouch-Client-OS` header).
    pub client_os: Option<String>,
    /// Client CPU architecture (from `Vouch-Client-Arch` header).
    pub client_arch: Option<String>,
    /// Client version (from `Vouch-Client-Version` header).
    pub client_version: Option<String>,
}

impl FromRequestParts<Arc<AppState>> for ClientInfo {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let peer_ip = parts
            .extensions
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
            .map(|ci| ci.0.ip().to_canonical());

        let config = state.config.load();
        let client_ip = resolve_client_ip(peer_ip, &parts.headers, &config.trusted_proxies);

        let mut info = Self::from(&parts.headers);
        info.client_ip = client_ip;
        Ok(info)
    }
}

impl From<&HeaderMap> for ClientInfo {
    fn from(headers: &HeaderMap) -> Self {
        let user_agent = headers
            .get("user-agent")
            .and_then(|h| h.to_str().ok())
            .map(String::from);

        let client_hostname =
            extract_validated_header(headers, "vouch-client-hostname", MAX_HOSTNAME_LEN);
        let client_os = extract_validated_header(headers, "vouch-client-os", MAX_CLIENT_HEADER_LEN);
        let client_arch =
            extract_validated_header(headers, "vouch-client-arch", MAX_CLIENT_HEADER_LEN);
        let client_version =
            extract_validated_header(headers, "vouch-client-version", MAX_CLIENT_HEADER_LEN);

        Self {
            client_ip: None,
            user_agent,
            client_hostname,
            client_os,
            client_arch,
            client_version,
        }
    }
}

/// Resolve the real client IP address, accounting for trusted reverse proxies.
///
/// When `trusted_cidrs` is empty, returns the TCP peer IP directly (safe for
/// servers exposed without a reverse proxy).
///
/// When `trusted_cidrs` is configured, parses `X-Forwarded-For` rightmost-first
/// and returns the first IP not in the trusted set. If the peer IP itself is not
/// trusted, `X-Forwarded-For` is ignored entirely (fail closed).
///
/// This implements the "rightmost-trusted" algorithm per RFC 7239.
pub(crate) fn resolve_client_ip(
    peer_ip: Option<IpAddr>,
    headers: &HeaderMap,
    trusted_cidrs: &[IpNet],
) -> Option<IpAddr> {
    // No trusted proxies configured → use TCP peer directly
    if trusted_cidrs.is_empty() {
        return peer_ip;
    }

    let peer = peer_ip?;

    // If the peer is not in the trusted set, ignore X-Forwarded-For
    if !is_trusted(peer, trusted_cidrs) {
        return Some(peer);
    }

    // Parse X-Forwarded-For header
    let xff = match headers.get("x-forwarded-for").and_then(|h| h.to_str().ok()) {
        Some(val) if !val.trim().is_empty() => val,
        _ => return Some(peer),
    };

    // Walk addresses right-to-left (closest proxy first)
    // Stop at the first IP not in the trusted set — that's the real client
    let addrs: Vec<&str> = xff.split(',').map(str::trim).collect();
    let mut idx = addrs.len();
    while idx > 0 {
        idx = idx.saturating_sub(1);
        let addr_str = addrs.get(idx).copied().unwrap_or("");
        if let Ok(addr) = addr_str.parse::<IpAddr>() {
            let addr = addr.to_canonical();
            if !is_trusted(addr, trusted_cidrs) {
                return Some(addr);
            }
        } else {
            // Unparseable entry — treat as untrusted boundary, stop
            break;
        }
    }

    // All XFF entries are trusted (or empty) — fall back to peer
    Some(peer)
}

/// Check if an IP address falls within any of the trusted CIDRs.
fn is_trusted(addr: IpAddr, trusted_cidrs: &[IpNet]) -> bool {
    trusted_cidrs.iter().any(|cidr| cidr.contains(&addr))
}

/// Extract and validate a client metadata header value.
///
/// Returns `None` if the header is missing, empty, exceeds `max_len`,
/// or contains non-printable ASCII characters (control chars, null bytes).
fn extract_validated_header(headers: &HeaderMap, name: &str, max_len: usize) -> Option<String> {
    let value = headers.get(name).and_then(|h| h.to_str().ok())?;
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > max_len {
        return None;
    }
    if !trimmed.bytes().all(|b| (0x20..0x7f).contains(&b)) {
        return None;
    }
    Some(trimmed.to_string())
}

/// Optional client certificate extracted from mTLS connection.
///
/// Reads the certificate from [`PeerClientCert`] injected via
/// [`axum::extract::ConnectInfo`] when the request arrives on the mTLS
/// port (direct TLS handshake).
///
/// On the main (non-mTLS) port this always yields `None`.
#[derive(Debug, Clone)]
pub struct OptionalClientCert(pub Option<crate::services::oidc::mtls::ClientCertificate>);

impl FromRequestParts<Arc<AppState>> for OptionalClientCert {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let from_tls = parts
            .extensions
            .get::<axum::extract::ConnectInfo<crate::infra::mtls_listener::PeerClientCert>>()
            .and_then(|ci| ci.0.0.as_ref())
            .and_then(|der| crate::services::oidc::mtls::parse_client_certificate(der).ok());

        Ok(Self(from_tls))
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    // ========================================================================
    // resolve_client_ip Tests
    // ========================================================================

    fn cidrs(strs: &[&str]) -> Vec<IpNet> {
        strs.iter().map(|s| s.parse().unwrap()).collect()
    }

    #[test]
    fn test_resolve_no_trusted_proxies_returns_peer() {
        let headers = HeaderMap::new();
        let peer = Some("203.0.113.1".parse().unwrap());
        assert_eq!(resolve_client_ip(peer, &headers, &[]), peer);
    }

    #[test]
    fn test_resolve_untrusted_peer_ignores_xff() {
        let trusted = cidrs(&["10.0.0.0/8"]);
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("1.2.3.4, 10.0.0.5"),
        );
        let peer: IpAddr = "203.0.113.1".parse().unwrap();
        // Peer is not in 10.0.0.0/8, so XFF is ignored
        assert_eq!(
            resolve_client_ip(Some(peer), &headers, &trusted),
            Some(peer)
        );
    }

    #[test]
    fn test_resolve_single_trusted_proxy() {
        let trusted = cidrs(&["10.0.0.0/8"]);
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.1, 10.0.0.5"),
        );
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        let expected: IpAddr = "203.0.113.1".parse().unwrap();
        assert_eq!(
            resolve_client_ip(Some(peer), &headers, &trusted),
            Some(expected)
        );
    }

    #[test]
    fn test_resolve_multiple_trusted_proxies() {
        let trusted = cidrs(&["10.0.0.0/8", "172.16.0.0/12"]);
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.1, 172.16.0.5, 10.0.0.5"),
        );
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        let expected: IpAddr = "203.0.113.1".parse().unwrap();
        assert_eq!(
            resolve_client_ip(Some(peer), &headers, &trusted),
            Some(expected)
        );
    }

    #[test]
    fn test_resolve_empty_xff_returns_peer() {
        let trusted = cidrs(&["10.0.0.0/8"]);
        let headers = HeaderMap::new();
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(
            resolve_client_ip(Some(peer), &headers, &trusted),
            Some(peer)
        );
    }

    #[test]
    fn test_resolve_all_xff_trusted_returns_peer() {
        let trusted = cidrs(&["10.0.0.0/8"]);
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("10.0.0.2, 10.0.0.3"),
        );
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(
            resolve_client_ip(Some(peer), &headers, &trusted),
            Some(peer)
        );
    }

    #[test]
    fn test_resolve_istio_sidecar() {
        // Istio sidecar uses 127.0.0.6 as source
        let trusted = cidrs(&["127.0.0.6/32"]);
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.50"));
        let peer: IpAddr = "127.0.0.6".parse().unwrap();
        let expected: IpAddr = "203.0.113.50".parse().unwrap();
        assert_eq!(
            resolve_client_ip(Some(peer), &headers, &trusted),
            Some(expected)
        );
    }

    #[test]
    fn test_resolve_no_peer_returns_none() {
        let trusted = cidrs(&["10.0.0.0/8"]);
        let headers = HeaderMap::new();
        assert_eq!(resolve_client_ip(None, &headers, &trusted), None);
    }

    // ========================================================================
    // ClientInfo Header Extraction Tests
    // ========================================================================

    #[test]
    fn test_extract_user_agent() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "user-agent",
            HeaderValue::from_static("vouch-cli/0.1.0 (macos; aarch64)"),
        );

        let info = ClientInfo::from(&headers);
        assert_eq!(
            info.user_agent,
            Some("vouch-cli/0.1.0 (macos; aarch64)".to_string())
        );
    }

    #[test]
    fn test_extract_no_headers() {
        let headers = HeaderMap::new();
        let info = ClientInfo::from(&headers);
        assert_eq!(info.client_ip, None);
        assert_eq!(info.user_agent, None);
        assert_eq!(info.client_hostname, None);
        assert_eq!(info.client_os, None);
        assert_eq!(info.client_arch, None);
        assert_eq!(info.client_version, None);
    }

    // ========================================================================
    // Vouch-Client-* Header Extraction Tests
    // ========================================================================

    #[test]
    fn test_extract_vouch_client_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "vouch-client-hostname",
            HeaderValue::from_static("dev.local"),
        );
        headers.insert("vouch-client-os", HeaderValue::from_static("macos"));
        headers.insert("vouch-client-arch", HeaderValue::from_static("aarch64"));
        headers.insert("vouch-client-version", HeaderValue::from_static("1.2.3"));

        let info = ClientInfo::from(&headers);
        assert_eq!(info.client_hostname.as_deref(), Some("dev.local"));
        assert_eq!(info.client_os.as_deref(), Some("macos"));
        assert_eq!(info.client_arch.as_deref(), Some("aarch64"));
        assert_eq!(info.client_version.as_deref(), Some("1.2.3"));
    }

    #[test]
    fn test_extract_vouch_client_header_rejects_too_long() {
        let mut headers = HeaderMap::new();
        let long_value = "a".repeat(MAX_CLIENT_HEADER_LEN + 1);
        headers.insert(
            "vouch-client-os",
            HeaderValue::from_str(&long_value).unwrap(),
        );

        let info = ClientInfo::from(&headers);
        assert_eq!(info.client_os, None);
    }

    #[test]
    fn test_extract_vouch_client_header_rejects_empty() {
        let mut headers = HeaderMap::new();
        headers.insert("vouch-client-os", HeaderValue::from_static(""));

        let info = ClientInfo::from(&headers);
        assert_eq!(info.client_os, None);
    }

    #[test]
    fn test_extract_vouch_client_header_trims_whitespace() {
        let mut headers = HeaderMap::new();
        headers.insert("vouch-client-os", HeaderValue::from_static("  macos  "));

        let info = ClientInfo::from(&headers);
        assert_eq!(info.client_os.as_deref(), Some("macos"));
    }

    #[test]
    fn test_extract_vouch_client_hostname_max_length() {
        let mut headers = HeaderMap::new();
        // Exactly at the 253-char limit should be accepted
        let hostname = "a".repeat(MAX_HOSTNAME_LEN);
        headers.insert(
            "vouch-client-hostname",
            HeaderValue::from_str(&hostname).unwrap(),
        );
        let info = ClientInfo::from(&headers);
        assert_eq!(info.client_hostname.as_deref(), Some(hostname.as_str()));

        // One over should be rejected
        let too_long = "a".repeat(MAX_HOSTNAME_LEN + 1);
        let mut headers2 = HeaderMap::new();
        headers2.insert(
            "vouch-client-hostname",
            HeaderValue::from_str(&too_long).unwrap(),
        );
        let info2 = ClientInfo::from(&headers2);
        assert_eq!(info2.client_hostname, None);
    }

    #[test]
    fn test_extract_validated_header_rejects_control_chars() {
        let mut headers = HeaderMap::new();
        // Tab character (0x09) is a control character
        headers.insert(
            "vouch-client-os",
            HeaderValue::from_bytes(b"mac\tos").unwrap(),
        );

        let info = ClientInfo::from(&headers);
        assert_eq!(info.client_os, None);
    }

    #[test]
    fn test_extract_validated_header_accepts_printable_ascii() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "vouch-client-version",
            HeaderValue::from_static("1.2.3-beta+build.456"),
        );

        let info = ClientInfo::from(&headers);
        assert_eq!(info.client_version.as_deref(), Some("1.2.3-beta+build.456"));
    }

    #[test]
    fn test_valid_uuid_accepts_valid() {
        let json = "\"019508a7-cc17-7a7c-a00b-632964b2750e\"";
        let uuid: ValidUuid = serde_json::from_str(json).unwrap();
        assert_eq!(&*uuid, "019508a7-cc17-7a7c-a00b-632964b2750e");
    }

    #[test]
    fn test_valid_uuid_normalizes_uppercase() {
        let json = "\"019508A7-CC17-7A7C-A00B-632964B2750E\"";
        let uuid: ValidUuid = serde_json::from_str(json).unwrap();
        assert_eq!(&*uuid, "019508a7-cc17-7a7c-a00b-632964b2750e");
    }

    #[test]
    fn test_valid_uuid_rejects_invalid() {
        let json = "\"not-a-uuid\"";
        let result: Result<ValidUuid, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_valid_uuid_rejects_empty() {
        let json = "\"\"";
        let result: Result<ValidUuid, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_valid_uuid_display() {
        let json = "\"019508a7-cc17-7a7c-a00b-632964b2750e\"";
        let uuid: ValidUuid = serde_json::from_str(json).unwrap();
        assert_eq!(format!("{uuid}"), "019508a7-cc17-7a7c-a00b-632964b2750e");
    }

    #[test]
    fn test_valid_uuid_as_ref() {
        let json = "\"019508a7-cc17-7a7c-a00b-632964b2750e\"";
        let uuid: ValidUuid = serde_json::from_str(json).unwrap();
        let s: &str = uuid.as_ref();
        assert_eq!(s, "019508a7-cc17-7a7c-a00b-632964b2750e");
    }

    #[test]
    fn test_valid_uuid_accepts_v4() {
        // UUID v4 (random) format is valid
        let json = "\"550e8400-e29b-41d4-a716-446655440000\"";
        let result: Result<ValidUuid, _> = serde_json::from_str(json);
        assert!(result.is_ok());
        assert_eq!(&*result.unwrap(), "550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn test_valid_uuid_accepts_compact_no_hyphens() {
        // The uuid crate accepts compact format (no hyphens) and normalizes it
        let json = "\"019508a7cc177a7ca00b632964b2750e\"";
        let result: Result<ValidUuid, _> = serde_json::from_str(json);
        assert!(result.is_ok());
        // uuid crate normalizes to hyphenated lowercase
        assert_eq!(&*result.unwrap(), "019508a7-cc17-7a7c-a00b-632964b2750e");
    }

    #[test]
    fn test_valid_uuid_accepts_null_uuid() {
        // Nil UUID is syntactically valid
        let json = "\"00000000-0000-0000-0000-000000000000\"";
        let result: Result<ValidUuid, _> = serde_json::from_str(json);
        assert!(result.is_ok());
        assert_eq!(&*result.unwrap(), "00000000-0000-0000-0000-000000000000");
    }

    // ========================================================================
    // OptionalClientCert Tests
    // ========================================================================

    /// When `PeerClientCert` contains invalid DER bytes, the `.ok()` in
    /// `from_request_parts` swallows the parse error and yields `None` rather
    /// than returning an error response. This keeps the extractor infallible.
    #[tokio::test]
    async fn test_optional_client_cert_with_invalid_der_returns_none() {
        use crate::infra::mtls_listener::PeerClientCert;
        use axum::extract::ConnectInfo;

        let mut request = http::Request::builder().body(()).unwrap();
        request
            .extensions_mut()
            .insert(ConnectInfo(PeerClientCert(Some(vec![
                0xFF, 0xFF, 0xDE, 0xAD,
            ]))));
        let (parts, _) = request.into_parts();

        // OptionalClientCert::from_request_parts requires Arc<AppState>, but all it
        // does with _state is ignore it — the cert extraction only reads extensions.
        // We exercise the same code path by replicating the extractor logic inline,
        // which lets us verify the `.ok()` swallows the DER parse error.
        let cert = parts
            .extensions
            .get::<ConnectInfo<PeerClientCert>>()
            .and_then(|ci| ci.0.0.as_ref())
            .and_then(|der| crate::services::oidc::mtls::parse_client_certificate(der).ok());

        assert!(
            cert.is_none(),
            "Invalid DER must yield None, not an error or panic"
        );
    }

    /// When no `PeerClientCert` extension is present (non-mTLS connection),
    /// the extractor must yield `None` without panicking.
    #[tokio::test]
    async fn test_optional_client_cert_no_extension_returns_none() {
        use crate::infra::mtls_listener::PeerClientCert;
        use axum::extract::ConnectInfo;

        let request = http::Request::builder().body(()).unwrap();
        let (parts, _) = request.into_parts();

        let cert = parts
            .extensions
            .get::<ConnectInfo<PeerClientCert>>()
            .and_then(|ci| ci.0.0.as_ref())
            .and_then(|der| crate::services::oidc::mtls::parse_client_certificate(der).ok());

        assert!(cert.is_none(), "Missing extension must yield None");
    }

    /// When `PeerClientCert` wraps `None` (client connected but presented no cert),
    /// the extractor must yield `None` without panicking.
    #[tokio::test]
    async fn test_optional_client_cert_with_none_der_returns_none() {
        use crate::infra::mtls_listener::PeerClientCert;
        use axum::extract::ConnectInfo;

        let mut request = http::Request::builder().body(()).unwrap();
        request
            .extensions_mut()
            .insert(ConnectInfo(PeerClientCert(None)));
        let (parts, _) = request.into_parts();

        let cert = parts
            .extensions
            .get::<ConnectInfo<PeerClientCert>>()
            .and_then(|ci| ci.0.0.as_ref())
            .and_then(|der| crate::services::oidc::mtls::parse_client_certificate(der).ok());

        assert!(cert.is_none(), "PeerClientCert(None) must yield None");
    }

    #[test]
    fn test_valid_uuid_rejects_wrong_segment_count() {
        // Too few segments to be a UUID
        let json = "\"not-valid\"";
        let result: Result<ValidUuid, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_valid_uuid_rejects_wrong_length() {
        // Correct hyphen positions but wrong total length (one char short)
        let json = "\"019508a7-cc17-7a7c-a00b-632964b2750\"";
        let result: Result<ValidUuid, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_valid_uuid_rejects_non_hex_chars() {
        // UUID-shaped but contains non-hex characters
        let json = "\"zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz\"";
        let result: Result<ValidUuid, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_valid_uuid_output_is_always_hyphenated_lowercase() {
        // Compact input normalizes to canonical hyphenated form
        let compact = "\"019508a7cc177a7ca00b632964b2750e\"";
        let uuid: ValidUuid = serde_json::from_str(compact).unwrap();
        let output = uuid.to_string();
        // Must contain hyphens
        assert!(output.contains('-'), "output must be hyphenated: {output}");
        // Must be lowercase
        assert_eq!(
            output,
            output.to_lowercase(),
            "output must be lowercase: {output}"
        );
    }
}
