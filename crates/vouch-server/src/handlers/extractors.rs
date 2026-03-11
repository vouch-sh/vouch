// SPDX-License-Identifier: BUSL-1.1
//! HTTP request extractors for authentication context.

use axum::extract::rejection::PathRejection;
use axum::extract::{FromRequestParts, Path};
use axum::http::{HeaderMap, StatusCode};
use http::request::Parts;
use serde::Deserialize;

use std::net::IpAddr;

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

impl<S: Send + Sync> FromRequestParts<S> for ClientInfo {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let client_ip = parts
            .extensions
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
            .map(|ci| ci.0.ip().to_canonical());

        let mut info = Self::from_headers(&parts.headers);
        info.client_ip = client_ip;
        Ok(info)
    }
}

impl ClientInfo {
    /// Extract client metadata from HTTP headers.
    ///
    /// Extracts User-Agent and `Vouch-Client-*` headers. Does NOT extract
    /// `client_ip` — that comes from the TCP socket in `FromRequestParts`.
    #[must_use]
    pub fn from_headers(headers: &HeaderMap) -> Self {
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn test_extract_user_agent() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "user-agent",
            HeaderValue::from_static("vouch-cli/0.1.0 (macos; aarch64)"),
        );

        let info = ClientInfo::from_headers(&headers);
        assert_eq!(
            info.user_agent,
            Some("vouch-cli/0.1.0 (macos; aarch64)".to_string())
        );
    }

    #[test]
    fn test_extract_no_headers() {
        let headers = HeaderMap::new();
        let info = ClientInfo::from_headers(&headers);
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

        let info = ClientInfo::from_headers(&headers);
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

        let info = ClientInfo::from_headers(&headers);
        assert_eq!(info.client_os, None);
    }

    #[test]
    fn test_extract_vouch_client_header_rejects_empty() {
        let mut headers = HeaderMap::new();
        headers.insert("vouch-client-os", HeaderValue::from_static(""));

        let info = ClientInfo::from_headers(&headers);
        assert_eq!(info.client_os, None);
    }

    #[test]
    fn test_extract_vouch_client_header_trims_whitespace() {
        let mut headers = HeaderMap::new();
        headers.insert("vouch-client-os", HeaderValue::from_static("  macos  "));

        let info = ClientInfo::from_headers(&headers);
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
        let info = ClientInfo::from_headers(&headers);
        assert_eq!(info.client_hostname.as_deref(), Some(hostname.as_str()));

        // One over should be rejected
        let too_long = "a".repeat(MAX_HOSTNAME_LEN + 1);
        let mut headers2 = HeaderMap::new();
        headers2.insert(
            "vouch-client-hostname",
            HeaderValue::from_str(&too_long).unwrap(),
        );
        let info2 = ClientInfo::from_headers(&headers2);
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

        let info = ClientInfo::from_headers(&headers);
        assert_eq!(info.client_os, None);
    }

    #[test]
    fn test_extract_validated_header_accepts_printable_ascii() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "vouch-client-version",
            HeaderValue::from_static("1.2.3-beta+build.456"),
        );

        let info = ClientInfo::from_headers(&headers);
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
