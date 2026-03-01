// SPDX-License-Identifier: BUSL-1.1
//! HTTP request extractors for authentication context.

use axum::extract::rejection::PathRejection;
use axum::extract::{FromRequestParts, Path};
use axum::http::{HeaderMap, StatusCode};
use http::request::Parts;
use serde::Deserialize;

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

/// Client information extracted from HTTP headers.
#[derive(Debug, Clone, Default)]
pub struct ClientInfo {
    /// Client IP address (from X-Forwarded-For or X-Real-IP headers).
    pub client_ip: Option<String>,
    /// User-Agent header.
    pub user_agent: Option<String>,
}

impl ClientInfo {
    /// Extract client information from HTTP headers.
    ///
    /// Extracts:
    /// - Client IP from X-Forwarded-For (first IP) or X-Real-IP headers
    /// - User-Agent header
    #[must_use]
    pub fn from_headers(headers: &HeaderMap) -> Self {
        let client_ip = extract_client_ip(headers);
        let user_agent = headers
            .get("user-agent")
            .and_then(|h| h.to_str().ok())
            .map(String::from);

        Self {
            client_ip,
            user_agent,
        }
    }
}

/// Extract client IP from headers.
///
/// Checks in order:
/// 1. X-Forwarded-For (first IP in the list)
/// 2. X-Real-IP
/// 3. CF-Connecting-IP (Cloudflare)
fn extract_client_ip(headers: &HeaderMap) -> Option<String> {
    // Try X-Forwarded-For first (may contain multiple IPs)
    if let Some(xff) = headers.get("x-forwarded-for").and_then(|h| h.to_str().ok()) {
        // X-Forwarded-For format: "client, proxy1, proxy2"
        // We want the first (leftmost) IP which is the original client
        if let Some(first_ip) = xff.split(',').next() {
            let trimmed = first_ip.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }

    // Try X-Real-IP (single IP)
    if let Some(real_ip) = headers.get("x-real-ip").and_then(|h| h.to_str().ok()) {
        let trimmed = real_ip.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }

    // Try CF-Connecting-IP (Cloudflare)
    if let Some(cf_ip) = headers
        .get("cf-connecting-ip")
        .and_then(|h| h.to_str().ok())
    {
        let trimmed = cf_ip.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }

    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn test_extract_x_forwarded_for_single() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("192.168.1.1"));

        let info = ClientInfo::from_headers(&headers);
        assert_eq!(info.client_ip, Some("192.168.1.1".to_string()));
    }

    #[test]
    fn test_extract_x_forwarded_for_multiple() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.1, 198.51.100.1, 192.0.2.1"),
        );

        let info = ClientInfo::from_headers(&headers);
        assert_eq!(info.client_ip, Some("203.0.113.1".to_string()));
    }

    #[test]
    fn test_extract_x_real_ip() {
        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", HeaderValue::from_static("10.0.0.1"));

        let info = ClientInfo::from_headers(&headers);
        assert_eq!(info.client_ip, Some("10.0.0.1".to_string()));
    }

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
