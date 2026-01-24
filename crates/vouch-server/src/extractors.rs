//! HTTP request extractors for authentication context.

use axum::http::HeaderMap;

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
}
