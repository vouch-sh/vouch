// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 9728 §5.2: `WWW-Authenticate: resource_metadata` injection.
//!
//! This middleware decorates 401 responses from OAuth 2.0 protected
//! resources with the `resource_metadata` parameter that points
//! clients at the Protected Resource Metadata document.
//!
//! Per RFC 9728 §5.2:
//!
//! > Upon receiving a request with an access token, the protected
//! > resource, if the request is not authorized, responds with an
//! > HTTP 401 (Unauthorized) status code. The WWW-Authenticate
//! > response header … MAY include a `resource_metadata` parameter.
//!
//! The middleware is idempotent: if the upstream handler already
//! emitted a `resource_metadata` parameter, we leave it untouched.
//! When no `WWW-Authenticate` header is present, we insert a minimal
//! `Bearer` challenge with only the `resource_metadata` parameter.
//!
//! Scope: apply ONLY to protected-resource sub-routers (credential
//! issuance, userinfo, introspect, register, keys, admin API, SCIM,
//! applications). Do not apply to authorization-server metadata or
//! pure UI routes — those aren't OAuth protected resources and 401s
//! there have different semantics.

use crate::AppState;
use axum::{
    extract::{Request, State},
    http::{HeaderName, HeaderValue, StatusCode, header::WWW_AUTHENTICATE},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;

/// Name of the `WWW-Authenticate` parameter defined by RFC 9728 §5.2.
const RESOURCE_METADATA_PARAM: &str = "resource_metadata";

/// Axum `from_fn_with_state` layer: append `resource_metadata` to
/// 401 `WWW-Authenticate` headers.
///
/// Uses a single snapshot of `AppState.config()` per request to pick
/// up the current `base_url` (which is hot-reloadable).
pub async fn layer(State(state): State<Arc<AppState>>, req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;

    if resp.status() != StatusCode::UNAUTHORIZED {
        return resp;
    }

    // Snapshot configuration exactly once for this response.
    let base_url = state.config().base_url.clone();
    let metadata_url = format!(
        "{}{}",
        base_url.trim_end_matches('/'),
        crate::services::oidc::protected_resource::WELL_KNOWN_SUFFIX,
    );

    append_resource_metadata(resp.headers_mut(), &metadata_url);
    resp
}

/// Idempotently add a `resource_metadata="<url>"` parameter to the
/// `WWW-Authenticate` header.
///
/// * No existing header → insert `Bearer resource_metadata="<url>"`.
/// * Existing header that already contains a `resource_metadata`
///   parameter → leave unchanged.
/// * Existing header without the parameter → append
///   `, resource_metadata="<url>"`.
///
/// The `<url>` value is emitted inside an RFC 7235 `quoted-string`.
/// Base URLs contain no characters that require escaping (URL-safe
/// ASCII), but as a defense-in-depth measure we strip `\` and `"`
/// from the URL before interpolation.
fn append_resource_metadata(headers: &mut axum::http::HeaderMap, url: &str) {
    let sanitized_url = sanitize_for_quoted_string(url);
    let parameter = format!("{RESOURCE_METADATA_PARAM}=\"{sanitized_url}\"");

    match headers.get(WWW_AUTHENTICATE) {
        None => {
            if let Ok(value) = HeaderValue::from_str(&format!("Bearer {parameter}")) {
                headers.insert(WWW_AUTHENTICATE, value);
            }
        }
        Some(existing) => {
            let Ok(existing_str) = existing.to_str() else {
                // Non-ASCII value we cannot safely extend; leave alone.
                return;
            };
            if has_resource_metadata_parameter(existing_str) {
                return;
            }
            let new_value = format!("{existing_str}, {parameter}");
            if let Ok(value) = HeaderValue::from_str(&new_value) {
                headers.insert(WWW_AUTHENTICATE, value);
            }
        }
    }

    // `HeaderName` comparison guard: silence unused_imports if the
    // module is compiled without any WWW_AUTHENTICATE usage (it is
    // always used above, but clippy sometimes grumbles).
    let _ = HeaderName::from_static("www-authenticate");
}

/// Check whether the given `WWW-Authenticate` header already carries a
/// `resource_metadata` parameter.
///
/// This is a simple case-insensitive byte-boundary scan that is
/// sufficient for idempotence — we never need to parse the full
/// header grammar here, only detect our own prior injection. Uses
/// byte indexing because the `resource_metadata` token is pure ASCII
/// and byte offsets in a case-folded ASCII string are equivalent to
/// char offsets for our purposes.
fn has_resource_metadata_parameter(header: &str) -> bool {
    let lower = header.to_ascii_lowercase();
    let lower_bytes = lower.as_bytes();
    let needle = RESOURCE_METADATA_PARAM.as_bytes();
    if needle.is_empty() || lower_bytes.len() < needle.len() {
        return false;
    }
    let last_start = lower_bytes.len() - needle.len();
    let mut i = 0usize;
    while i <= last_start {
        if lower_bytes.get(i..i + needle.len()) == Some(needle) {
            let before_ok = i == 0
                || matches!(
                    lower_bytes.get(i.saturating_sub(1)),
                    Some(b' ' | b',' | b'\t'),
                );
            let after_idx = i + needle.len();
            let after_ok = matches!(lower_bytes.get(after_idx), Some(b'=') | None);
            if before_ok && after_ok {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// Strip characters that would break an RFC 7235 `quoted-string`.
///
/// `quoted-string` forbids unescaped `"` and `\` and bare control
/// characters. URLs produced by `format!("{base_url}{suffix}")`
/// never legitimately contain any of these, so removal is a safe
/// conservative choice that also prevents accidental header
/// injection if `base_url` is ever misconfigured.
fn sanitize_for_quoted_string(value: &str) -> String {
    value
        .chars()
        .filter(|c| !c.is_control() && *c != '"' && *c != '\\')
        .collect()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn appends_when_no_header_present() {
        let mut headers = axum::http::HeaderMap::new();
        append_resource_metadata(
            &mut headers,
            "https://example.test/.well-known/oauth-protected-resource",
        );
        let v = headers.get(WWW_AUTHENTICATE).unwrap().to_str().unwrap();
        assert_eq!(
            v,
            "Bearer resource_metadata=\"https://example.test/.well-known/oauth-protected-resource\""
        );
    }

    #[test]
    fn appends_to_existing_header() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            WWW_AUTHENTICATE,
            HeaderValue::from_static("Bearer error=\"invalid_token\", error_description=\"bad\""),
        );
        append_resource_metadata(
            &mut headers,
            "https://example.test/.well-known/oauth-protected-resource",
        );
        let v = headers.get(WWW_AUTHENTICATE).unwrap().to_str().unwrap();
        assert!(v.contains("error=\"invalid_token\""));
        assert!(v.contains(
            "resource_metadata=\"https://example.test/.well-known/oauth-protected-resource\""
        ));
    }

    #[test]
    fn idempotent_when_already_present() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            WWW_AUTHENTICATE,
            HeaderValue::from_static(
                "Bearer resource_metadata=\"https://pre-existing.test/.well-known/oauth-protected-resource\"",
            ),
        );
        append_resource_metadata(
            &mut headers,
            "https://new.test/.well-known/oauth-protected-resource",
        );
        let v = headers.get(WWW_AUTHENTICATE).unwrap().to_str().unwrap();
        assert!(v.contains("pre-existing.test"));
        assert!(!v.contains("new.test"));
    }

    #[test]
    fn has_resource_metadata_parameter_respects_boundaries() {
        assert!(has_resource_metadata_parameter(
            "Bearer resource_metadata=\"x\""
        ));
        assert!(has_resource_metadata_parameter(
            "Bearer error=\"x\", resource_metadata=\"y\""
        ));
        // Should not match a longer parameter whose prefix happens
        // to be `resource_metadata` (defensive).
        assert!(!has_resource_metadata_parameter(
            "Bearer resource_metadata_extra=\"x\""
        ));
    }

    #[test]
    fn sanitize_strips_quotes_and_backslashes() {
        let raw = "https://bad\"example.com\\/foo";
        let cleaned = sanitize_for_quoted_string(raw);
        assert!(!cleaned.contains('"'));
        assert!(!cleaned.contains('\\'));
    }
}
