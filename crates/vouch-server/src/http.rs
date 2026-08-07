// SPDX-License-Identifier: Apache-2.0 OR MIT
//! HTTP authentication wire helpers (RFC 9110 / RFC 6750).
//!
//! Crate-root shared module (like `config` and `email`): importable from
//! every layer, so handlers and infra parse and build `Authorization` /
//! `WWW-Authenticate` values through one implementation.

/// Extract the token from an `Authorization` header value when its
/// auth-scheme matches `scheme`.
///
/// RFC 9110 Section 11.1: the auth-scheme token is case-insensitive, so
/// `BEARER`, `bearer`, and `BeArEr` all match `Bearer` (likewise `DPoP`).
/// This is the single scheme matcher — comparing schemes by hand at call
/// sites is how non-canonical casings ended up accepted by token auth but
/// rejected by signature key resolution.
#[must_use]
pub(crate) fn strip_auth_scheme<'a>(header_value: &'a str, scheme: &str) -> Option<&'a str> {
    let (value_scheme, token) = header_value.split_once(' ')?;
    value_scheme.eq_ignore_ascii_case(scheme).then_some(token)
}

/// Extract a Bearer token from a request's `Authorization` header.
///
/// Composes the header lookup with [`strip_auth_scheme`] for the common
/// bearer-only case. Callers that must distinguish a missing header from a
/// wrong scheme (for distinct error messages), or that also accept `DPoP`,
/// use [`strip_auth_scheme`] directly.
#[must_use]
pub(crate) fn bearer_token(headers: &axum::http::HeaderMap) -> Option<&str> {
    let value = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    strip_auth_scheme(value, "Bearer")
}

/// Filter a challenge parameter value to RFC 6750 Section 3's permitted set
/// (%x20-21 / %x23-5B / %x5D-7E — no double quote, no backslash, no control
/// characters), so no value can produce a malformed or quote-escaping
/// challenge.
pub(crate) fn sanitize_challenge_value(value: &str) -> String {
    let mut sanitized = String::with_capacity(value.len());
    for c in value.chars() {
        if (' '..='!').contains(&c) || ('#'..='[').contains(&c) || (']'..='~').contains(&c) {
            sanitized.push(c);
        }
    }
    sanitized
}

/// Build an RFC 6750 Section 3 `WWW-Authenticate: Bearer ...` challenge.
///
/// Every parameter value passes through [`sanitize_challenge_value`]. This is
/// the single constructor for bearer challenges — do not `format!` one by
/// hand; the sanitization only guards values that go through here.
///
/// Empty `params` produce the bare `Bearer` challenge used when a request
/// carries no credentials at all: RFC 6750 Section 3.1 says that response
/// SHOULD NOT include error information, and the bare scheme is valid under
/// RFC 9110 Section 11.6.1's challenge grammar (auth-params are optional).
pub(crate) fn bearer_challenge(params: &[(&str, &str)]) -> String {
    if params.is_empty() {
        return "Bearer".to_string();
    }
    let mut rendered = Vec::with_capacity(params.len());
    for (name, value) in params {
        let value = sanitize_challenge_value(value);
        rendered.push(format!("{name}=\"{value}\""));
    }
    format!("Bearer {}", rendered.join(", "))
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::{bearer_token, strip_auth_scheme};
    use axum::http::HeaderMap;

    fn headers_with_auth(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            value.parse().expect("valid header value"),
        );
        headers
    }

    #[test]
    fn bearer_token_accepts_scheme_case_variants() {
        for scheme in ["Bearer", "BEARER", "bearer", "BeArEr"] {
            let headers = headers_with_auth(&format!("{scheme} reg-token"));
            assert_eq!(
                bearer_token(&headers),
                Some("reg-token"),
                "{scheme} scheme must be accepted (RFC 9110 case-insensitivity)"
            );
        }
    }

    #[test]
    fn bearer_token_rejects_unrecognized_scheme_or_missing_header() {
        assert_eq!(bearer_token(&headers_with_auth("Basic dXNlcjpwYXNz")), None);
        assert_eq!(bearer_token(&headers_with_auth("Bearer")), None);
        assert_eq!(bearer_token(&HeaderMap::new()), None);
    }

    #[test]
    fn matches_scheme_case_insensitively() {
        assert_eq!(strip_auth_scheme("Bearer tok", "Bearer"), Some("tok"));
        assert_eq!(strip_auth_scheme("BEARER tok", "Bearer"), Some("tok"));
        assert_eq!(strip_auth_scheme("bEaReR tok", "Bearer"), Some("tok"));
        assert_eq!(strip_auth_scheme("DPOP tok", "DPoP"), Some("tok"));
    }

    #[test]
    fn rejects_other_schemes() {
        assert_eq!(strip_auth_scheme("Basic dXNlcg==", "Bearer"), None);
        assert_eq!(strip_auth_scheme("Bearer tok", "DPoP"), None);
    }

    #[test]
    fn rejects_missing_token_separator() {
        assert_eq!(strip_auth_scheme("Bearer", "Bearer"), None);
        assert_eq!(strip_auth_scheme("", "Bearer"), None);
    }

    #[test]
    fn preserves_token_case() {
        // The token itself is case-sensitive (base64url) and may contain
        // further spaces; only the first space splits scheme from token.
        assert_eq!(
            strip_auth_scheme("Bearer AbC. dEf", "Bearer"),
            Some("AbC. dEf")
        );
    }

    #[test]
    fn bearer_challenge_formats_params() {
        assert_eq!(
            super::bearer_challenge(&[("error", "invalid_token"), ("error_description", "bad")]),
            "Bearer error=\"invalid_token\", error_description=\"bad\""
        );
    }

    #[test]
    fn bearer_challenge_empty_params_is_bare_scheme() {
        assert_eq!(super::bearer_challenge(&[]), "Bearer");
    }

    #[test]
    fn bearer_challenge_sanitizes_values() {
        // A quote or backslash in a value must not escape the quoted-string.
        let challenge = super::bearer_challenge(&[("error_description", "a\"b\\c\u{7}d")]);
        assert_eq!(challenge, "Bearer error_description=\"abcd\"");
    }

    #[test]
    fn sanitize_keeps_permitted_ascii() {
        assert_eq!(
            super::sanitize_challenge_value("Use Bearer or DPoP (RFC 9449)!"),
            "Use Bearer or DPoP (RFC 9449)!"
        );
    }
}
