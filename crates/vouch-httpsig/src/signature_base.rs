// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 9421 Signature Base construction (Section 2.5).
//!
//! The signature base is the canonical byte sequence that gets signed/verified.
//! Each covered component contributes one line: `"component-id": value\n`.
//! The final line is `"@signature-params": (inner-list)` with NO trailing newline.

use crate::error::HttpSigError;
use crate::signature_params::SignatureParams;

/// Build the signature base for an HTTP request.
///
/// # Errors
///
/// Returns [`HttpSigError::MissingComponent`] if a required component cannot
/// be resolved from the request.
pub fn build_request_base<T>(
    req: &http::Request<T>,
    params: &SignatureParams,
) -> Result<Vec<u8>, HttpSigError> {
    let params_str = params.serialize();
    build_request_base_with_params_str(req, params, &params_str)
}

/// Build the signature base using a pre-serialized params string.
///
/// This avoids double-serialization when the caller needs the params string
/// for both the signature base and the `Signature-Input` header.
pub fn build_request_base_with_params_str<T>(
    req: &http::Request<T>,
    params: &SignatureParams,
    params_str: &str,
) -> Result<Vec<u8>, HttpSigError> {
    let mut base = Vec::new();

    for component in &params.components {
        let value = component.resolve_from_request(req)?;
        let id = component.serialize_id();
        base.extend_from_slice(id.as_bytes());
        base.extend_from_slice(b": ");
        base.extend_from_slice(value.as_bytes());
        base.push(b'\n');
    }

    base.extend_from_slice(b"\"@signature-params\": ");
    base.extend_from_slice(params_str.as_bytes());

    Ok(base)
}

/// Build the signature base for an HTTP response.
///
/// An optional related request may be provided for components with the `;req` flag.
///
/// # Errors
///
/// Returns [`HttpSigError::MissingComponent`] if a required component cannot
/// be resolved from the response (or the related request when `;req` is set).
pub fn build_response_base<T, U>(
    resp: &http::Response<T>,
    req: Option<&http::Request<U>>,
    params: &SignatureParams,
) -> Result<Vec<u8>, HttpSigError> {
    let params_str = params.serialize();
    build_response_base_with_params_str(resp, req, params, &params_str)
}

/// Build the response signature base using a pre-serialized params string.
pub fn build_response_base_with_params_str<T, U>(
    resp: &http::Response<T>,
    req: Option<&http::Request<U>>,
    params: &SignatureParams,
    params_str: &str,
) -> Result<Vec<u8>, HttpSigError> {
    let mut base = Vec::new();

    for component in &params.components {
        let value = component.resolve_from_response(resp, req)?;
        let id = component.serialize_id();
        base.extend_from_slice(id.as_bytes());
        base.extend_from_slice(b": ");
        base.extend_from_slice(value.as_bytes());
        base.push(b'\n');
    }

    base.extend_from_slice(b"\"@signature-params\": ");
    base.extend_from_slice(params_str.as_bytes());

    Ok(base)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
mod tests {
    use super::*;
    use crate::component::ComponentIdentifier;

    fn make_request(method: &str, uri: &str, headers: &[(&str, &str)]) -> http::Request<()> {
        let mut builder = http::Request::builder().method(method).uri(uri);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder.body(()).unwrap()
    }

    #[test]
    fn test_basic_request_base() {
        let req = make_request(
            "POST",
            "https://example.com/foo?param=Value&Pet=dog",
            &[
                ("host", "example.com"),
                ("content-type", "application/json"),
            ],
        );

        let params = SignatureParams {
            components: vec![
                ComponentIdentifier::method(),
                ComponentIdentifier::authority(),
                ComponentIdentifier::path(),
                ComponentIdentifier::field("content-type"),
            ],
            alg: Some("hmac-sha256".into()),
            keyid: Some("test-key".into()),
            created: Some(1_618_884_473),
            expires: None,
            nonce: None,
            tag: None,
        };

        let base = build_request_base(&req, &params).unwrap();
        let base_str = std::str::from_utf8(&base).unwrap();

        // Verify individual lines
        assert!(base_str.starts_with("\"@method\": POST\n"));
        assert!(base_str.contains("\"@authority\": example.com\n"));
        assert!(base_str.contains("\"@path\": /foo\n"));
        assert!(base_str.contains("\"content-type\": application/json\n"));

        // Verify @signature-params is last and has no trailing newline
        assert!(base_str.contains("\"@signature-params\": "));
        assert!(!base_str.ends_with('\n'));
    }

    #[test]
    fn test_signature_params_is_final_line() {
        let req = make_request("GET", "https://example.com/", &[]);

        let params = SignatureParams {
            components: vec![ComponentIdentifier::method()],
            alg: None,
            keyid: None,
            created: Some(100),
            expires: None,
            nonce: None,
            tag: None,
        };

        let base = build_request_base(&req, &params).unwrap();
        let base_str = std::str::from_utf8(&base).unwrap();
        let lines: Vec<&str> = base_str.split('\n').collect();

        // Last line should start with "@signature-params"
        let last = lines.last().unwrap();
        assert!(
            last.starts_with("\"@signature-params\": "),
            "last line: {last}"
        );

        // No trailing newline
        assert!(!base_str.ends_with('\n'));
    }

    #[test]
    fn test_response_base_with_status() {
        let resp = http::Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .body(())
            .unwrap();

        let params = SignatureParams {
            components: vec![
                ComponentIdentifier::status(),
                ComponentIdentifier::field("content-type"),
            ],
            alg: None,
            keyid: None,
            created: Some(100),
            expires: None,
            nonce: None,
            tag: None,
        };

        let base = build_response_base::<(), ()>(&resp, None, &params).unwrap();
        let base_str = std::str::from_utf8(&base).unwrap();
        assert!(base_str.starts_with("\"@status\": 200\n"));
        assert!(base_str.contains("\"content-type\": application/json\n"));
    }

    #[test]
    fn test_empty_components() {
        let req = make_request("GET", "https://example.com/", &[]);
        let params = SignatureParams {
            components: vec![],
            alg: None,
            keyid: None,
            created: Some(100),
            expires: None,
            nonce: None,
            tag: None,
        };

        let base = build_request_base(&req, &params).unwrap();
        let base_str = std::str::from_utf8(&base).unwrap();
        assert!(base_str.starts_with("\"@signature-params\": "));
    }

    #[test]
    fn test_query_component_in_base() {
        let req = make_request("GET", "https://example.com/path?param=value", &[]);
        let params = SignatureParams {
            components: vec![ComponentIdentifier::path(), ComponentIdentifier::query()],
            alg: None,
            keyid: None,
            created: Some(100),
            expires: None,
            nonce: None,
            tag: None,
        };

        let base = build_request_base(&req, &params).unwrap();
        let base_str = std::str::from_utf8(&base).unwrap();
        assert!(base_str.contains("\"@path\": /path\n"));
        assert!(base_str.contains("\"@query\": ?param=value\n"));
    }

    #[test]
    fn test_missing_component_error() {
        let req = make_request("GET", "https://example.com/", &[]);
        let params = SignatureParams {
            components: vec![ComponentIdentifier::field("x-missing")],
            alg: None,
            keyid: None,
            created: Some(100),
            expires: None,
            nonce: None,
            tag: None,
        };

        let result = build_request_base(&req, &params);
        assert!(result.is_err());
    }
}
