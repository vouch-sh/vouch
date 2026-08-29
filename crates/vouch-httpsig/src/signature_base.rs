// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 9421 Signature Base construction (Section 2.5).
//!
//! The signature base is the canonical byte sequence that gets signed/verified.
//! Each covered component contributes one line: `"component-id": value\n`.
//! The final line is `"@signature-params": (inner-list)` with NO trailing newline.

use crate::component::ComponentIdentifier;
use crate::error::HttpSigError;
use crate::signature_params::SignatureParams;

/// Build the signature base using a pre-serialized params string.
///
/// This avoids double-serialization when the caller needs the params string
/// for both the signature base and the `Signature-Input` header.
///
/// # Errors
///
/// Returns [`HttpSigError`] when a component cannot be resolved or when the
/// resulting base would violate RFC 9421 §2.5 — see [`BaseBuilder`].
pub fn build_request_base_with_params_str<T>(
    req: &http::Request<T>,
    params: &SignatureParams,
    params_str: &str,
) -> Result<Vec<u8>, HttpSigError> {
    let mut base = BaseBuilder::new();

    for component in &params.components {
        let value = component.resolve_from_request(req)?;
        base.push(component, &value)?;
    }

    base.finish(params_str)
}

/// Build the response signature base using a pre-serialized params string.
///
/// # Errors
///
/// Returns [`HttpSigError`] when a component cannot be resolved or when the
/// resulting base would violate RFC 9421 §2.5 — see [`BaseBuilder`].
pub fn build_response_base_with_params_str<T, U>(
    resp: &http::Response<T>,
    req: Option<&http::Request<U>>,
    params: &SignatureParams,
    params_str: &str,
) -> Result<Vec<u8>, HttpSigError> {
    let mut base = BaseBuilder::new();

    for component in &params.components {
        let value = component.resolve_from_response(resp, req)?;
        base.push(component, &value)?;
    }

    base.finish(params_str)
}

/// Accumulates signature base lines, enforcing the RFC 9421 §2.5 rules that
/// constrain the base as a whole rather than a single component value.
///
/// Requests and responses share it so those rules cannot end up applied on one
/// side only. §2.5 is emphatic about the consequence of a violation: "All
/// errors produced as described MUST fail the algorithm immediately, without
/// outputting a signature base."
struct BaseBuilder {
    base: Vec<u8>,
    seen: Vec<String>,
}

impl BaseBuilder {
    fn new() -> Self {
        Self {
            base: Vec::new(),
            seen: Vec::new(),
        }
    }

    /// Append one `"component-id": value` line (§2.5 steps 2.2 through 2.7).
    fn push(&mut self, component: &ComponentIdentifier, value: &str) -> Result<(), HttpSigError> {
        let id = component.serialize_id();

        // Step 2.1: "If the component identifier (including its parameters) has
        // already been added to the signature base, produce an error."
        if self.seen.contains(&id) {
            return Err(HttpSigError::BaseConstruction(format!(
                "component identifier {id} appears more than once in the covered components"
            )));
        }

        // The signature-base-line ABNF admits only `*( VCHAR / SP )` in a
        // component value, annotated "no obs-fold nor obs-text". A value
        // carrying a newline would forge an additional line in the base.
        if let Some(byte) = value.bytes().find(|byte| !(0x20..=0x7e).contains(byte)) {
            return Err(HttpSigError::BaseConstruction(format!(
                "component {id} resolved to a value containing byte 0x{byte:02x}, \
                 which the signature base does not admit"
            )));
        }

        self.base.extend_from_slice(id.as_bytes());
        self.base.extend_from_slice(b": ");
        self.base.extend_from_slice(value.as_bytes());
        self.base.push(b'\n');
        self.seen.push(id);

        Ok(())
    }

    /// Append the `@signature-params` line and return the base (§2.5 steps 3
    /// and 4).
    fn finish(mut self, params_str: &str) -> Result<Vec<u8>, HttpSigError> {
        self.base.extend_from_slice(b"\"@signature-params\": ");
        self.base.extend_from_slice(params_str.as_bytes());

        // Step 4: "Produce an error if the output string contains any non-ASCII
        // characters."
        if !self.base.is_ascii() {
            return Err(HttpSigError::BaseConstruction(
                "signature base contains non-ASCII characters".into(),
            ));
        }

        Ok(self.base)
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;
    use crate::component::{ComponentIdentifier, ComponentParam, ComponentParams};

    fn make_request(method: &str, uri: &str, headers: &[(&str, &str)]) -> http::Request<()> {
        let mut builder = http::Request::builder().method(method).uri(uri);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder.body(()).unwrap()
    }

    // RFC 9421 §2.5: each covered component contributes one line to the signature base.
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

        let base = build_request_base_with_params_str(&req, &params, &params.serialize()).unwrap();
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

    // RFC 9421 §2.5: @signature-params is the final line and carries no trailing newline.
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

        let base = build_request_base_with_params_str(&req, &params, &params.serialize()).unwrap();
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

    // RFC 9421 §2.5: a response base includes the @status derived component.
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

        let base = build_response_base_with_params_str::<(), ()>(
            &resp,
            None,
            &params,
            &params.serialize(),
        )
        .unwrap();
        let base_str = std::str::from_utf8(&base).unwrap();
        assert!(base_str.starts_with("\"@status\": 200\n"));
        assert!(base_str.contains("\"content-type\": application/json\n"));
    }

    // RFC 9421 §2.5: a base covering no components is still well formed.
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

        let base = build_request_base_with_params_str(&req, &params, &params.serialize()).unwrap();
        let base_str = std::str::from_utf8(&base).unwrap();
        assert!(base_str.starts_with("\"@signature-params\": "));
    }

    // RFC 9421 §2.5: the @query derived component appears verbatim in the base.
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

        let base = build_request_base_with_params_str(&req, &params, &params.serialize()).unwrap();
        let base_str = std::str::from_utf8(&base).unwrap();
        assert!(base_str.contains("\"@path\": /path\n"));
        assert!(base_str.contains("\"@query\": ?param=value\n"));
    }

    // RFC 9421 §2.5: a component that cannot be resolved is an error in base generation.
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

        let result = build_request_base_with_params_str(&req, &params, &params.serialize());
        assert!(result.is_err());
    }

    fn base_for(
        req: &http::Request<()>,
        components: Vec<ComponentIdentifier>,
    ) -> Result<Vec<u8>, HttpSigError> {
        let params = SignatureParams {
            components,
            alg: None,
            keyid: None,
            created: Some(100),
            expires: None,
            nonce: None,
            tag: None,
        };
        build_request_base_with_params_str(req, &params, &params.serialize())
    }

    // RFC 9421 §2.5 step 2.1: "If the component identifier (including its
    // parameters) has already been added to the signature base, produce an
    // error."
    #[test]
    fn test_repeated_component_identifier_is_an_error() {
        let req = make_request("GET", "https://example.com/p", &[]);
        assert!(
            base_for(
                &req,
                vec![ComponentIdentifier::method(), ComponentIdentifier::method()],
            )
            .is_err()
        );
    }

    // RFC 9421 §2.1.2: "Each parameterized key for a given field MUST NOT
    // appear more than once in the signature base." Two different keys on the
    // same field are distinct identifiers and stay legal.
    #[test]
    fn test_repeated_dictionary_key_is_an_error_but_distinct_keys_are_not() {
        let req = make_request("GET", "https://example.com/p", &[("x-dict", "a=1, b=2")]);
        let keyed = |key: &str| ComponentIdentifier::Field {
            name: "x-dict".into(),
            params: ComponentParams::from_iter([ComponentParam::Key(key.into())]),
        };

        assert!(base_for(&req, vec![keyed("a"), keyed("a")]).is_err());
        assert!(base_for(&req, vec![keyed("a"), keyed("b")]).is_ok());
    }

    // RFC 9421 §2.5 step 4: "Produce an error if the output string contains any
    // non-ASCII characters." Field resolution rejects such a value first, per
    // §2.1, so no base is produced either way — which is the property this
    // pins. The check in `finish` remains the backstop for the rest of the
    // base, the `@signature-params` line included.
    #[test]
    fn test_non_ascii_component_value_never_reaches_a_base() {
        let req = make_request("GET", "https://example.com/p", &[("x-val", "caf\u{e9}")]);
        assert!(base_for(&req, vec![ComponentIdentifier::field("x-val")]).is_err());
    }

    // RFC 9421 §2.5: the signature-base-line ABNF admits only
    // `*( VCHAR / SP )` as a component value — "no obs-fold nor obs-text". A
    // value carrying a newline would forge an extra line in the base, so the
    // builder refuses it. No resolver can currently produce one — `http`
    // rejects control characters in header values, and §2.2.8 re-encoding
    // escapes them — which makes this the backstop rather than the first line
    // of defence, and the reason it is exercised against the builder directly.
    #[test]
    fn test_newline_in_component_value_is_refused() {
        let mut base = BaseBuilder::new();
        assert!(
            base.push(&ComponentIdentifier::field("x-val"), "line\nbreak")
                .is_err()
        );
    }
}
