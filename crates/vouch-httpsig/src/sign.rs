// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 9421 signature creation.
//!
//! Provides a builder API for constructing HTTP message signatures and
//! attaching them as `Signature-Input` + `Signature` headers.

use crate::algorithm::SigningAlgorithm;
use crate::component::ComponentIdentifier;
use crate::error::HttpSigError;
use crate::sfv::types::{SfvBareItem, SfvDictMember, SfvDictionary, SfvItem, SfvParams};
use crate::signature_base::{
    build_request_base_with_params_str, build_response_base_with_params_str,
};
use crate::signature_params::SignatureParams;

/// Builder for creating HTTP message signatures.
pub struct SignatureBuilder {
    label: String,
    components: Vec<ComponentIdentifier>,
    created: Option<i64>,
    expires: Option<i64>,
    nonce: Option<String>,
    tag: Option<String>,
}

impl SignatureBuilder {
    /// Create a new signature builder with the given label.
    ///
    /// The label identifies this signature in the `Signature-Input` and
    /// `Signature` dictionary headers (e.g., `"sig1"`).
    #[must_use]
    pub fn new(label: &str) -> Self {
        Self {
            label: label.to_string(),
            components: Vec::new(),
            created: None,
            expires: None,
            nonce: None,
            tag: None,
        }
    }

    /// Add the `@method` derived component.
    #[must_use]
    pub fn method(mut self) -> Self {
        self.components.push(ComponentIdentifier::method());
        self
    }

    /// Add the `@authority` derived component.
    #[must_use]
    pub fn authority(mut self) -> Self {
        self.components.push(ComponentIdentifier::authority());
        self
    }

    /// Add the `@path` derived component.
    #[must_use]
    pub fn path(mut self) -> Self {
        self.components.push(ComponentIdentifier::path());
        self
    }

    /// Add the `@query` derived component.
    #[must_use]
    pub fn query(mut self) -> Self {
        self.components.push(ComponentIdentifier::query());
        self
    }

    /// Add the `@status` derived component (responses only).
    #[must_use]
    pub fn status(mut self) -> Self {
        self.components.push(ComponentIdentifier::status());
        self
    }

    /// Add the `@target-uri` derived component.
    #[must_use]
    pub fn target_uri(mut self) -> Self {
        self.components.push(ComponentIdentifier::target_uri());
        self
    }

    /// Add the `@scheme` derived component.
    #[must_use]
    pub fn scheme(mut self) -> Self {
        self.components.push(ComponentIdentifier::scheme());
        self
    }

    /// Add the `@request-target` derived component.
    #[must_use]
    pub fn request_target(mut self) -> Self {
        self.components.push(ComponentIdentifier::request_target());
        self
    }

    /// Add an HTTP field (header) component.
    #[must_use]
    pub fn field(mut self, name: &str) -> Self {
        self.components.push(ComponentIdentifier::field(name));
        self
    }

    /// Set the `created` parameter to the current time.
    #[must_use]
    pub fn created_now(mut self) -> Self {
        self.created = Some(jiff::Timestamp::now().as_second());
        self
    }

    /// Set the `created` parameter to a specific timestamp.
    #[must_use]
    pub fn created(mut self, timestamp: i64) -> Self {
        self.created = Some(timestamp);
        self
    }

    /// Set the `expires` parameter relative to `created`.
    ///
    /// If `created` is not set, this uses the current time as the base.
    #[must_use]
    pub fn expires_in(mut self, seconds: i64) -> Self {
        let base = self
            .created
            .unwrap_or_else(|| jiff::Timestamp::now().as_second());
        self.expires = Some(base + seconds);
        self
    }

    /// Set the `nonce` parameter.
    #[must_use]
    pub fn nonce(mut self, nonce: &str) -> Self {
        self.nonce = Some(nonce.to_string());
        self
    }

    /// Set the `tag` parameter.
    #[must_use]
    pub fn tag(mut self, tag: &str) -> Self {
        self.tag = Some(tag.to_string());
        self
    }

    /// Sign an HTTP request and attach `Signature-Input` + `Signature` headers.
    ///
    /// # Errors
    ///
    /// Returns [`HttpSigError`] on base construction or signing failure.
    pub fn sign_request<T>(
        self,
        req: &mut http::Request<T>,
        signer: &dyn SigningAlgorithm,
    ) -> Result<(), HttpSigError> {
        let params = self.build_params(signer);
        // Serialize the params once — used for both signature base and Signature-Input header
        let params_str = params.serialize();
        let base = build_request_base_with_params_str(req, &params, &params_str)?;
        let signature = signer.sign(&base)?;

        append_signature_headers_with_params_str(
            req.headers_mut(),
            &self.label,
            &params_str,
            &signature,
        )
    }

    /// Sign an HTTP response and attach `Signature-Input` + `Signature` headers.
    ///
    /// # Errors
    ///
    /// Returns [`HttpSigError`] on base construction or signing failure.
    pub fn sign_response<T, U>(
        self,
        resp: &mut http::Response<T>,
        req: Option<&http::Request<U>>,
        signer: &dyn SigningAlgorithm,
    ) -> Result<(), HttpSigError> {
        let params = self.build_params(signer);
        let params_str = params.serialize();
        let base = build_response_base_with_params_str(resp, req, &params, &params_str)?;
        let signature = signer.sign(&base)?;

        append_signature_headers_with_params_str(
            resp.headers_mut(),
            &self.label,
            &params_str,
            &signature,
        )
    }

    fn build_params(&self, signer: &dyn SigningAlgorithm) -> SignatureParams {
        SignatureParams {
            components: self.components.clone(),
            alg: Some(signer.algorithm_id().to_string()),
            keyid: Some(signer.key_id().to_string()),
            created: self.created,
            expires: self.expires,
            nonce: self.nonce.clone(),
            tag: self.tag.clone(),
        }
    }
}

/// Append `Signature-Input` and `Signature` headers using a pre-serialized params string.
fn append_signature_headers_with_params_str(
    headers: &mut http::HeaderMap,
    label: &str,
    params_str: &str,
    signature: &[u8],
) -> Result<(), HttpSigError> {
    // Build Signature-Input directly from the pre-serialized params string
    let sig_input = format!("{label}={params_str}");
    let sig_value = build_signature_dict(label, signature);

    let input_hv = http::HeaderValue::from_str(&sig_input)
        .map_err(|e| HttpSigError::BaseConstruction(format!("Signature-Input header: {e}")))?;
    let sig_hv = http::HeaderValue::from_str(&sig_value)
        .map_err(|e| HttpSigError::BaseConstruction(format!("Signature header: {e}")))?;

    headers.append("signature-input", input_hv);
    headers.append("signature", sig_hv);

    Ok(())
}

/// Build the `Signature` header value as an SFV Dictionary.
fn build_signature_dict(label: &str, signature: &[u8]) -> String {
    let dict = SfvDictionary {
        entries: vec![(
            label.to_string(),
            SfvDictMember::Item(SfvItem {
                value: SfvBareItem::ByteSequence(signature.to_vec()),
                params: SfvParams::new(),
            }),
        )],
    };
    crate::sfv::serialize::serialize_dictionary(&dict)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code: panic on assertion failure is acceptable")]
mod tests {
    use super::*;
    use crate::algorithm::hmac_sha256::HmacSha256Key;

    fn make_request(method: &str, uri: &str, headers: &[(&str, &str)]) -> http::Request<()> {
        let mut builder = http::Request::builder().method(method).uri(uri);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder.body(()).unwrap()
    }

    #[test]
    fn test_sign_request_adds_headers() {
        let key = HmacSha256Key::new(b"test-secret", "test-key-1");
        let mut req = make_request(
            "POST",
            "https://example.com/foo",
            &[("content-type", "application/json")],
        );

        SignatureBuilder::new("sig1")
            .method()
            .authority()
            .path()
            .field("content-type")
            .created(1_618_884_473)
            .tag("test")
            .sign_request(&mut req, &key)
            .unwrap();

        assert!(req.headers().contains_key("signature-input"));
        assert!(req.headers().contains_key("signature"));

        let sig_input = req
            .headers()
            .get("signature-input")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(sig_input.starts_with("sig1="));
        assert!(sig_input.contains("\"@method\""));
        assert!(sig_input.contains("\"@authority\""));
        assert!(sig_input.contains("\"@path\""));
        assert!(sig_input.contains("\"content-type\""));
        assert!(sig_input.contains(";created=1618884473"));
        assert!(sig_input.contains(";tag=\"test\""));
    }

    #[test]
    fn test_sign_response_adds_headers() {
        let key = HmacSha256Key::new(b"test-secret", "server-key");
        let mut resp = http::Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .body(())
            .unwrap();

        SignatureBuilder::new("sig1")
            .status()
            .field("content-type")
            .created(100)
            .sign_response(&mut resp, None::<&http::Request<()>>, &key)
            .unwrap();

        assert!(resp.headers().contains_key("signature-input"));
        assert!(resp.headers().contains_key("signature"));
    }

    #[test]
    fn test_multiple_signatures() {
        let key1 = HmacSha256Key::new(b"secret1", "k1");
        let key2 = HmacSha256Key::new(b"secret2", "k2");

        let mut req = make_request("GET", "https://example.com/", &[]);

        SignatureBuilder::new("sig1")
            .method()
            .created(100)
            .sign_request(&mut req, &key1)
            .unwrap();

        SignatureBuilder::new("sig2")
            .method()
            .authority()
            .created(100)
            .sign_request(&mut req, &key2)
            .unwrap();

        // Both signature-input and signature headers should have 2 entries
        let inputs: Vec<_> = req.headers().get_all("signature-input").iter().collect();
        assert_eq!(inputs.len(), 2);

        let sigs: Vec<_> = req.headers().get_all("signature").iter().collect();
        assert_eq!(sigs.len(), 2);
    }

    #[test]
    fn test_expires_in() {
        let key = HmacSha256Key::new(b"s", "k");
        let mut req = make_request("GET", "https://example.com/", &[]);

        SignatureBuilder::new("sig1")
            .method()
            .created(1000)
            .expires_in(3600)
            .sign_request(&mut req, &key)
            .unwrap();

        let sig_input = req
            .headers()
            .get("signature-input")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(sig_input.contains(";expires=4600"));
    }

    #[test]
    fn test_nonce_included() {
        let key = HmacSha256Key::new(b"s", "k");
        let mut req = make_request("GET", "https://example.com/", &[]);

        SignatureBuilder::new("sig1")
            .method()
            .created(100)
            .nonce("abc-123")
            .sign_request(&mut req, &key)
            .unwrap();

        let sig_input = req
            .headers()
            .get("signature-input")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(sig_input.contains(";nonce=\"abc-123\""));
    }
}
